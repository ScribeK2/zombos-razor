//! A fake release server over https (a throwaway CA) and minisign signing for the update tests.
//! Needs `#[path = "common/tls.rs"] mod pki;` next to it.
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use blake2::{Blake2b512, Digest as _};
use data_encoding::BASE64;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use sha2::Sha256;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use zombo_core::update::Endpoints;

use super::pki::Ca;

/// The seed behind the public key embedded in `update_key.pub` while it holds the TEST key.
pub const TEST_SEED: [u8; 32] = *b"zombo-razor-update-test-key-seed";
pub const KEY_ID: [u8; 8] = *b"ZRTESTKY";
pub const REPO: &str = "owner/repo";

pub struct TestKey {
    pair: Ed25519KeyPair,
    key_id: [u8; 8],
}

impl TestKey {
    pub fn embedded() -> TestKey {
        TestKey { pair: Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap(), key_id: KEY_ID }
    }

    pub fn random() -> TestKey {
        let mut seed = [0u8; 32];
        SystemRandom::new().fill(&mut seed).unwrap();
        let mut key_id = [0u8; 8];
        SystemRandom::new().fill(&mut key_id).unwrap();
        TestKey { pair: Ed25519KeyPair::from_seed_unchecked(&seed).unwrap(), key_id }
    }

    /// The two lines of a minisign public key file.
    pub fn public_file(&self) -> String {
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(self.pair.public_key().as_ref());
        format!("untrusted comment: minisign public key\n{}\n", BASE64.encode(&raw))
    }

    /// What `minisign -S -t <trusted>` writes for `data` (the default, pre-hashed mode).
    pub fn sign(&self, data: &[u8], trusted: &str) -> String {
        let digest = Blake2b512::digest(data);
        let sig = self.pair.sign(&digest);
        let mut raw = b"ED".to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(sig.as_ref());
        let mut global = sig.as_ref().to_vec();
        global.extend_from_slice(trusted.as_bytes());
        let global = self.pair.sign(&global);
        format!(
            "untrusted comment: signature from minisign secret key\n{}\ntrusted comment: {trusted}\n{}\n",
            BASE64.encode(&raw),
            BASE64.encode(global.as_ref())
        )
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// One release as the server publishes it. Tests mutate the fields before serving.
#[derive(Clone)]
pub struct Fixture {
    pub tag: String,
    pub name: String,
    pub appimage: Vec<u8>,
    pub sums: Vec<u8>,
    pub sig: String,
    pub notes: String,
    pub declared_size: Option<u64>,
}

impl Fixture {
    /// A release whose checksums are signed by `key` and bound to `version`.
    pub fn signed(version: &str, appimage: &[u8], key: &TestKey) -> Fixture {
        let name = format!("zombo-razor-{version}-x86_64.AppImage");
        let sums = format!("{}  {name}\n{}  other.txt\n", sha256_hex(appimage), sha256_hex(b"other")).into_bytes();
        let sig = key.sign(&sums, &format!("zombo-razor {version}"));
        Fixture {
            tag: format!("v{version}"),
            name,
            appimage: appimage.to_vec(),
            sums,
            sig,
            notes: "Fixes things.".into(),
            declared_size: None,
        }
    }

    pub fn metadata(&self, port: u16) -> String {
        let asset = |n: &str, size: usize| {
            format!(r#"{{"name":"{n}","browser_download_url":"https://127.0.0.1:{port}/dl/{n}","size":{size}}}"#)
        };
        format!(
            r#"[{{"tag_name":"{}","draft":false,"prerelease":false,"body":{},"html_url":"https://github.com/{REPO}/releases/tag/{}","assets":[{},{},{}]}}]"#,
            self.tag,
            serde_json::to_string(&self.notes).unwrap(),
            self.tag,
            asset(&self.name, self.declared_size.map_or(self.appimage.len(), |s| s as usize)),
            asset("SHA256SUMS", self.sums.len()),
            asset("SHA256SUMS.minisig", self.sig.len()),
        )
    }

    /// The standard routes. A test wraps this to break one of them.
    pub fn reply(&self, path: &str, port: u16) -> Reply {
        if path.starts_with("/repos/") && path.contains("/releases") {
            return Reply::ok(self.metadata(port).into_bytes());
        }
        if path == format!("/dl/{}", self.name) {
            return Reply::ok(self.appimage.clone());
        }
        match path {
            "/dl/SHA256SUMS" => Reply::ok(self.sums.clone()),
            "/dl/SHA256SUMS.minisig" => Reply::ok(self.sig.clone().into_bytes()),
            _ => Reply { status: 404, ..Reply::ok(vec![]) },
        }
    }
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Claim a different Content-Length than the body has.
    pub declared_len: Option<usize>,
    /// Send the body chunked, with no Content-Length.
    pub chunked: bool,
    pub delay: Duration,
}

impl Reply {
    pub fn ok(body: Vec<u8>) -> Reply {
        Reply { status: 200, headers: vec![], body, declared_len: None, chunked: false, delay: Duration::ZERO }
    }

    pub fn redirect(to: &str) -> Reply {
        Reply { status: 302, headers: vec![("Location".into(), to.into())], ..Reply::ok(vec![]) }
    }
}

type Headers = Vec<(String, String)>;

pub struct Server {
    pub port: u16,
    pub ca_der: Vec<u8>,
    /// The request headers of every request, lowercase names.
    pub seen: Arc<Mutex<Vec<Headers>>>,
}

pub async fn serve(handler: impl Fn(&str, u16) -> Reply + Send + Sync + 'static) -> Server {
    let ca = Ca::root("Update Test Root");
    let now = OffsetDateTime::now_utc();
    let leaf = ca.leaf(&["127.0.0.1"], now - time::Duration::days(1), now + time::Duration::days(30));
    let acceptor = TlsAcceptor::from(super::pki::server_config(vec![leaf.der], leaf.key));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (handler, seen) = (Arc::new(handler), Arc::new(Mutex::new(vec![])));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, handler, log) = (acceptor.clone(), handler.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else { return };
                let mut raw = vec![];
                let mut buf = [0u8; 2048];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_string();
                let mut lines = text.lines();
                let path = lines.next().and_then(|l| l.split(' ').nth(1)).unwrap_or("/").to_string();
                let headers: Vec<(String, String)> = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                log.lock().unwrap().push(headers);
                let r = handler(&path, port);
                tokio::time::sleep(r.delay).await;
                let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", r.status);
                if r.chunked {
                    head.push_str("Transfer-Encoding: chunked\r\n");
                } else {
                    head.push_str(&format!("Content-Length: {}\r\n", r.declared_len.unwrap_or(r.body.len())));
                }
                for (k, v) in &r.headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = s.write_all(head.as_bytes()).await;
                if r.chunked {
                    let _ = s.write_all(format!("{:x}\r\n", r.body.len()).as_bytes()).await;
                    let _ = s.write_all(&r.body).await;
                    let _ = s.write_all(b"\r\n0\r\n\r\n").await;
                } else {
                    let _ = s.write_all(&r.body).await;
                }
                let _ = s.shutdown().await;
            });
        }
    });
    Server { port, ca_der: ca.der().to_vec(), seen }
}

impl Server {
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    pub fn endpoints(&self, key: &TestKey) -> Endpoints {
        Endpoints {
            api_base: format!("https://127.0.0.1:{}", self.port),
            repo: REPO.into(),
            key: key.public_file(),
            roots: Some(vec![self.ca_der.clone()]),
            user_agent: "zombo/0.0.1".into(),
            metadata_deadline: Duration::from_secs(10),
            download_deadline: Duration::from_secs(20),
            max_metadata: 256 * 1024,
            max_sums: 64 * 1024,
            max_appimage: 1024 * 1024,
        }
    }
}

/// A scratch directory holding the "installed" AppImage, removed on drop.
pub struct Install {
    pub dir: std::path::PathBuf,
    pub path: std::path::PathBuf,
}

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub const OLD: &[u8] = b"#!/bin/sh\necho old\n";

impl Install {
    pub fn new(tag: &str) -> Install {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "zombo-update-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Zombos-Razor.AppImage");
        std::fs::write(&path, OLD).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        Install { dir, path }
    }

    pub fn untouched(&self) -> bool {
        std::fs::read(&self.path).is_ok_and(|b| b == OLD) && std::fs::read_dir(&self.dir).unwrap().count() == 1
    }
}

impl Drop for Install {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
