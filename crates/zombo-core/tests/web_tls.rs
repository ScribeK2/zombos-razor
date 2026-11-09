//! The origin comparison over TLS: the public name is served with a certificate the
//! test trusts, the origin presents a self-signed one.

mod common;
#[path = "common/tls.rs"]
mod pki;
#[path = "common/web.rs"]
mod site;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use common::FakeDns;
use pki::{Ca, Leaf};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::PrivateKeyDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use site::closed_port;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use zombo_core::{
    Finding, Severity,
    web::{CertCheck, Ports, WebOptions, WebResult, check_web, web_findings},
};

#[derive(Debug)]
struct Resolver {
    key: Arc<CertifiedKey>,
    sni: Arc<Mutex<Vec<String>>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.sni.lock().unwrap().push(hello.server_name().unwrap_or_default().to_string());
        Some(self.key.clone())
    }
}

struct Https {
    sni: Arc<Mutex<Vec<String>>>,
    hosts: Arc<Mutex<Vec<String>>>,
}

async fn serve(ip: &str, port: u16, leaf: Leaf, body: &'static str) -> (SocketAddr, Https) {
    let provider = Arc::new(ring::default_provider());
    let signing = provider.key_provider.load_private_key(PrivateKeyDer::Pkcs8(leaf.key)).unwrap();
    let (sni, hosts) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(vec![])));
    let resolver = Resolver { key: Arc::new(CertifiedKey::new(vec![leaf.der], signing)), sni: sni.clone() };
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind((ip, port)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = hosts.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen) = (acceptor.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else { return };
                let mut raw = vec![];
                let mut buf = [0u8; 1024];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
                if let Some(h) = text.lines().find_map(|l| l.strip_prefix("host:")) {
                    seen.lock().unwrap().push(h.trim().to_string());
                }
                let reply =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = s.write_all(reply.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, Https { sni, hosts })
}

fn real_leaf(ca: &Ca) -> Leaf {
    let now = OffsetDateTime::now_utc();
    ca.leaf(&["example.com"], now - time::Duration::days(1), now + time::Duration::days(30))
}

async fn compare(origin_cert: CertCheck) -> (WebResult, Vec<Finding>, Https) {
    let ca = Ca::root("Test Root");
    let (public, _) = serve("127.0.0.1", 0, real_leaf(&ca), "cdn").await;
    let (_, origin) = serve("127.0.0.2", public.port(), pki::self_signed(&["example.com"]), "origin").await;
    let dns = FakeDns::start("").await;
    let opts = WebOptions {
        timeout: Duration::from_secs(8),
        resolver: Some(dns.addr),
        ports: Ports { http: closed_port().await, https: public.port() },
        pin: Some("127.0.0.1".parse().unwrap()),
        origin: Some("127.0.0.2".parse().unwrap()),
        origin_cert,
        trusted_roots: vec![ca.der().to_vec()],
    };
    let r = check_web("example.com", "/", &opts).await;
    let fs = web_findings("example.com", &r);
    (r, fs, origin)
}

fn get<'a>(fs: &'a [Finding], code: &str) -> Option<&'a Finding> {
    fs.iter().find(|f| f.code == code)
}

#[tokio::test]
async fn a_rejected_origin_certificate_is_not_reported_as_silence() {
    let (r, fs, _) = compare(CertCheck::Verify).await;
    assert_eq!(r.status, Some(200), "{:?}", r.error);
    let f = get(&fs, "website_origin_cert_rejected")
        .unwrap_or_else(|| panic!("{:?}", fs.iter().map(|f| f.code).collect::<Vec<_>>()));
    assert!(f.message.contains("the origin answered but its certificate was rejected: it is "), "{}", f.message);
    assert!(f.message.contains(", try --insecure-origin."), "{}", f.message);
    assert!(get(&fs, "website_origin_unreachable").is_none());
    assert!(!r.origin.unwrap().verification_skipped);
}

#[tokio::test]
async fn insecure_origin_compares_anyway_and_says_what_it_skipped() {
    let (r, fs, origin) = compare(CertCheck::SkipVerification).await;
    let o = r.origin.as_ref().unwrap();
    assert!(o.verification_skipped);
    assert_eq!(o.answer.status, Some(200), "{:?}", o.answer.error);
    assert!(get(&fs, "website_origin_cert_rejected").is_none());
    let f = get(&fs, "web_origin_cert_not_verified").unwrap();
    assert_eq!(f.severity, Severity::Info);
    assert!(f.message.contains("example.com") && f.message.contains("valid until"), "{}", f.message);
    // Both the fetch and the certificate read sent the real name.
    assert!(origin.sni.lock().unwrap().iter().all(|s| s == "example.com"));
    assert!(
        origin.hosts.lock().unwrap().iter().any(|h| h.starts_with("example.com")),
        "{:?}",
        origin.hosts.lock().unwrap()
    );
}
