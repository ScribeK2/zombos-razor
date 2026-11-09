//! Fake registries for tests: an HTTP server (RDAP) and a port-43 server
//! (WHOIS), plus the fixtures in `testdata/registration`.
#![allow(dead_code)]

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/registration/{name}"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// An RDAP domain object expiring at `expires`, with the given RDAP statuses.
pub fn rdap_domain(expires: OffsetDateTime, statuses: &[&str]) -> String {
    let statuses = if statuses.is_empty() { &["client transfer prohibited"][..] } else { statuses };
    fixture("rdap_domain.json")
        .replace("__STATUS__", &serde_json::to_string(statuses).unwrap())
        .replace("__EXPIRES__", &expires.format(&Rfc3339).unwrap())
}

/// A VeriSign-style WHOIS reply expiring at `expires` (already formatted).
pub fn whois_verisign(expires: &str) -> String {
    fixture("whois_verisign.txt").replace("__EXPIRES__", expires)
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Reply { status, headers: vec![("Content-Type".into(), "application/rdap+json".into())], body: body.into() }
    }
    pub fn redirect(to: &str) -> Self {
        Reply { status: 302, headers: vec![("Location".into(), to.into())], body: vec![] }
    }
}

/// An HTTP/1.1 server that answers every request through `handler(path)`.
pub struct FakeHttp {
    /// `http://127.0.0.1:port/`
    pub base: String,
    hits: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
}

impl FakeHttp {
    pub async fn start(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", ln.local_addr().unwrap());
        let (hits, paths) = (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(vec![])));
        let handler = Arc::new(handler);
        let (h, p) = (hits.clone(), paths.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = ln.accept().await else { return };
                let (handler, h, p) = (handler.clone(), h.clone(), p.clone());
                tokio::spawn(async move {
                    let mut req = vec![];
                    let mut buf = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 16 * 1024 {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&req).lines().next().unwrap_or_default().to_string();
                    let path = line.split(' ').nth(1).unwrap_or("/").to_string();
                    h.fetch_add(1, Ordering::SeqCst);
                    p.lock().unwrap().push(path.clone());
                    let r = handler(&path);
                    let mut head =
                        format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n", r.status, r.body.len());
                    for (k, v) in &r.headers {
                        head += &format!("{k}: {v}\r\n");
                    }
                    head += "\r\n";
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&r.body).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        FakeHttp { base, hits, paths }
    }

    /// Serve `body` with `status` for /domain/*, and 404 elsewhere.
    pub async fn domain(status: u16, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        Self::start(
            move |path| {
                if path.starts_with("/domain/") { Reply::new(status, body.clone()) } else { Reply::new(404, "") }
            },
        )
        .await
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
    pub fn paths(&self) -> Vec<String> {
        self.paths.lock().unwrap().clone()
    }
}

/// A port-43 server that answers each query line through `handler(query)`.
pub struct FakeWhois {
    /// `127.0.0.1:port`
    pub addr: String,
    queries: Arc<Mutex<Vec<String>>>,
}

impl FakeWhois {
    pub async fn start(handler: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) -> Self {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        let queries = Arc::new(Mutex::new(vec![]));
        let handler = Arc::new(handler);
        let q = queries.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = ln.accept().await else { return };
                let (handler, q) = (handler.clone(), q.clone());
                tokio::spawn(async move {
                    let mut line = vec![];
                    let mut b = [0u8; 1];
                    while line.last() != Some(&b'\n') && line.len() < 1024 {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => line.push(b[0]),
                        }
                    }
                    let query = String::from_utf8_lossy(&line).trim().to_string();
                    q.lock().unwrap().push(query.clone());
                    let _ = s.write_all(&handler(&query)).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        FakeWhois { addr, queries }
    }

    /// Answer every query with `text`.
    pub async fn reply(text: impl Into<Vec<u8>>) -> Self {
        let text = text.into();
        Self::start(move |_| text.clone()).await
    }

    pub fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }
}

/// A server that accepts connections and never answers.
pub async fn silent() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = vec![];
        while let Ok((s, _)) = ln.accept().await {
            held.push(s);
        }
    });
    addr
}

/// An address nothing listens on.
pub async fn closed_port() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    ln.local_addr().unwrap().to_string()
}
