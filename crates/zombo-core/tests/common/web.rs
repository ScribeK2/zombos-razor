//! A fake web server for the web inspection tests: every response is the handler's,
//! so tests can serve redirect chains, errors, slow headers and stalled or huge bodies.
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/web/{name}"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[derive(Debug, Clone)]
pub struct Req {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Wait this long before answering at all.
    pub delay: Duration,
    /// Promise the whole body, send `body`, then hold the connection open.
    pub stall_after_body: bool,
}

impl Resp {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Resp { status, headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())], body: body.into(), delay: Duration::ZERO, stall_after_body: false }
    }
    pub fn ok(body: &str) -> Self {
        Self::new(200, body)
    }
    pub fn redirect(status: u16, to: &str) -> Self {
        Resp { headers: vec![("Location".into(), to.into())], ..Self::new(status, "") }
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
    /// Every security header, as a well-configured site sends them.
    pub fn secure(self) -> Self {
        self.header("Strict-Transport-Security", "max-age=31536000")
            .header("Content-Security-Policy", "default-src 'self'")
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .header("Referrer-Policy", "no-referrer")
            .header("Permissions-Policy", "camera=()")
    }
}

pub struct FakeSite {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Req>>>,
}

impl FakeSite {
    /// Listen on `ip:port` (port 0 picks one).
    pub async fn start_on(ip: &str, port: u16, handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> Self {
        let ln = TcpListener::bind((ip, port)).await.unwrap_or_else(|e| panic!("bind {ip}:{port}: {e}"));
        let addr = ln.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(vec![]));
        let (handler, log) = (Arc::new(handler), seen.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = ln.accept().await else { return };
                let (handler, log) = (handler.clone(), log.clone());
                tokio::spawn(async move {
                    let mut raw = vec![];
                    let mut buf = [0u8; 1024];
                    while !raw.windows(4).any(|w| w == b"\r\n\r\n") && raw.len() < 64 * 1024 {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => raw.extend_from_slice(&buf[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    let mut lines = text.split("\r\n");
                    let path = lines.next().unwrap_or_default().split(' ').nth(1).unwrap_or("/").to_string();
                    let headers = lines.take_while(|l| !l.is_empty()).filter_map(|l| l.split_once(':')).map(|(n, v)| (n.trim().to_string(), v.trim().to_string())).collect();
                    let req = Req { path, headers };
                    let r = handler(&req);
                    log.lock().unwrap().push(req);
                    tokio::time::sleep(r.delay).await;
                    let promised = if r.stall_after_body { r.body.len() + 1000 } else { r.body.len() };
                    let mut head = format!("HTTP/1.1 {} X\r\nContent-Length: {promised}\r\nConnection: close\r\n", r.status);
                    for (k, v) in &r.headers {
                        head += &format!("{k}: {v}\r\n");
                    }
                    head += "\r\n";
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&r.body).await;
                    if r.stall_after_body {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    let _ = s.shutdown().await;
                });
            }
        });
        FakeSite { addr, seen }
    }

    pub async fn start(handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> Self {
        Self::start_on("127.0.0.1", 0, handler).await
    }

    pub fn requests(&self) -> Vec<Req> {
        self.seen.lock().unwrap().clone()
    }
}

/// A port nothing listens on.
pub async fn closed_port() -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    ln.local_addr().unwrap().port()
}
