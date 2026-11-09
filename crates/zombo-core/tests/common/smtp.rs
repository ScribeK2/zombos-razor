//! A scripted SMTP server on 127.0.0.1. A script is a list of steps run in
//! order on every connection, so a test writes the server's side of the
//! dialogue, including hostile ones. Nothing real is contacted.
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use rustls::ServerConfig;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub enum Step {
    /// Send this text (CRLF is not added).
    Say(String),
    Raw(Vec<u8>),
    /// Read one line from the client, record it, and drop the connection unless it starts with this (any case).
    Expect(&'static str),
    /// Read and record one line whatever it is.
    ExpectAny,
    /// Do a TLS handshake as the server; every later step runs inside TLS.
    Tls(Arc<ServerConfig>),
    /// Stay silent for this long.
    Hold(Duration),
    /// Send a line of a multi-line reply every interval until the client goes away.
    Drip(Duration),
    Close,
}

pub fn say(s: &str) -> Step {
    Step::Say(s.to_string())
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct FakeSmtp {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
}

impl FakeSmtp {
    pub async fn start(script: Vec<Step>) -> FakeSmtp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(vec![]));
        let shared = log.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(run(Box::new(tcp), script.clone(), shared.clone()));
            }
        });
        FakeSmtp { addr, log }
    }

    /// Every line the client sent, across connections, in order.
    pub fn received(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

/// An address nothing listens on.
pub async fn closed_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

async fn line(s: &mut Box<dyn Io>) -> Option<String> {
    let mut out = vec![];
    let read = async {
        loop {
            let mut b = [0u8; 1];
            if s.read(&mut b).await.ok()? == 0 {
                return None;
            }
            if b[0] == b'\n' {
                return Some(String::from_utf8_lossy(&out).trim_end_matches('\r').to_string());
            }
            out.push(b[0]);
        }
    };
    timeout(Duration::from_secs(5), read).await.ok().flatten()
}

async fn run(mut stream: Box<dyn Io>, script: Vec<Step>, log: Arc<Mutex<Vec<String>>>) {
    for step in script {
        match step {
            Step::Say(t) => {
                if stream.write_all(t.as_bytes()).await.is_err() {
                    return;
                }
            }
            Step::Raw(b) => {
                if stream.write_all(&b).await.is_err() {
                    return;
                }
            }
            Step::Expect(prefix) => {
                let Some(l) = line(&mut stream).await else { return };
                log.lock().unwrap().push(l.clone());
                if !l.to_ascii_uppercase().starts_with(prefix) {
                    return;
                }
            }
            Step::ExpectAny => {
                let Some(l) = line(&mut stream).await else { return };
                log.lock().unwrap().push(l);
            }
            Step::Tls(cfg) => {
                let plain = stream;
                stream = match TlsAcceptor::from(cfg).accept(plain).await {
                    Ok(t) => Box::new(t),
                    Err(_) => return,
                };
            }
            Step::Hold(d) => sleep(d).await,
            Step::Drip(every) => loop {
                if stream.write_all(b"220-more\r\n").await.is_err() {
                    return;
                }
                sleep(every).await;
            },
            Step::Close => return,
        }
    }
    sleep(Duration::from_millis(200)).await;
}
