//! Mail servers on chosen loopback addresses, all on one port, so that a test can make some MX hosts
//! answer and others refuse. Each server greets, answers EHLO without STARTTLS and answers QUIT, and
//! counts the connections it took. Nothing real is contacted.
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

pub struct MailHost {
    pub addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

impl MailHost {
    /// Listen on `ip:port` (port 0 picks one) and greet as `greeting_name`.
    pub async fn start(ip: &str, port: u16, greeting_name: &'static str) -> MailHost {
        let listener = TcpListener::bind((ip, port)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(dialogue(tcp, greeting_name));
            }
        });
        MailHost { addr, connections }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

async fn dialogue(tcp: tokio::net::TcpStream, name: &str) {
    let (read, mut write) = tcp.into_split();
    let mut lines = BufReader::new(read).lines();
    if write.write_all(format!("220 {name} ESMTP ready\r\n").as_bytes()).await.is_err() {
        return;
    }
    while let Ok(Some(line)) = lines.next_line().await {
        let reply = match line.to_ascii_uppercase().split_whitespace().next() {
            Some("EHLO") => format!("250-{name}\r\n250 PIPELINING\r\n"),
            Some("QUIT") => "221 bye\r\n".to_string(),
            _ => "502 not implemented\r\n".to_string(),
        };
        if write.write_all(reply.as_bytes()).await.is_err() || line.to_ascii_uppercase().starts_with("QUIT") {
            return;
        }
    }
}
