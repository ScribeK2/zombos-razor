//! One DNS query to one server. Every Check's DNS goes through `exchange`.

use std::{net::SocketAddr, time::Duration};

use hickory_proto::{
    op::{Edns, Message, Query},
    rr::{Name, RecordType},
};
use crate::finding::{Finding, Severity};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

const EDNS_PAYLOAD: u16 = 1232;

#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("timed out")]
    Timeout,
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("unusable answer: {0}")]
    Bad(String),
}

/// What to ask for besides the question itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryFlags {
    pub recursion_desired: bool,
    /// The DO bit: also send the DNSSEC records (RRSIG and the like).
    pub dnssec_ok: bool,
    /// The CD bit: a validating resolver should answer even if validation fails.
    pub checking_disabled: bool,
}

/// Send a query (recursive unless `recursion_desired` is false, as when asking
/// an authoritative nameserver directly): UDP first, then TCP when the UDP answer is
/// truncated or unusable. Some public resolvers cut an oversized UDP reply
/// mid-record instead of setting TC, which fails to parse; TCP gets it whole.
/// `limit` covers both attempts.
pub async fn exchange(
    server: SocketAddr,
    name: &Name,
    rtype: RecordType,
    recursion_desired: bool,
    limit: Duration,
) -> Result<Message, ExchangeError> {
    let flags = QueryFlags { recursion_desired, ..QueryFlags::default() };
    exchange_with(server, name, rtype, flags, limit).await
}

/// `exchange` with the DNSSEC flags: see `QueryFlags`.
pub async fn exchange_with(
    server: SocketAddr,
    name: &Name,
    rtype: RecordType,
    flags: QueryFlags,
    limit: Duration,
) -> Result<Message, ExchangeError> {
    let mut q = Message::query();
    q.metadata.recursion_desired = flags.recursion_desired;
    q.metadata.checking_disabled = flags.checking_disabled;
    q.add_query(Query::query(name.clone(), rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(flags.dnssec_ok);
    q.set_edns(edns);
    let wire = q.to_vec().map_err(|e| ExchangeError::Bad(e.to_string()))?;
    let id = q.metadata.id;

    timeout(limit, async {
        match udp(server, &wire, id).await {
            Ok(m) if !m.metadata.truncation => Ok(m),
            Ok(_) | Err(ExchangeError::Bad(_)) => tcp(server, &wire, id).await,
            Err(e) => Err(e),
        }
    })
    .await
    .map_err(|_| ExchangeError::Timeout)?
}

async fn udp(server: SocketAddr, wire: &[u8], id: u16) -> Result<Message, ExchangeError> {
    let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.connect(server).await?; // the kernel drops datagrams from any other source
    sock.send(wire).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        match Message::from_vec(&buf[..n]) {
            Ok(m) if m.metadata.id == id => return Ok(m),
            Ok(_) => continue, // a stray answer to another query; keep waiting
            Err(e) => return Err(ExchangeError::Bad(e.to_string())),
        }
    }
}

async fn tcp(server: SocketAddr, wire: &[u8], id: u16) -> Result<Message, ExchangeError> {
    let mut s = TcpStream::connect(server).await?;
    s.write_all(&(wire.len() as u16).to_be_bytes()).await?;
    s.write_all(wire).await?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).await?;
    let m = Message::from_vec(&buf).map_err(|e| ExchangeError::Bad(e.to_string()))?;
    if m.metadata.id != id {
        return Err(ExchangeError::Bad("answer id does not match the query".into()));
    }
    Ok(m)
}

/// Nameservers that all answer without the authoritative flag but offering
/// recursion are not nameservers: something on the path (a router, a firewall,
/// an ISP) is answering DNS queries itself.
pub fn interception_finding(servers: &[&str]) -> Finding {
    Finding {
        code: "dns_network_intercepts",
        severity: Severity::Warning,
        title: "This network appears to intercept DNS".into(),
        message: format!(
            "{} are different nameservers, yet all answered without the authoritative flag and offered recursion, which real authoritative servers do not do. A router, firewall or ISP is probably answering DNS queries itself, so these results do not show what the rest of the internet sees.",
            servers.join(", ")
        ),
        recommendation: Some("Re-run from another network (a phone hotspot or a server), or ask the network owner to stop redirecting port 53.".into()),
    }
}
