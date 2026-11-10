//! A DNS server whose answers a test writes by hand, over UDP only: for
//! hostile replies (an alias in front of an address, a flood of records) and
//! for names that must stay silent while others answer, which `FakeDns` cannot do.
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME, MX, PTR},
    },
};
use tokio::net::UdpSocket;

pub enum Reply {
    Silent,
    NxDomain,
    /// NOERROR with exactly these answers.
    Answers(Vec<Record>),
}

pub fn a(name: &str, ip: &str) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), 300, RData::A(A(ip.parse().unwrap())))
}

pub fn cname(name: &str, to: &str) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), 300, RData::CNAME(CNAME(Name::from_ascii(to).unwrap())))
}

pub fn mx(name: &str, preference: u16, host: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        300,
        RData::MX(MX::new(preference, Name::from_ascii(host).unwrap())),
    )
}

pub fn ptr(name: &str, to: &str) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), 300, RData::PTR(PTR(Name::from_ascii(to).unwrap())))
}

/// Serve `handler(lowercased name without the trailing dot, type)` on a loopback UDP port.
pub async fn serve(handler: impl Fn(&str, RecordType) -> Reply + Send + Sync + 'static) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
            let Ok(req) = Message::from_vec(&buf[..n]) else { continue };
            let Some(q) = req.queries.first().cloned() else { continue };
            let name = q.name().to_string().trim_end_matches('.').to_ascii_lowercase();
            let mut m = Message::response(req.metadata.id, OpCode::Query);
            m.metadata.message_type = MessageType::Response;
            m.metadata.recursion_desired = req.metadata.recursion_desired;
            m.metadata.recursion_available = true;
            m.add_query(q.clone());
            match handler(&name, q.query_type()) {
                Reply::Silent => continue,
                Reply::NxDomain => m.metadata.response_code = ResponseCode::NXDomain,
                Reply::Answers(records) => {
                    for r in records {
                        m.add_answer(r);
                    }
                }
            }
            if let Ok(wire) = m.to_vec() {
                let _ = sock.send_to(&wire, peer).await;
            }
        }
    });
    addr
}
