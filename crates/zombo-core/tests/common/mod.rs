//! A fake DNS server for tests: serves zone text over UDP and TCP on one port,
//! like a real resolver. Zones are the shared files in `testdata/zones`.
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, Record, RecordType},
    serialize::txt::Parser,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

pub fn zone(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/zones/{name}.zone"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[derive(Default)]
struct State {
    records: Vec<Record>,
    silent: bool,
    refuse: Vec<RecordType>,
    authoritative: bool,
}

pub struct FakeDns {
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

/// A line-per-record zone: `name ttl IN TYPE rdata`. hickory's zone parser
/// insists on an SOA, and some fixture zones have none, so parse line by line
/// with a throwaway SOA prepended.
fn parse_zone(text: &str) -> Vec<Record> {
    let mut out = vec![];
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let soa = "$ORIGIN .\nx. 1 IN SOA x. x. 1 1 1 1 1\n";
        let (_, sets) = Parser::new(format!("{soa}{line}\n"), None, Some(Name::root()))
            .parse()
            .unwrap_or_else(|e| panic!("bad zone line {line:?}: {e}"));
        for (_, set) in sets {
            for r in set.records_without_rrsigs() {
                if r.name.to_string() != "x." {
                    out.push(r.clone());
                }
            }
        }
    }
    out
}

impl FakeDns {
    pub async fn start(zone_text: &str) -> Self {
        let state = Arc::new(Mutex::new(State { records: parse_zone(zone_text), ..Default::default() }));
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                break (udp, tcp);
            }
        };
        let addr = udp.local_addr().unwrap();
        let st = state.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf).await else { return };
                if let Some(resp) = answer(&st, &buf[..n], true) {
                    let _ = udp.send_to(&resp, peer).await;
                }
            }
        });
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = tcp.accept().await else { return };
                let st = st.clone();
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    if let Some(resp) = answer(&st, &q, false) {
                        let _ = s.write_all(&(resp.len() as u16).to_be_bytes()).await;
                        let _ = s.write_all(&resp).await;
                    }
                });
            }
        });
        FakeDns { addr, state }
    }

    /// A server that never answers.
    pub async fn silent() -> Self {
        let s = Self::start("").await;
        s.state.lock().unwrap().silent = true;
        s
    }

    /// Behave like an authoritative nameserver: set the AA flag, and refuse
    /// queries that ask it to recurse (as some real nameservers do).
    pub fn authoritative(self) -> Self {
        self.state.lock().unwrap().authoritative = true;
        self
    }

    /// Answer REFUSED to queries of this type.
    pub fn refuse(self, t: RecordType) -> Self {
        self.state.lock().unwrap().refuse.push(t);
        self
    }
}

fn answer(state: &Mutex<State>, query: &[u8], udp: bool) -> Option<Vec<u8>> {
    let st = state.lock().unwrap();
    if st.silent {
        return None;
    }
    let req = Message::from_vec(query).ok()?;
    let q = req.queries.first()?.clone();
    let mut m = Message::response(req.metadata.id, OpCode::Query);
    m.metadata.message_type = MessageType::Response;
    m.metadata.recursion_desired = req.metadata.recursion_desired;
    m.metadata.recursion_available = !st.authoritative;
    m.metadata.authoritative = st.authoritative;
    m.add_query(q.clone());
    if st.refuse.contains(&q.query_type()) || (st.authoritative && req.metadata.recursion_desired) {
        m.metadata.response_code = ResponseCode::Refused;
        return m.to_vec().ok();
    }
    let mut known = false;
    for r in &st.records {
        if r.name.to_string().eq_ignore_ascii_case(&q.name().to_string()) {
            known = true;
            if r.record_type() == q.query_type() {
                m.add_answer(r.clone());
            }
        }
    }
    if !known {
        m.metadata.response_code = ResponseCode::NXDomain;
    }
    let wire = m.to_vec().ok()?;
    let limit = req.edns.as_ref().map_or(512, |e| e.max_payload().max(512)) as usize;
    if udp && wire.len() > limit {
        return m.truncate().to_vec().ok();
    }
    Some(wire)
}
