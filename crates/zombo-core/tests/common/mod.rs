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
    rr::{Name, RData, Record, RecordType, rdata::NULL},
    serialize::{binary::BinEncodable, txt::Parser},
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
    referral: bool,
    ra: Option<bool>,
    validating: bool,
    bogus: bool,
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
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(';')) {
        if let Some(r) = dnssec_record(line) {
            out.push(r);
            continue;
        }
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

/// DNSKEY, DS and RRSIG lines in presentation form, as `name ttl IN TYPE rdata`.
/// hickory's zone parser refuses them without its crypto features, so they are
/// built from their wire rdata, which is also how the code under test sees them.
fn dnssec_record(line: &str) -> Option<Record> {
    let mut f = line.split_whitespace();
    let (name, ttl, _, rtype) = (f.next()?, f.next()?, f.next()?, f.next()?);
    let rest: Vec<&str> = f.collect();
    let num = |s: &str| s.parse::<u64>().unwrap_or_else(|_| panic!("bad number in {line:?}"));
    let b64 = |s: &[&str]| data_encoding::BASE64.decode(s.concat().as_bytes()).unwrap_or_else(|e| panic!("bad base64 in {line:?}: {e}"));
    let mut rd = vec![];
    let code = match rtype {
        "DNSKEY" => {
            rd.extend((num(rest[0]) as u16).to_be_bytes());
            rd.extend([num(rest[1]) as u8, num(rest[2]) as u8]);
            rd.extend(b64(&rest[3..]));
            RecordType::DNSKEY
        }
        "DS" => {
            rd.extend((num(rest[0]) as u16).to_be_bytes());
            rd.extend([num(rest[1]) as u8, num(rest[2]) as u8]);
            rd.extend(data_encoding::HEXLOWER_PERMISSIVE.decode(rest[3..].concat().as_bytes()).unwrap_or_else(|e| panic!("bad hex in {line:?}: {e}")));
            RecordType::DS
        }
        "RRSIG" => {
            let covered: RecordType = rest[0].parse().unwrap_or_else(|_| panic!("bad type in {line:?}"));
            rd.extend(u16::from(covered).to_be_bytes());
            rd.extend([num(rest[1]) as u8, num(rest[2]) as u8]);
            rd.extend((num(rest[3]) as u32).to_be_bytes());
            rd.extend(epoch(rest[4]).to_be_bytes());
            rd.extend(epoch(rest[5]).to_be_bytes());
            rd.extend((num(rest[6]) as u16).to_be_bytes());
            rd.extend(Name::from_ascii(rest[7]).unwrap().to_lowercase().to_bytes().unwrap());
            rd.extend(b64(&rest[8..]));
            RecordType::RRSIG
        }
        _ => return None,
    };
    let rdata = RData::Unknown { code, rdata: NULL::with(rd) };
    Some(Record::from_rdata(Name::from_ascii(name).unwrap(), num(ttl) as u32, rdata))
}

/// An RRSIG time: `YYYYMMDDHHMMSS` (UTC) or plain epoch seconds.
fn epoch(s: &str) -> u32 {
    if s.len() != 14 {
        return s.parse().unwrap();
    }
    let n = |r: std::ops::Range<usize>| s[r].parse::<i64>().unwrap();
    let (y, m, d) = (n(0..4), n(4..6), n(6..8));
    // days since 1970-01-01 from a civil date (Howard Hinnant's algorithm)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    (days * 86400 + n(8..10) * 3600 + n(10..12) * 60 + n(12..14)) as u32
}

pub fn dnssec_zone(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/dnssec/{name}.zone"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
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

    /// Override the recursion-available flag (by default it is set unless the server is authoritative).
    pub fn recursion_available(self, ra: bool) -> Self {
        self.state.lock().unwrap().ra = Some(ra);
        self
    }

    /// Behave like a parent zone: answer NS queries with a referral (the NS
    /// records in the authority section, their addresses as glue in the
    /// additional section) instead of an answer.
    pub fn referral(self) -> Self {
        self.state.lock().unwrap().referral = true;
        self
    }

    /// Behave like a validating resolver: set the AD flag on answers to queries
    /// that ask for DNSSEC (the DO bit) without disabling checking (CD).
    pub fn validating(self) -> Self {
        self.state.lock().unwrap().validating = true;
        self
    }

    /// Behave like a validating resolver in front of a zone whose DNSSEC is broken:
    /// answer SERVFAIL unless the query sets CD (checking disabled).
    pub fn bogus(self) -> Self {
        self.state.lock().unwrap().bogus = true;
        self
    }

    /// Answer REFUSED to queries of this type.
    pub fn refuse(self, t: RecordType) -> Self {
        self.state.lock().unwrap().refuse.push(t);
        self
    }
}

/// Whether an RRSIG record covers this type (its rdata starts with the covered type).
fn covers(rrsig: &Record, t: RecordType) -> bool {
    matches!(&rrsig.data, RData::Unknown { rdata, .. } if rdata.anything.get(..2) == Some(&u16::from(t).to_be_bytes()[..]))
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
    m.metadata.recursion_available = st.ra.unwrap_or(!st.authoritative);
    m.metadata.authoritative = st.authoritative;
    m.add_query(q.clone());
    let dnssec_ok = req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
    if st.bogus && !req.metadata.checking_disabled {
        m.metadata.response_code = ResponseCode::ServFail;
        return m.to_vec().ok();
    }
    m.metadata.authentic_data = st.validating && dnssec_ok && !req.metadata.checking_disabled;
    if st.refuse.contains(&q.query_type()) || (st.authoritative && req.metadata.recursion_desired) {
        m.metadata.response_code = ResponseCode::Refused;
        return m.to_vec().ok();
    }
    if st.referral && q.query_type() == RecordType::NS {
        let same = |a: &Name, b: &Name| a.to_string().eq_ignore_ascii_case(&b.to_string());
        for r in st.records.iter().filter(|r| r.record_type() == RecordType::NS && same(&r.name, q.name())) {
            m.add_authority(r.clone());
            if let hickory_proto::rr::RData::NS(ns) = &r.data {
                for g in st.records.iter().filter(|g| matches!(g.record_type(), RecordType::A | RecordType::AAAA) && same(&g.name, &ns.0)) {
                    m.add_additional(g.clone());
                }
            }
        }
        return m.to_vec().ok();
    }
    let mut known = false;
    for r in &st.records {
        if r.name.to_string().eq_ignore_ascii_case(&q.name().to_string()) {
            known = true;
            if r.record_type() == q.query_type() {
                m.add_answer(r.clone());
            }
            if dnssec_ok && r.record_type() == RecordType::RRSIG && covers(r, q.query_type()) {
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
