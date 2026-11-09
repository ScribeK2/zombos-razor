use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use hickory_proto::{
    op::ResponseCode,
    rr::{Name, RData, RecordType},
};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::dns::exchange;

pub const LOOKUP_TYPES: [RecordType; 8] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::NS,
    RecordType::TXT,
    RecordType::SOA,
    RecordType::CAA,
];

/// Whether the name exists. NXDOMAIN is a valid answer, not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Rcode {
    #[serde(rename = "NOERROR")]
    NoError,
    #[serde(rename = "NXDOMAIN")]
    NxDomain,
}

/// One record as a resolver returned it: the data in zone-file form, plus its TTL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Value {
    pub text: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct LookupResult {
    pub rcode: Rcode,
    /// Every answer carried the authoritative-answer (AA) flag.
    pub authoritative: bool,
    /// Any answer offered recursion (the RA flag). Real authoritative servers rarely do.
    pub recursion_available: bool,
    pub records: BTreeMap<String, Vec<Value>>,
    /// Record type -> why that query failed.
    pub errors: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    #[error("{0} is not a valid DNS name")]
    BadName(String),
    #[error("no answer from DNS resolver {server}: {why}")]
    NoAnswer { server: SocketAddr, why: String },
}

/// Query every given record type concurrently against one server. A failed
/// query for one type goes under `errors`; the lookup fails only if no query
/// got an answer.
pub async fn dns_lookup(
    server: SocketAddr,
    target: &str,
    types: &[RecordType],
    recursion_desired: bool,
    limit: Duration,
) -> Result<LookupResult, LookupError> {
    let name = Name::from_ascii(target).map_err(|_| LookupError::BadName(target.into()))?;
    let mut set = JoinSet::new();
    for &t in types {
        let name = name.clone();
        set.spawn(async move { (t, exchange(server, &name, t, recursion_desired, limit).await) });
    }
    let mut res = LookupResult {
        rcode: Rcode::NoError,
        authoritative: true,
        recursion_available: false,
        records: BTreeMap::new(),
        errors: BTreeMap::new(),
    };
    let (mut answers, mut first_err) = (0, String::new());
    while let Some(Ok((t, out))) = set.join_next().await {
        let typ = t.to_string();
        match out {
            Err(e) => {
                if first_err.is_empty() || t == RecordType::A {
                    first_err = e.to_string();
                }
                res.errors.insert(typ, e.to_string());
            }
            Ok(m) => {
                answers += 1;
                res.authoritative &= m.metadata.authoritative;
                res.recursion_available |= m.metadata.recursion_available;
                match m.metadata.response_code {
                    ResponseCode::NoError => {}
                    ResponseCode::NXDomain => res.rcode = Rcode::NxDomain,
                    other => {
                        res.errors.insert(typ.clone(), other.to_str().to_string());
                    }
                }
                for r in m.answers.iter().filter(|r| r.record_type() == t) {
                    res.records.entry(typ.clone()).or_default().push(Value { text: presentation(&r.data), ttl: r.ttl });
                }
            }
        }
    }
    if answers == 0 {
        return Err(LookupError::NoAnswer { server, why: first_err });
    }
    Ok(res)
}

/// Record data in zone-file presentation form, as the Go engine printed it.
/// hickory's `Display` leaves TXT strings unquoted, so TXT is done by hand.
pub(crate) fn presentation(d: &RData) -> String {
    let RData::TXT(t) = d else { return d.to_string() };
    t.txt_data
        .iter()
        .map(|part| {
            let mut s = String::from("\"");
            for &b in part.iter() {
                match b {
                    b'"' | b'\\' => {
                        s.push('\\');
                        s.push(b as char);
                    }
                    0x20..=0x7e => s.push(b as char),
                    _ => s.push_str(&format!("\\{b:03}")),
                }
            }
            s.push('"');
            s
        })
        .collect::<Vec<_>>()
        .join(" ")
}
