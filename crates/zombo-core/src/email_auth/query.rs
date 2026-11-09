//! The only DNS the email checks do: a few questions to one resolver, over `crate::dns::exchange`.

use std::{future::Future, net::SocketAddr, time::Duration};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RData, RecordType},
};
use tokio::task::JoinSet;

use super::{clip, printable};
use crate::dns::exchange;

const MAX_CNAMES: usize = 8;

/// One resolver and how long each question may take. Cheap to copy into a task.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dns {
    pub server: SocketAddr,
    pub limit: Duration,
}

/// The TXT records at a name, each record's strings joined.
#[derive(Debug, Default)]
pub(crate) struct Txt {
    pub records: Vec<String>,
    /// The last alias followed to reach them.
    pub cname: Option<String>,
}

fn host(n: &Name) -> String {
    printable(n.to_string().trim_end_matches('.'))
}

impl Dns {
    /// NXDOMAIN is an answer (the name has nothing); any other failure is an error.
    async fn ask(&self, name: &str, rtype: RecordType) -> Result<Message, String> {
        let parsed = Name::from_ascii(name).map_err(|_| format!("{:?} is not a valid DNS name", clip(name)))?;
        let m = exchange(self.server, &parsed, rtype, true, self.limit).await.map_err(|e| e.to_string())?;
        match m.metadata.response_code {
            ResponseCode::NoError | ResponseCode::NXDomain => Ok(m),
            other => Err(other.to_str().to_string()),
        }
    }

    /// TXT records, following CNAMEs. A resolver chases them itself, but a stub
    /// or an authoritative server answers the alias alone, so an empty answer
    /// is followed up with an explicit CNAME query.
    pub async fn txt(&self, name: &str) -> Result<Txt, String> {
        let (mut name, mut out) = (name.to_string(), Txt::default());
        for _ in 0..MAX_CNAMES {
            let m = self.ask(&name, RecordType::TXT).await?;
            for a in &m.answers {
                match &a.data {
                    RData::TXT(t) => {
                        let bytes: Vec<u8> = t.txt_data.iter().flat_map(|part| part.iter().copied()).collect();
                        out.records.push(printable(&String::from_utf8_lossy(&bytes)));
                    }
                    RData::CNAME(c) => out.cname = Some(host(&c.0)),
                    _ => {}
                }
            }
            if !m.answers.is_empty() || m.metadata.response_code == ResponseCode::NXDomain {
                return Ok(out);
            }
            let alias = self.ask(&name, RecordType::CNAME).await?.answers.iter().find_map(|a| match &a.data {
                RData::CNAME(c) => Some(c.0.to_string()),
                _ => None,
            });
            match alias {
                None => return Ok(out),
                Some(target) => {
                    out.cname = Some(printable(target.trim_end_matches('.')));
                    name = target;
                }
            }
        }
        Err(format!("CNAME chain too long at {}", clip(&name)))
    }

    /// How many records of `rtype` the name has (none for NXDOMAIN).
    pub async fn count(&self, name: &str, rtype: RecordType) -> Result<usize, String> {
        Ok(self.ask(name, rtype).await?.answers.iter().filter(|a| a.record_type() == rtype).count())
    }

    /// The MX hosts, most preferred first.
    pub async fn mx_hosts(&self, name: &str) -> Result<Vec<String>, String> {
        let m = self.ask(name, RecordType::MX).await?;
        let mut mx: Vec<(u16, String)> = m
            .answers
            .iter()
            .filter_map(|a| match &a.data {
                RData::MX(mx) => Some((mx.preference, host(&mx.exchange).to_ascii_lowercase())),
                _ => None,
            })
            .collect();
        mx.sort();
        Ok(mx.into_iter().map(|(_, h)| h).collect())
    }
}

/// Run futures at the same time; results come back in input order. A task
/// that dies leaves `None` in its place.
pub(crate) async fn concurrently<T, F>(futures: Vec<F>) -> Vec<Option<T>>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let mut set = JoinSet::new();
    let mut out: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    for (i, f) in futures.into_iter().enumerate() {
        set.spawn(async move { (i, f.await) });
    }
    while let Some(Ok((i, v))) = set.join_next().await {
        out[i] = Some(v);
    }
    out
}
