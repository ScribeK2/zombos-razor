//! Which DNS servers a Check asks, and the one way it asks them.
//!
//! Blocklists and reverse DNS must be asked through the machine's own resolver:
//! some lists refuse, or answer wrongly, queries that arrive via big public resolvers.

use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RecordType},
};

use crate::{dns::exchange, email_auth::clip};

const RESOLV_CONF_MAX_BYTES: u64 = 64 * 1024;
/// glibc's own limit.
const MAX_SERVERS: usize = 3;

/// The `nameserver` lines of a resolv.conf, in order, on port 53. Anything else is ignored.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = vec![];
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let (Some("nameserver"), Some(ip)) = (words.next(), words.next()) else { continue };
        // A scoped link-local address ("fe80::1%eth0") does not parse and is skipped.
        let Ok(ip) = ip.parse::<IpAddr>() else { continue };
        let server = SocketAddr::new(ip, 53);
        if !ip.is_unspecified() && !out.contains(&server) {
            out.push(server);
        }
    }
    out.truncate(MAX_SERVERS);
    out
}

/// The machine's resolvers from `/etc/resolv.conf`; empty when there are none or the file is unreadable.
pub fn system_resolvers() -> Vec<SocketAddr> {
    let mut bytes = vec![];
    let read = std::fs::File::open("/etc/resolv.conf").and_then(|f| f.take(RESOLV_CONF_MAX_BYTES).read_to_end(&mut bytes));
    if read.is_err() {
        return vec![];
    }
    parse_resolv_conf(&String::from_utf8_lossy(&bytes))
}

/// A list of servers tried in order, and how long each question may take on one server.
#[derive(Debug, Clone)]
pub struct Resolver {
    servers: Vec<SocketAddr>,
    limit: Duration,
}

impl Resolver {
    pub fn new(servers: &[SocketAddr], limit: Duration) -> Self {
        Resolver { servers: servers.to_vec(), limit }
    }

    /// NXDOMAIN is an answer (the name has nothing); any other failure is an
    /// error. The next server is tried only when one gives no answer at all.
    pub async fn ask(&self, name: &str, rtype: RecordType) -> Result<Message, String> {
        let parsed = Name::from_ascii(name).map_err(|_| format!("{:?} is not a valid DNS name", clip(name)))?;
        let mut last = "no DNS resolver to ask".to_string();
        for &server in &self.servers {
            match exchange(server, &parsed, rtype, true, self.limit).await {
                Ok(m) => {
                    return match m.metadata.response_code {
                        ResponseCode::NoError | ResponseCode::NXDomain => Ok(m),
                        other => Err(other.to_str().to_string()),
                    };
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nameserver_lines_and_ignores_the_rest() {
        let text = "# c\nsearch lan\nnameserver 192.168.1.1\nnameserver\nnameserver not-an-ip\nnameserver fe80::1%eth0\n\
                    nameserver 2001:db8::53 # tail\nnameserver 192.168.1.1\nnameserver 0.0.0.0\nnameservers 9.9.9.9\nnameserver 10.0.0.1\nnameserver 10.0.0.2\n";
        let got: Vec<String> = parse_resolv_conf(text).iter().map(ToString::to_string).collect();
        assert_eq!(got, ["192.168.1.1:53", "[2001:db8::53]:53", "10.0.0.1:53"]);
    }

    #[test]
    fn junk_gives_nothing() {
        assert!(parse_resolv_conf("\u{0}\u{1}nameserver\n\n").is_empty());
    }
}
