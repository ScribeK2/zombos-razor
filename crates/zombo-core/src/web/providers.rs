//! Who serves a site: a CDN or host, told from response headers, the CNAME chain
//! of the host name, and the origin AS of its addresses (Team Cymru's DNS service).
//! Everything read from the network here is untrusted text.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use hickory_proto::{
    op::ResponseCode,
    rr::{Name, RData, RecordType},
};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::{dns::exchange, email_auth::clip, text::printable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Cdn,
    Host,
}

/// One provider and everything that pointed at it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    pub provider: &'static str,
    pub kind: ProviderKind,
    pub evidence: Vec<String>,
}

/// The origin AS of one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsnInfo {
    pub ip: IpAddr,
    pub asn: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// What DNS and the headers say about who serves the final host.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Hosting {
    pub host: String,
    pub detections: Vec<Detection>,
    /// Aliases from the host to the name that has addresses, in order.
    pub cname_chain: Vec<String>,
    pub addresses: Vec<IpAddr>,
    pub asns: Vec<AsnInfo>,
    /// Why the DNS half could not be done, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_error: Option<String>,
}

impl Hosting {
    fn add(&mut self, provider: &'static str, kind: ProviderKind, evidence: String) {
        match self.detections.iter_mut().find(|d| d.provider == provider) {
            Some(d) => {
                if !d.evidence.contains(&evidence) {
                    d.evidence.push(evidence);
                }
                if kind == ProviderKind::Cdn {
                    d.kind = kind;
                }
            }
            None => self.detections.push(Detection { provider, kind, evidence: vec![evidence] }),
        }
    }
}

use ProviderKind::{Cdn, Host};

/// (header, substring its lowercase value must contain or None for "present", provider, kind).
const HEADER_RULES: &[(&str, Option<&str>, &str, ProviderKind)] = &[
    ("cf-ray", None, "Cloudflare", Cdn),
    ("cf-cache-status", None, "Cloudflare", Cdn),
    ("server", Some("cloudflare"), "Cloudflare", Cdn),
    ("x-amz-cf-id", None, "Amazon CloudFront", Cdn),
    ("x-amz-cf-pop", None, "Amazon CloudFront", Cdn),
    ("via", Some("cloudfront"), "Amazon CloudFront", Cdn),
    ("x-cache", Some("cloudfront"), "Amazon CloudFront", Cdn),
    ("x-fastly-request-id", None, "Fastly", Cdn),
    ("x-served-by", Some("cache-"), "Fastly", Cdn),
    ("via", Some("fastly"), "Fastly", Cdn),
    ("x-akamai-transformed", None, "Akamai", Cdn),
    ("akamai-grn", None, "Akamai", Cdn),
    ("server", Some("akamaighost"), "Akamai", Cdn),
    ("server", Some("akamainetstorage"), "Akamai", Cdn),
    ("x-azure-ref", None, "Azure Front Door", Cdn),
    ("server", Some("bunnycdn"), "Bunny CDN", Cdn),
    ("x-sucuri-id", None, "Sucuri", Cdn),
    ("server", Some("sucuri"), "Sucuri", Cdn),
    ("x-iinfo", None, "Imperva", Cdn),
    ("x-cdn", Some("imperva"), "Imperva", Cdn),
    ("x-cdn", Some("incapsula"), "Imperva", Cdn),
    ("x-vercel-id", None, "Vercel", Host),
    ("server", Some("vercel"), "Vercel", Host),
    ("x-nf-request-id", None, "Netlify", Host),
    ("server", Some("netlify"), "Netlify", Host),
    ("x-github-request-id", None, "GitHub Pages", Host),
    ("x-pantheon-styx-hostname", None, "Pantheon", Host),
    ("x-kinsta-cache", None, "Kinsta", Host),
    ("x-powered-by", Some("wp engine"), "WP Engine", Host),
    ("x-shopify-stage", None, "Shopify", Host),
    ("x-wix-request-id", None, "Wix", Host),
    ("server", Some("gws"), "Google", Host),
];

/// (CNAME suffix with its leading dot, provider, kind).
const CNAME_RULES: &[(&str, &str, ProviderKind)] = &[
    (".cloudfront.net", "Amazon CloudFront", Cdn),
    (".cdn.cloudflare.net", "Cloudflare", Cdn),
    (".cloudflare.net", "Cloudflare", Cdn),
    (".fastly.net", "Fastly", Cdn),
    (".fastlylb.net", "Fastly", Cdn),
    (".akamaiedge.net", "Akamai", Cdn),
    (".akamai.net", "Akamai", Cdn),
    (".edgekey.net", "Akamai", Cdn),
    (".edgesuite.net", "Akamai", Cdn),
    (".akamaitechnologies.com", "Akamai", Cdn),
    (".azureedge.net", "Azure CDN", Cdn),
    (".azurefd.net", "Azure Front Door", Cdn),
    (".b-cdn.net", "Bunny CDN", Cdn),
    (".sucuri.net", "Sucuri", Cdn),
    (".incapdns.net", "Imperva", Cdn),
    (".cdn77.org", "CDN77", Cdn),
    (".stackpathdns.com", "StackPath", Cdn),
    (".stackpathcdn.com", "StackPath", Cdn),
    (".edgecastcdn.net", "Edgecast", Cdn),
    (".llnwd.net", "Limelight", Cdn),
    (".gcdn.co", "G-Core", Cdn),
    (".netlify.app", "Netlify", Host),
    (".netlify.com", "Netlify", Host),
    (".vercel-dns.com", "Vercel", Host),
    (".vercel.app", "Vercel", Host),
    (".github.io", "GitHub Pages", Host),
    (".herokuapp.com", "Heroku", Host),
    (".herokudns.com", "Heroku", Host),
    (".wpengine.com", "WP Engine", Host),
    (".kinsta.cloud", "Kinsta", Host),
    (".pantheonsite.io", "Pantheon", Host),
    (".myshopify.com", "Shopify", Host),
    (".squarespace.com", "Squarespace", Host),
    (".wixdns.net", "Wix", Host),
    (".elb.amazonaws.com", "Amazon Web Services", Host),
    (".azurewebsites.net", "Microsoft Azure", Host),
];

/// (AS number, provider, kind).
const ASN_RULES: &[(u32, &str, ProviderKind)] = &[
    (13335, "Cloudflare", Cdn),
    (54113, "Fastly", Cdn),
    (20940, "Akamai", Cdn),
    (16625, "Akamai", Cdn),
    (19551, "Imperva", Cdn),
    (30148, "Sucuri", Cdn),
    (16509, "Amazon Web Services", Host),
    (14618, "Amazon Web Services", Host),
    (8075, "Microsoft Azure", Host),
    (15169, "Google", Host),
    (396982, "Google Cloud", Host),
    (14061, "DigitalOcean", Host),
    (16276, "OVHcloud", Host),
    (24940, "Hetzner", Host),
    (20473, "Vultr", Host),
    (63949, "Akamai Connected Cloud (Linode)", Host),
    (26496, "GoDaddy", Host),
    (46606, "Unified Layer (Bluehost, HostGator)", Host),
];

pub(crate) fn provider_from_header(headers: &[(String, String)], hosting: &mut Hosting) {
    for &(name, needle, provider, kind) in HEADER_RULES {
        let Some((_, value)) = headers.iter().find(|(n, _)| n == name) else { continue };
        if needle.is_none_or(|n| value.to_ascii_lowercase().contains(n)) {
            hosting.add(provider, kind, format!("header {name}: {}", clip(value)));
        }
    }
}

fn provider_from_name(name: &str, hosting: &mut Hosting) {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    for &(suffix, provider, kind) in CNAME_RULES {
        if lower.ends_with(suffix) {
            hosting.add(provider, kind, format!("CNAME {}", clip(&lower)));
            return; // the first rule is the most specific
        }
    }
}

fn provider_from_asn(asn: u32, hosting: &mut Hosting) {
    if let Some(&(_, provider, kind)) = ASN_RULES.iter().find(|r| r.0 == asn) {
        hosting.add(provider, kind, format!("AS{asn}"));
    }
}

const MAX_CNAMES: usize = 8;
const MAX_ADDRESSES: usize = 4;
const MAX_ASNS_PER_IP: usize = 2;

/// The name Team Cymru answers for: `1.2.3.4` is asked as `4.3.2.1.origin.asn.cymru.com`,
/// and an IPv6 address by its 32 reversed nibbles under `origin6.asn.cymru.com`.
pub fn cymru_origin_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let nibbles: Vec<String> =
                a.octets().iter().flat_map(|b| [b >> 4, b & 0xf]).rev().map(|n| format!("{n:x}")).collect();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    }
}

fn clean_field(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| clip(&printable(s)))
}

/// `"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"`: the AS numbers (several are possible,
/// separated by spaces), the prefix and the country. Anything else is ignored.
pub fn parse_cymru_origin(txt: &str) -> Vec<(u32, Option<String>, Option<String>)> {
    let mut f = txt.split('|');
    let asns: Vec<u32> =
        f.next().unwrap_or_default().split_whitespace().filter_map(|a| a.parse().ok()).take(MAX_ASNS_PER_IP).collect();
    let (prefix, country) = (f.next().and_then(clean_field), f.next().and_then(clean_field));
    asns.into_iter().map(|a| (a, prefix.clone(), country.clone())).collect()
}

/// `"15169 | US | arin | 2000-03-30 | GOOGLE, US"`: the AS name is the last field.
pub fn parse_cymru_name(txt: &str) -> Option<String> {
    txt.splitn(5, '|').nth(4).and_then(clean_field)
}

pub(crate) fn txt_strings(m: &hickory_proto::op::Message) -> Vec<String> {
    m.answers
        .iter()
        .filter_map(|a| match &a.data {
            RData::TXT(t) => Some(
                String::from_utf8_lossy(&t.txt_data.iter().flat_map(|p| p.iter().copied()).collect::<Vec<u8>>())
                    .into_owned(),
            ),
            _ => None,
        })
        .collect()
}

async fn ask(
    server: SocketAddr,
    name: &str,
    rtype: RecordType,
    limit: Duration,
) -> Result<hickory_proto::op::Message, String> {
    let parsed = Name::from_ascii(name).map_err(|_| format!("{:?} is not a valid DNS name", clip(name)))?;
    let m = exchange(server, &parsed, rtype, true, limit).await.map_err(|e| e.to_string())?;
    match m.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(m),
        other => Err(other.to_str().to_string()),
    }
}

/// The aliases from `host`, then the addresses of the name they end at.
async fn resolve(server: SocketAddr, host: &str, limit: Duration) -> Result<(Vec<String>, Vec<IpAddr>), String> {
    let (mut name, mut chain) = (host.to_string(), vec![]);
    for _ in 0..MAX_CNAMES {
        let m = ask(server, &name, RecordType::CNAME, limit).await?;
        let alias = m.answers.iter().find_map(|a| match &a.data {
            RData::CNAME(c) => Some(c.0.to_string().trim_end_matches('.').to_ascii_lowercase()),
            _ => None,
        });
        match alias {
            Some(a) if chain.contains(&a) => return Err(format!("CNAME loop at {}", clip(&a))),
            Some(a) => {
                chain.push(a.clone());
                name = a;
            }
            None => break,
        }
    }
    let (a, aaaa) = tokio::join!(ask(server, &name, RecordType::A, limit), ask(server, &name, RecordType::AAAA, limit));
    let mut ips = vec![];
    for m in [&a, &aaaa].into_iter().filter_map(|r| r.as_ref().ok()) {
        for r in &m.answers {
            match &r.data {
                RData::A(a) => ips.push(IpAddr::V4(a.0)),
                RData::AAAA(a) => ips.push(IpAddr::V6(a.0)),
                _ => {}
            }
        }
    }
    ips.dedup();
    ips.truncate(MAX_ADDRESSES);
    match (a, aaaa) {
        (Err(e), Err(_)) => Err(e),
        _ => Ok((chain, ips)),
    }
}

async fn asns_of(server: SocketAddr, ip: IpAddr, limit: Duration) -> Vec<AsnInfo> {
    let Ok(m) = ask(server, &cymru_origin_name(ip), RecordType::TXT, limit).await else { return vec![] };
    let Some(found) = txt_strings(&m).iter().map(|t| parse_cymru_origin(t)).find(|v| !v.is_empty()) else {
        return vec![];
    };
    let mut out = vec![];
    for (asn, prefix, country) in found {
        let name = match ask(server, &format!("AS{asn}.asn.cymru.com"), RecordType::TXT, limit).await {
            Ok(m) => txt_strings(&m).iter().find_map(|t| parse_cymru_name(t)),
            Err(_) => None,
        };
        out.push(AsnInfo { ip, asn, prefix, country, name });
    }
    out
}

/// Work out who serves `host`: the headers of its response, its CNAME chain, and
/// the AS of its addresses. DNS failures land in `dns_error`; the header evidence stays.
pub async fn detect_hosting(
    host: &str,
    headers: &[(String, String)],
    resolver: SocketAddr,
    limit: Duration,
) -> Hosting {
    let mut h = Hosting { host: host.to_string(), ..Hosting::default() };
    provider_from_header(headers, &mut h);
    match resolve(resolver, host, limit).await {
        Err(e) => h.dns_error = Some(e),
        Ok((chain, ips)) => {
            for name in &chain {
                provider_from_name(name, &mut h);
            }
            h.cname_chain = chain;
            let mut set = JoinSet::new();
            for (i, ip) in ips.iter().copied().enumerate() {
                set.spawn(async move { (i, asns_of(resolver, ip, limit).await) });
            }
            let mut found = vec![];
            while let Some(Ok(r)) = set.join_next().await {
                found.push(r);
            }
            found.sort_by_key(|(i, _)| *i);
            for info in found.into_iter().flat_map(|(_, v)| v) {
                provider_from_asn(info.asn, &mut h);
                h.asns.push(info);
            }
            h.addresses = ips;
        }
    }
    h
}

/// The first nameserver in /etc/resolv.conf, or Cloudflare's resolver when there is none.
pub fn system_resolver() -> SocketAddr {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|v| v.trim().parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .next()
        .unwrap_or_else(|| SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cymru_names_reverse_the_address() {
        assert_eq!(cymru_origin_name("192.0.2.1".parse().unwrap()), "1.2.0.192.origin.asn.cymru.com");
        let v6 = cymru_origin_name("2001:db8::1".parse().unwrap());
        assert!(v6.starts_with("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6"), "{v6}");
    }

    #[test]
    fn cymru_replies_parse_defensively() {
        assert_eq!(
            parse_cymru_origin("15169 | 8.8.8.0/24 | US | arin | 1992-12-01"),
            vec![(15169, Some("8.8.8.0/24".into()), Some("US".into()))]
        );
        assert_eq!(parse_cymru_origin("13335 13336 | 1.1.1.0/24 | AU").len(), 2);
        assert!(parse_cymru_origin("garbage").is_empty());
        assert!(parse_cymru_origin("").is_empty());
        assert_eq!(parse_cymru_origin("64500").first().map(|r| r.0), Some(64500));
        assert_eq!(parse_cymru_name("15169 | US | arin | 2000-03-30 | GOOGLE, US").as_deref(), Some("GOOGLE, US"));
        assert_eq!(parse_cymru_name("15169 | US"), None);
        // A control character from the network never reaches the output.
        assert_eq!(parse_cymru_name("1 | US | x | y | A\u{1b}[2JB").as_deref(), Some("A\u{fffd}[2JB"));
    }

    #[test]
    fn cname_suffix_matches_on_a_label_boundary() {
        let mut h = Hosting::default();
        provider_from_name("d111.cloudfront.net.", &mut h);
        assert_eq!(h.detections[0].provider, "Amazon CloudFront");
        let mut h = Hosting::default();
        provider_from_name("evilcloudfront.net", &mut h);
        assert!(h.detections.is_empty());
    }
}
