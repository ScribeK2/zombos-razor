//! DNSSEC Check: is a domain's DNSSEC healthy, and when it is not, why?
//!
//! Two parts, and no signature cryptography. First, known-validating public
//! resolvers are asked for the same record with and without the CD (checking
//! disabled) flag: SERVFAIL that turns into an answer is DNSSEC breaking the
//! domain. Second, the DS records at the parent and the DNSKEY and signature
//! the zone's own nameservers serve are compared, which explains why.
//! DNSSEC records are read from raw RDATA: hickory decodes them only with its
//! crypto features, which Zombo does not use.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde::{Serialize, Serializer};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};
use tokio::task::JoinSet;

use crate::{
    dns::{QueryFlags, exchange_with},
    finding::{Finding, Severity},
    propagation::{DiscoverError, Vantage, ipv6_available},
};

/// RFC 4034 Appendix B key tag: a checksum that names a DNSKEY, so a DS or an
/// RRSIG can say which key it refers to. Not unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct KeyTag(pub u16);

impl fmt::Display for KeyTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn key_tag(rdata: &[u8], algorithm: Algorithm) -> KeyTag {
    if algorithm == Algorithm::RsaMd5 {
        // The one exception in Appendix B: the top 16 of the last 24 bits of the key.
        return KeyTag(rdata.len().checked_sub(3).map_or(0, |i| u16::from_be_bytes([rdata[i], rdata[i + 1]])));
    }
    let mut sum: u32 = rdata.iter().enumerate().map(|(i, &b)| u32::from(b) << if i % 2 == 0 { 8 } else { 0 }).sum();
    sum += sum >> 16;
    KeyTag((sum & 0xffff) as u16)
}

/// DNSSEC algorithm numbers (IANA registry), with the ones Zombo knows named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaMd5,
    Dsa,
    RsaSha1,
    DsaNsec3Sha1,
    RsaSha1Nsec3Sha1,
    RsaSha256,
    RsaSha512,
    Gost,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    Ed448,
    Unknown(u8),
}

use Algorithm::*;

/// (algorithm, number, name, deprecated). Deprecated means weak or no longer
/// accepted by modern resolvers.
const ALGORITHMS: [(Algorithm, u8, &str, bool); 12] = [
    (RsaMd5, 1, "RSAMD5", true),
    (Dsa, 3, "DSA", true),
    (RsaSha1, 5, "RSASHA1", true),
    (DsaNsec3Sha1, 6, "DSA-NSEC3-SHA1", true),
    (RsaSha1Nsec3Sha1, 7, "RSASHA1-NSEC3-SHA1", true),
    (RsaSha256, 8, "RSASHA256", false),
    (RsaSha512, 10, "RSASHA512", false),
    (Gost, 12, "ECC-GOST", true),
    (EcdsaP256Sha256, 13, "ECDSAP256SHA256", false),
    (EcdsaP384Sha384, 14, "ECDSAP384SHA384", false),
    (Ed25519, 15, "ED25519", false),
    (Ed448, 16, "ED448", false),
];

impl Algorithm {
    pub fn from_number(n: u8) -> Self {
        ALGORITHMS.iter().find(|a| a.1 == n).map_or(Unknown(n), |a| a.0)
    }

    fn row(self) -> Option<&'static (Algorithm, u8, &'static str, bool)> {
        ALGORITHMS.iter().find(|a| a.0 == self)
    }

    pub fn number(self) -> u8 {
        match self {
            Unknown(n) => n,
            known => known.row().map_or(0, |a| a.1),
        }
    }

    pub fn deprecated(self) -> bool {
        self.row().is_some_and(|a| a.3)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.row() {
            Some(a) => write!(f, "{} ({})", a.2, a.1),
            None => write!(f, "algorithm {}", self.number()),
        }
    }
}

impl Serialize for Algorithm {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// DS digest types (IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    Sha1,
    Sha256,
    Sha384,
    Unknown(u8),
}

fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}
fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
fn sha384(data: &[u8]) -> Vec<u8> {
    Sha384::digest(data).to_vec()
}

const DIGESTS: [(DigestType, u8, &str, fn(&[u8]) -> Vec<u8>); 3] = [
    (DigestType::Sha1, 1, "SHA-1", sha1),
    (DigestType::Sha256, 2, "SHA-256", sha256),
    (DigestType::Sha384, 4, "SHA-384", sha384),
];

impl DigestType {
    pub fn from_number(n: u8) -> Self {
        DIGESTS.iter().find(|d| d.1 == n).map_or(DigestType::Unknown(n), |d| d.0)
    }

    pub fn number(self) -> u8 {
        match self {
            DigestType::Unknown(n) => n,
            known => DIGESTS.iter().find(|d| d.0 == known).map_or(0, |d| d.1),
        }
    }

    /// The digest of `data`, or `None` for a type Zombo cannot compute.
    pub fn digest(self, data: &[u8]) -> Option<Vec<u8>> {
        DIGESTS.iter().find(|d| d.0 == self).map(|d| d.3(data))
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match DIGESTS.iter().find(|d| d.0 == *self) {
            Some(d) => f.write_str(d.2),
            None => write!(f, "digest type {}", self.number()),
        }
    }
}

impl Serialize for DigestType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

fn hex<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// A DNSKEY record as a zone serves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dnskey {
    pub flags: u16,
    #[serde(skip)]
    protocol: u8,
    pub algorithm: Algorithm,
    pub key_tag: KeyTag,
    #[serde(skip)]
    pub public_key: Vec<u8>,
}

impl Dnskey {
    pub fn new(flags: u16, protocol: u8, algorithm: Algorithm, public_key: Vec<u8>) -> Self {
        let mut k = Dnskey { flags, protocol, algorithm, key_tag: KeyTag(0), public_key };
        k.key_tag = key_tag(&k.rdata(), algorithm);
        k
    }

    /// From the record's wire RDATA: flags, protocol, algorithm, key.
    pub fn from_rdata(rdata: &[u8]) -> Option<Self> {
        let (&[f0, f1, protocol, alg], key) = rdata.split_first_chunk()?;
        Some(Dnskey::new(u16::from_be_bytes([f0, f1]), protocol, Algorithm::from_number(alg), key.to_vec()))
    }

    fn rdata(&self) -> Vec<u8> {
        let mut out = self.flags.to_be_bytes().to_vec();
        out.extend([self.protocol, self.algorithm.number()]);
        out.extend(&self.public_key);
        out
    }

    /// The secure entry point flag: a key signing key, the one a DS points at.
    pub fn is_ksk(&self) -> bool {
        self.flags & 0x0001 != 0
    }
}

/// A DS record: the parent zone's statement of which child key to trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ds {
    pub key_tag: KeyTag,
    pub algorithm: Algorithm,
    pub digest_type: DigestType,
    #[serde(serialize_with = "hex")]
    pub digest: Vec<u8>,
}

impl Ds {
    /// From the record's wire RDATA: key tag, algorithm, digest type, digest.
    pub fn from_rdata(rdata: &[u8]) -> Option<Self> {
        let (&[t0, t1, alg, digest_type], digest) = rdata.split_first_chunk()?;
        Some(Ds {
            key_tag: KeyTag(u16::from_be_bytes([t0, t1])),
            algorithm: Algorithm::from_number(alg),
            digest_type: DigestType::from_number(digest_type),
            digest: digest.to_vec(),
        })
    }

    /// Whether this DS points at `key`, a DNSKEY of the zone named `owner`: same
    /// key tag and algorithm, and the digest of owner name plus key is the one
    /// the DS holds. A digest type Zombo cannot compute is given the benefit of
    /// the doubt once tag and algorithm agree, so it never produces a false mismatch.
    pub fn matches(&self, owner: &Name, key: &Dnskey) -> bool {
        if self.key_tag != key.key_tag || self.algorithm != key.algorithm {
            return false;
        }
        let mut input = canonical_wire(owner);
        input.extend(key.rdata());
        self.digest_type.digest(&input).is_none_or(|d| d == self.digest)
    }
}

/// A name as it is hashed: lowercase labels, each with its length, ending in the root.
fn canonical_wire(name: &Name) -> Vec<u8> {
    let mut out = vec![];
    for label in name.iter() {
        out.push(label.len() as u8);
        out.extend(label.to_ascii_lowercase());
    }
    out.push(0);
    out
}

/// An RRSIG record: a signature over one record set, valid between two times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rrsig {
    #[serde(skip)]
    covered: RecordType,
    pub algorithm: Algorithm,
    pub key_tag: KeyTag,
    pub signer: String,
    /// Seconds since 1970, modulo 2^32 (RFC 4034 section 3.1.5).
    pub inception: u32,
    pub expiration: u32,
}

/// Where "now" falls against an RRSIG's validity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SigWindow {
    NotYetValid { starts_in: u32 },
    Valid { expires_in: u32 },
    Expired { ago: u32 },
}

impl Rrsig {
    /// From the record's wire RDATA: type covered, algorithm, labels, original
    /// TTL, expiration, inception, key tag, signer name, signature.
    pub fn from_rdata(rdata: &[u8]) -> Option<Self> {
        let (head, rest) = rdata.split_first_chunk::<18>()?;
        let u32_at = |i: usize| u32::from_be_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]);
        let mut signer = String::new();
        let mut labels = rest;
        loop {
            let (&len, tail) = labels.split_first()?;
            if len == 0 {
                break;
            }
            // A signer name is never compressed, so a pointer here means garbage.
            let (label, tail) = tail.split_at_checked(usize::from(len)).filter(|_| len < 64)?;
            signer.push_str(&String::from_utf8_lossy(label));
            signer.push('.');
            labels = tail;
        }
        Some(Rrsig {
            covered: RecordType::from(u16::from_be_bytes([head[0], head[1]])),
            algorithm: Algorithm::from_number(head[2]),
            key_tag: KeyTag(u16::from_be_bytes([head[16], head[17]])),
            signer: if signer.is_empty() { ".".into() } else { signer },
            expiration: u32_at(8),
            inception: u32_at(12),
        })
    }

    pub fn type_covered(&self) -> RecordType {
        self.covered
    }

    /// Where `now` falls against the validity period. The times are serial
    /// numbers (RFC 1982): a plain comparison would break when they wrap in 2106.
    pub fn window(&self, now: SystemTime) -> SigWindow {
        let now = epoch_secs(now);
        let until_start = self.inception.wrapping_sub(now) as i32;
        let until_end = self.expiration.wrapping_sub(now) as i32;
        if until_start > 0 {
            SigWindow::NotYetValid { starts_in: until_start.unsigned_abs() }
        } else if until_end < 0 {
            SigWindow::Expired { ago: until_end.unsigned_abs() }
        } else {
            SigWindow::Valid { expires_in: until_end.unsigned_abs() }
        }
    }
}

/// Seconds since 1970 modulo 2^32, the form RRSIG times use.
fn epoch_secs(t: SystemTime) -> u32 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32)
}

/// What one validating resolver says about the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverStatus {
    /// Answered, and set the AD flag: the answer was validated.
    Secure,
    /// Answered without AD: the domain is not signed, as far as this resolver can tell.
    Insecure,
    /// SERVFAIL, but an answer once checking is disabled: DNSSEC itself is broken.
    Bogus,
    /// Anything else, such as SERVFAIL even with checking disabled, which is a
    /// plain DNS failure and says nothing about DNSSEC.
    Failed,
    NoAnswer,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverVerdict {
    pub resolver: String,
    pub status: ResolverStatus,
}

/// Public resolvers that validate DNSSEC. Verified to SERVFAIL on a broken
/// signature and answer when the CD flag is set; a resolver that does not
/// validate would make every domain look fine.
pub fn validating_resolvers() -> Vec<Vantage> {
    [
        ("Google", "Global anycast", "8.8.8.8"),
        ("Cloudflare", "Global anycast", "1.1.1.1"),
        ("Quad9", "Global anycast", "9.9.9.9"),
        ("OpenDNS", "United States", "208.67.222.222"),
    ]
    .map(|(n, l, ip)| Vantage::resolver(n, l, SocketAddr::new(ip.parse().unwrap(), 53)))
    .into()
}

/// A nameserver's own DNSKEY set and SOA signature, asked directly.
#[derive(Debug, Clone, Serialize)]
pub struct NameserverView {
    pub name: String,
    /// Set when the nameserver gave no usable answer, with why.
    pub error: Option<String>,
    pub authoritative: bool,
    pub recursion_available: bool,
    pub dnskeys: Vec<Dnskey>,
    /// The signature over the zone's SOA with the latest expiry (during a key
    /// rollover there can be two).
    pub soa_rrsig: Option<Rrsig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DsStatus {
    #[serde(flatten)]
    pub ds: Ds,
    /// Whether it points at a DNSKEY some nameserver serves.
    pub matched: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnssecResult {
    pub apex: String,
    /// Seconds since 1970 when the Check ran: what signature times are judged against.
    pub checked_at: u64,
    pub resolvers: Vec<ResolverVerdict>,
    /// The DS records the parent zone publishes for the apex.
    pub ds: Vec<DsStatus>,
    pub nameservers: Vec<NameserverView>,
}

#[derive(Debug, thiserror::Error)]
pub enum DnssecError {
    #[error(transparent)]
    Discover(#[from] DiscoverError),
    #[error("{0} is not a valid DNS name")]
    BadName(String),
    #[error("no resolver could say whether {0} has a DS record at its parent")]
    NoDs(String),
    #[error("neither the validating resolvers nor the nameservers answered; outbound DNS may be blocked on this network")]
    NoneAnswered,
}

/// Run the Check for the zone `target` is in. `ns_port` is 53 outside tests.
///
/// The zone and its nameservers are found with CD set: a validating
/// bootstrap resolver would otherwise SERVFAIL on exactly the broken zones
/// this Check exists to explain.
pub async fn check_dnssec(
    bootstrap: &[SocketAddr],
    validating: &[Vantage],
    target: &str,
    ns_port: u16,
    now: SystemTime,
    limit: Duration,
) -> Result<DnssecResult, DnssecError> {
    let (apex, ns_names) = find_zone(bootstrap, target, limit).await?;
    let nameservers = nameserver_vantages(bootstrap, &ns_names, ns_port, limit).await;
    dnssec_with(bootstrap, validating, &nameservers, &apex, now, limit).await
}

/// The Check against a known zone and known nameservers.
pub async fn dnssec_with(
    bootstrap: &[SocketAddr],
    validating: &[Vantage],
    nameservers: &[Vantage],
    apex: &str,
    now: SystemTime,
    limit: Duration,
) -> Result<DnssecResult, DnssecError> {
    let apex_name = Name::from_ascii(apex).map_err(|_| DnssecError::BadName(apex.into()))?;
    let resolver_jobs: Vec<_> = validating.iter().cloned().map(|v| verdict(v, apex_name.clone(), limit)).collect();
    let ns_jobs: Vec<_> = nameservers.iter().cloned().map(|v| nameserver_view(v, apex_name.clone(), now, limit)).collect();
    let (resolvers, nameservers, ds_answer) =
        tokio::join!(in_order(resolver_jobs), in_order(ns_jobs), lookup(bootstrap, &apex_name, RecordType::DS, limit));
    let ds_answer = ds_answer.filter(|m| m.metadata.response_code == ResponseCode::NoError).ok_or_else(|| DnssecError::NoDs(apex.into()))?;

    if resolvers.iter().all(|r| r.status == ResolverStatus::NoAnswer) && nameservers.iter().all(|n| n.error.is_some()) {
        return Err(DnssecError::NoneAnswered);
    }
    let keys: Vec<&Dnskey> = nameservers.iter().flat_map(|n| &n.dnskeys).collect();
    let ds = rdata_of(&ds_answer, RecordType::DS)
        .filter_map(Ds::from_rdata)
        .map(|ds| DsStatus { matched: keys.iter().any(|k| ds.matches(&apex_name, k)), ds })
        .collect();
    Ok(DnssecResult { apex: apex.into(), checked_at: u64::from(epoch_secs(now)), resolvers, ds, nameservers })
}

/// A signature this close to expiring is a warning: zones are normally re-signed days ahead.
const EXPIRING_SOON_SECS: u32 = 3 * 86_400;

fn span(secs: u32) -> String {
    let (n, unit) = match secs {
        0..=119 => (secs, "second"),
        120..=7199 => (secs / 60, "minute"),
        7200..=172_799 => (secs / 3600, "hour"),
        _ => (secs / 86_400, "day"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

fn tags(keys: &[Dnskey]) -> String {
    match keys {
        [] => "no keys".into(),
        keys => format!("key{} {}", if keys.len() == 1 { "" } else { "s" }, keys.iter().map(|k| k.key_tag.to_string()).collect::<Vec<_>>().join(", ")),
    }
}

/// What the Check found, in plain sentences for a support rep.
pub fn dnssec_findings(r: &DnssecResult) -> Vec<Finding> {
    let mut out = vec![];
    let answered: Vec<&NameserverView> = r.nameservers.iter().filter(|n| n.error.is_none()).collect();
    let resolvers = |s: ResolverStatus| r.resolvers.iter().filter(|v| v.status == s).map(|v| v.resolver.as_str()).collect::<Vec<_>>();
    let (bogus, secure) = (resolvers(ResolverStatus::Bogus), resolvers(ResolverStatus::Secure));

    let any_keys = answered.iter().any(|n| !n.dnskeys.is_empty());
    let ds_without_dnskey = !r.ds.is_empty() && !answered.is_empty() && !any_keys;
    let ds_mismatch = !r.ds.is_empty() && any_keys && r.ds.iter().all(|d| !d.matched);

    let now = UNIX_EPOCH + Duration::from_secs(r.checked_at);
    let windows: Vec<(&str, SigWindow)> = answered.iter().filter_map(|n| n.soa_rrsig.as_ref().map(|s| (n.name.as_str(), s.window(now)))).collect();
    let expired: Vec<String> = windows
        .iter()
        .filter_map(|(n, w)| match w {
            SigWindow::Expired { ago } => Some(format!("{n} (expired {} ago)", span(*ago))),
            _ => None,
        })
        .collect();
    // Under three days left, but never more than a quarter of the signature's lifetime: some
    // providers (Cloudflare) sign for just two days and re-sign continuously, so a flat three
    // days would flag them permanently.
    let expiring: Vec<String> = answered
        .iter()
        .filter_map(|n| n.soa_rrsig.as_ref().map(|s| (n, s, s.expiration.wrapping_sub(s.inception))))
        .filter_map(|(n, s, lifetime)| match s.window(now) {
            SigWindow::Valid { expires_in } if expires_in < EXPIRING_SOON_SECS.min(lifetime / 4) => Some(format!("{} (expires in {})", n.name, span(expires_in))),
            _ => None,
        })
        .collect();

    if answered.len() >= 2 && answered.iter().all(|n| !n.authoritative && n.recursion_available) {
        let names: Vec<&str> = answered.iter().map(|n| n.name.as_str()).collect();
        out.push(crate::dns::interception_finding(&names));
    }

    if !bogus.is_empty() {
        let cause = if ds_without_dnskey {
            " The likely cause: the parent zone publishes a DS record but the zone serves no DNSKEY, so it looks unsigned."
        } else if ds_mismatch {
            " The likely cause: the DS record at the parent matches none of the keys the zone serves."
        } else if !expired.is_empty() {
            " The likely cause: the zone's signatures have expired."
        } else {
            ""
        };
        out.push(Finding {
            code: "dnssec_bogus",
            severity: Severity::Critical,
            title: "Validating resolvers reject this domain",
            message: format!(
                "{} answer SERVFAIL for {} but answer normally when DNSSEC checking is turned off, so the domain's DNSSEC is broken. Validating resolvers refuse to answer, so the domain is unreachable for most users.{cause}",
                bogus.join(", "),
                r.apex
            ),
            recommendation: Some("Fix the DNSSEC problem reported with this finding. If it cannot be fixed quickly, remove the DS record at the registrar: the domain then works again, without DNSSEC."),
        });
    }
    if ds_without_dnskey {
        out.push(Finding {
            code: "dnssec_ds_without_dnskey",
            severity: Severity::Critical,
            title: "DS record but no DNSKEY",
            message: format!(
                "The parent zone publishes a DS record for {}, which says the zone is signed, but its nameservers serve no DNSKEY. The zone is unsigned or its DNS provider stopped signing, and validating resolvers will treat every answer as forged.",
                r.apex
            ),
            recommendation: Some("Turn DNSSEC signing back on at the DNS provider, or remove the DS record at the registrar."),
        });
    }
    if ds_mismatch {
        let ds: Vec<String> = r.ds.iter().map(|d| format!("{} ({})", d.ds.key_tag, d.ds.digest_type)).collect();
        let served: Vec<String> = answered.iter().flat_map(|n| n.dnskeys.iter().filter(|k| k.is_ksk())).map(|k| k.key_tag.to_string()).collect();
        let served: std::collections::BTreeSet<String> = served.into_iter().collect();
        out.push(Finding {
            code: "dnssec_ds_mismatch",
            severity: Severity::Critical,
            title: "DS record matches none of the zone's keys",
            message: format!(
                "The parent zone publishes DS for key {} but the nameservers serve {}, so the chain of trust is broken and validating resolvers reject the zone. This usually happens after moving DNS to a new provider.",
                ds.join(", "),
                if served.is_empty() { "no signing key".to_string() } else { format!("signing key {}", served.into_iter().collect::<Vec<_>>().join(", ")) }
            ),
            recommendation: Some("Give the registrar the new provider's DS record, or remove the DS record to turn DNSSEC off."),
        });
    }
    if !expired.is_empty() {
        out.push(Finding {
            code: "dnssec_signature_expired",
            severity: Severity::Critical,
            title: "The zone's signatures have expired",
            message: format!("The signature on the zone's SOA record has expired: {}. Validating resolvers reject every answer from the zone.", expired.join(", ")),
            recommendation: Some("Have the zone re-signed. DNS providers do this automatically, so ask the provider why it stopped."),
        });
    }
    if !expiring.is_empty() {
        out.push(Finding {
            code: "dnssec_signature_expiring",
            severity: Severity::Warning,
            title: "The zone's signatures expire soon",
            message: format!("The signature on the zone's SOA record is about to expire: {}. Zones are normally re-signed well before that, so signing may have stopped.", expiring.join(", ")),
            recommendation: Some("Check that the zone is being re-signed. If it is not, validating resolvers will reject the domain when the signature expires."),
        });
    }
    let deprecated: std::collections::BTreeMap<u8, Algorithm> = r
        .ds
        .iter()
        .map(|d| d.ds.algorithm)
        .chain(answered.iter().flat_map(|n| n.dnskeys.iter().map(|k| k.algorithm)))
        .filter(|a| a.deprecated())
        .map(|a| (a.number(), a))
        .collect();
    if !deprecated.is_empty() {
        out.push(Finding {
            code: "dnssec_algorithm_deprecated",
            severity: Severity::Warning,
            title: "Deprecated signing algorithm",
            message: format!(
                "The zone is signed with {}, which is deprecated: it is weak, and validating resolvers are dropping support for it, which can make the domain look unsigned or broken.",
                deprecated.values().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
            recommendation: Some("Ask the DNS provider to switch the zone to a modern algorithm such as ECDSAP256SHA256 (13)."),
        });
    }
    let key_sets: Vec<std::collections::BTreeSet<(u16, u8, &[u8])>> =
        answered.iter().map(|n| n.dnskeys.iter().map(|k| (k.flags, k.algorithm.number(), k.public_key.as_slice())).collect()).collect();
    if key_sets.windows(2).any(|w| w[0] != w[1]) {
        let each: Vec<String> = answered.iter().map(|n| format!("{} serves {}", n.name, tags(&n.dnskeys))).collect();
        out.push(Finding {
            code: "dnssec_nameservers_disagree",
            severity: Severity::Warning,
            title: "Nameservers serve different keys",
            message: format!(
                "The nameservers do not serve the same DNSKEY set ({}). The zone is out of sync or in the middle of a key rollover, and validation can fail depending on which nameserver a resolver reaches.",
                each.join("; ")
            ),
            recommendation: Some("Make every nameserver serve the same signed zone. If a key rollover is under way, wait for it to finish and check again."),
        });
    }
    if r.ds.is_empty() && !answered.is_empty() {
        if any_keys {
            out.push(Finding {
                code: "dnssec_ds_missing",
                severity: Severity::Info,
                title: "Signed, but not linked to the parent",
                message: format!("The nameservers serve DNSKEY records but the parent zone has no DS record for {}, so validating resolvers ignore the signatures and treat the zone as unsigned.", r.apex),
                recommendation: Some("If DNSSEC should be on, publish the zone's DS record at the registrar."),
            });
        } else {
            out.push(Finding {
                code: "dnssec_not_signed",
                severity: Severity::Info,
                title: "DNSSEC is not enabled",
                message: format!("{} has no DS record at its parent and its nameservers serve no DNSKEY, so the zone is not signed. That works everywhere, but its answers cannot be verified.", r.apex),
                recommendation: None,
            });
        }
    }
    if out.is_empty() && !secure.is_empty() && r.ds.iter().any(|d| d.matched) {
        let left = windows.iter().filter_map(|(_, w)| if let SigWindow::Valid { expires_in } = w { Some(*expires_in) } else { None }).min();
        out.push(Finding {
            code: "dnssec_secure",
            severity: Severity::Ok,
            title: "DNSSEC is healthy",
            message: format!(
                "{} confirm the answers for {} are authentic, the DS record at the parent matches the zone's key, and the signatures are valid{}.",
                secure.join(", "),
                r.apex,
                left.map_or(String::new(), |s| format!(" for another {}", span(s)))
            ),
            recommendation: None,
        });
    }
    out
}

/// Run the jobs at the same time and return their results in the order given.
async fn in_order<T: Send + 'static>(jobs: Vec<impl Future<Output = T> + Send + 'static>) -> Vec<T> {
    let mut set = JoinSet::new();
    let mut slots: Vec<Option<T>> = jobs.iter().map(|_| None).collect();
    for (i, job) in jobs.into_iter().enumerate() {
        set.spawn(async move { (i, job.await) });
    }
    while let Some(Ok((i, out))) = set.join_next().await {
        slots[i] = Some(out);
    }
    slots.into_iter().flatten().collect()
}

/// The raw RDATA of the answers of one type.
fn rdata_of(m: &Message, t: RecordType) -> impl Iterator<Item = &[u8]> {
    m.answers.iter().filter(move |r| r.record_type() == t).filter_map(|r| match &r.data {
        RData::Unknown { rdata, .. } => Some(rdata.anything.as_slice()),
        _ => None,
    })
}

fn classify(checked: Option<(ResponseCode, bool)>, unchecked: Option<(ResponseCode, bool)>) -> ResolverStatus {
    use ResponseCode::{NoError, ServFail};
    match (checked, unchecked) {
        (None, _) => ResolverStatus::NoAnswer,
        (Some((NoError, true)), _) => ResolverStatus::Secure,
        (Some((NoError, false)), _) => ResolverStatus::Insecure,
        (Some((ServFail, _)), Some((NoError, _))) => ResolverStatus::Bogus,
        _ => ResolverStatus::Failed,
    }
}

/// Ask the apex A record twice, with and without checking: a resolver that fails
/// only when it checks is rejecting the domain's DNSSEC.
async fn verdict(v: Vantage, apex: Name, limit: Duration) -> ResolverVerdict {
    let ask = |checking_disabled| {
        let flags = QueryFlags { recursion_desired: true, dnssec_ok: true, checking_disabled };
        exchange_with(v.address, &apex, RecordType::A, flags, limit)
    };
    let (checked, unchecked) = tokio::join!(ask(false), ask(true));
    let summary = |m: Result<Message, _>| m.ok().map(|m| (m.metadata.response_code, m.metadata.authentic_data));
    ResolverVerdict { status: classify(summary(checked), summary(unchecked)), resolver: v.name }
}

async fn nameserver_view(v: Vantage, apex: Name, now: SystemTime, limit: Duration) -> NameserverView {
    let ask = |t| exchange_with(v.address, &apex, t, QueryFlags { recursion_desired: false, dnssec_ok: true, checking_disabled: false }, limit);
    let (keys, soa) = tokio::join!(ask(RecordType::DNSKEY), ask(RecordType::SOA));
    let mut view = NameserverView {
        name: v.name,
        error: None,
        authoritative: false,
        recursion_available: false,
        dnskeys: vec![],
        soa_rrsig: None,
    };
    match keys {
        Err(e) => view.error = Some(e.to_string()),
        Ok(m) if m.metadata.response_code != ResponseCode::NoError => view.error = Some(m.metadata.response_code.to_str().into()),
        Ok(m) => {
            view.authoritative = m.metadata.authoritative;
            view.recursion_available = m.metadata.recursion_available;
            view.dnskeys = rdata_of(&m, RecordType::DNSKEY).filter_map(Dnskey::from_rdata).collect();
        }
    }
    let until_expiry = |s: &Rrsig| s.expiration.wrapping_sub(epoch_secs(now)) as i32;
    view.soa_rrsig = soa
        .ok()
        .iter()
        .flat_map(|m| rdata_of(m, RecordType::RRSIG))
        .filter_map(Rrsig::from_rdata)
        .filter(|s| s.type_covered() == RecordType::SOA)
        .max_by_key(until_expiry);
    view
}

/// One recursive answer for `name`, asked with DO and CD set so that a
/// validating resolver still answers for a zone whose DNSSEC is broken. The
/// first resolver to give a NOERROR answer wins, else the first answer at all.
async fn lookup(bootstrap: &[SocketAddr], name: &Name, t: RecordType, limit: Duration) -> Option<Message> {
    let flags = QueryFlags { recursion_desired: true, dnssec_ok: true, checking_disabled: true };
    let mut fallback = None;
    for &s in bootstrap {
        match exchange_with(s, name, t, flags, limit).await {
            Ok(m) if m.metadata.response_code == ResponseCode::NoError => return Some(m),
            Ok(m) => fallback = fallback.or(Some(m)),
            Err(_) => {}
        }
    }
    fallback
}

/// The zone `target` is in: walks up from the target (never above its
/// registrable domain) until a name has NS records.
async fn find_zone(bootstrap: &[SocketAddr], target: &str, limit: Duration) -> Result<(String, Vec<Name>), DiscoverError> {
    let floor = psl::domain_str(target).unwrap_or(target).to_string();
    let mut zone = target.to_string();
    loop {
        let name = Name::from_ascii(&zone).map_err(|_| DiscoverError::NoNameservers(target.into()))?;
        let m = lookup(bootstrap, &name, RecordType::NS, limit).await.ok_or_else(|| DiscoverError::NoResolver(target.into()))?;
        let ns: Vec<Name> = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::NS(ns) => Some(ns.0.clone()),
                _ => None,
            })
            .collect();
        if !ns.is_empty() {
            return Ok((zone, ns));
        }
        match zone.split_once('.') {
            Some((_, parent)) if zone != floor => zone = parent.to_string(),
            _ => return Err(DiscoverError::NoNameservers(target.into())),
        }
    }
}

/// The zone's nameservers as Vantages: one IPv4 and one IPv6 address each (IPv6
/// only when this machine has a route), as `discover_nameservers` does.
async fn nameserver_vantages(bootstrap: &[SocketAddr], names: &[Name], port: u16, limit: Duration) -> Vec<Vantage> {
    let mut out = vec![];
    for ns in names.iter().take(8) {
        let mut ips = vec![];
        for t in [RecordType::A, RecordType::AAAA] {
            if let Some(m) = lookup(bootstrap, ns, t, limit).await {
                ips.extend(m.answers.iter().filter_map(|r| match &r.data {
                    RData::A(a) => Some(IpAddr::V4(a.0)),
                    RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                    _ => None,
                }));
            }
        }
        let v4 = ips.iter().find(|ip| ip.is_ipv4());
        let v6 = ips.iter().find(|ip| ip.is_ipv6()).filter(|_| ipv6_available());
        let picked: Vec<&IpAddr> = v4.into_iter().chain(v6).collect();
        let label = ns.to_string();
        let label = label.trim_end_matches('.');
        for ip in &picked {
            let name = if picked.len() > 1 { format!("{label} {ip}") } else { label.to_string() };
            out.push(Vantage::nameserver(&name, SocketAddr::new(**ip, port)));
        }
    }
    out
}
