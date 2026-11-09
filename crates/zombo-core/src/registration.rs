//! Domain registration: who holds a domain, until when, in what state. Asks the
//! registry over RDAP and falls back to WHOIS (port 43) when RDAP is unavailable.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::OnceLock,
    time::{Duration, Instant},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::finding::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Rdap,
    Whois,
}

/// Where to ask. `Endpoints::default()` is the real registries; tests point
/// these at fake servers.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// TLD -> RDAP base URL, ahead of the bundled IANA bootstrap.
    pub rdap: BTreeMap<String, String>,
    /// TLD -> WHOIS `host:port`, ahead of the built-in table and IANA referrals.
    pub whois: BTreeMap<String, String>,
    pub whois_iana: String,
    /// Port of the server an IANA referral names.
    pub whois_referral_port: u16,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints { rdap: BTreeMap::new(), whois: BTreeMap::new(), whois_iana: "whois.iana.org:43".into(), whois_referral_port: 43 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RdapError {
    #[error("no RDAP service for .{0}")]
    NoService(String),
    #[error("{0}")]
    Request(String),
    #[error("RDAP server answered {0}")]
    Status(String),
    #[error("unreadable RDAP answer: {0}")]
    Unreadable(String),
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("{0:?} is not a valid domain name")]
    BadName(String),
    #[error("timed out")]
    TimedOut,
    #[error("RDAP: {0}")]
    Rdap(RdapError),
}

/// A registry's answer is never bigger than this; anything larger is an attack or a bug.
const MAX_REPLY: u64 = 1 << 20;
const MAX_REDIRECTS: u32 = 3;

/// Look up who registered `target` (a domain or a name below one), asking RDAP
/// first. The whole lookup, however many servers it asks, takes at most `limit`.
pub async fn check_registration(target: &str, endpoints: &Endpoints, limit: Duration) -> Result<Registration, RegistrationError> {
    let name = registrable_domain(&clean_name(target)?);
    let deadline = Instant::now() + limit;
    tokio::time::timeout(limit, async {
        let tld = name.rsplit('.').next().unwrap_or_default();
        let base = endpoints.rdap.get(tld).map(String::as_str).or_else(|| rdap_bases().get(tld).map(String::as_str));
        let rdap = match base {
            None => RdapError::NoService(tld.into()),
            Some(base) => match rdap_lookup(base, &name, deadline).await {
                Ok(r) => return Ok(r),
                Err(e) => e,
            },
        };
        Err(RegistrationError::Rdap(rdap))
    })
    .await
    .map_err(|_| RegistrationError::TimedOut)?
}

/// Lowercase, no trailing dot, and only what a DNS name can hold: the name goes
/// into a URL and a WHOIS query line, so nothing else may pass.
fn clean_name(target: &str) -> Result<String, RegistrationError> {
    let name = target.trim_end_matches('.').to_ascii_lowercase();
    let ok = name.contains('.')
        && name.len() <= 253
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')));
    if ok { Ok(name) } else { Err(RegistrationError::BadName(target.into())) }
}

// RDAP

/// IANA's RDAP bootstrap for domains (https://data.iana.org/rdap/dns.json).
const BOOTSTRAP: &str = include_str!("../data/rdap_bootstrap.json");

#[derive(Deserialize)]
struct Bootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

/// TLD -> RDAP base URL, always https: a registry that lists http (rdap.cctld.kg
/// does) is asked over https, and if it does not serve it the lookup falls back to
/// WHOIS rather than sending a rep's query in the clear.
fn rdap_bases() -> &'static HashMap<String, String> {
    static BASES: OnceLock<HashMap<String, String>> = OnceLock::new();
    BASES.get_or_init(|| {
        let b: Bootstrap = serde_json::from_str(BOOTSTRAP).unwrap_or(Bootstrap { services: vec![] });
        let mut m = HashMap::new();
        for (tlds, urls) in b.services {
            let Some(first) = urls.first() else { continue };
            let url = urls.iter().find(|u| u.starts_with("https://")).cloned().unwrap_or_else(|| first.replacen("http://", "https://", 1));
            for tld in tlds {
                m.insert(tld.to_ascii_lowercase(), url.clone());
            }
        }
        m
    })
}

/// A JSON `null` where the schema promises a list reads as an empty list.
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(d: D) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Default)]
struct RdapDomain {
    #[serde(default, deserialize_with = "nullable")]
    status: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    events: Vec<RdapEvent>,
    #[serde(default, deserialize_with = "nullable")]
    nameservers: Vec<RdapNameserver>,
    #[serde(default, rename = "secureDNS")]
    secure_dns: Option<RdapSecureDns>,
    #[serde(default, deserialize_with = "nullable")]
    entities: Vec<RdapEntity>,
}

#[derive(Deserialize)]
struct RdapEvent {
    #[serde(default, rename = "eventAction")]
    action: String,
    #[serde(default, rename = "eventDate")]
    date: String,
}

#[derive(Deserialize)]
struct RdapNameserver {
    #[serde(default, rename = "ldhName")]
    ldh_name: String,
}

#[derive(Deserialize)]
struct RdapSecureDns {
    #[serde(default, rename = "delegationSigned")]
    delegation_signed: Option<bool>,
}

#[derive(Deserialize)]
struct RdapEntity {
    #[serde(default, deserialize_with = "nullable")]
    roles: Vec<String>,
    #[serde(default, rename = "vcardArray", deserialize_with = "nullable")]
    vcard: Vec<serde_json::Value>,
}

impl RdapEntity {
    /// The "fn" (formatted name) row of a registrar entity's jCard.
    fn registrar_name(&self) -> Option<String> {
        if !self.roles.iter().any(|r| r == "registrar") {
            return None;
        }
        let rows = self.vcard.get(1)?.as_array()?;
        rows.iter()
            .filter_map(|row| row.as_array())
            .filter(|row| row.len() >= 4 && row[0] == "fn")
            .filter_map(|row| row[3].as_str())
            .next_back()
            .filter(|s| !s.is_empty())
            .map(String::from)
    }
}

async fn rdap_lookup(base: &str, name: &str, deadline: Instant) -> Result<Registration, RdapError> {
    let url = format!("{}/domain/{name}", base.trim_end_matches('/'));
    // Plain http is accepted only when the caller named such a base itself (a test server).
    let https_only = !base.starts_with("http://");
    let left = deadline.saturating_duration_since(Instant::now());
    let (status, body) = tokio::task::spawn_blocking(move || rdap_get(&url, https_only, left))
        .await
        .map_err(|e| RdapError::Request(e.to_string()))??;
    let mut r = Registration::empty(name, Source::Rdap, base);
    if status == 404 {
        return Ok(r); // the registry has no such domain
    }
    if status != 200 {
        return Err(RdapError::Status(status.to_string()));
    }
    let d: RdapDomain = serde_json::from_slice(&body).map_err(|e| RdapError::Unreadable(e.to_string()))?;
    r.registered = true;
    r.registrar = d.entities.iter().filter_map(RdapEntity::registrar_name).next_back();
    r.statuses = d.status.iter().map(|s| epp_status(s)).collect();
    for e in &d.events {
        match e.action.to_lowercase().as_str() {
            "registration" => r.created = Some(normalize_date(&e.date)),
            "expiration" => r.expires = Some(normalize_date(&e.date)),
            "last changed" => r.updated = Some(normalize_date(&e.date)),
            _ => {}
        }
    }
    r.nameservers = d.nameservers.iter().map(|n| n.ldh_name.trim_end_matches('.').to_lowercase()).collect();
    r.dnssec = d.secure_dns.and_then(|s| s.delegation_signed);
    r.statuses.sort();
    r.nameservers.sort();
    Ok(r)
}

/// One bounded GET: (status, body). The body is read only for a 200, and an
/// oversized one is an error, not a truncation.
fn rdap_get(url: &str, https_only: bool, limit: Duration) -> Result<(ureq::http::StatusCode, Vec<u8>), RdapError> {
    let fail = |e: ureq::Error| RdapError::Request(e.to_string());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(limit))
        .max_redirects(MAX_REDIRECTS)
        .https_only(https_only)
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent.get(url).header("Accept", "application/rdap+json, application/json").call().map_err(fail)?;
    let status = resp.status();
    if status != 200 {
        return Ok((status, vec![]));
    }
    let body = resp.body_mut().with_config().limit(MAX_REPLY).read_to_vec().map_err(fail)?;
    Ok((status, body))
}

/// A date as a registry gave it: normalised to UTC when it is in a format we
/// know, otherwise kept as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegDate {
    At(OffsetDateTime),
    Raw(String),
}

impl fmt::Display for RegDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegDate::At(t) => {
                let t = t.to_offset(time::UtcOffset::UTC).replace_nanosecond(0).unwrap_or(*t);
                f.write_str(&t.format(&Rfc3339).map_err(|_| fmt::Error)?)
            }
            RegDate::Raw(s) => f.write_str(s),
        }
    }
}

impl Serialize for RegDate {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Registration {
    /// The registrable name looked up.
    pub domain: String,
    pub source: Source,
    /// The server that answered: an RDAP base URL or a WHOIS host:port.
    pub server: String,
    pub registered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    /// EPP camelCase, sorted, e.g. clientHold.
    pub statuses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<RegDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<RegDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<RegDate>,
    /// Lowercase, no trailing dot, sorted.
    pub nameservers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<bool>,
    /// Why WHOIS was used instead of RDAP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdap_error: Option<String>,
}

impl Registration {
    pub fn empty(domain: &str, source: Source, server: &str) -> Self {
        Registration {
            domain: domain.into(),
            source,
            server: server.into(),
            registered: false,
            registrar: None,
            statuses: vec![],
            created: None,
            updated: None,
            expires: None,
            nameservers: vec![],
            dnssec: None,
            rdap_error: None,
        }
    }
}

// Problem statuses and what they mean for the rep.
const HOLDS: [&str; 2] = ["clientHold", "serverHold"];
const DELETION: [&str; 3] = ["redemptionPeriod", "pendingDelete", "pendingRestore"];

/// `_target` keeps the shared Check signature; the Findings name the
/// registrable domain that was looked up, which `r.domain` carries.
pub fn registration_findings(_target: &str, r: &Registration) -> Vec<Finding> {
    registration_findings_at(r, OffsetDateTime::now_utc())
}

/// `registration_findings` against a given clock.
pub fn registration_findings_at(r: &Registration, now: OffsetDateTime) -> Vec<Finding> {
    let d = &r.domain;
    let finding = |code, severity, title, message, recommendation| Finding { code, severity, title, message, recommendation };
    if !r.registered {
        let via = match r.source {
            Source::Rdap => format!("The registry's RDAP service has no record of {d}."),
            Source::Whois => format!("The WHOIS reply for {d} carries no registrar or dates, which means it is not registered."),
        };
        return vec![finding(
            "registration_not_registered",
            Severity::Critical,
            "Not registered",
            via,
            Some("Check the spelling; if it is the customer's domain, it has lapsed or was never registered, so register it (or restore it at the registrar) as soon as possible."),
        )];
    }
    let mut out = vec![];
    if let Some(RegDate::At(exp)) = &r.expires {
        let left = *exp - now;
        let days = left.whole_days();
        let when = format!("{} {} {}", exp.day(), exp.month(), exp.year());
        if left.is_negative() {
            out.push(finding(
                "registration_expired",
                Severity::Critical,
                "Domain expired",
                format!("{d} expired on {when}. Websites and email on it may stop working at any time."),
                Some("Renew it at the registrar now, before it enters redemption and costs more to restore."),
            ));
        } else if days <= 30 {
            let n = if days == 1 { "1 day".to_string() } else { format!("{days} days") };
            out.push(finding(
                "registration_expiring_soon",
                Severity::Warning,
                "Expires within 30 days",
                format!("{d} expires on {when}, in {n}."),
                Some("Renew it now, or confirm auto-renew is on and the payment card on file is valid."),
            ));
        } else if days <= 60 {
            out.push(finding(
                "registration_expiring",
                Severity::Info,
                "Expires within 60 days",
                format!("{d} expires on {when}, in {days} days. Worth confirming auto-renew is on."),
                None,
            ));
        }
    }
    let among = |set: &[&str]| r.statuses.iter().filter(|s| set.contains(&s.as_str())).cloned().collect::<Vec<_>>().join(", ");
    let holds = among(&HOLDS);
    if !holds.is_empty() {
        out.push(finding(
            "registration_on_hold",
            Severity::Critical,
            "Domain is on hold",
            format!("{d} has status {holds}: the registry has removed it from DNS, so its website and email are down. A clientHold is set by the registrar (often an unpaid renewal or unverified contact email); a serverHold by the registry (often a legal or abuse action)."),
            Some("Contact the registrar to find out why and get the hold lifted."),
        ));
    }
    let deleting = among(&DELETION);
    if !deleting.is_empty() {
        out.push(finding(
            "registration_pending_delete",
            Severity::Critical,
            "Domain is being deleted",
            format!("{d} has status {deleting}: it expired and is on its way to being released. During the redemption period the registrar can still restore it, for a fee; once pending delete it cannot be saved."),
            Some("Ask the registrar to restore it immediately if it is still in redemption."),
        ));
    }
    if !out.iter().any(|f| matches!(f.severity, Severity::Critical | Severity::Warning)) {
        let mut msg = format!("{d} is registered");
        if let Some(who) = &r.registrar {
            msg += &format!(" with {who}");
        }
        if let Some(RegDate::At(exp)) = &r.expires {
            msg += &format!(" until {} {} {}", exp.day(), exp.month(), exp.year());
        }
        out.push(finding("registration_ok", Severity::Ok, "Registered", msg + ".", None));
    }
    out
}

/// The ICANN registrable name: foo.github.io is registered as github.io.
pub fn registrable_domain(host: &str) -> String {
    let icann = |s: &str| psl::suffix(s.as_bytes()).is_some_and(|x| x.typ() == Some(psl::Type::Icann));
    let mut s = psl::suffix_str(host).unwrap_or(host);
    while !icann(s) {
        let Some((_, rest)) = s.split_once('.') else { break };
        s = rest;
    }
    if s == host {
        return host.into();
    }
    let rest = host.strip_suffix(s).and_then(|r| r.strip_suffix('.')).unwrap_or(host);
    format!("{}.{s}", rest.rsplit('.').next().unwrap_or(rest))
}

/// RDAP says "client hold" and WHOIS says "clientHold https://icann.org/epp#clientHold";
/// both become the EPP spelling, clientHold.
fn epp_status(s: &str) -> String {
    let mut words: Vec<&str> = s.split_whitespace().collect();
    if words.len() > 1 && words[words.len() - 1].starts_with("http") {
        words.pop(); // WHOIS appends the ICANN explainer URL
    }
    let Some((first, rest)) = words.split_first() else { return String::new() };
    if rest.is_empty() && *first == first.to_uppercase() {
        return first.to_lowercase(); // some ccTLDs shout: ACTIVE
    }
    let with_first = |w: &str, f: fn(char) -> String| {
        let mut c = w.chars();
        c.next().map(|h| f(h) + c.as_str()).unwrap_or_default()
    };
    let mut out = with_first(first, |h| h.to_lowercase().to_string());
    for w in rest {
        out += &with_first(w, |h| h.to_uppercase().to_string());
    }
    out
}

/// RFC 3339 UTC when `s` is a date format registries are known to use, else `s` as written.
fn normalize_date(s: &str) -> RegDate {
    let s = s.trim();
    parse_date(s).map_or_else(|| RegDate::Raw(s.into()), RegDate::At)
}

fn parse_date(s: &str) -> Option<OffsetDateTime> {
    use time::{Date, PrimitiveDateTime, format_description::{FormatItem, well_known::Rfc3339}};
    if let Ok(t) = OffsetDateTime::parse(s, &Rfc3339) {
        return Some(t);
    }
    let datetime: [&[FormatItem<'static>]; 2] = [
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second][optional [.[subsecond]]]"),
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second][optional [.[subsecond]]]"),
    ];
    // A trailing zone abbreviation (UTC, GMT, CET) is read as UTC, as Go does for names it does not know.
    let bare = s.rsplit_once(' ').filter(|(_, z)| (3..=5).contains(&z.len()) && z.bytes().all(|b| b.is_ascii_uppercase())).map_or(s, |(t, _)| t);
    if let Some(t) = datetime.iter().find_map(|f| PrimitiveDateTime::parse(bare, f).ok()) {
        return Some(t.assume_utc());
    }
    let date: [&[FormatItem<'static>]; 6] = [
        time::macros::format_description!("[year]-[month]-[day]"),
        time::macros::format_description!("[day]-[month repr:short case_sensitive:false]-[year]"),
        time::macros::format_description!("[year].[month].[day]"),
        time::macros::format_description!("[day].[month].[year]"),
        time::macros::format_description!("[year]/[month]/[day]"),
        time::macros::format_description!("[month repr:long case_sensitive:false] [day padding:none] [year]"),
    ];
    date.iter().find_map(|f| Date::parse(s, f).ok()).map(|d| d.midnight().assume_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_bootstrap_maps_tlds_to_https_bases() {
        let b = rdap_bases();
        assert!(b.len() > 500, "{} TLDs", b.len());
        assert_eq!(b["com"], "https://rdap.verisign.com/com/v1/");
        assert_eq!(b["kg"], "https://rdap.cctld.kg/", "an http-only entry is upgraded");
        assert!(b.values().all(|u| u.starts_with("https://")));
        assert!(!b.contains_key("test"));
    }

    #[test]
    fn registrable_names() {
        for (host, want) in [
            ("example.com", "example.com"),
            ("www.example.com", "example.com"),
            ("a.b.example.co.uk", "example.co.uk"),
            ("foo.github.io", "github.io"),
            ("github.io", "github.io"),
            ("nope.test", "nope.test"),
            ("www.nope.test", "nope.test"),
            ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ] {
            assert_eq!(registrable_domain(host), want, "{host}");
        }
    }

    #[test]
    fn status_spellings_become_epp_camel_case() {
        for (raw, want) in [
            ("client hold", "clientHold"),
            ("clientHold https://icann.org/epp#clientHold", "clientHold"),
            ("ACTIVE", "active"),
            ("active", "active"),
            ("Pending Delete", "pendingDelete"),
            ("  redemption   period ", "redemptionPeriod"),
            ("", ""),
            ("connect", "connect"),
        ] {
            assert_eq!(epp_status(raw), want, "{raw:?}");
        }
    }

    #[test]
    fn dates_are_normalised_to_rfc3339_utc() {
        for (raw, want) in [
            ("1995-08-14T04:00:00Z", "1995-08-14T04:00:00Z"),
            ("2024-12-19T13:33:43+01:00", "2024-12-19T12:33:43Z"),
            ("2026-08-13T04:00:00.123Z", "2026-08-13T04:00:00Z"),
            ("2024-01-02T03:04:05", "2024-01-02T03:04:05Z"),
            ("2024-01-02 03:04:05", "2024-01-02T03:04:05Z"),
            ("2024-01-02 03:04:05 UTC", "2024-01-02T03:04:05Z"),
            ("2024-01-02", "2024-01-02T00:00:00Z"),
            ("14-Aug-1995", "1995-08-14T00:00:00Z"),
            ("14-aug-1995", "1995-08-14T00:00:00Z"),
            ("2024.01.02", "2024-01-02T00:00:00Z"),
            ("02.01.2024", "2024-01-02T00:00:00Z"),
            ("2024/01/02", "2024-01-02T00:00:00Z"),
            ("January 2 2024", "2024-01-02T00:00:00Z"),
            ("  2024-01-02  ", "2024-01-02T00:00:00Z"),
            ("next tuesday", "next tuesday"),
            ("", ""),
        ] {
            assert_eq!(normalize_date(raw).to_string(), want, "{raw:?}");
        }
        assert!(matches!(normalize_date("2024-01-02"), RegDate::At(_)));
        assert!(matches!(normalize_date("next tuesday"), RegDate::Raw(_)));
    }
}
