//! Domain registration: who holds a domain, until when, in what state. Asks the
//! registry over RDAP and falls back to WHOIS (port 43) when RDAP is unavailable.

use std::fmt;

use serde::{Serialize, Serializer};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::finding::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Rdap,
    Whois,
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
