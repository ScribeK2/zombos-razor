//! Pasted email headers: the message path, the authentication verdicts and
//! the things that look wrong. Ported from the Go `headers.go`.

use std::{collections::HashMap, fmt, net::IpAddr, sync::LazyLock};

use regex::Regex;
use serde::{Serialize, Serializer};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, format_description::well_known::Rfc3339};

use super::{EvidenceError, Extracted, MAX_INPUT, MAX_LINE, bracket_ip, capture, clean_lines, cut, re};
use crate::{Finding, Severity};

const LABEL: &str = "email headers";
/// More header fields than this in one paste is not a mail message.
const MAX_FIELDS: usize = 1000;
/// Received headers analysed (the newest ones); a real message has fewer than 30.
const MAX_HOPS: usize = 250;
const MAX_SIGNATURES: usize = 16;
const KNOWN_HEADERS: [&str; 11] = [
    "from",
    "to",
    "subject",
    "date",
    "received",
    "message-id",
    "return-path",
    "authentication-results",
    "delivered-to",
    "dkim-signature",
    "reply-to",
];
/// A hop that waited longer than this is reported.
const SLOW_HOP_SECONDS: i64 = 600;
/// SpamAssassin's default threshold.
const DEFAULT_SPAM_THRESHOLD: f64 = 5.0;
const SCL_SPAM_LEVEL: i32 = 5;

static RECEIVED_FROM: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bfrom\s+(\S+)"));
static RECEIVED_IP: LazyLock<Regex> = LazyLock::new(|| re(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]"));
static RECEIVED_BY: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bby\s+(\S+)"));
static RECEIVED_WITH: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bwith\s+(\S+)"));
static AUTH_DKIM_DOMAIN: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)header\.d=([^\s;]+)"));
static AUTH_DKIM_IDENTITY: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)header\.i=[^@\s;]*@([^\s;]+)"));
static SPAM_STATUS: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)^(yes|no)\b.*?score=(-?[0-9.]+).*?required=(-?[0-9.]+)"));
static SCL_VALUE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bSCL:(-?\d+)"));

/// A receiving server's word on one check. The common words are variants; any
/// other word is kept as it was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Fail,
    Softfail,
    Neutral,
    None,
    Temperror,
    Permerror,
    Policy,
    #[serde(untagged)]
    Other(String),
}

impl Verdict {
    fn from_word(word: &str) -> Self {
        match word.to_ascii_lowercase().as_str() {
            "pass" => Self::Pass,
            "fail" => Self::Fail,
            "softfail" => Self::Softfail,
            "neutral" => Self::Neutral,
            "none" => Self::None,
            "temperror" => Self::Temperror,
            "permerror" => Self::Permerror,
            "policy" => Self::Policy,
            other => Self::Other(cut(other, 32).to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Softfail => "softfail",
            Self::Neutral => "neutral",
            Self::None => "none",
            Self::Temperror => "temperror",
            Self::Permerror => "permerror",
            Self::Policy => "policy",
            Self::Other(w) => w,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub message_id: String,
    pub return_path: String,
    pub reply_to: String,
}

fn rfc3339<S: Serializer>(at: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error> {
    match at.as_ref().and_then(|t| t.format(&Rfc3339).ok()) {
        Some(text) => s.serialize_str(&text),
        None => s.serialize_none(),
    }
}

/// One Received header: a server that handled the message.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Hop {
    pub from_host: String,
    pub from_ip: Option<IpAddr>,
    pub by_host: String,
    pub with: String,
    #[serde(serialize_with = "rfc3339")]
    pub at: Option<OffsetDateTime>,
    /// Seconds since the previous hop; negative when the clocks disagree.
    pub delay_s: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DkimSignature {
    pub domain: String,
    pub selector: String,
}

/// What the receiving server decided. Each verdict comes from the topmost
/// Authentication-Results header; SPF falls back to Received-SPF.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuthResults {
    pub spf: Option<Verdict>,
    pub dkim: Option<Verdict>,
    pub dmarc: Option<Verdict>,
    pub compauth: Option<Verdict>,
    /// The domain of the DKIM signature the verdict is about.
    pub dkim_domain: String,
    /// The DKIM-Signature headers as written. Anyone can write one, so they prove nothing alone.
    pub dkim_signatures: Vec<DkimSignature>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Alignment {
    pub from_domain: String,
    pub return_path_domain: String,
    pub message_id_domain: String,
    pub dkim_domain: String,
    pub from_return_path_aligned: Option<bool>,
    pub message_id_aligned: Option<bool>,
    pub dkim_aligned: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SpamSignals {
    pub score: Option<f64>,
    pub required: Option<f64>,
    /// Microsoft spam confidence level.
    pub scl: Option<i32>,
    pub flagged: bool,
}

/// Something in the headers that is odd in itself, apart from the verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anomaly {
    /// RFC 5322 allows one From header; a second one is a spoofing trick.
    MultipleFrom { count: usize },
    /// A hop is dated before the one that handed it the message.
    ClockSkew { hop: usize },
    /// The oldest hops were not analysed.
    TooManyHops { total: usize },
    /// A line, a header or the number of headers went over the limits.
    Truncated,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HeaderAnalysis {
    pub headers: Summary,
    /// Oldest first.
    pub hops: Vec<Hop>,
    pub total_transit_s: Option<i64>,
    /// The earliest public address in the chain. Those lines are the sender's
    /// to write, so it can be forged.
    pub origin_ip: Option<IpAddr>,
    /// The latest public address: recorded by the recipient's own server about
    /// who connected to it.
    pub delivering_ip: Option<IpAddr>,
    pub auth: AuthResults,
    pub alignment: Alignment,
    pub spam: SpamSignals,
    pub anomalies: Vec<Anomaly>,
    /// Every IP and host name that appears in the Received chain.
    pub extracted: Extracted,
}

struct Block {
    fields: HashMap<String, Vec<String>>,
    froms: usize,
    truncated: bool,
}

impl Block {
    fn first(&self, name: &str) -> &str {
        self.fields.get(name).and_then(|v| v.first()).map_or("", String::as_str)
    }

    fn all(&self, name: &str) -> &[String] {
        self.fields.get(name).map_or(&[], Vec::as_slice)
    }
}

/// `^(\s*>\s?)+`: forward quote marks, each with at most one space after it.
fn strip_quotes(mut s: &str) -> &str {
    while let Some(rest) = s.trim_start().strip_prefix('>') {
        s = rest.strip_prefix(char::is_whitespace).unwrap_or(rest);
    }
    s
}

/// `Name: value` with a name of letters, digits and hyphens.
fn split_header(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    let mut chars = name.chars();
    let valid =
        chars.next().is_some_and(|c| c.is_ascii_alphanumeric()) && chars.all(|c| c.is_ascii_alphanumeric() || c == '-');
    valid.then_some((name, value.strip_prefix(char::is_whitespace).unwrap_or(value)))
}

/// Read a pasted header block the way reps paste it: with forward quote marks,
/// folded lines, and the body after the first blank line (ignored).
fn parse_block(raw: &str) -> Block {
    let mut b = Block { fields: HashMap::new(), froms: 0, truncated: false };
    let (mut last, mut seen, mut count) = (String::new(), false, 0usize);
    for (line, cut) in clean_lines(raw) {
        b.truncated |= cut;
        let line = strip_quotes(&line);
        if line.trim().is_empty() {
            if seen {
                break;
            }
            continue;
        }
        if line.starts_with([' ', '\t']) && !last.is_empty() {
            if let Some(v) = b.fields.get_mut(&last).and_then(|v| v.last_mut()) {
                if v.len() < MAX_LINE {
                    v.push(' ');
                    v.push_str(line.trim());
                } else {
                    b.truncated = true;
                }
            }
        } else if let Some((name, value)) = split_header(line) {
            if count == MAX_FIELDS {
                b.truncated = true;
                break;
            }
            count += 1;
            last = name.to_ascii_lowercase();
            b.froms += usize::from(last == "from");
            b.fields.entry(last.clone()).or_default().push(value.trim().to_string());
            seen = true;
        }
    }
    b
}

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/// An RFC 5322 date: `[Wed,] 14 Jun 2026 10:02[:00] -0700 [(comment)]`. Named
/// zones other than the US ones and GMT count as UTC, like Go's `mail.ParseDate`.
fn parse_date(s: &str) -> Option<OffsetDateTime> {
    let mut text = String::new();
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => text.push(c),
            _ => {}
        }
    }
    let mut tokens = text.split_whitespace();
    let mut day = tokens.next()?;
    if day.ends_with(',') {
        day = tokens.next()?;
    }
    let (month, year, clock, zone) = (tokens.next()?, tokens.next()?, tokens.next()?, tokens.next()?);
    let month = MONTHS.iter().position(|m| month.get(..3).is_some_and(|p| p.eq_ignore_ascii_case(m)))?;
    let month = Month::try_from(u8::try_from(month + 1).ok()?).ok()?;
    let year = match year.parse::<i32>().ok()? {
        y @ 0..50 => y + 2000,
        y @ 50..1000 => y + 1900,
        y => y,
    };
    let mut hms = clock.split(':').map(|p| p.parse::<u8>().ok());
    let (h, m, sec) = (hms.next()??, hms.next()??, hms.next().unwrap_or(Some(0))?);
    let date = Date::from_calendar_date(year, month, day.parse().ok()?).ok()?;
    let offset = parse_zone(zone)?;
    Some(PrimitiveDateTime::new(date, Time::from_hms(h, m, sec).ok()?).assume_offset(offset))
}

fn parse_zone(zone: &str) -> Option<UtcOffset> {
    let named = |hours: i8| UtcOffset::from_hms(hours, 0, 0).ok();
    match zone.to_ascii_uppercase().as_str() {
        "EST" => named(-5),
        "EDT" => named(-4),
        "CST" => named(-6),
        "CDT" => named(-5),
        "MST" => named(-7),
        "MDT" => named(-6),
        "PST" => named(-8),
        "PDT" => named(-7),
        z if z.starts_with(['+', '-']) => {
            let digits = z.get(1..)?;
            if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let (h, m): (i8, i8) = (digits.get(..2)?.parse().ok()?, digits.get(2..)?.parse().ok()?);
            let sign = if z.starts_with('-') { -1 } else { 1 };
            UtcOffset::from_hms(sign * h, sign * m, 0).ok()
        }
        z if z.chars().all(|c| c.is_ascii_alphabetic()) => Some(UtcOffset::UTC),
        _ => None,
    }
}

fn parse_hop(received: &str) -> Hop {
    // The date follows the last ';'.
    let (route, date) = received.rsplit_once(';').unwrap_or((received, ""));
    let from_part = route.split_once(" by ").map_or(route, |(from, _)| from);
    Hop {
        from_host: capture(&RECEIVED_FROM, from_part).unwrap_or_default().trim_matches(['(', ')']).to_string(),
        from_ip: bracket_ip(&RECEIVED_IP, from_part),
        by_host: capture(&RECEIVED_BY, route).unwrap_or_default().to_string(),
        with: capture(&RECEIVED_WITH, route).unwrap_or_default().to_string(),
        at: parse_date(date),
        delay_s: None,
    }
}

/// Public means a global unicast address that is not private. Documentation
/// ranges count as public, so the fixtures and the RFC examples read like real mail.
fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_private())
        }
        IpAddr::V6(a) => {
            let first = a.segments()[0];
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || first & 0xffc0 == 0xfe80
                || first & 0xfe00 == 0xfc00)
        }
    }
}

/// The domain of `Name <a@b.com>`, `<a@b.com>` or `a@b.com`. A quoted display
/// name may hold `<` and `@`: only a `<...>` outside quotes is the address.
fn address_domain(s: &str) -> String {
    let (mut in_quote, mut escaped, mut open) = (false, false, None);
    let mut address = s;
    for (i, c) in s.char_indices() {
        match (c, in_quote, escaped) {
            (_, true, true) => escaped = false,
            ('\\', true, false) => escaped = true,
            ('"', _, _) => in_quote = !in_quote,
            ('<', false, _) => open = Some(i + 1),
            ('>', false, _) => {
                if let Some(start) = open.take() {
                    address = &s[start..i];
                }
            }
            _ => {}
        }
    }
    let address = address.trim().trim_matches(['<', '>']);
    address.rsplit_once('@').map_or(String::new(), |(_, d)| d.trim_end_matches(['>', '.', ' ']).to_ascii_lowercase())
}

/// DMARC-style relaxed alignment: the same organisational domain. `None` when
/// either side is missing; a name with no organisational domain never aligns.
fn aligned(a: &str, b: &str) -> Option<bool> {
    if a.is_empty() || b.is_empty() {
        return None;
    }
    Some(matches!((psl::domain_str(a), psl::domain_str(b)), (Some(x), Some(y)) if x == y))
}

fn parse_auth(auth: &mut AuthResults, header: &str) {
    for part in header.split(';') {
        let Some((key, rest)) = part.split_once('=') else { continue };
        let Some(verdict) = leading_verdict(rest) else { continue };
        match key.trim().to_ascii_lowercase().as_str() {
            "spf" => auth.spf = Some(verdict),
            "dkim" if auth.dkim.is_none() || verdict == Verdict::Pass => {
                auth.dkim = Some(verdict);
                // Gmail reports header.i, not header.d.
                if let Some(d) = capture(&AUTH_DKIM_DOMAIN, part).or_else(|| capture(&AUTH_DKIM_IDENTITY, part)) {
                    auth.dkim_domain = d.to_ascii_lowercase();
                }
            }
            "dmarc" => auth.dmarc = Some(verdict),
            "compauth" => auth.compauth = Some(verdict),
            _ => {}
        }
    }
}

fn parse_signature(header: &str) -> DkimSignature {
    let tag = |name: &str| {
        header
            .split(';')
            .find_map(|t| t.split_once('=').filter(|(k, _)| k.trim() == name))
            .map_or(String::new(), |(_, v)| v.split_whitespace().collect::<String>().to_ascii_lowercase())
    };
    DkimSignature { domain: tag("d"), selector: tag("s") }
}

fn parse_spam(b: &Block) -> SpamSignals {
    let mut sp = SpamSignals::default();
    for name in ["x-spam-score", "x-spamd-score"] {
        let score =
            b.first(name).split_whitespace().next().and_then(|w| w.parse::<f64>().ok()).filter(|s| s.is_finite());
        sp.score = score.or(sp.score);
    }
    if let Some(m) = SPAM_STATUS.captures(b.first("x-spam-status")) {
        let num = |i| m.get(i).and_then(|x| x.as_str().parse::<f64>().ok());
        if let (Some(score), Some(required)) = (num(2), num(3)) {
            sp.score = Some(score);
            sp.required = Some(required);
            sp.flagged = m[1].eq_ignore_ascii_case("yes");
        }
    }
    if b.first("x-spam-flag").trim().eq_ignore_ascii_case("yes") {
        sp.flagged = true;
    }
    if let Some(score) = sp.score {
        sp.flagged |= score >= sp.required.unwrap_or(DEFAULT_SPAM_THRESHOLD);
    }
    let scl = Some(b.first("x-ms-exchange-organization-scl"))
        .filter(|s| !s.is_empty())
        .or_else(|| capture(&SCL_VALUE, b.first("x-forefront-antispam-report")));
    if let Some(n) = scl.and_then(|s| s.trim().parse::<i32>().ok()) {
        sp.scl = Some(n);
        sp.flagged |= n >= SCL_SPAM_LEVEL;
    }
    sp
}

/// Analyse pasted email headers. Pure: it reads the text and nothing else.
pub fn analyse_headers(raw: &str) -> Result<HeaderAnalysis, EvidenceError> {
    if raw.len() > MAX_INPUT {
        return Err(EvidenceError::TooLarge);
    }
    let b = parse_block(raw);
    if !KNOWN_HEADERS.iter().any(|k| !b.all(k).is_empty()) {
        return Err(EvidenceError::NotThisKind(LABEL));
    }
    let mut a = HeaderAnalysis {
        headers: Summary {
            from: b.first("from").into(),
            to: b.first("to").into(),
            subject: b.first("subject").into(),
            date: b.first("date").into(),
            message_id: b.first("message-id").into(),
            return_path: b.first("return-path").into(),
            reply_to: b.first("reply-to").into(),
        },
        ..HeaderAnalysis::default()
    };
    if b.truncated {
        a.anomalies.push(Anomaly::Truncated);
    }
    if b.froms > 1 {
        a.anomalies.push(Anomaly::MultipleFrom { count: b.froms });
    }

    // Received headers are added newest first; the story reads oldest first.
    let received = b.all("received");
    if received.len() > MAX_HOPS {
        a.anomalies.push(Anomaly::TooManyHops { total: received.len() });
    }
    a.hops = received.iter().take(MAX_HOPS).rev().map(|r| parse_hop(r)).collect();
    for i in 1..a.hops.len() {
        let before = a.hops.get(i - 1).and_then(|h| h.at);
        if let (Some(before), Some(hop)) = (before, a.hops.get_mut(i))
            && let Some(now) = hop.at
        {
            let delay = (now - before).whole_seconds();
            hop.delay_s = Some(delay);
            if delay < 0 {
                a.anomalies.push(Anomaly::ClockSkew { hop: i });
            }
        }
    }
    if let ([first, .., last], true) = (a.hops.as_slice(), a.hops.len() > 1) {
        a.total_transit_s = first.at.zip(last.at).map(|(f, l)| (l - f).whole_seconds());
    }
    for hop in &a.hops {
        a.extracted.ip(hop.from_ip);
        a.extracted.host(&hop.from_host);
        a.extracted.host(&hop.by_host);
        if let Some(ip) = hop.from_ip.filter(|ip| is_public(*ip)) {
            a.origin_ip = a.origin_ip.or(Some(ip));
            a.delivering_ip = Some(ip);
        }
    }

    parse_auth(&mut a.auth, b.first("authentication-results"));
    if a.auth.spf.is_none() {
        a.auth.spf = leading_verdict(b.first("received-spf"));
    }
    a.auth.dkim_signatures = b.all("dkim-signature").iter().take(MAX_SIGNATURES).map(|s| parse_signature(s)).collect();

    let al = &mut a.alignment;
    al.from_domain = address_domain(&a.headers.from);
    al.return_path_domain = address_domain(&a.headers.return_path);
    al.message_id_domain = address_domain(a.headers.message_id.trim_matches(['<', '>']));
    // Only a signature the receiving server verified can align the sender:
    // anyone can write a DKIM-Signature header claiming any domain.
    if a.auth.dkim == Some(Verdict::Pass) {
        al.dkim_domain = a.auth.dkim_domain.clone();
        if al.dkim_domain.is_empty() {
            al.dkim_domain = a.auth.dkim_signatures.first().map(|s| s.domain.clone()).unwrap_or_default();
        }
    }
    al.from_return_path_aligned = aligned(&al.from_domain, &al.return_path_domain);
    al.message_id_aligned = aligned(&al.from_domain, &al.message_id_domain);
    al.dkim_aligned = aligned(&al.from_domain, &al.dkim_domain);
    a.spam = parse_spam(&b);
    Ok(a)
}

/// The verdict word a header value starts with.
fn leading_verdict(value: &str) -> Option<Verdict> {
    let word: String = value.trim_start().chars().take_while(char::is_ascii_alphabetic).collect();
    (!word.is_empty()).then(|| Verdict::from_word(&word))
}

fn orunknown(s: &str) -> &str {
    if s.is_empty() { "an unknown server" } else { s }
}

fn minutes(seconds: i64) -> String {
    let s = seconds as f64;
    if s >= 3600.0 { format!("{:.1} hours", s / 3600.0) } else { format!("{:.0} minutes", s / 60.0) }
}

/// The Findings for one header analysis, wording as in the Go version.
pub fn header_findings(a: &HeaderAnalysis) -> Vec<Finding> {
    let mut out = vec![];
    let mut add =
        |code: &'static str, severity, title: String, message: String, recommendation: Option<&'static str>| {
            out.push(Finding {
                code,
                severity,
                title: title.into(),
                message,
                recommendation: recommendation.map(Into::into),
            });
        };
    let au = &a.auth;
    let al = &a.alignment;
    if au.spf.is_none() && au.dkim.is_none() && au.dmarc.is_none() {
        add(
            "email_headers_no_auth_results",
            Severity::Info,
            "No authentication verdict".into(),
            "There is no Authentication-Results header: this copy wasn't checked by a receiving server, or the header was left out of the paste.".into(),
            None,
        );
    }
    match &au.spf {
        None | Some(Verdict::Pass) => {}
        Some(Verdict::Fail) => add(
            "email_headers_spf_fail",
            Severity::Critical,
            "SPF failed".into(),
            format!(
                "The receiving server says the sending server isn't allowed to send for {}.",
                orunknown(&al.return_path_domain)
            ),
            Some("Add the sending service to the domain's SPF record, or check whether this message is forged."),
        ),
        Some(v) => add(
            "email_headers_spf_fail",
            Severity::Warning,
            format!("SPF {v}"),
            format!("The receiving server's SPF result was {v}, not pass."),
            Some("Run Email Authentication on the sending domain to see its SPF record."),
        ),
    }
    match &au.dkim {
        None | Some(Verdict::Pass) => {}
        Some(Verdict::None) => add(
            "email_headers_dkim_fail",
            Severity::Warning,
            "Not DKIM-signed".into(),
            "The message carried no DKIM signature the receiving server could check.".into(),
            Some("Enable DKIM signing at the sending service."),
        ),
        Some(v) => add(
            "email_headers_dkim_fail",
            Severity::Warning,
            format!("DKIM {v}"),
            format!(
                "The DKIM signature did not verify ({v}). Forwarding or a mailing list that rewrites the message can cause this."
            ),
            Some("Check the signing domain's published key with Email Authentication."),
        ),
    }
    match &au.dmarc {
        None | Some(Verdict::Pass) => {}
        Some(Verdict::Fail) => add(
            "email_headers_dmarc_fail",
            Severity::Critical,
            "DMARC failed".into(),
            format!(
                "Neither SPF nor DKIM passed in alignment with the From domain {}, so receivers may reject or quarantine it.",
                orunknown(&al.from_domain)
            ),
            Some("If this mail is legitimate, align SPF or DKIM with the From domain; if not, it is spoofed."),
        ),
        Some(v) => add(
            "email_headers_dmarc_none",
            Severity::Info,
            format!("No DMARC verdict ({v})"),
            format!("The receiving server reported DMARC as {v}."),
            None,
        ),
    }
    if [&au.spf, &au.dkim, &au.dmarc].iter().all(|v| **v == Some(Verdict::Pass)) {
        add(
            "email_headers_authenticated",
            Severity::Ok,
            "Authenticated".into(),
            "SPF, DKIM and DMARC all passed at the receiving server.".into(),
            None,
        );
    }
    if al.from_return_path_aligned == Some(false) && al.dkim_aligned != Some(true) {
        add(
            "email_headers_misaligned",
            Severity::Warning,
            "Sender identities don't match".into(),
            format!(
                "The From domain ({}) and the bounce address domain ({}) belong to different organisations, and no aligned DKIM signature ties them together.",
                al.from_domain, al.return_path_domain
            ),
            Some(
                "For legitimate mail sent through a provider, set a custom bounce domain or DKIM signing for the From domain.",
            ),
        );
    }
    if let Some((prev, slow)) = a
        .hops
        .windows(2)
        .filter_map(|w| Some((w.first()?, w.get(1)?)))
        .find(|(_, x)| x.delay_s.is_some_and(|d| d > SLOW_HOP_SECONDS))
    {
        add(
            "email_headers_delayed",
            Severity::Warning,
            "Delayed in transit".into(),
            format!(
                "It waited {} between {} and {}.",
                minutes(slow.delay_s.unwrap_or_default()),
                orunknown(&prev.by_host),
                orunknown(&slow.by_host)
            ),
            Some("Look for queueing, greylisting or a retry at that server; its logs will say why."),
        );
    }
    if a.spam.flagged {
        let mut msg = "The receiving side marked this message as spam".to_string();
        if let Some(score) = a.spam.score {
            msg += &format!(" (score {score:.1})");
        }
        if let Some(scl) = a.spam.scl {
            msg += &format!(" (Microsoft SCL {scl})");
        }
        add(
            "email_headers_spam",
            Severity::Warning,
            "Flagged as spam".into(),
            msg + ".",
            Some("Fix any authentication problems above first; then check content and sender reputation (Blacklist)."),
        );
    }
    for anomaly in &a.anomalies {
        match anomaly {
            Anomaly::MultipleFrom { count } => add(
                "email_headers_multiple_from",
                Severity::Warning,
                "More than one From header".into(),
                format!(
                    "The message has {count} From headers; a legitimate message has one. Mail programs may show a different sender than the one a receiving server checked."
                ),
                Some("Treat the message as forged unless the sender can explain it."),
            ),
            Anomaly::ClockSkew { hop } => add(
                "email_headers_clock_skew",
                Severity::Info,
                "Hop dates run backwards".into(),
                format!(
                    "Hop {} is dated before the server that handed it the message, so a server clock is wrong or a Received line was edited.",
                    hop + 1
                ),
                None,
            ),
            Anomaly::TooManyHops { total } => add(
                "email_headers_too_many_hops",
                Severity::Info,
                "Very long Received chain".into(),
                format!(
                    "The message has {total} Received headers; only the newest {MAX_HOPS} were analysed, so the origin may be missing."
                ),
                None,
            ),
            Anomaly::Truncated => add(
                "email_headers_truncated",
                Severity::Info,
                "Part of the paste was skipped".into(),
                "A line, a header or the number of headers went over the analysis limits; the rest was left out."
                    .into(),
                None,
            ),
        }
    }
    out
}
