//! SPF: the record parser and the typed tree an audit walks it into.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use serde::Serialize;

use super::clip;

/// RFC 7208 4.6.4: more DNS-querying terms than this is a permerror.
pub const MAX_LOOKUPS: usize = 10;
/// RFC 7208 4.6.4: more void lookups than this is a permerror.
pub const MAX_VOIDS: usize = 2;
/// Stop resolving past this, so a runaway tree cannot eat the timeout.
pub const LOOKUP_CAP: usize = 30;
/// Real records have dozens of terms; a 64 KB record can hold ten thousand.
const MAX_TERMS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Qualifier {
    /// `+`, also what no qualifier means.
    Pass,
    /// `-`
    Fail,
    /// `~`
    SoftFail,
    /// `?`
    Neutral,
}

impl Qualifier {
    pub fn symbol(self) -> char {
        match self {
            Qualifier::Pass => '+',
            Qualifier::Fail => '-',
            Qualifier::SoftFail => '~',
            Qualifier::Neutral => '?',
        }
    }
}

/// The target of an `a` or `mx` term: a domain (the record's own when absent)
/// and the text after a `/` (the CIDR lengths), kept as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostSpec {
    pub domain: Option<String>,
    pub cidr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    /// The domain is empty when the record gave none (an error, but still a lookup).
    Include(String),
    Redirect(String),
    A(HostSpec),
    Mx(HostSpec),
    Ptr(Option<String>),
    Exists(String),
    Ip4(Ipv4Addr, Option<u8>),
    Ip6(Ipv6Addr, Option<u8>),
    All,
    Exp(String),
}

impl Mechanism {
    /// Whether the term costs a DNS lookup against the limit of ten.
    pub fn is_lookup(&self) -> bool {
        matches!(self, Mechanism::Include(_) | Mechanism::Redirect(_) | Mechanism::A(_) | Mechanism::Mx(_) | Mechanism::Ptr(_) | Mechanism::Exists(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpfTerm {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
    /// An `a`, `mx` or `exists` lookup that found nothing.
    pub void: bool,
    /// The resolved include or redirect.
    pub target: Option<Box<SpfNode>>,
}

/// Why an include or redirect target has no terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeError {
    Loop,
    LookupFailed(String),
    NoRecord,
    MultipleRecords,
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Loop => f.write_str("loop"),
            NodeError::LookupFailed(why) => write!(f, "lookup failed: {why}"),
            NodeError::NoRecord => f.write_str("no SPF record"),
            NodeError::MultipleRecords => f.write_str("multiple SPF records"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpfNode {
    pub domain: String,
    pub record: Option<String>,
    pub terms: Vec<SpfTerm>,
    pub error: Option<NodeError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefKind {
    Include,
    Redirect,
}

impl fmt::Display for RefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RefKind::Include => "include",
            RefKind::Redirect => "redirect",
        })
    }
}

/// A permerror cause other than the lookup limit. `Display` gives the wording
/// the Go engine used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpfError {
    DuplicateModifier { domain: String, name: &'static str },
    BadTerm { domain: String, term: String },
    MissingDomain { domain: String, mechanism: &'static str },
    BadAddress { domain: String, term: String },
    UnknownMechanism { domain: String, term: String },
    TooManyTerms { domain: String },
    Loop { kind: RefKind, domain: String },
    NoRecord { kind: RefKind, domain: String },
    MultipleRecords { kind: RefKind, domain: String, count: usize },
    TooManyVoids(usize),
}

impl fmt::Display for SpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpfError::DuplicateModifier { domain, name } => write!(f, "{domain}: more than one {name}= modifier"),
            SpfError::BadTerm { domain, term } => write!(f, "{domain}: bad term {term:?}"),
            SpfError::MissingDomain { domain, mechanism } => write!(f, "{domain}: {mechanism} needs a domain"),
            SpfError::BadAddress { domain, term } => write!(f, "{domain}: bad address {term:?}"),
            SpfError::UnknownMechanism { domain, term } => write!(f, "{domain}: unknown mechanism {term:?}"),
            SpfError::TooManyTerms { domain } => write!(f, "{domain}: more than {MAX_TERMS} terms"),
            SpfError::Loop { kind, domain } => write!(f, "{kind} loops back to {domain}"),
            SpfError::NoRecord { kind, domain } => write!(f, "{kind} target {domain} has no SPF record"),
            SpfError::MultipleRecords { kind, domain, count } => write!(f, "{kind} target {domain} has {count} SPF records"),
            SpfError::TooManyVoids(n) => write!(f, "{n} void lookups (limit {MAX_VOIDS})"),
        }
    }
}

/// The terms of one record, and what is wrong with them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSpf {
    pub terms: Vec<SpfTerm>,
    pub errors: Vec<SpfError>,
}

/// Every `v=spf1` record among a name's TXT records.
pub fn spf_records(txts: &[String]) -> Vec<String> {
    txts.iter().filter(|t| t.split_whitespace().next().is_some_and(|v| v.eq_ignore_ascii_case("v=spf1"))).cloned().collect()
}

/// Parse one SPF record. `domain` only labels the errors.
pub fn parse_spf(domain: &str, record: &str) -> ParsedSpf {
    let mut out = ParsedSpf::default();
    let (mut has_redirect, mut has_exp) = (false, false);
    for tok in record.split_whitespace().skip(1) {
        if out.terms.len() >= MAX_TERMS {
            out.errors.push(SpfError::TooManyTerms { domain: domain.into() });
            break;
        }
        let term = |qualifier, mechanism| SpfTerm { qualifier, mechanism, void: false, target: None };
        // A modifier is `name=value`: the `=` comes before any `:` or `/`.
        if let Some(i) = tok.find(['=', ':', '/']).filter(|&i| i > 0 && tok.as_bytes()[i] == b'=') {
            let (name, value) = (tok[..i].to_ascii_lowercase(), &tok[i + 1..]);
            let (mechanism, seen, label) = match name.as_str() {
                "redirect" => (Mechanism::Redirect(value.into()), &mut has_redirect, "redirect"),
                "exp" => (Mechanism::Exp(value.into()), &mut has_exp, "exp"),
                _ => continue, // RFC 7208 4.6.3: unknown modifiers are ignored
            };
            if std::mem::replace(seen, true) {
                out.errors.push(SpfError::DuplicateModifier { domain: domain.into(), name: label });
            }
            out.terms.push(term(Qualifier::Pass, mechanism));
            continue;
        }
        let (qualifier, tok) = match tok.as_bytes()[0] {
            b'+' => (Qualifier::Pass, &tok[1..]),
            b'-' => (Qualifier::Fail, &tok[1..]),
            b'~' => (Qualifier::SoftFail, &tok[1..]),
            b'?' => (Qualifier::Neutral, &tok[1..]),
            _ => (Qualifier::Pass, tok),
        };
        let (name, mut rest) = tok.split_once(':').unwrap_or((tok, ""));
        let mut name = name;
        if let (Some(i), true) = (name.find('/'), rest.is_empty()) {
            (name, rest) = (&tok[..i], &tok[i..]);
        }
        let (d, text) = (|| domain.to_string(), || clip(tok));
        let lower = name.to_ascii_lowercase();
        let mechanism = match lower.as_str() {
            "all" => {
                if !rest.is_empty() {
                    out.errors.push(SpfError::BadTerm { domain: d(), term: text() });
                }
                Mechanism::All
            }
            "include" | "exists" => {
                let include = lower == "include";
                if rest.is_empty() {
                    out.errors.push(SpfError::MissingDomain { domain: d(), mechanism: if include { "include" } else { "exists" } });
                }
                if include { Mechanism::Include(rest.into()) } else { Mechanism::Exists(rest.into()) }
            }
            "a" => Mechanism::A(host_spec(rest)),
            "mx" => Mechanism::Mx(host_spec(rest)),
            "ptr" => Mechanism::Ptr(Some(rest).filter(|r| !r.is_empty()).map(Into::into)),
            "ip4" | "ip6" => match ip_term(lower == "ip4", rest) {
                Some(m) => m,
                None => {
                    out.errors.push(SpfError::BadAddress { domain: d(), term: text() });
                    continue;
                }
            },
            _ => {
                out.errors.push(SpfError::UnknownMechanism { domain: d(), term: text() });
                continue;
            }
        };
        out.terms.push(term(qualifier, mechanism));
    }
    out
}

fn host_spec(rest: &str) -> HostSpec {
    let (host, cidr) = match rest.split_once('/') {
        Some((h, c)) => (h, Some(c)),
        None => (rest, None),
    };
    HostSpec { domain: Some(host).filter(|h| !h.is_empty()).map(Into::into), cidr: cidr.map(Into::into) }
}

/// `ip4:` or `ip6:` with an address and an optional prefix length.
fn ip_term(v4: bool, value: &str) -> Option<Mechanism> {
    let (addr, prefix) = match value.split_once('/') {
        Some((a, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (a, Some(p.parse::<u8>().ok()?)),
        Some(_) => return None,
        None => (value, None),
    };
    if v4 {
        prefix.is_none_or(|p| p <= 32).then_some(())?;
        Some(Mechanism::Ip4(addr.parse().ok()?, prefix))
    } else {
        prefix.is_none_or(|p| p <= 128).then_some(())?;
        Some(Mechanism::Ip6(addr.parse().ok()?, prefix))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "qualifier")]
pub enum EffectiveAll {
    /// The record, and any redirect behind it, has no `all`.
    Absent,
    /// A redirect that was not resolved: a macro, the lookup cap, or a failed or broken target.
    Unknown,
    All(Qualifier),
}

/// The `all` that ends evaluation: the record's own, else its redirect's.
pub fn effective_all(node: &SpfNode) -> EffectiveAll {
    if let Some(t) = node.terms.iter().find(|t| t.mechanism == Mechanism::All) {
        return EffectiveAll::All(t.qualifier);
    }
    match node.terms.iter().find(|t| matches!(t.mechanism, Mechanism::Redirect(_))) {
        None => EffectiveAll::Absent,
        Some(t) => match t.target.as_deref() {
            Some(n) if n.error.is_none() => effective_all(n),
            _ => EffectiveAll::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(rec: &str) -> ParsedSpf {
        parse_spf("example.com", rec)
    }
    fn mechs(rec: &str) -> Vec<Mechanism> {
        p(rec).terms.into_iter().map(|t| t.mechanism).collect()
    }
    fn errs(rec: &str) -> Vec<String> {
        p(rec).errors.iter().map(ToString::to_string).collect()
    }
    fn host(d: Option<&str>, c: Option<&str>) -> HostSpec {
        HostSpec { domain: d.map(Into::into), cidr: c.map(Into::into) }
    }

    #[test]
    fn every_mechanism_parses_to_its_variant() {
        let rec = "v=spf1 include:_spf.x.test a a:h.test a/24 mx:m.test/24 ptr ptr:p.test exists:e.test ip4:192.0.2.0/24 ip6:2001:db8::/32 -all exp=why.test redirect=r.test";
        assert_eq!(
            mechs(rec),
            [
                Mechanism::Include("_spf.x.test".into()),
                Mechanism::A(host(None, None)),
                Mechanism::A(host(Some("h.test"), None)),
                Mechanism::A(host(None, Some("24"))),
                Mechanism::Mx(host(Some("m.test"), Some("24"))),
                Mechanism::Ptr(None),
                Mechanism::Ptr(Some("p.test".into())),
                Mechanism::Exists("e.test".into()),
                Mechanism::Ip4("192.0.2.0".parse().unwrap(), Some(24)),
                Mechanism::Ip6("2001:db8::".parse().unwrap(), Some(32)),
                Mechanism::All,
                Mechanism::Exp("why.test".into()),
                Mechanism::Redirect("r.test".into()),
            ]
        );
        assert!(p(rec).errors.is_empty());
    }

    #[test]
    fn qualifiers_and_case() {
        let t = p("V=SPF1 +a -ALL ~mx ?ptr include:Foo.TEST").terms;
        let q: Vec<_> = t.iter().map(|t| t.qualifier).collect();
        assert_eq!(q, [Qualifier::Pass, Qualifier::Fail, Qualifier::SoftFail, Qualifier::Neutral, Qualifier::Pass]);
        assert_eq!(t[1].mechanism, Mechanism::All);
        assert_eq!(Qualifier::SoftFail.symbol(), '~');
    }

    #[test]
    fn the_wording_of_each_syntax_error_is_the_go_engines() {
        assert_eq!(errs("v=spf1 ip4:300.1.1.1"), [r#"example.com: bad address "ip4:300.1.1.1""#]);
        assert_eq!(errs("v=spf1 ip6:192.0.2.1"), [r#"example.com: bad address "ip6:192.0.2.1""#]);
        assert_eq!(errs("v=spf1 ip4:2001:db8::1"), [r#"example.com: bad address "ip4:2001:db8::1""#]);
        assert_eq!(errs("v=spf1 bogus"), [r#"example.com: unknown mechanism "bogus""#]);
        assert_eq!(errs("v=spf1 all:x"), [r#"example.com: bad term "all:x""#]);
        assert_eq!(errs("v=spf1 include"), ["example.com: include needs a domain"]);
        assert_eq!(errs("v=spf1 exists:"), ["example.com: exists needs a domain"]);
        assert_eq!(errs("v=spf1 redirect=a.test redirect=b.test"), ["example.com: more than one redirect= modifier"]);
        assert_eq!(errs("v=spf1 exp=a exp=b"), ["example.com: more than one exp= modifier"]);
    }

    #[test]
    fn a_bad_ip_prefix_is_an_error() {
        for bad in ["ip4:192.0.2.0/33", "ip4:192.0.2.0/", "ip4:192.0.2.0/+8", "ip6:::1/129", "ip4:", "ip4:192.0.2.0/-1"] {
            assert_eq!(p(&format!("v=spf1 {bad}")).errors.len(), 1, "{bad}");
        }
    }

    #[test]
    fn unknown_modifiers_are_ignored_as_the_rfc_says() {
        let r = p("v=spf1 foo=bar -all");
        assert!(r.errors.is_empty());
        assert_eq!(r.terms.len(), 1);
    }

    #[test]
    fn lookup_terms_are_the_ones_rfc_7208_counts() {
        let n = |rec| p(rec).terms.iter().filter(|t| t.mechanism.is_lookup()).count();
        assert_eq!(n("v=spf1 include:a.test a mx ptr exists:b.test redirect=c.test"), 6);
        assert_eq!(n("v=spf1 ip4:192.0.2.1 ip6:::1 all exp=x.test"), 0);
    }

    #[test]
    fn only_v_spf1_records_count_and_case_is_ignored() {
        let txts: Vec<String> = ["v=spf1 -all", "V=SPF1 ~all", "v=spf10 -all", "google-site-verification=x", "", "  v=spf1", "xv=spf1"].map(Into::into).into();
        assert_eq!(spf_records(&txts), ["v=spf1 -all", "V=SPF1 ~all", "  v=spf1"]);
    }

    #[test]
    fn a_bare_version_is_an_empty_record() {
        let r = p("v=spf1");
        assert!(r.terms.is_empty() && r.errors.is_empty());
    }

    #[test]
    fn hostile_input_is_bounded_and_does_not_panic() {
        // A 70 KB record of includes: parsing stops at the term cap.
        let big = format!("v=spf1 {}", "include:example.com ".repeat(3_500));
        let r = p(&big);
        assert_eq!(r.terms.len(), 512);
        assert!(r.errors.iter().any(|e| matches!(e, SpfError::TooManyTerms { .. })));
        // One 64 KB token: the error message stays short.
        let long = format!("v=spf1 {}", "x".repeat(65_000));
        assert!(errs(&long)[0].len() < 200);
        // Garbage, controls, multibyte text and lone qualifiers.
        for junk in ["v=spf1 +", "v=spf1 ~ ? -", "v=spf1 \u{0}\u{1b}[31m", "v=spf1 =:/", "v=spf1 :::", "v=spf1 /", "v=spf1 é:ü/ö", "v=spf1 a:/", "v=spf1 mx//64", "v=spf1 \u{85}\u{2028}x"] {
            let _ = p(junk);
        }
    }

    #[test]
    fn an_include_of_a_domain_with_a_macro_keeps_the_macro_text() {
        assert_eq!(mechs("v=spf1 include:%{d}._spf.test"), [Mechanism::Include("%{d}._spf.test".into())]);
    }

    fn node(terms: Vec<SpfTerm>) -> SpfNode {
        SpfNode { domain: "example.com".into(), record: Some(String::new()), terms, error: None }
    }
    fn term(q: Qualifier, m: Mechanism, target: Option<SpfNode>) -> SpfTerm {
        SpfTerm { qualifier: q, mechanism: m, void: false, target: target.map(Box::new) }
    }

    #[test]
    fn the_effective_all_is_the_records_own_else_its_redirects() {
        let all = |q| term(q, Mechanism::All, None);
        assert_eq!(effective_all(&node(vec![all(Qualifier::Fail)])), EffectiveAll::All(Qualifier::Fail));
        assert_eq!(effective_all(&node(vec![])), EffectiveAll::Absent);
        let via = |target| node(vec![term(Qualifier::Pass, Mechanism::Redirect("r.test".into()), target)]);
        assert_eq!(effective_all(&via(Some(node(vec![all(Qualifier::SoftFail)])))), EffectiveAll::All(Qualifier::SoftFail));
        assert_eq!(effective_all(&via(None)), EffectiveAll::Unknown);
        let mut broken = node(vec![]);
        broken.error = Some(NodeError::NoRecord);
        assert_eq!(effective_all(&via(Some(broken))), EffectiveAll::Unknown);
        // A record that carries its own all ignores the redirect.
        let both = node(vec![term(Qualifier::Pass, Mechanism::Redirect("r.test".into()), None), all(Qualifier::Fail)]);
        assert_eq!(effective_all(&both), EffectiveAll::All(Qualifier::Fail));
    }
}
