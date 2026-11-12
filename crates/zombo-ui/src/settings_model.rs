use std::{fmt, net::SocketAddr, time::Duration};

use serde::{Deserialize, Serialize};
use zombo_core::{email_auth::parse_selectors, registration::check_proxy, resolver::parse_addr, text::single_line};

use crate::section::Section;

/// A settings file is a handful of lines. Anything bigger is not ours.
pub const MAX_FILE_BYTES: usize = 64 * 1024;
pub const MIN_TIMEOUT_SECS: i64 = 1;
pub const MAX_TIMEOUT_SECS: i64 = 120;
pub const MAX_RESOLVERS: usize = 20;
pub const MAX_SELECTORS: usize = 20;
const MAX_LABEL: usize = 63;
const MAX_SELECTOR: usize = 100;
const MAX_PROXY: usize = 2048;

/// What the rep can change (DESIGN.md, "Settings"). Nothing else is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub resolvers: Vec<SocketAddr>,
    pub selectors: Vec<String>,
    /// `None` means each Check keeps its own default limit.
    pub timeout: Option<Duration>,
    /// `None` honours `HTTP_PROXY` and `HTTPS_PROXY`. Registration only.
    pub proxy: Option<String>,
    pub notifications: bool,
    /// Ask GitHub once a day for a newer AppImage. Used only when running as an AppImage.
    pub check_updates: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            resolvers: vec![],
            selectors: vec![],
            timeout: None,
            proxy: None,
            notifications: true,
            check_updates: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    Resolvers,
    Selectors,
    Timeout,
    Proxy,
}

impl Field {
    pub fn label(self) -> &'static str {
        match self {
            Field::Resolvers => "Extra resolvers",
            Field::Selectors => "Extra DKIM selectors",
            Field::Timeout => "Check timeout",
            Field::Proxy => "HTTP proxy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub field: Field,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    TooLarge,
    NotText,
    /// The text is not valid TOML, has a value of the wrong type, or has a key this app does not know.
    Syntax(String),
    Invalid(Vec<FieldError>),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::TooLarge => write!(f, "the file is larger than {} KiB", MAX_FILE_BYTES / 1024),
            LoadError::NotText => write!(f, "the file is not text"),
            LoadError::Syntax(s) => write!(f, "{}", s.trim_end().replace('\n', " ")),
            LoadError::Invalid(errors) => {
                let parts: Vec<String> = errors.iter().map(|e| format!("{}: {}", e.field.label(), e.message)).collect();
                write!(f, "{}", parts.join("; "))
            }
        }
    }
}

/// The form as typed: what the pane holds and what the file says, before any check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Draft {
    pub resolvers: Vec<String>,
    pub selectors: Vec<String>,
    pub timeout: String,
    pub proxy: String,
    pub notifications: bool,
    pub check_updates: bool,
}

/// Split a typed list on commas, semicolons and whitespace.
pub fn split_list(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn addr_text(a: &SocketAddr) -> String {
    if a.port() == 53 { a.ip().to_string() } else { a.to_string() }
}

impl From<&Settings> for Draft {
    fn from(s: &Settings) -> Self {
        Draft {
            resolvers: s.resolvers.iter().map(addr_text).collect(),
            selectors: s.selectors.clone(),
            timeout: s.timeout.map(|t| t.as_secs().to_string()).unwrap_or_default(),
            proxy: s.proxy.clone().unwrap_or_default(),
            notifications: s.notifications,
            check_updates: s.check_updates,
        }
    }
}

impl Draft {
    /// Every field is checked, and every bad field is reported, so the pane can mark each one.
    pub fn validate(&self) -> Result<Settings, Vec<FieldError>> {
        let mut errors = vec![];
        let mut fail = |field, message: String| errors.push(FieldError { field, message });
        let resolvers = resolvers(&self.resolvers).map_err(|m| fail(Field::Resolvers, m)).unwrap_or_default();
        let selectors = selectors(&self.selectors).map_err(|m| fail(Field::Selectors, m)).unwrap_or_default();
        let timeout = timeout(&self.timeout).map_err(|m| fail(Field::Timeout, m)).unwrap_or_default();
        let proxy = proxy(&self.proxy).map_err(|m| fail(Field::Proxy, m)).unwrap_or_default();
        if errors.is_empty() {
            Ok(Settings {
                resolvers,
                selectors,
                timeout,
                proxy,
                notifications: self.notifications,
                check_updates: self.check_updates,
            })
        } else {
            Err(errors)
        }
    }
}

fn resolvers(items: &[String]) -> Result<Vec<SocketAddr>, String> {
    let mut out: Vec<SocketAddr> = vec![];
    for item in items {
        let a =
            parse_addr(item).map_err(|_| format!("{} is not an IP address, with or without a port", shown(item)))?;
        if a.port() == 0 {
            return Err(format!("{} uses port 0", shown(item)));
        }
        if a.ip().is_unspecified() || a.ip().is_multicast() {
            return Err(format!("{} is not an address a resolver can have", shown(item)));
        }
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.len() > MAX_RESOLVERS {
        return Err(format!("at most {MAX_RESOLVERS} extra resolvers"));
    }
    Ok(out)
}

fn selectors(items: &[String]) -> Result<Vec<String>, String> {
    let out = parse_selectors(items).map_err(|e| clip(&e))?;
    for s in &out {
        if s.len() > MAX_SELECTOR || s.split('.').any(|l| l.len() > MAX_LABEL) {
            return Err(format!("{} is too long for a DNS name", shown(s)));
        }
    }
    Ok(out)
}

fn timeout(text: &str) -> Result<Option<Duration>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let range = format!("enter whole seconds from {MIN_TIMEOUT_SECS} to {MAX_TIMEOUT_SECS}, or leave it empty");
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(range);
    }
    match text.parse::<i64>() {
        Ok(n) if (MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&n) => Ok(Some(Duration::from_secs(n as u64))),
        _ => Err(range),
    }
}

fn proxy(text: &str) -> Result<Option<String>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if text.len() > MAX_PROXY || text.chars().any(zombo_core::text::is_unsafe_char) {
        return Err("not a usable proxy address".into());
    }
    check_proxy(text).map_err(|e| clip(&e))?;
    Ok(Some(text.to_string()))
}

/// A bad value shown back to the rep: bounded, and with no control characters.
fn shown(v: &str) -> String {
    let clean: String = single_line(v).chars().take(40).collect();
    format!("\"{clean}{}\"", if v.chars().count() > 40 { "..." } else { "" })
}

fn clip(text: &str) -> String {
    let clean: String = single_line(text).chars().take(160).collect();
    clean
}

/// The file as written. Unknown keys are an error, so a typo is never silently ignored.
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct FileForm {
    resolvers: Vec<String>,
    dkim_selectors: Vec<String>,
    timeout_seconds: Option<i64>,
    proxy: Option<String>,
    notifications: Option<bool>,
    check_updates: Option<bool>,
}

/// Parse a config file. Missing keys take their defaults; everything present is validated.
pub fn parse(text: &str) -> Result<Settings, LoadError> {
    if text.len() > MAX_FILE_BYTES {
        return Err(LoadError::TooLarge);
    }
    let f: FileForm = toml::from_str(text).map_err(|e| LoadError::Syntax(clip(&e.to_string())))?;
    let draft = Draft {
        resolvers: f.resolvers,
        selectors: f.dkim_selectors,
        timeout: f.timeout_seconds.map(|n| n.to_string()).unwrap_or_default(),
        proxy: f.proxy.unwrap_or_default(),
        notifications: f.notifications.unwrap_or(Settings::default().notifications),
        check_updates: f.check_updates.unwrap_or(Settings::default().check_updates),
    };
    draft.validate().map_err(LoadError::Invalid)
}

/// The file text for these settings. `parse(to_toml(s)) == s`.
pub fn to_toml(s: &Settings) -> String {
    let f = FileForm {
        resolvers: s.resolvers.iter().map(addr_text).collect(),
        dkim_selectors: s.selectors.clone(),
        timeout_seconds: s.timeout.map(|t| t.as_secs() as i64),
        proxy: s.proxy.clone(),
        notifications: Some(s.notifications),
        check_updates: Some(s.check_updates),
    };
    toml::to_string(&f).unwrap_or_default()
}

/// How long one Check may run, and how long one question inside it may wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub whole: Duration,
    pub query: Duration,
}

const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// The limits a Check has with no setting: `(whole, query)`. An on-demand Check has no
/// query limit of its own here; its module keeps its own.
fn default_budget(section: Section) -> Budget {
    if let Some(check) = section.check() {
        return Budget { whole: check.budget.0, query: check.budget.1 };
    }
    let (whole, query) = match section {
        Section::Registration => (15, 12),
        Section::Email => (25, 4),
        Section::Web => (12, 10),
        Section::Tls | Section::TlsPort => (10, 8),
        Section::Smtp => (40, 40),
        Section::Blacklist => (25, 25),
        _ => (20, 4),
    };
    Budget { whole: secs(whole), query: secs(query) }
}

/// The settings timeout, or the Check's default. The query limit scales with the whole limit.
/// An on-demand Check never gets less than its default: those Checks need time to connect.
pub fn budget(section: Section, setting: Option<Duration>) -> Budget {
    let d = default_budget(section);
    let Some(t) = setting else { return d };
    let whole = if section.is_on_demand() { t.max(d.whole) } else { t };
    let query = if section.is_on_demand() {
        d.query
    } else {
        whole.mul_f64(d.query.as_secs_f64() / d.whole.as_secs_f64()).max(Duration::from_millis(250))
    };
    Budget { whole, query }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> Draft {
        Draft { notifications: true, check_updates: true, ..Draft::default() }
    }
    fn only(d: Draft) -> (Field, String) {
        let mut e = d.validate().unwrap_err();
        assert_eq!(e.len(), 1, "{e:?}");
        let e = e.remove(0);
        (e.field, e.message)
    }
    fn items(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_empty_file_is_the_defaults() {
        assert_eq!(parse("").unwrap(), Settings::default());
        assert!(Settings::default().notifications);
        assert_eq!(Settings::default().timeout, None);
    }

    #[test]
    fn a_full_file_round_trips() {
        let s = Settings {
            resolvers: vec!["9.9.9.10:53".parse().unwrap(), "[2001:db8::1]:5353".parse().unwrap()],
            selectors: items(&["acme2024", "s1.k"]),
            timeout: Some(secs(45)),
            proxy: Some("http://proxy.example:3128".into()),
            notifications: false,
            check_updates: false,
        };
        assert_eq!(parse(&to_toml(&s)).unwrap(), s);
        assert_eq!(parse(&to_toml(&Settings::default())).unwrap(), Settings::default());
    }

    #[test]
    fn update_checks_are_on_by_default_and_can_be_switched_off_in_the_file() {
        assert!(Settings::default().check_updates);
        assert!(parse("").unwrap().check_updates);
        assert!(!parse("check_updates = false\n").unwrap().check_updates);
    }

    #[test]
    fn a_file_with_one_key_keeps_the_other_defaults() {
        let s = parse("timeout_seconds = 30\n").unwrap();
        assert_eq!(s, Settings { timeout: Some(secs(30)), ..Settings::default() });
    }

    #[test]
    fn the_resolver_addresses_use_the_cli_parser() {
        let s = parse("resolvers = [\"9.9.9.10\", \"[2001:db8::1]:5353\", \"2001:db8::2\", \"9.9.9.10:53\"]").unwrap();
        let want: Vec<SocketAddr> =
            ["9.9.9.10:53", "[2001:db8::1]:5353", "[2001:db8::2]:53"].iter().map(|a| a.parse().unwrap()).collect();
        assert_eq!(s.resolvers, want);
    }

    #[test]
    fn bad_resolvers_say_which_value_is_wrong() {
        for bad in ["dns.example", "1.2.3", "1.1.1.1:0", "0.0.0.0", "::", "224.0.0.1", "1.1.1.1:99999", ""] {
            let mut d = draft();
            d.resolvers = items(&[bad]);
            if bad.is_empty() {
                assert!(d.validate().is_err(), "empty item");
                continue;
            }
            let (field, message) = only(d);
            assert_eq!(field, Field::Resolvers, "{bad}");
            assert!(message.contains(&format!("\"{bad}\"")), "{message}");
        }
    }

    #[test]
    fn the_resolver_count_is_capped_at_twenty() {
        let many = |n: usize| (0..n).map(|i| format!("10.0.0.{}", i + 1)).collect::<Vec<_>>();
        let mut d = draft();
        d.resolvers = many(20);
        assert_eq!(d.validate().unwrap().resolvers.len(), 20);
        d.resolvers = many(21);
        assert_eq!(only(d).0, Field::Resolvers);
    }

    #[test]
    fn selectors_follow_the_dkim_rules_and_the_cap_of_twenty() {
        let mut d = draft();
        d.selectors = items(&["Acme2024", "acme2024", "a.b", "c_d-e"]);
        assert_eq!(d.validate().unwrap().selectors, ["acme2024", "a.b", "c_d-e"]);
        for bad in ["bad..name", "-x", "x-", "sp ace!", "a/b", "ünï"] {
            d.selectors = items(&[bad]);
            assert_eq!(only(d.clone()).0, Field::Selectors, "{bad}");
        }
        d.selectors = (0..20).map(|i| format!("s{i}")).collect();
        assert_eq!(d.validate().unwrap().selectors.len(), 20);
        d.selectors = (0..21).map(|i| format!("s{i}")).collect();
        assert_eq!(only(d.clone()), (Field::Selectors, "at most 20 custom DKIM selectors".to_string()));
        d.selectors = items(&[&"a".repeat(64)]);
        assert_eq!(only(d.clone()).0, Field::Selectors);
        d.selectors = items(&[&"a".repeat(63)]);
        assert!(d.validate().is_ok());
        d.selectors = items(&[&["a".repeat(60), "b".repeat(60)].join(".")]);
        assert_eq!(only(d).0, Field::Selectors);
    }

    #[test]
    fn the_timeout_is_one_to_one_hundred_twenty_seconds() {
        let mut d = draft();
        for (text, want) in [("1", Some(1)), ("120", Some(120)), (" 30 ", Some(30)), ("", None)] {
            d.timeout = text.into();
            assert_eq!(d.validate().unwrap().timeout, want.map(secs), "{text:?}");
        }
        for bad in ["0", "121", "-5", "1.5", "ten", "99999999999999999999999", "+5", "1e2"] {
            d.timeout = bad.into();
            assert_eq!(only(d.clone()).0, Field::Timeout, "{bad}");
        }
    }

    #[test]
    fn a_proxy_is_an_http_or_https_url_or_empty() {
        let mut d = draft();
        for ok in ["http://proxy.example:3128", "https://user:pw@proxy.example", " http://10.0.0.1:8080 "] {
            d.proxy = ok.into();
            assert_eq!(d.validate().unwrap().proxy.as_deref(), Some(ok.trim()), "{ok}");
        }
        d.proxy = "".into();
        assert_eq!(d.validate().unwrap().proxy, None);
        for bad in ["proxy.example:3128", "socks5://p:1080", "ftp://p", "http://", "http://bad host", "http://p\u{7}x"]
        {
            d.proxy = bad.into();
            assert_eq!(only(d.clone()).0, Field::Proxy, "{bad:?}");
        }
        d.proxy = format!("http://{}", "a".repeat(3000));
        assert_eq!(only(d).0, Field::Proxy);
    }

    #[test]
    fn every_bad_field_is_reported_at_once() {
        let d = Draft {
            resolvers: items(&["nope"]),
            selectors: items(&["a..b"]),
            timeout: "0".into(),
            proxy: "x".into(),
            notifications: true,
            check_updates: true,
        };
        let fields: Vec<Field> = d.validate().unwrap_err().iter().map(|e| e.field).collect();
        assert_eq!(fields, [Field::Resolvers, Field::Selectors, Field::Timeout, Field::Proxy]);
    }

    #[test]
    fn an_unknown_key_is_an_error_that_names_it() {
        let e = parse("theme = \"light\"\n").unwrap_err();
        assert!(matches!(&e, LoadError::Syntax(m) if m.contains("theme")), "{e:?}");
        assert!(parse("[extra]\nx = 1\n").is_err());
    }

    #[test]
    fn a_wrong_type_or_broken_toml_is_a_syntax_error() {
        for bad in [
            "timeout_seconds = \"ten\"",
            "resolvers = \"8.8.8.8\"",
            "notifications = 1",
            "resolvers = [",
            "= = =",
            "timeout_seconds = 1.5",
        ] {
            assert!(matches!(parse(bad), Err(LoadError::Syntax(_))), "{bad}");
        }
    }

    #[test]
    fn a_file_value_out_of_range_is_a_field_error_not_a_syntax_error() {
        for (text, field) in [
            ("timeout_seconds = 0", Field::Timeout),
            ("timeout_seconds = 121", Field::Timeout),
            ("timeout_seconds = -1", Field::Timeout),
            ("resolvers = [\"x\"]", Field::Resolvers),
        ] {
            match parse(text) {
                Err(LoadError::Invalid(e)) => assert_eq!(e[0].field, field, "{text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_hostile_file_is_an_error_and_never_a_panic() {
        assert_eq!(parse(&" ".repeat(MAX_FILE_BYTES + 1)), Err(LoadError::TooLarge));
        assert!(parse(&"#".repeat(MAX_FILE_BYTES)).is_ok());
        let deep = format!("a = {}{}", "[".repeat(30_000), "]".repeat(30_000));
        assert!(parse(&deep).is_err());
        let deep_tables = (0..5_000).map(|i| format!("[a{i}]\n")).collect::<String>();
        assert!(parse(&deep_tables).is_err());
        let dotted = format!("{} = 1", vec!["a"; 20_000].join("."));
        assert!(parse(&dotted).is_err());
        let many = format!("resolvers = [{}]", "\"1.1.1.1\",".repeat(6_000));
        assert!(parse(&many).is_ok());
        let mixed = "resolvers = [\"\u{0}\", \"\u{1b}[31m\"]\nproxy = \"\u{7}\"\n";
        let e = parse(mixed).unwrap_err().to_string();
        assert!(!e.chars().any(zombo_core::text::is_unsafe_char), "{e:?}");
        assert!(parse("\u{feff}\u{0}\u{1}").is_err());
    }

    #[test]
    fn an_error_text_is_one_short_line_without_control_characters() {
        let e = parse(&format!("resolvers = [\"{}\"]", "x\u{1b}y".repeat(500))).unwrap_err().to_string();
        assert!(e.len() < 200 && !e.chars().any(zombo_core::text::is_unsafe_char), "{e:?}");
    }

    #[test]
    fn without_a_setting_every_check_keeps_the_limits_it_had() {
        let want = [
            (Section::Dns, 20, 4),
            (Section::Delegation, 20, 4),
            (Section::Dnssec, 20, 4),
            (Section::Email, 25, 4),
            (Section::Web, 12, 10),
            (Section::Tls, 10, 8),
            (Section::Registration, 15, 12),
            (Section::Smtp, 40, 40),
            (Section::TlsPort, 10, 8),
            (Section::Blacklist, 25, 25),
            (Section::Ports, 20, 4),
        ];
        for (s, whole, query) in want {
            assert_eq!(budget(s, None), Budget { whole: secs(whole), query: secs(query) }, "{s:?}");
        }
    }

    #[test]
    fn the_setting_replaces_an_automatic_limit_and_scales_the_question_limit() {
        let b = budget(Section::Registration, Some(secs(30)));
        assert_eq!(b.whole, secs(30));
        assert_eq!(b.query, secs(24));
        assert_eq!(budget(Section::Dns, Some(secs(5))), Budget { whole: secs(5), query: Duration::from_secs_f64(1.0) });
        assert_eq!(budget(Section::Web, Some(secs(1))).whole, secs(1));
        assert!(budget(Section::Dns, Some(secs(1))).query >= Duration::from_millis(250));
    }

    #[test]
    fn an_on_demand_check_never_gets_less_than_its_default() {
        for s in [Section::Ports, Section::Smtp, Section::TlsPort, Section::Blacklist] {
            let d = budget(s, None);
            assert_eq!(budget(s, Some(secs(1))), d, "{s:?}");
            assert_eq!(budget(s, Some(secs(120))).whole, secs(120));
            assert_eq!(budget(s, Some(secs(120))).query, d.query);
        }
    }
}
