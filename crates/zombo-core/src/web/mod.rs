//! Web inspection: load a site over HTTPS (falling back to HTTP), record every
//! redirect hop, the security headers and the status; probe whether plain HTTP
//! redirects to HTTPS; say who serves it (CDN, host, AS); and optionally ask the
//! origin server directly to tell a CDN problem from an origin problem. Ported from
//! the Go `website_inspection` Check, plus the provider and origin parts.

pub(crate) mod fetch;
mod findings;
mod origin;
pub(crate) mod providers;

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::text::printable;
use fetch::{Fetch, TlsMode, fetch_chain};

pub use fetch::{CertCheck, Hop, MAX_REDIRECTS, Pin};
pub use findings::web_findings;
pub use origin::Answer;
pub use providers::{
    AsnInfo, Detection, Hosting, ProviderKind, cymru_origin_name, detect_hosting, parse_cymru_name, parse_cymru_origin,
    system_resolver,
};

/// Evaluated on the final response, in display order.
pub const SECURITY_HEADERS: [&str; 6] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
];

/// Two fetches (HTTPS, then the HTTP fallback or probe) must fit in the overall timeout.
const FETCH_LIMIT: Duration = Duration::from_secs(6);
/// One DNS question to the resolver.
const DNS_LIMIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Serialize)]
pub struct HeaderState {
    pub present: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// The header that satisfied it, when not itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<&'static str>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WordPress {
    pub detected: bool,
    pub evidence: Vec<&'static str>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    pub critical_error: bool,
    pub maintenance: bool,
}

/// Where the standard ports are. Tests point these at fake servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    pub http: u16,
    pub https: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Ports { http: 80, https: 443 }
    }
}

#[derive(Debug, Clone)]
pub struct WebOptions {
    /// Covers the whole Check: every fetch and every DNS question.
    pub timeout: Duration,
    /// Ask this address directly, with the real Host header, and compare.
    pub origin: Option<IpAddr>,
    /// The DNS server for CNAME and ASN questions; `system_resolver()` when none.
    pub resolver: Option<SocketAddr>,
    pub ports: Ports,
    /// Make the target resolve here instead of through DNS (a test seam).
    pub pin: Option<IpAddr>,
    /// Whether the origin's certificate is checked. The public name is always checked.
    pub origin_cert: CertCheck,
    /// DER certificates trusted instead of the bundled roots (a test seam).
    pub trusted_roots: Vec<Vec<u8>>,
}

impl Default for WebOptions {
    fn default() -> Self {
        WebOptions {
            timeout: Duration::from_secs(10),
            origin: None,
            resolver: None,
            ports: Ports::default(),
            pin: None,
            origin_cert: CertCheck::Verify,
            trusted_roots: vec![],
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("{0:?} is not a valid domain, host name or URL")]
    BadTarget(String),
    #[error("give a URL without a port: the standard ports 443 and 80 are inspected")]
    PortGiven,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WebResult {
    /// The URL inspected (http:// after a fallback).
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Total, across every redirect.
    pub time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Every response, redirects then the final one.
    pub chain: Vec<Hop>,
    pub redirect_loop: bool,
    pub too_many_redirects: bool,
    /// The first step of the chain from https:// to http://.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downgrade: Option<Downgrade>,
    /// Why HTTPS failed, when it fell back to HTTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub https_error: Option<String>,
    /// The site could not be loaded at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether http:// redirects to https:// (None: not probed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_to_https: Option<bool>,
    pub headers: BTreeMap<&'static str, HeaderState>,
    pub wordpress: WordPress,
    /// Every response header of the final response, for provider detection.
    pub response_headers: Vec<(String, String)>,
    pub hosting: Hosting,
    /// The origin server's own answer, when `--origin` was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginAnswer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OriginAnswer {
    pub ip: IpAddr,
    pub answer: Answer,
    /// The origin certificate was not verified because `--insecure-origin` was given.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub verification_skipped: bool,
    /// What the origin presented, read only when verification was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<OriginCert>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OriginCert {
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
    /// Why a verifying client would refuse it, when it would.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_fail: Option<String>,
}

/// A redirect that moved from https:// to http://.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Downgrade {
    pub from: String,
    pub to: String,
}

/// The first hop whose URL is https and whose next URL (the next hop, or the last
/// hop's Location) is http.
pub fn redirect_downgrade(chain: &[Hop]) -> Option<Downgrade> {
    let next =
        chain.iter().skip(1).map(|h| Some(h.url.as_str())).chain([chain.last().and_then(|h| h.location.as_deref())]);
    chain.iter().zip(next).find_map(|(h, to)| {
        let to = to?;
        (h.url.starts_with("https://") && to.starts_with("http://"))
            .then(|| Downgrade { from: h.url.clone(), to: to.to_string() })
    })
}

/// Split what the rep typed into a host and the path to ask for. Scheme and
/// fragment are dropped; a port is refused, not silently ignored.
pub fn parse_web_target(raw: &str) -> Result<(String, String), WebError> {
    let raw = raw.trim();
    let bad = || WebError::BadTarget(raw.chars().take(100).collect());
    let u = url::Url::parse(&if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") })
        .map_err(|_| bad())?;
    if u.port().is_some() {
        return Err(WebError::PortGiven);
    }
    let host = match u.host() {
        Some(url::Host::Domain(d)) if d.contains('.') => d.trim_end_matches('.').to_ascii_lowercase(),
        _ => return Err(bad()),
    };
    let mut path = u.path().to_string();
    if let Some(q) = u.query() {
        path = format!("{path}?{q}");
    }
    Ok((host, path))
}

fn site_url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let default = if scheme == "https" { 443 } else { 80 };
    if port == default { format!("{scheme}://{host}{path}") } else { format!("{scheme}://{host}:{port}{path}") }
}

/// Inspect `host` (`path` starts with `/`). `limit` bounds the whole Check.
pub async fn check_web(host: &str, path: &str, opts: &WebOptions) -> WebResult {
    let started = Instant::now();
    let deadline = started + opts.timeout;
    let pin = opts.pin.map(|ip| Pin { host: host.to_string(), ip });
    let (https_url, http_url) =
        (site_url("https", host, opts.ports.https, path), site_url("http", host, opts.ports.http, path));
    let public_tls = TlsMode { check: CertCheck::Verify, roots: opts.trusted_roots.clone() };
    let fetch = {
        let pin = pin.clone();
        move |url: &str| {
            fetch_chain(
                url,
                pin.as_ref(),
                deadline.saturating_duration_since(Instant::now()).min(FETCH_LIMIT),
                &public_tls,
            )
        }
    };
    let (public_urls, public_fetch) = ((https_url.clone(), http_url.clone()), fetch.clone());
    let site = tokio::task::spawn_blocking(move || inspect_with(&public_urls.0, &public_urls.1, &public_fetch));
    let mut res = site.await.unwrap_or_else(|e| failed(&https_url, e.to_string()));

    let dns_host = res
        .final_url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| host.to_string());
    let resolver = opts.resolver.unwrap_or_else(system_resolver);
    let hosting = async {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(
            left,
            detect_hosting(&dns_host, &res.response_headers, resolver, DNS_LIMIT.min(left)),
        )
        .await
        {
            Ok(h) => h,
            Err(_) => Hosting { host: dns_host.clone(), dns_error: Some("timed out".into()), ..Hosting::default() },
        }
    };
    let origin_url = res.url.clone();
    let origin = async {
        let ip = opts.origin?;
        let pin = Pin { host: host.to_string(), ip };
        let limit = deadline.saturating_duration_since(Instant::now()).min(FETCH_LIMIT);
        let tls = TlsMode { check: opts.origin_cert, roots: opts.trusted_roots.clone() };
        let url = origin_url.clone();
        let f = tokio::task::spawn_blocking(move || fetch_chain(&url, Some(&pin), limit, &tls)).await.ok()?;
        let skipped = opts.origin_cert == CertCheck::SkipVerification && origin_url.starts_with("https://");
        let certificate = if skipped { origin_cert(&origin_url, ip, host, deadline).await } else { None };
        Some(OriginAnswer { ip, answer: Answer::from_fetch(&f), verification_skipped: skipped, certificate })
    };
    let (hosting, origin) = tokio::join!(hosting, origin);
    res.hosting = hosting;
    res.origin = origin;
    res
}

/// Read what the origin presents, in a handshake that sends nothing but the hello.
async fn origin_cert(url: &str, ip: IpAddr, host: &str, deadline: Instant) -> Option<OriginCert> {
    let port = url::Url::parse(url).ok()?.port_or_known_default()?;
    let left = deadline.saturating_duration_since(Instant::now()).min(FETCH_LIMIT);
    let r =
        crate::tls::check_tls_via((ip, port), host, &crate::tls::public_roots(), time::OffsetDateTime::now_utc(), left)
            .await
            .ok()?;
    let c = r.chain.first()?;
    let not_after = c.not_after.format(&time::format_description::well_known::Rfc3339).ok()?;
    Some(OriginCert { subject: c.subject.clone(), issuer: c.issuer.clone(), not_after, would_fail: r.verify_error })
}

fn failed(url: &str, error: String) -> WebResult {
    WebResult { url: url.to_string(), error: Some(error), ..WebResult::default() }
}

/// HTTPS first, HTTP when HTTPS cannot connect; when HTTPS works, also probe whether
/// plain HTTP redirects to it. The fetches are the only I/O, so tests feed canned ones.
pub(crate) fn inspect_with(https_url: &str, http_url: &str, fetch: &dyn Fn(&str) -> Fetch) -> WebResult {
    let mut res = WebResult { url: https_url.to_string(), ..WebResult::default() };
    let mut f = fetch(https_url);
    if let (Some(e), true) = (&f.error, f.chain.is_empty()) {
        res.https_error = Some(e.clone());
        res.url = http_url.to_string();
        f = fetch(http_url);
    } else if f.error.is_none() {
        let p = fetch(http_url);
        if p.error.is_none() {
            res.http_to_https = Some(p.chain.iter().any(|h| h.url.starts_with("https://")));
        }
    }
    res.time_ms = u64::try_from(f.elapsed.as_millis()).unwrap_or(u64::MAX);
    res.downgrade = redirect_downgrade(&f.chain);
    res.redirect_loop = f.redirect_loop;
    res.too_many_redirects = f.too_many;
    if let Some(e) = &f.error {
        res.error = Some(e.clone());
        res.chain = f.chain;
        return res;
    }
    let Some(last) = f.chain.last() else { return res };
    res.final_url = Some(last.url.clone());
    res.status = Some(last.status);
    res.server = f.header("server").map(str::to_string);
    res.content_type = f.header("content-type").map(str::to_string);
    res.headers = security_headers(&f);
    res.wordpress = wordpress(&String::from_utf8_lossy(&f.body));
    res.response_headers = f.headers;
    res.chain = f.chain;
    res
}

pub(crate) fn security_headers(f: &Fetch) -> BTreeMap<&'static str, HeaderState> {
    SECURITY_HEADERS
        .iter()
        .map(|&name| {
            let mut value = f.header(name).unwrap_or_default().to_string();
            let mut via = None;
            if name == "X-Frame-Options" && value.is_empty() {
                // frame-ancestors in the CSP does the same job.
                for d in f.header("content-security-policy").unwrap_or_default().split(';') {
                    let d = d.trim();
                    if d.to_ascii_lowercase().starts_with("frame-ancestors") {
                        (value, via) = (d.to_string(), Some("Content-Security-Policy"));
                    }
                }
            }
            (name, HeaderState { present: !value.is_empty(), value, via })
        })
        .collect()
}

const WP_CRITICAL: [&str; 2] =
    ["There has been a critical error on this website", "There has been a critical error on your website"];
const WP_MAINTENANCE: &str = "Briefly unavailable for scheduled maintenance";

/// The WordPress markers in a page, as the Go Check read them.
fn wordpress(body: &str) -> WordPress {
    let mut wp = WordPress::default();
    if let Some(version) = generator_version(body) {
        wp.evidence.push("generator meta");
        wp.version = version;
    }
    if body.contains("/wp-content/") || body.contains("/wp-includes/") {
        wp.evidence.push("wp-content/wp-includes paths");
    }
    if body.contains("/wp-json") || body.contains("api.w.org") {
        wp.evidence.push("wp-json link");
    }
    if WP_CRITICAL.iter().any(|s| body.contains(s)) {
        wp.critical_error = true;
        wp.evidence.push("critical-error page");
    }
    if body.contains(WP_MAINTENANCE) {
        wp.maintenance = true;
        wp.evidence.push("maintenance page");
    }
    wp.detected = !wp.evidence.is_empty();
    wp
}

/// The version in `<meta name="generator" content="WordPress 6.5.2">` ("" when it has none).
fn generator_version(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase(); // same length: only ASCII letters change
    let mut from = 0;
    while let Some(i) = lower[from..].find("<meta") {
        let start = from + i;
        let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
        let tag = &lower[start..end];
        from = end.max(start + 5);
        let Some(n) = ["name=\"generator\"", "name='generator'"].iter().find_map(|k| tag.find(k).map(|p| p + k.len()))
        else {
            continue;
        };
        let rest = &tag[n..];
        let Some(c) =
            ["content=\"wordpress", "content='wordpress"].iter().find_map(|k| rest.find(k).map(|p| p + k.len()))
        else {
            continue;
        };
        let version: String =
            rest[c..].trim_start().chars().take_while(|ch| ch.is_ascii_digit() || *ch == '.').collect();
        return Some(printable(&version));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_version_reads_both_quote_styles_and_survives_junk() {
        assert_eq!(
            generator_version(r#"<meta name="generator" content="WordPress 6.5.2" />"#).as_deref(),
            Some("6.5.2")
        );
        assert_eq!(generator_version("<META NAME='generator' CONTENT='WordPress'>").as_deref(), Some(""));
        assert_eq!(generator_version(r#"<meta name="generator" content="Hugo 0.1">"#), None);
        assert_eq!(generator_version("<meta <meta <meta"), None);
        assert_eq!(generator_version("<meta name=\"generator\" content=\"wordpress é 1"), Some(String::new()));
        assert_eq!(generator_version("é<meta name=\"generator\" content=\"WordPress 6.0\">").as_deref(), Some("6.0"));
    }

    fn page(url: &str, status: u16) -> Fetch {
        Fetch { chain: vec![Hop { url: url.into(), status, location: None }], ..Fetch::default() }
    }

    fn redirect_to_https() -> Fetch {
        let mut f = page("http://x.test/", 301);
        f.chain[0].location = Some("https://x.test/".into());
        f.chain.push(Hop { url: "https://x.test/".into(), status: 200, location: None });
        f
    }

    fn probe(http: impl Fn() -> Fetch) -> WebResult {
        let fetch = |u: &str| if u.starts_with("https") { page(u, 200) } else { http() };
        inspect_with("https://x.test/", "http://x.test/", &fetch)
    }

    #[test]
    fn http_probe_says_whether_plain_http_reaches_https() {
        assert_eq!(probe(redirect_to_https).http_to_https, Some(true));
        assert_eq!(probe(|| page("http://x.test/", 200)).http_to_https, Some(false));
        // A probe that fails says nothing either way.
        assert_eq!(probe(|| Fetch { error: Some("refused".into()), ..Fetch::default() }).http_to_https, None);
    }

    #[test]
    fn https_that_cannot_connect_falls_back_and_is_not_probed() {
        let asked = std::cell::RefCell::new(vec![]);
        let fetch = |u: &str| {
            asked.borrow_mut().push(u.to_string());
            if u.starts_with("https") {
                Fetch { error: Some("refused".into()), ..Fetch::default() }
            } else {
                page(u, 200)
            }
        };
        let r = inspect_with("https://x.test/", "http://x.test/", &fetch);
        assert_eq!(
            (r.https_error.as_deref(), r.url.as_str(), r.status, r.http_to_https),
            (Some("refused"), "http://x.test/", Some(200), None)
        );
        assert_eq!(*asked.borrow(), ["https://x.test/", "http://x.test/"]);
        // A failure after a hop (the redirect target is down) is not a connection failure: no fallback.
        let mut broken = page("https://x.test/", 302);
        broken.error = Some("refused".into());
        let asked = std::cell::Cell::new(0);
        let r = inspect_with("https://x.test/", "http://x.test/", &|_| {
            asked.set(asked.get() + 1);
            Fetch { chain: broken.chain.clone(), error: broken.error.clone(), ..Fetch::default() }
        });
        assert_eq!((asked.get(), r.https_error, r.chain.len()), (1, None, 1));
    }

    fn hop(url: &str, status: u16, location: Option<&str>) -> Hop {
        Hop { url: url.into(), status, location: location.map(Into::into) }
    }

    #[test]
    fn a_redirect_from_https_to_http_is_found_and_the_reverse_is_not() {
        let down = [hop("https://x.test/", 301, Some("http://x.test/a")), hop("http://x.test/a", 200, None)];
        assert_eq!(
            redirect_downgrade(&down),
            Some(Downgrade { from: "https://x.test/".into(), to: "http://x.test/a".into() })
        );
        let up = [hop("http://x.test/", 301, Some("https://x.test/")), hop("https://x.test/", 200, None)];
        assert_eq!(redirect_downgrade(&up), None);
        assert_eq!(redirect_downgrade(&[hop("https://x.test/", 200, None)]), None);
        assert_eq!(redirect_downgrade(&[]), None);
        // The target failed, so only the Location of the last hop shows the downgrade.
        assert!(redirect_downgrade(&[hop("https://x.test/", 302, Some("http://x.test/"))]).is_some());
        // Downgrade in the middle of a longer chain.
        let mid = [
            hop("http://x.test/", 301, Some("https://x.test/")),
            hop("https://x.test/", 301, Some("http://y.test/")),
            hop("http://y.test/", 200, None),
        ];
        assert_eq!(redirect_downgrade(&mid).unwrap().to, "http://y.test/");
    }

    #[test]
    fn the_downgrade_finding_names_both_urls() {
        use crate::finding::Severity;
        let r = WebResult {
            status: Some(200),
            final_url: Some("http://y.test/".into()),
            downgrade: Some(Downgrade { from: "https://x.test/".into(), to: "http://y.test/".into() }),
            ..WebResult::default()
        };
        let fs = web_findings("x.test", &r);
        let f = fs.iter().find(|f| f.code == "web_redirect_downgrade").unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.title.contains("https://x.test/") && f.title.contains("http://y.test/"), "{}", f.title);
        assert!(f.message.contains("https://x.test/") && f.message.contains("http://y.test/"));
        assert!(f.recommendation.as_deref().is_some_and(|r| r.contains("https")));
        assert!(
            !web_findings("x.test", &WebResult { status: Some(200), ..WebResult::default() })
                .iter()
                .any(|f| f.code == "web_redirect_downgrade")
        );
    }

    #[test]
    fn inspect_records_the_downgrade_it_saw() {
        let mut f = page("https://x.test/", 301);
        f.chain[0].location = Some("http://x.test/".into());
        f.chain.push(Hop { url: "http://x.test/".into(), status: 200, location: None });
        let r = inspect_with("https://x.test/", "http://x.test/", &|u| {
            if u.starts_with("https") { Fetch { chain: f.chain.clone(), ..Fetch::default() } } else { page(u, 200) }
        });
        assert_eq!(r.downgrade.unwrap().to, "http://x.test/");
        assert_eq!(r.chain.len(), 2);
    }

    #[test]
    fn target_parsing_keeps_the_path_and_refuses_a_port() {
        assert_eq!(parse_web_target("Example.COM").unwrap(), ("example.com".into(), "/".into()));
        assert_eq!(
            parse_web_target("http://example.com/a/b?x=1#frag").unwrap(),
            ("example.com".into(), "/a/b?x=1".into())
        );
        assert!(matches!(parse_web_target("example.com:8443"), Err(WebError::PortGiven)));
        assert!(parse_web_target("192.0.2.1").is_err());
        assert!(parse_web_target("localhost").is_err());
        assert!(parse_web_target("").is_err());
    }
}
