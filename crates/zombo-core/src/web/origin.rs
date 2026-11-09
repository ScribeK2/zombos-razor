//! Origin versus CDN: the same URL asked of the public name and of the origin
//! address directly, with the same Host header. Only the comparison lives here;
//! the fetch is `fetch_chain` with a `Pin`.

use std::{collections::BTreeMap, net::IpAddr};

use serde::Serialize;

use super::{Fetch, HeaderState, Hop, SECURITY_HEADERS, WebResult, security_headers};
use crate::finding::{Finding, Severity};

/// What one side of the comparison answered.
#[derive(Debug, Clone, Serialize)]
pub struct Answer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub chain: Vec<Hop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub headers: BTreeMap<&'static str, HeaderState>,
    /// The server answered TLS but its certificate was refused, and why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_rejected: Option<String>,
}

impl Answer {
    pub(crate) fn from_fetch(f: &Fetch) -> Self {
        let last = f.chain.last();
        Answer {
            final_url: last.map(|h| h.url.clone()),
            status: last.filter(|_| f.error.is_none()).map(|h| h.status),
            chain: f.chain.clone(),
            error: f.error.clone(),
            time_ms: u64::try_from(f.elapsed.as_millis()).unwrap_or(u64::MAX),
            server: f.header("server").map(str::to_string),
            content_type: f.header("content-type").map(str::to_string),
            headers: if f.error.is_none() { security_headers(f) } else { BTreeMap::new() },
            cert_rejected: f.cert_rejected.clone(),
        }
    }

    pub(crate) fn of_public(r: &WebResult) -> Self {
        Answer {
            final_url: r.final_url.clone(),
            status: r.status,
            chain: r.chain.clone(),
            error: r.error.clone(),
            time_ms: r.time_ms,
            server: r.server.clone(),
            content_type: r.content_type.clone(),
            headers: r.headers.clone(),
            cert_rejected: None,
        }
    }

    fn describe(&self) -> String {
        match (self.status, &self.error) {
            (Some(s), _) => format!("HTTP {s}"),
            (None, Some(e)) => format!("no answer ({e})"),
            (None, None) => "no answer".into(),
        }
    }

    fn good(&self) -> bool {
        self.status.is_some_and(|s| s < 400)
    }

    fn locations(&self) -> Vec<&str> {
        self.chain.iter().filter_map(|h| h.location.as_deref()).collect()
    }
}

fn find(code: &'static str, severity: Severity, title: &'static str, message: String, rec: Option<&'static str>) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation: rec.map(Into::into) }
}

/// Compare the public (CDN-facing) answer with the origin's. Differences are the
/// point: they say which side holds the problem.
pub(crate) fn origin_findings(ip: IpAddr, public: &Answer, origin: &Answer) -> Vec<Finding> {
    let (p, o) = (public.describe(), origin.describe());
    if let Some(reason) = &origin.cert_rejected {
        return vec![find(
            "website_origin_cert_rejected",
            Severity::Warning,
            "Origin certificate rejected",
            format!("For the origin {ip}: the origin answered but its certificate was rejected: {reason}, try --insecure-origin. The public site answers {p}."),
            Some("The origin may present a certificate for another name, a self-signed one or an expired one. Fix it, or rerun with --insecure-origin to compare the answers anyway."),
        )];
    }
    if public.status.is_none() && origin.status.is_none() {
        return vec![find(
            "website_origin_unreachable",
            Severity::Warning,
            "Neither the site nor the origin answered",
            format!("The public name gave {p}, and the origin {ip} gave {o}."),
            Some("The origin itself is down or unreachable. Check the server and its firewall before looking at the CDN."),
        )];
    }
    if origin.status.is_none() {
        return vec![find(
            "website_origin_unreachable",
            Severity::Warning,
            "Origin did not answer directly",
            format!("The public site answers {p}, but the origin {ip} gave {o}."),
            Some("The origin may accept only the CDN's addresses, or its certificate may not match the site name. Ask it from the CDN's side, or check its firewall and certificate."),
        )];
    }
    let mut out = vec![];
    let mut differs = false;
    if public.status != origin.status {
        differs = true;
        let who = match (public.good(), origin.good()) {
            (false, true) => "The origin is healthy, so the fault is in front of it: the CDN, its configuration, or DNS.",
            (true, false) => "The CDN is serving a good page (possibly a cached copy) while the origin fails: the origin is broken and the CDN is masking it.",
            _ => "Both answers are failures or redirects that differ: compare the two redirect chains.",
        };
        out.push(find(
            "website_origin_status_differs",
            Severity::Warning,
            "Origin and CDN answer differently",
            format!("The public site answers {p}, but the origin {ip} answers {o}. {who}"),
            None,
        ));
    }
    if public.status.is_some() && public.locations() != origin.locations() {
        differs = true;
        out.push(find(
            "website_origin_redirect_differs",
            Severity::Warning,
            "Origin and CDN redirect differently",
            format!(
                "The public site ends at {} through {}, and the origin ends at {} through {}.",
                public.final_url.as_deref().unwrap_or("nowhere"),
                chain_text(&public.chain),
                origin.final_url.as_deref().unwrap_or("nowhere"),
                chain_text(&origin.chain)
            ),
            Some("A redirect rule at the CDN or at the origin is not the same as the other. Check where HTTPS and www redirects are set."),
        ));
    }
    let diffs = header_differences(public, origin);
    if !differs {
        out.push(find(
            "website_origin_matches",
            Severity::Ok,
            "Origin and CDN agree",
            format!("The public site and the origin {ip} both answer {p} and redirect the same way, so the CDN is not changing the outcome."),
            None,
        ));
    }
    if !diffs.is_empty() {
        out.push(find(
            "website_origin_headers_differ",
            Severity::Info,
            "Headers differ between CDN and origin",
            format!("{}.", diffs.join("; ")),
            None,
        ));
    }
    out
}

fn chain_text(chain: &[Hop]) -> String {
    if chain.is_empty() {
        return "no response".into();
    }
    chain.iter().map(|h| h.status.to_string()).collect::<Vec<_>>().join(" > ")
}

fn header_differences(public: &Answer, origin: &Answer) -> Vec<String> {
    let mut out = vec![];
    let same = |a: &Option<String>, b: &Option<String>| a.as_deref().map(str::to_ascii_lowercase) == b.as_deref().map(str::to_ascii_lowercase);
    for (name, a, b) in [("Server", &public.server, &origin.server), ("Content-Type", &public.content_type, &origin.content_type)] {
        if !same(a, b) {
            let show = |v: &Option<String>| v.as_deref().map_or("none".to_string(), |v| format!("{v:?}"));
            out.push(format!("{name}: {} at the CDN, {} at the origin", show(a), show(b)));
        }
    }
    for name in SECURITY_HEADERS {
        let present = |a: &Answer| a.headers.get(name).is_some_and(|h| h.present);
        match (present(public), present(origin)) {
            (true, false) => out.push(format!("{name}: set at the CDN, missing at the origin")),
            (false, true) => out.push(format!("{name}: missing at the CDN, set at the origin")),
            _ => {}
        }
    }
    out
}
