//! Findings from a `WebResult`. Pure functions: no network. The `website_inspection_*`
//! codes, titles and wording are the Go Check's; the `website_cdn_*`, `website_host_*`,
//! `website_asn` and `website_origin_*` ones are new.

use super::{Answer, MAX_REDIRECTS, OriginAnswer, ProviderKind, SECURITY_HEADERS, WebResult, origin::origin_findings};
use crate::finding::{Finding, Severity};

const SLOW_MS: u64 = 3000;

fn finding(code: &'static str, severity: Severity, title: impl Into<std::borrow::Cow<'static, str>>, message: String, rec: Option<&'static str>) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation: rec.map(Into::into) }
}

pub fn web_findings(target: &str, r: &WebResult) -> Vec<Finding> {
    let mut out = inspection_findings(target, r);
    out.extend(downgrade_finding(r));
    out.extend(provider_findings(r));
    if let Some(o) = &r.origin {
        out.extend(origin_findings(o.ip, &Answer::of_public(r), &o.answer));
        out.extend(unverified_origin_finding(o));
    }
    out
}

fn downgrade_finding(r: &WebResult) -> Option<Finding> {
    let d = r.downgrade.as_ref()?;
    Some(Finding {
        code: "web_redirect_downgrade",
        severity: Severity::Warning,
        title: format!("Redirect from HTTPS to HTTP: {} to {}", d.from, d.to).into(),
        message: format!("{} redirects to {}, which drops the connection from HTTPS to plain HTTP. Anything sent after that hop is readable and changeable on the network.", d.from, d.to),
        recommendation: Some("Redirect to https:// URLs only.".into()),
    })
}

fn unverified_origin_finding(o: &OriginAnswer) -> Option<Finding> {
    if !o.verification_skipped {
        return None;
    }
    let seen = match &o.certificate {
        Some(c) => format!(
            "It presented a certificate for {} issued by {}, valid until {}{}.",
            c.subject,
            c.issuer,
            c.not_after,
            c.would_fail.as_deref().map_or(String::new(), |w| format!("; a verifying client would refuse it ({w})"))
        ),
        None => "The certificate could not be read.".to_string(),
    };
    Some(Finding {
        code: "web_origin_cert_not_verified",
        severity: Severity::Info,
        title: "Origin certificate was not verified".into(),
        message: format!("The origin {} was asked with --insecure-origin, so its certificate was not verified. {seen}", o.ip),
        recommendation: None,
    })
}

fn inspection_findings(target: &str, r: &WebResult) -> Vec<Finding> {
    use Severity::{Critical, Info, Warning};
    if let Some(e) = &r.error {
        let mut msg = format!("{} could not be loaded: {e}.", r.url);
        if let Some(last) = r.chain.last() {
            // It answered, but a redirect led somewhere that failed.
            msg = format!("{} redirects to {}, which failed: {e}.", last.url, last.location.as_deref().unwrap_or_default());
        } else if let Some(h) = &r.https_error {
            msg = format!("Neither HTTPS nor HTTP answered. HTTPS: {h}; HTTP: {e}.");
        }
        return vec![Finding {
            code: "website_inspection_unreachable",
            severity: Critical,
            title: "Site unreachable".into(),
            message: msg,
            recommendation: Some(format!("Confirm the web server is running and listening on ports 443/80, and that DNS points {target} at it.").into()),
        }];
    }
    let status = r.status.unwrap_or_default();
    let final_url = r.final_url.as_deref().unwrap_or_default();
    let mut out = vec![];
    if r.redirect_loop {
        out.push(finding(
            "website_inspection_redirect_loop",
            Critical,
            "Redirect loop",
            format!("{} redirects back to a URL it already visited, so browsers give up with \"too many redirects\".", r.url),
            Some("Check the redirect rules in the server config, .htaccess and CDN (a common cause is HTTPS forced both at the CDN and the origin, or a WordPress siteurl mismatch)."),
        ));
    } else if r.too_many_redirects {
        out.push(finding(
            "website_inspection_too_many_redirects",
            Warning,
            "Too many redirects",
            format!("{} was still redirecting after {MAX_REDIRECTS} hops.", r.url),
            Some("Shorten the redirect chain; each hop adds latency and some clients stop following."),
        ));
    } else if r.wordpress.critical_error {
        out.push(finding(
            "website_inspection_wp_critical_error",
            Critical,
            "WordPress critical error",
            format!("{final_url} shows WordPress's \"There has been a critical error\" page (HTTP {status})."),
            Some("A plugin or theme is fatally erroring: check wp-content/debug.log or the PHP error log, and deactivate recently changed plugins."),
        ));
    } else if r.wordpress.maintenance {
        out.push(finding(
            "website_inspection_wp_maintenance",
            Warning,
            "WordPress maintenance mode",
            format!("{final_url} shows \"Briefly unavailable for scheduled maintenance\" (HTTP {status})."),
            Some("If no update is running, an update was interrupted: delete the .maintenance file in the WordPress root."),
        ));
    } else if status >= 500 {
        out.push(finding(
            "website_inspection_server_error",
            Critical,
            "Server error",
            format!("{final_url} answered HTTP {status}."),
            Some("Check the web server and application (PHP) error logs."),
        ));
    } else if status >= 400 {
        out.push(finding(
            "website_inspection_client_error",
            Warning,
            format!("Homepage returns HTTP {status}"),
            format!("{final_url} answered HTTP {status}."),
            Some("Check the document root, index file, and access or firewall rules (a 403 can be a WAF blocking automated requests)."),
        ));
    } else if (200..300).contains(&status) {
        out.push(finding("website_inspection_healthy", Severity::Ok, "Site is up", format!("{final_url} answered HTTP {status} in {} ms.", r.time_ms), None));
    }
    if let Some(e) = &r.https_error {
        out.push(finding(
            "website_inspection_https_failed",
            Warning,
            "HTTPS failed; HTTP only",
            format!("HTTPS did not work ({e}), so the site was inspected over plain HTTP."),
            Some("Install a valid certificate and serve the site on port 443."),
        ));
    }
    if r.http_to_https == Some(false) {
        out.push(finding(
            "website_inspection_https_not_enforced",
            Warning,
            "HTTPS not enforced",
            format!("http://{target}/ does not redirect to HTTPS."),
            Some("Redirect all plain HTTP requests to https:// with a 301."),
        ));
    }
    if !r.redirect_loop && !r.too_many_redirects {
        let https = final_url.starts_with("https://");
        let mut missing = vec![];
        for name in SECURITY_HEADERS {
            if r.headers.get(name).is_some_and(|h| h.present) {
                continue;
            }
            if name != "Strict-Transport-Security" {
                missing.push(name);
            } else if https {
                // HSTS is ignored over plain HTTP.
                out.push(finding(
                    "website_inspection_missing_hsts",
                    Warning,
                    "No HSTS",
                    "The site does not send Strict-Transport-Security, so browsers may still try plain HTTP first.".into(),
                    Some("Add Strict-Transport-Security: max-age=31536000 once HTTPS works everywhere on the site."),
                ));
            }
        }
        if !missing.is_empty() {
            let title = if missing.len() == 1 { "Missing 1 security header".to_string() } else { format!("Missing {} security headers", missing.len()) };
            out.push(finding(
                "website_inspection_missing_headers",
                Info,
                title,
                format!("Not set: {}.", missing.join(", ")),
                Some("Add them in the web server or CDN config (or a security plugin on WordPress)."),
            ));
        }
    }
    if r.time_ms > SLOW_MS {
        out.push(finding(
            "website_inspection_slow",
            Info,
            "Slow response",
            format!("The homepage took {} ms to respond, redirects included.", r.time_ms),
            Some("Check server load, caching and slow plugins or database queries."),
        ));
    }
    out
}

fn provider_findings(r: &WebResult) -> Vec<Finding> {
    let h = &r.hosting;
    let mut out = vec![];
    for d in &h.detections {
        let (code, title) = match d.kind {
            ProviderKind::Cdn => ("website_cdn_detected", format!("Served through {}", d.provider)),
            ProviderKind::Host => ("website_host_detected", format!("Hosted on {}", d.provider)),
        };
        out.push(finding(code, Severity::Info, title, format!("{} points to {} ({}).", h.host, d.provider, d.evidence.join("; ")), None));
    }
    if !h.asns.is_empty() {
        // One entry per AS, with the addresses in it; prefix and country stay in the JSON.
        let mut list: Vec<(u32, Option<&str>, Vec<String>)> = vec![];
        for a in &h.asns {
            match list.iter_mut().find(|e| e.0 == a.asn) {
                Some(e) => e.2.push(a.ip.to_string()),
                None => list.push((a.asn, a.name.as_deref(), vec![a.ip.to_string()])),
            }
        }
        let text: Vec<String> = list.iter().map(|(asn, name, ips)| format!("AS{asn}{} ({})", name.map_or(String::new(), |n| format!(" {n}")), ips.join(", "))).collect();
        out.push(finding("website_asn", Severity::Info, "Network that serves the site", format!("{} is announced by {}.", h.host, text.join("; ")), None));
    }
    if let Some(e) = &h.dns_error {
        out.push(finding(
            "website_provider_dns_failed",
            Severity::Info,
            "Could not look up the CDN or host",
            format!("The DNS questions about {} failed ({e}), so only the response headers were used to look for a CDN or host.", h.host),
            None,
        ));
    }
    out
}
