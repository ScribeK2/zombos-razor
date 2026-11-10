#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! Web inspection against fake servers: the Go `website_inspection` scenarios, the
//! hostile-input cases, origin versus CDN, and provider detection.
//! HTTPS is never served here (no certificate to trust offline): the HTTPS port is
//! closed, so each run takes the documented fallback to plain HTTP.

mod common;
#[path = "common/web.rs"]
mod site;

use std::{net::IpAddr, time::Duration};

use common::{FakeDns, zone};
use site::{FakeSite, Req, Resp, closed_port, fixture};
use zombo_core::{
    Finding, Severity,
    web::{HeaderState, Ports, WebOptions, WebResult, check_web, detect_hosting, web_findings},
};

const LOCAL: &str = "127.0.0.1";

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

fn sev(fs: &[Finding], code: &str) -> Option<Severity> {
    fs.iter().find(|f| f.code == code).map(|f| f.severity)
}

fn get<'a>(fs: &'a [Finding], code: &str) -> &'a Finding {
    fs.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("no {code} in {:?}", codes(fs)))
}

/// A resolver that knows nothing, so provider detection stays quiet.
async fn empty_dns() -> FakeDns {
    FakeDns::start("").await
}

async fn options(http: &FakeSite, dns: &FakeDns) -> WebOptions {
    WebOptions {
        timeout: Duration::from_secs(8),
        resolver: Some(dns.addr),
        ports: Ports { http: http.addr.port(), https: closed_port().await },
        pin: Some(LOCAL.parse().unwrap()),
        ..WebOptions::default()
    }
}

/// Inspect example.com served by `handler` on plain HTTP.
async fn inspect(handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> (WebResult, Vec<Finding>) {
    let (site, dns) = (FakeSite::start(handler).await, empty_dns().await);
    let r = check_web("example.com", "/", &options(&site, &dns).await).await;
    let fs = web_findings("example.com", &r);
    (r, fs)
}

#[tokio::test]
async fn healthy_site_with_every_header() {
    let (r, fs) = inspect(|_| Resp::ok("<html>hello</html>").secure().header("Server", "nginx")).await;
    assert_eq!((r.status, r.server.as_deref()), (Some(200), Some("nginx")));
    assert!(r.content_type.as_deref().is_some_and(|c| c.starts_with("text/html")));
    assert_eq!(r.headers.len(), 6);
    assert!(r.headers.values().all(|h| h.present && !h.value.is_empty()), "{:?}", r.headers);
    assert!(!r.wordpress.detected);
    // The only findings besides "up" are about this test's missing HTTPS; HSTS is not asked over plain HTTP.
    assert_eq!(codes(&fs), ["website_inspection_healthy", "website_inspection_https_failed"]);
    assert!(get(&fs, "website_inspection_healthy").message.contains("200"));
}

#[tokio::test]
async fn records_the_redirect_chain_with_relative_locations() {
    let (r, fs) = inspect(|q| match q.path.as_str() {
        "/" => Resp::redirect(302, "/en/"),
        "/en/" => Resp::redirect(301, "home"),
        _ => Resp::ok("home").secure(),
    })
    .await;
    let seen: Vec<(String, u16, Option<&str>)> = r
        .chain
        .iter()
        .map(|h| (h.url.rsplit_once('/').map(|x| x.1).unwrap_or("").to_string(), h.status, h.location.as_deref()))
        .collect();
    assert_eq!(seen, [("".into(), 302, Some("/en/")), ("".into(), 301, Some("home")), ("home".into(), 200, None)]);
    assert!(r.final_url.as_deref().unwrap().ends_with("/en/home"), "{:?}", r.final_url);
    assert_eq!(sev(&fs, "website_inspection_healthy"), Some(Severity::Ok));
}

#[tokio::test]
async fn scheme_relative_location_keeps_the_scheme() {
    // Port 1 is closed, so the follow-up fails; the hop shows the Location as sent,
    // and the failed request went to http (the scheme of the page that sent it).
    let (r, fs) = inspect(|_| Resp::redirect(302, "//example.com:1/never")).await;
    assert_eq!(r.chain[0].location.as_deref(), Some("//example.com:1/never"));
    assert!(r.error.is_some());
    assert!(get(&fs, "website_inspection_unreachable").message.contains("which failed"));
}

#[tokio::test]
async fn detects_a_redirect_loop() {
    let (r, fs) = inspect(|q| if q.path == "/" { Resp::redirect(302, "/a") } else { Resp::redirect(302, "/") }).await;
    assert!(r.redirect_loop);
    assert_eq!(r.chain.len(), 2);
    assert_eq!(sev(&fs, "website_inspection_redirect_loop"), Some(Severity::Critical));
    assert!(!codes(&fs).contains(&"website_inspection_healthy"));
}

#[tokio::test]
async fn stops_after_ten_redirects() {
    let (r, fs) = inspect(|q| {
        let n: u32 = q.path.trim_start_matches('/').parse().unwrap_or(0);
        Resp::redirect(302, &format!("/{}", n + 1))
    })
    .await;
    assert!(r.too_many_redirects && !r.redirect_loop, "{r:?}");
    assert_eq!(r.chain.len(), 10);
    assert_eq!(sev(&fs, "website_inspection_too_many_redirects"), Some(Severity::Warning));
    assert!(!codes(&fs).contains(&"website_inspection_missing_headers"));
}

#[tokio::test]
async fn never_follows_a_redirect_to_another_scheme() {
    for target in ["ftp://example.com/x", "file:///etc/passwd", "javascript:alert(1)"] {
        let (r, fs) = inspect(move |_| Resp::redirect(302, target)).await;
        let e = r.error.as_deref().unwrap_or_default();
        assert!(e.contains("unsupported scheme"), "{target}: {e}");
        assert_eq!(r.chain.len(), 1, "{target}");
        let f = get(&fs, "website_inspection_unreachable");
        assert!(f.message.contains("redirects to") && f.message.contains("which failed"), "{}", f.message);
    }
}

#[tokio::test]
async fn unreachable_when_nothing_listens() {
    let (dns, port) = (empty_dns().await, closed_port().await);
    let opts = WebOptions {
        ports: Ports { http: port, https: closed_port().await },
        resolver: Some(dns.addr),
        pin: Some(LOCAL.parse().unwrap()),
        ..WebOptions::default()
    };
    let r = check_web("example.com", "/", &opts).await;
    let fs = web_findings("example.com", &r);
    assert!(r.error.is_some() && r.status.is_none());
    assert_eq!(codes(&fs), ["website_inspection_unreachable"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert!(fs[0].message.starts_with("Neither HTTPS nor HTTP answered"), "{}", fs[0].message);
}

#[tokio::test]
async fn redirect_to_a_dead_https_is_unreachable() {
    let closed = closed_port().await;
    let (r, fs) = inspect(move |_| Resp::redirect(301, &format!("https://example.com:{closed}/"))).await;
    assert!(r.error.is_some() && r.https_error.is_some());
    assert_eq!((r.chain.len(), r.chain[0].status), (1, 301));
    assert_eq!(sev(&fs, "website_inspection_unreachable"), Some(Severity::Critical));
    assert!(fs[0].message.contains(&format!("redirects to https://example.com:{closed}/")), "{}", fs[0].message);
}

#[tokio::test]
async fn falls_back_to_http_when_https_fails() {
    let (r, fs) = inspect(|_| Resp::ok("plain").secure()).await;
    assert!(r.https_error.is_some());
    assert!(r.final_url.as_deref().unwrap().starts_with("http://example.com:"));
    assert_eq!(sev(&fs, "website_inspection_https_failed"), Some(Severity::Warning));
    assert!(!codes(&fs).contains(&"website_inspection_missing_hsts"), "HSTS means nothing over plain HTTP");
}

#[tokio::test]
async fn server_and_client_errors() {
    let (_, fs) = inspect(|_| Resp::new(502, "").secure()).await;
    assert_eq!(sev(&fs, "website_inspection_server_error"), Some(Severity::Critical));
    assert!(!codes(&fs).contains(&"website_inspection_healthy"));
    let (_, fs) = inspect(|_| Resp::new(403, "").secure()).await;
    assert_eq!(sev(&fs, "website_inspection_client_error"), Some(Severity::Warning));
    assert_eq!(get(&fs, "website_inspection_client_error").title, "Homepage returns HTTP 403");
}

#[tokio::test]
async fn missing_headers_with_frame_ancestors_standing_in_for_x_frame_options() {
    let (r, fs) = inspect(|_| {
        Resp::ok("ok")
            .header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            .header("X-Content-Type-Options", "nosniff")
    })
    .await;
    let xfo = &r.headers["X-Frame-Options"];
    assert!(xfo.present && xfo.via == Some("Content-Security-Policy"), "{xfo:?}");
    assert!(!r.headers["Strict-Transport-Security"].present);
    let m = get(&fs, "website_inspection_missing_headers");
    assert_eq!((m.severity, m.title.as_ref()), (Severity::Info, "Missing 2 security headers"));
    assert!(
        m.message.contains("Referrer-Policy")
            && m.message.contains("Permissions-Policy")
            && !m.message.contains("X-Frame-Options"),
        "{}",
        m.message
    );
}

#[tokio::test]
async fn detects_wordpress_and_its_failure_pages() {
    let page = fixture("wordpress_site.html");
    let (r, fs) = inspect(move |_| Resp::ok(&page).secure()).await;
    let wp = &r.wordpress;
    assert!(wp.detected && wp.version == "6.5.2" && !wp.critical_error && !wp.maintenance, "{wp:?}");
    assert_eq!(wp.evidence, ["generator meta", "wp-content/wp-includes paths", "wp-json link"]);
    assert_eq!(sev(&fs, "website_inspection_healthy"), Some(Severity::Ok));

    let page = fixture("wordpress_critical.html");
    let (r, fs) = inspect(move |_| Resp::new(500, page.clone()).secure()).await;
    assert!(r.wordpress.critical_error && r.wordpress.detected);
    // The specific finding replaces the generic 5xx one.
    assert_eq!(
        codes(&fs)
            .iter()
            .filter(|c| c.starts_with("website_inspection_wp") || **c == "website_inspection_server_error")
            .collect::<Vec<_>>(),
        [&"website_inspection_wp_critical_error"]
    );

    let page = fixture("wordpress_maintenance.html");
    let (r, fs) = inspect(move |_| Resp::new(503, page.clone()).secure()).await;
    assert!(r.wordpress.maintenance);
    assert_eq!(sev(&fs, "website_inspection_wp_maintenance"), Some(Severity::Warning));
}

#[tokio::test]
async fn slow_response_is_flagged() {
    let (r, fs) = inspect(|_| Resp { delay: Duration::from_millis(3100), ..Resp::ok("slow").secure() }).await;
    assert!(r.time_ms >= 3000, "{}", r.time_ms);
    assert_eq!(sev(&fs, "website_inspection_slow"), Some(Severity::Info));
    assert_eq!(sev(&fs, "website_inspection_healthy"), Some(Severity::Ok));
}

#[tokio::test]
async fn a_stalled_body_cannot_hold_the_check_past_its_deadline() {
    let (site, dns) = (
        FakeSite::start(|_| Resp { stall_after_body: true, ..Resp::ok("<html>partial").secure() }).await,
        empty_dns().await,
    );
    let opts = WebOptions { timeout: Duration::from_secs(2), ..options(&site, &dns).await };
    let started = std::time::Instant::now();
    let r = check_web("example.com", "/", &opts).await;
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    // The headers arrived, so the answer stands; the slow body does not count as a slow response.
    assert_eq!(r.status, Some(200));
    assert!(r.time_ms < 1000, "{}", r.time_ms);
}

#[tokio::test]
async fn a_server_that_never_answers_times_out_as_unreachable() {
    let (site, dns) =
        (FakeSite::start(|_| Resp { delay: Duration::from_secs(20), ..Resp::ok("late") }).await, empty_dns().await);
    let opts = WebOptions { timeout: Duration::from_millis(800), ..options(&site, &dns).await };
    let started = std::time::Instant::now();
    let r = check_web("example.com", "/", &opts).await;
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert_eq!(r.error.as_deref(), Some("timed out"));
}

#[tokio::test]
async fn only_the_start_of_a_huge_body_is_read() {
    let filler = "x".repeat(5 << 20);
    let early = format!("<a href=\"/wp-json\">{filler}");
    let (r, _) = inspect(move |_| Resp::ok(&early)).await;
    assert!(r.wordpress.evidence.contains(&"wp-json link"), "{:?}", r.wordpress);
    // A marker past the 64 KiB cap is never seen: the body is not read that far.
    let late = format!("{}<a href=\"/wp-json\">", "x".repeat(100 * 1024));
    let (r, _) = inspect(move |_| Resp::ok(&late)).await;
    assert!(!r.wordpress.detected, "{:?}", r.wordpress);
}

#[tokio::test]
async fn oversized_and_numerous_headers_are_capped() {
    let (r, _) = inspect(|_| (0..100).fold(Resp::ok("ok"), |r, i| r.header(&format!("X-Pad-{i}"), "v"))).await;
    assert_eq!(r.status, Some(200));
    assert!(r.response_headers.len() <= 128, "{}", r.response_headers.len());
    // Past the HTTP parser's header count limit the answer is an error, not a crash.
    let (r, _) = inspect(|_| (0..300).fold(Resp::ok("ok"), |r, i| r.header(&format!("X-Pad-{i}"), "v"))).await;
    assert!(r.error.is_some() && r.status.is_none());
    // A header block over the cap is an error, not an allocation.
    let (r, fs) = inspect(|_| Resp::ok("ok").header("X-Huge", &"a".repeat(200 * 1024))).await;
    assert!(r.error.is_some(), "{:?}", r.status);
    assert_eq!(sev(&fs, "website_inspection_unreachable"), Some(Severity::Critical));
}

#[tokio::test]
async fn control_characters_in_headers_never_reach_the_result() {
    let (r, _) =
        inspect(|_| Resp::ok("ok").header("Server", "ngi\tnx").header("Content-Security-Policy", "default-src 'self'"))
            .await;
    assert_eq!(r.server.as_deref(), Some("ngi\u{fffd}nx"));
}

#[tokio::test]
async fn sends_a_plain_user_agent_and_no_cookies() {
    let (site, dns) = (
        FakeSite::start(|q| {
            if q.path == "/" {
                Resp::redirect(302, "/next").header("Set-Cookie", "sid=abc; Path=/")
            } else {
                Resp::ok("ok")
            }
        })
        .await,
        empty_dns().await,
    );
    let r = check_web("example.com", "/", &options(&site, &dns).await).await;
    assert_eq!(r.chain.len(), 2);
    let seen = site.requests();
    assert!(seen.len() >= 2);
    for q in &seen {
        assert!(
            q.header("user-agent")
                .is_some_and(|u| u == format!("zombo/{}", zombo_core::VERSION) && !u.contains("Mozilla")),
            "{:?}",
            q.header("user-agent")
        );
        assert!(q.header("cookie").is_none() && q.header("authorization").is_none(), "{:?}", q.headers);
        assert_eq!(q.header("host"), Some(format!("example.com:{}", site.addr.port()).as_str()));
    }
}

#[tokio::test]
async fn the_path_of_a_url_is_inspected() {
    let (site, dns) = (FakeSite::start(|q| Resp::ok(&q.path)).await, empty_dns().await);
    let r = check_web("example.com", "/login?next=1", &options(&site, &dns).await).await;
    assert!(r.final_url.as_deref().unwrap().ends_with("/login?next=1"), "{:?}", r.final_url);
    assert_eq!(site.requests()[0].path, "/login?next=1");
}

// Origin versus CDN

/// A CDN-facing site on 127.0.0.1 and an origin on 127.0.0.2, both on one port.
async fn pair(
    cdn: impl Fn(&Req) -> Resp + Send + Sync + 'static,
    origin: impl Fn(&Req) -> Resp + Send + Sync + 'static,
) -> (FakeSite, FakeSite) {
    let public = FakeSite::start(cdn).await;
    let origin = FakeSite::start_on("127.0.0.2", public.addr.port(), origin).await;
    (public, origin)
}

async fn compare(
    cdn: impl Fn(&Req) -> Resp + Send + Sync + 'static,
    origin: impl Fn(&Req) -> Resp + Send + Sync + 'static,
) -> (WebResult, Vec<Finding>, FakeSite) {
    let (public, origin_site) = pair(cdn, origin).await;
    let dns = empty_dns().await;
    let opts = WebOptions { origin: Some("127.0.0.2".parse().unwrap()), ..options(&public, &dns).await };
    let r = check_web("example.com", "/", &opts).await;
    let fs = web_findings("example.com", &r);
    (r, fs, origin_site)
}

#[tokio::test]
async fn origin_asked_with_the_real_host_header() {
    let (_, _, origin) = compare(|_| Resp::ok("cdn").secure(), |_| Resp::ok("origin").secure()).await;
    let q = &origin.requests()[0];
    assert_eq!(q.header("host"), Some(format!("example.com:{}", origin.addr.port()).as_str()));
}

#[tokio::test]
async fn a_healthy_origin_behind_a_failing_cdn_blames_the_cdn() {
    let (r, fs, _) = compare(
        |_| Resp::new(503, "").header("Server", "cloudflare").header("CF-RAY", "8a1b-LHR"),
        |_| Resp::ok("fine").header("Server", "nginx"),
    )
    .await;
    let f = get(&fs, "website_origin_status_differs");
    assert_eq!(f.severity, Severity::Warning);
    assert!(
        f.message.contains("HTTP 503") && f.message.contains("HTTP 200") && f.message.contains("origin is healthy"),
        "{}",
        f.message
    );
    assert_eq!(r.origin.as_ref().unwrap().answer.status, Some(200));
    let h = get(&fs, "website_origin_headers_differ");
    assert!(h.message.contains("Server: \"cloudflare\" at the CDN, \"nginx\" at the origin"), "{}", h.message);
    assert!(!codes(&fs).contains(&"website_origin_matches"));
    // The CDN is also named from its headers.
    assert!(get(&fs, "website_cdn_detected").title.contains("Cloudflare"));
}

#[tokio::test]
async fn a_cdn_masking_a_broken_origin_is_called_out() {
    let (_, fs, _) = compare(|_| Resp::ok("cached").secure(), |_| Resp::new(500, "")).await;
    let f = get(&fs, "website_origin_status_differs");
    assert!(f.message.contains("origin is broken") && f.message.contains("masking"), "{}", f.message);
}

#[tokio::test]
async fn redirects_that_differ_are_reported() {
    let (_, fs, _) = compare(
        |q| if q.path == "/" { Resp::redirect(301, "/home") } else { Resp::ok("ok").secure() },
        |q| if q.path == "/" { Resp::redirect(301, "/other") } else { Resp::ok("ok").secure() },
    )
    .await;
    let f = get(&fs, "website_origin_redirect_differs");
    assert!(f.message.contains("/home") && f.message.contains("/other"), "{}", f.message);
    assert!(!codes(&fs).contains(&"website_origin_status_differs"));
}

#[tokio::test]
async fn an_origin_that_answers_alike_is_ok_and_header_changes_are_info() {
    let (_, fs, _) =
        compare(|_| Resp::ok("same").secure(), |_| Resp::ok("same").header("X-Content-Type-Options", "nosniff")).await;
    assert_eq!(sev(&fs, "website_origin_matches"), Some(Severity::Ok));
    let h = get(&fs, "website_origin_headers_differ");
    assert_eq!(h.severity, Severity::Info);
    assert!(h.message.contains("Strict-Transport-Security: set at the CDN, missing at the origin"), "{}", h.message);
}

#[tokio::test]
async fn an_origin_that_does_not_answer_is_reported_without_blaming() {
    let (public, dns) = (FakeSite::start(|_| Resp::ok("cdn").secure()).await, empty_dns().await);
    // 127.0.0.3 has no listener on this port.
    let opts = WebOptions { origin: Some("127.0.0.3".parse().unwrap()), ..options(&public, &dns).await };
    let r = check_web("example.com", "/", &opts).await;
    let fs = web_findings("example.com", &r);
    let f = get(&fs, "website_origin_unreachable");
    assert!(f.message.contains("127.0.0.3") && f.message.contains("HTTP 200"), "{}", f.message);
}

// Providers

#[tokio::test]
async fn provider_comes_from_headers_cname_and_asn_together() {
    let dns = FakeDns::start(&common::zone("../web/cdn")).await;
    let headers = vec![("x-amz-cf-id".to_string(), "abc".to_string()), ("server".to_string(), "AmazonS3".to_string())];
    let h = detect_hosting("www.example.com", &headers, dns.addr, Duration::from_secs(2)).await;
    assert_eq!(h.cname_chain, ["d111.cloudfront.net"]);
    assert_eq!(h.addresses, ["192.0.2.10".parse::<IpAddr>().unwrap()]);
    assert_eq!(
        (h.asns[0].asn, h.asns[0].name.as_deref(), h.asns[0].country.as_deref(), h.asns[0].prefix.as_deref()),
        (16509, Some("AMAZON-02, US"), Some("US"), Some("192.0.2.0/24"))
    );
    let cf = h.detections.iter().find(|d| d.provider == "Amazon CloudFront").unwrap();
    assert_eq!(cf.evidence.len(), 2, "{:?}", cf.evidence);
    assert!(h.detections.iter().any(|d| d.provider == "Amazon Web Services"));
    assert!(h.dns_error.is_none());
}

#[tokio::test]
async fn provider_findings_name_each_provider_and_the_asn() {
    let dns = FakeDns::start(&zone("../web/cdn")).await;
    let site = FakeSite::start(|_| Resp::ok("ok").secure().header("X-Amz-Cf-Id", "abc")).await;
    let opts = WebOptions {
        resolver: Some(dns.addr),
        ports: Ports { http: site.addr.port(), https: closed_port().await },
        pin: Some(LOCAL.parse().unwrap()),
        ..WebOptions::default()
    };
    let r = check_web("www.example.com", "/", &opts).await;
    let fs = web_findings("www.example.com", &r);
    assert_eq!(get(&fs, "website_cdn_detected").title, "Served through Amazon CloudFront");
    assert!(
        get(&fs, "website_cdn_detected").message.contains("header x-amz-cf-id")
            && get(&fs, "website_cdn_detected").message.contains("CNAME d111.cloudfront.net")
    );
    assert_eq!(get(&fs, "website_host_detected").title, "Hosted on Amazon Web Services");
    let asn = get(&fs, "website_asn");
    assert!(asn.message == "www.example.com is announced by AS16509 AMAZON-02, US (192.0.2.10).", "{}", asn.message);
}

#[tokio::test]
async fn hostile_cymru_answers_yield_no_asn_and_no_control_characters() {
    let dns = FakeDns::start(&zone("../web/cymru_hostile")).await;
    let h = detect_hosting("plain.example.com", &[], dns.addr, Duration::from_secs(2)).await;
    assert_eq!(h.addresses.len(), 1);
    assert!(h.asns.is_empty(), "{:?}", h.asns);
    let h = detect_hosting("v6.example.com", &[], dns.addr, Duration::from_secs(2)).await;
    assert_eq!(h.asns.len(), 1, "{h:?}");
    let name = h.asns[0].name.as_deref().unwrap();
    assert!(!name.chars().any(char::is_control), "{name:?}");
}

#[tokio::test]
async fn dns_failure_keeps_the_header_evidence() {
    let dead = FakeDns::silent().await;
    let headers = vec![("cf-ray".to_string(), "8a-LHR".to_string())];
    let h = detect_hosting("example.com", &headers, dead.addr, Duration::from_millis(300)).await;
    assert!(h.dns_error.is_some());
    assert_eq!(h.detections[0].provider, "Cloudflare");
}

#[tokio::test]
async fn a_cname_loop_is_an_error_not_a_hang() {
    let dns =
        FakeDns::start("a.example.com. 60 IN CNAME b.example.com.\nb.example.com. 60 IN CNAME a.example.com.\n").await;
    let h = detect_hosting("a.example.com", &[], dns.addr, Duration::from_secs(2)).await;
    assert!(h.dns_error.as_deref().is_some_and(|e| e.contains("CNAME loop")), "{:?}", h.dns_error);
}

// Findings over a hand-built HTTPS result: the fake servers cannot speak TLS, so these
// two Go scenarios (HSTS only counts over HTTPS; HTTP that never reaches HTTPS) are pure.

fn https_result(missing: &[&str]) -> WebResult {
    let mut r = WebResult {
        url: "https://example.com/".into(),
        final_url: Some("https://example.com/".into()),
        status: Some(200),
        time_ms: 40,
        ..WebResult::default()
    };
    for name in zombo_core::web::SECURITY_HEADERS {
        let present = !missing.contains(&name);
        r.headers
            .insert(name, HeaderState { present, value: if present { "x".into() } else { String::new() }, via: None });
    }
    r
}

#[test]
fn https_site_without_hsts_is_warned_and_one_with_every_header_is_only_healthy() {
    let fs = web_findings("example.com", &https_result(&["Strict-Transport-Security"]));
    assert_eq!(codes(&fs), ["website_inspection_healthy", "website_inspection_missing_hsts"]);
    assert_eq!(sev(&fs, "website_inspection_missing_hsts"), Some(Severity::Warning));
    assert_eq!(codes(&web_findings("example.com", &https_result(&[]))), ["website_inspection_healthy"]);
}

#[test]
fn plain_http_that_never_reaches_https_is_flagged() {
    let mut r = https_result(&[]);
    r.http_to_https = Some(false);
    let fs = web_findings("example.com", &r);
    assert_eq!(sev(&fs, "website_inspection_https_not_enforced"), Some(Severity::Warning));
    assert_eq!(
        get(&fs, "website_inspection_https_not_enforced").message,
        "http://example.com/ does not redirect to HTTPS."
    );
    r.http_to_https = Some(true);
    assert!(!codes(&web_findings("example.com", &r)).contains(&"website_inspection_https_not_enforced"));
}
