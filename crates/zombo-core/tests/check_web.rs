#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The Web Check as the UI runs it. HTTPS is never served here (no certificate to trust offline), so
//! each run takes the fallback to plain HTTP: `dial` points the name at a fake site, `tls_port` at a
//! closed port, and `machine_resolvers` at a fake resolver for the hosting questions.
//! `tests/web_tls.rs` covers a served HTTPS site at the `check_web` level.

mod common;
#[path = "common/web.rs"]
mod site;

use std::time::{Duration, Instant};

use common::{FakeDns, zone};
use site::{FakeSite, Resp, closed_port};
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request},
    target::Kind,
    web::CHECK,
};

const T: Duration = Duration::from_secs(8);

fn rows(f: &[Fact]) -> Vec<String> {
    f.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

struct Rig {
    site: FakeSite,
    dns: FakeDns,
    https: u16,
}

impl Rig {
    async fn new(zone_text: &str, handler: impl Fn(&site::Req) -> Resp + Send + Sync + 'static) -> Rig {
        Rig { site: FakeSite::start(handler).await, dns: FakeDns::start(zone_text).await, https: closed_port().await }
    }

    async fn run(&self, name: &str, query: Duration) -> Result<Outcome, String> {
        let resolvers = [self.dns.addr];
        CHECK
            .run(&Request {
                dial: Some(self.site.addr),
                tls_port: self.https,
                machine_resolvers: Some(&resolvers),
                ..Request::system(name, query, &[])
            })
            .await
    }

    fn url(&self, path: &str) -> String {
        format!("http://www.example.com:{}{path}", self.site.addr.port())
    }
}

#[tokio::test]
async fn a_healthy_site_gives_url_status_server_and_hop_rows_and_the_findings() {
    let rig = Rig::new(&zone("../web/cdn"), |_| {
        Resp::ok("<html>hello</html>").secure().header("Server", "nginx").header("X-Amz-Cf-Id", "abc")
    })
    .await;
    let o = rig.run("www.example.com", T).await.unwrap();
    let url = rig.url("/");
    let keys: Vec<_> = o.facts.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys, ["URL", "Final URL", "Status", "Server", "HTTPS error"]);
    assert_eq!(
        rows(&o.facts)[..4],
        [format!("URL: {url}"), format!("Final URL: {url}"), "Status: 200".into(), "Server: nginx".into()]
    );
    assert_eq!(o.details_title, "Redirect chain");
    assert_eq!(rows(&o.details), [format!("Hop 1: 200 {url}")]);
    assert_eq!(
        found(&o),
        [
            ("website_inspection_healthy", Severity::Ok),
            ("website_inspection_https_failed", Severity::Warning),
            ("website_cdn_detected", Severity::Info),
            ("website_host_detected", Severity::Info),
            ("website_asn", Severity::Info),
        ]
    );
    let cdn = o.findings.iter().find(|f| f.code == "website_cdn_detected").unwrap();
    assert_eq!(cdn.title, "Served through Amazon CloudFront", "the request's resolver was not asked");
}

#[tokio::test]
async fn a_redirect_chain_is_one_detail_row_per_hop() {
    let rig = Rig::new("", |q| match q.path.as_str() {
        "/" => Resp::redirect(302, "/en/"),
        "/en/" => Resp::redirect(301, "home"),
        _ => Resp::ok("home").secure(),
    })
    .await;
    let o = rig.run("www.example.com", T).await.unwrap();
    assert_eq!(
        rows(&o.details),
        [
            format!("Hop 1: 302 {} to /en/", rig.url("/")),
            format!("Hop 2: 301 {} to home", rig.url("/en/")),
            format!("Hop 3: 200 {}", rig.url("/en/home")),
        ]
    );
    assert_eq!(rows(&o.facts)[1], format!("Final URL: {}", rig.url("/en/home")));
    assert!(found(&o).contains(&("website_inspection_healthy", Severity::Ok)), "{:?}", found(&o));
}

#[tokio::test]
async fn the_path_and_query_of_the_target_are_asked_and_the_scheme_and_fragment_are_not() {
    let rig = Rig::new("", |_| Resp::ok("ok")).await;
    rig.run("https://www.example.com/a/b?x=1#frag", T).await.unwrap();
    assert_eq!(rig.site.requests()[0].path, "/a/b?x=1");
}

#[tokio::test]
async fn an_invalid_target_gives_the_parse_text_and_asks_nothing() {
    let rig = Rig::new("", |_| Resp::ok("ok")).await;
    for bad in ["192.0.2.1", "localhost", ""] {
        let err = rig.run(bad, T).await.unwrap_err();
        assert_eq!(err, format!("{bad:?} is not a valid domain, host name or URL"));
    }
    let err = rig.run("example.com:8443", T).await.unwrap_err();
    assert_eq!(err, "give a URL without a port: the standard ports 443 and 80 are inspected");
    assert!(rig.site.requests().is_empty());
}

#[tokio::test]
async fn the_requests_proxy_is_not_used() {
    let proxy = FakeSite::start(|_| Resp::ok("proxied")).await;
    let rig = Rig::new("", |_| Resp::ok("direct").header("Server", "origin")).await;
    let resolvers = [rig.dns.addr];
    let proxy_url = format!("http://{}", proxy.addr);
    let request = Request {
        proxy: Some(&proxy_url),
        dial: Some(rig.site.addr),
        tls_port: rig.https,
        machine_resolvers: Some(&resolvers),
        ..Request::system("www.example.com", T, &[])
    };
    let o = CHECK.run(&request).await.unwrap();
    assert!(rows(&o.facts).contains(&"Server: origin".to_string()), "{:?}", rows(&o.facts));
    assert!(proxy.requests().is_empty(), "the proxy was asked: {:?}", proxy.requests());
    assert!(!rig.site.requests().is_empty());
}

#[tokio::test]
async fn the_requests_query_bounds_the_whole_check() {
    let rig = Rig::new("", |_| Resp { delay: Duration::from_secs(20), ..Resp::ok("late") }).await;
    let started = Instant::now();
    let o = rig.run("www.example.com", Duration::from_millis(300)).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(4), "the request's query was not used: {:?}", started.elapsed());
    assert!(found(&o).contains(&("website_inspection_unreachable", Severity::Critical)), "{:?}", found(&o));
    assert_eq!(rows(&o.facts)[0], format!("URL: {}", rig.url("/")));
    assert!(o.facts.iter().all(|f| f.key != "Status"));
}

#[test]
fn the_descriptor_names_the_row_the_kinds_it_runs_on_by_itself_and_what_it_owns() {
    assert_eq!(CHECK.label, "Web");
    assert_eq!(CHECK.automatic_for, [Kind::Domain, Kind::Hostname, Kind::Email]);
    assert!(!CHECK.is_on_demand() && CHECK.on_demand.is_none());
    assert!(!CHECK.takes_chosen_port, "the picker's port must not reach the Web Check");
    assert_eq!(CHECK.budget, (Duration::from_secs(12), Duration::from_secs(10)));
    assert_eq!(CHECK.owns, ["website_", "web_"]);
    assert_eq!(CHECK.blind_spots.len(), 4);
    assert!(CHECK.blind_spots[1].starts_with("The CDN's origin server"));
}

/// Dials a real site on ports 80 and 443. Run on a network that does not intercept DNS:
/// `cargo test -p zombo-core --test check_web -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_site_gives_a_url_row_and_a_redirect_chain_title() {
    let o = CHECK.run(&Request::system("example.com", Duration::from_secs(10), &[])).await.unwrap();
    assert_eq!(o.facts[0].key, "URL");
    assert_eq!(o.details_title, "Redirect chain");
}
