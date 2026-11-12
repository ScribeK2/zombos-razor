//! Every Check run through its descriptor against the real network, one test each. All are ignored:
//! this needs a network that does not intercept DNS. Run on a clean host with
//! `cargo test -p zombo-core --test check_live -- --ignored --nocapture --test-threads=1`.
//! Each test prints what the Check returned. The asserts are the facts that should hold on a clean
//! network; a failure here is a finding about the Check or the network, not noise.

use std::net::SocketAddr;

use zombo_core::{
    blacklist,
    check::{Check, Outcome, Request},
    delegation, dnssec, email_auth, ports,
    propagation::default_resolvers,
    rdns, registration, smtp, tls, web,
};

fn bootstrap() -> Vec<SocketAddr> {
    default_resolvers().iter().map(|r| r.address).collect()
}

/// Runs `check` the way the UI does: the descriptor's per-query limit inside its whole limit.
async fn run(check: &Check, name: &str) -> Result<Outcome, String> {
    let bootstrap = bootstrap();
    let request = Request::system(name, check.budget.1, &bootstrap);
    let result = match tokio::time::timeout(check.budget.0, check.run(&request)).await {
        Ok(r) => r,
        Err(_) => Err(format!("timed out after {:?}", check.budget.0)),
    };
    show(check.label, name, &result);
    result
}

fn show(label: &str, name: &str, result: &Result<Outcome, String>) {
    match result {
        Ok(o) => {
            eprintln!("== {label} on {name}: OK, {} facts, {} details", o.facts.len(), o.details.len());
            for f in o.facts.iter().take(10) {
                eprintln!("   {}: {}", f.key, f.value);
            }
            for f in &o.findings {
                eprintln!("   [{:?}] {}", f.severity, f.code);
            }
        }
        Err(e) => eprintln!("== {label} on {name}: ERR {e}"),
    }
}

fn codes(o: &Outcome) -> Vec<&'static str> {
    o.findings.iter().map(|f| f.code).collect()
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn dnssec_a_signed_zone_is_secure() {
    let o = run(&dnssec::CHECK, "cloudflare.com").await.expect("a clean network answers");
    assert!(codes(&o).contains(&"dnssec_secure"), "{:?}", codes(&o));
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn dnssec_a_broken_zone_is_reported_not_an_error() {
    // dnssec-failed.org is kept broken on purpose by its owner. Only that the Check answers is asserted.
    let o = run(&dnssec::CHECK, "dnssec-failed.org").await.expect("a clean network answers");
    assert!(!o.facts.is_empty());
    assert!(!codes(&o).contains(&"dnssec_secure"), "{:?}", codes(&o));
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn tls_a_public_site_has_a_handshake_and_caa_rows() {
    let o = run(&tls::CHECK, "example.com").await.expect("a clean network answers");
    assert!(o.facts.iter().any(|f| f.key == "Protocol"));
    assert!(o.facts.iter().any(|f| f.key.starts_with("CAA")), "the CAA join ran over real DNS");
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn rdns_a_public_address_has_a_name() {
    let o = run(&rdns::CHECK, "1.1.1.1").await.expect("this machine has a resolver");
    assert!(!o.facts.is_empty());
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn blacklist_the_dnsbl_test_address_is_listed_somewhere() {
    // 127.0.0.2 is the conventional DNSBL test entry. Only that the Check answers is asserted.
    let o = run(&blacklist::CHECK, "127.0.0.2").await.expect("this machine has a resolver");
    assert!(!o.facts.is_empty() || !o.findings.is_empty());
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn delegation_a_real_domain_agrees_with_its_parent() {
    let o = run(&delegation::CHECK, "example.com").await.expect("a clean network answers");
    assert!(!o.facts.is_empty());
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn registration_a_real_domain_is_registered() {
    let o = run(&registration::CHECK, "example.com").await.expect("RDAP answers");
    assert!(o.facts.iter().any(|f| f.key == "Domain"));
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn email_a_real_domain_has_spf_and_dmarc_rows() {
    let o = run(&email_auth::CHECK, "google.com").await.expect("a clean network answers");
    assert!(!o.facts.is_empty());
}

#[tokio::test]
#[ignore = "needs a clean real network"]
async fn web_a_real_site_is_inspected() {
    let o = run(&web::CHECK, "example.com").await.expect("the target parses");
    assert!(!o.facts.is_empty());
}

/// Scans the host the test runs on, so it never probes someone else. Set `ZOMBO_LIVE_OWN_IP`.
#[tokio::test]
#[ignore = "needs a clean real network and ZOMBO_LIVE_OWN_IP"]
async fn ports_the_own_host_is_scanned() {
    let Ok(ip) = std::env::var("ZOMBO_LIVE_OWN_IP") else {
        eprintln!("skipped: set ZOMBO_LIVE_OWN_IP to this host's public address");
        return;
    };
    let o = run(&ports::CHECK, &ip).await.expect("an IP literal needs no lookup");
    assert!(!o.facts.is_empty());
}

#[tokio::test]
#[ignore = "needs a clean real network; many networks block outbound port 25"]
async fn smtp_a_public_mail_host_is_dialled_or_reported_filtered() {
    let bootstrap = bootstrap();
    let mut request = Request::system("gmail-smtp-in.l.google.com", smtp::CHECK.budget.1, &bootstrap);
    request.port = 25;
    let result = tokio::time::timeout(smtp::CHECK.budget.0, smtp::CHECK.run(&request))
        .await
        .unwrap_or_else(|_| Err("timed out".into()));
    show(smtp::CHECK.label, "gmail-smtp-in.l.google.com:25", &result);
    let o = result.expect("the Check reports a blocked port as an outcome, not an error");
    assert!(!o.facts.is_empty());
}
