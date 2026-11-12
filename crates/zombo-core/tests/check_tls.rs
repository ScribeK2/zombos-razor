#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The TLS Checks as the UI runs them: a handshake against a local server with a throwaway
//! certificate, and CAA from a fake resolver. `localhost` stands in for the name, so the
//! certificate is not trusted by the public roots and a test port stands in for 443.

mod common;
#[path = "common/tls.rs"]
mod pki;

use std::{net::SocketAddr, time::Duration};

use common::FakeDns;
use pki::Ca;
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request},
    tls::{CHECK, ON_PORT},
};

const T: Duration = Duration::from_secs(5);
const CAA_DIGICERT: &str = "localhost. 300 IN CAA 0 issue \"digicert.com\"\n";

fn rows(o: &Outcome) -> Vec<String> {
    o.facts.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

async fn serve(ca: &Ca) -> u16 {
    let now = time::OffsetDateTime::now_utc();
    let leaf = ca.leaf(&["localhost"], now - time::Duration::days(365), now + time::Duration::days(365));
    pki::serve(vec![leaf.der], leaf.key).await.port()
}

async fn caa_resolver(zone: &str) -> SocketAddr {
    FakeDns::start(zone).await.addr
}

/// A port nothing listens on.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn request<'a>(name: &'a str, port: u16, bootstrap: &'a [SocketAddr]) -> Request<'a> {
    Request { port, ..Request::system(name, T, bootstrap) }
}

#[tokio::test]
async fn the_automatic_check_gives_handshake_rows_then_caa_rows_and_findings_worst_first() {
    let port = serve(&Ca::root("Let's Encrypt R3")).await;
    let dns = caa_resolver(CAA_DIGICERT).await;
    let o = CHECK.run(&request("localhost", port, &[dns])).await.unwrap();
    let r = rows(&o);
    let keys: Vec<_> = o.facts.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(
        keys,
        ["Port", "Protocol", "Cipher", "Trust", "Name matches", "Subject", "Issuer", "Expires", "CAA at localhost"]
    );
    assert_eq!(r[0], format!("Port: {port}"));
    assert_eq!(r[1], "Protocol: TLS 1.3");
    assert_eq!(r[3], "Trust: MissingIntermediate");
    assert_eq!(r[4], "Name matches: yes");
    assert_eq!(r[8], "CAA at localhost: 0 issue \"digicert.com\"");
    assert_eq!(o.details_title, "Certificate chain");
    assert_eq!(o.details.len(), 1);
    // Unsorted, the OCSP Info finding would come before the CAA Critical one.
    use Severity::{Critical, Info};
    let f = found(&o);
    assert_eq!(
        f,
        [("ssl_inspection_incomplete_chain", Critical), ("caa_forbids_issuer", Critical), ("tls_no_ocsp_staple", Info)]
    );
}

#[tokio::test]
async fn the_on_demand_check_names_the_port_and_asks_no_caa() {
    let port = serve(&Ca::root("Let's Encrypt R3")).await;
    let dns = caa_resolver(CAA_DIGICERT).await;
    let o = ON_PORT.run(&request("localhost", port, &[dns])).await.unwrap();
    let r = rows(&o);
    assert_eq!(r[0], format!("Port: {port}"));
    assert_eq!(r[1], "Protocol: TLS 1.3");
    assert!(r.iter().all(|l| !l.starts_with("CAA")), "{r:?}");
    let f = found(&o);
    assert!(f.iter().any(|(c, _)| *c == "tls_no_ocsp_staple"), "{f:?}");
    assert!(f.iter().all(|(c, _)| !c.starts_with("caa_")), "{f:?}");
    let ocsp = o.findings.iter().find(|x| x.code == "tls_no_ocsp_staple").unwrap();
    assert!(ocsp.message.contains(&format!("localhost:{port}")), "{}", ocsp.message);
}

#[tokio::test]
async fn a_failed_handshake_is_the_checks_own_error_and_drops_the_caa_answer() {
    let dns = caa_resolver(CAA_DIGICERT).await;
    for check in [&CHECK, &ON_PORT] {
        let e = check.run(&request("localhost", closed_port(), &[dns])).await.unwrap_err();
        assert!(e.starts_with("could not connect: "), "{e}");
        assert!(!e.contains("CAA"), "{e}");
    }
    let e = CHECK.run(&request("not a name", 443, &[dns])).await.unwrap_err();
    assert_eq!(e, "\"not a name\" is not a valid server name");
}

#[test]
fn the_system_request_asks_port_443() {
    assert_eq!(Request::system("example.com", T, &[]).port, 443);
}

#[test]
fn only_the_on_demand_descriptor_dials_the_port_the_rep_chose() {
    assert!(!CHECK.takes_chosen_port);
    assert!(ON_PORT.takes_chosen_port);
    assert!(!zombo_core::dnssec::CHECK.takes_chosen_port);
}

#[test]
fn the_two_descriptors_carry_the_limits_prefixes_and_blind_spots_the_ui_used_to_hold() {
    for c in [&CHECK, &ON_PORT] {
        assert_eq!(c.budget, (Duration::from_secs(10), Duration::from_secs(8)));
    }
    assert_eq!(CHECK.owns, ["ssl_", "tls_", "caa_"]);
    assert!(ON_PORT.owns.is_empty());
    assert_eq!(
        CHECK.blind_spots,
        [
            "Other ports: the TLS on a port Check asks for those.",
            "Protocol versions below TLS 1.2: this tool speaks only 1.2 and 1.3.",
            "Cipher suites the server accepts but did not choose.",
            "Revocation at the CA: only an OCSP response stapled by the server is seen.",
        ]
    );
    assert_eq!(
        ON_PORT.blind_spots,
        [
            "Services that start TLS after a plain greeting (STARTTLS): the SMTP banner check covers those.",
            "A server that requires a client certificate.",
            "Protocol versions below TLS 1.2, and revocation at the CA.",
        ]
    );
}
