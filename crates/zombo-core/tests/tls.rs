//! TLS inspection against a local server with throwaway certificates. The
//! scenarios are the Go `ssl_inspection` tests, plus the rules the Go code lacks.

#[path = "common/tls.rs"]
mod pki;

use std::time::Duration;

use pki::{Ca, NOW, days};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use zombo_core::{
    Finding, Severity,
    tls::{TlsError, TlsResult, Trust, assess, check_tls_via, inspect_stream, tls_findings_at},
};

const HOST: &str = "example.test";
const WAIT: Duration = Duration::from_secs(5);

async fn inspect(addr: std::net::SocketAddr, roots: &rustls::RootCertStore, now: time::OffsetDateTime) -> Result<TlsResult, TlsError> {
    check_tls_via(addr, HOST, roots, now, WAIT).await
}

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

fn find<'a>(fs: &'a [Finding], code: &str) -> &'a Finding {
    fs.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("no {code} in {:?}", codes(fs)))
}

#[tokio::test]
async fn a_valid_chain_is_shown_and_trusted() {
    let root = Ca::root("Test Root CA");
    let inter = root.intermediate("Test Intermediate");
    let leaf = inter.valid_leaf(&[HOST, "www.example.test"]);
    let addr = pki::serve(vec![leaf.der, inter.der()], leaf.key).await;

    let r = inspect(addr, &root.roots(), NOW).await.unwrap();
    assert_eq!(r.version, "TLS 1.3");
    assert!(r.cipher.starts_with("TLS_"), "{}", r.cipher);
    assert!(r.hostname_match && r.verified && r.trust == Trust::Ok && r.verify_error.is_none(), "{r:?}");
    assert_eq!(r.chain.len(), 2);
    let l = &r.chain[0];
    assert_eq!((l.subject.as_str(), l.issuer.as_str()), (HOST, "Test Intermediate"));
    assert_eq!(l.sans, [HOST, "www.example.test"]);
    assert_eq!((l.key.to_string().as_str(), l.signature.as_str()), ("ECDSA P-256", "ECDSA-SHA256"));
    assert!(!l.self_signed && !l.is_ca);
    assert_eq!((r.chain[1].subject.as_str(), r.chain[1].issuer.as_str()), ("Test Intermediate", "Test Root CA"));
    assert!(r.chain[1].is_ca);

    let fs = tls_findings_at(HOST, 443, &r, NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_valid"]);
    assert_eq!(fs[0].severity, Severity::Ok);
    assert!(fs[0].message.contains("Test Intermediate"), "{}", fs[0].message);
}

#[tokio::test]
async fn an_expired_certificate_is_only_expired() {
    let root = Ca::root("Test Root CA");
    let leaf = root.leaf(&[HOST], days(-90), days(-1));
    let addr = pki::serve(vec![leaf.der], leaf.key).await;

    let r = inspect(addr, &root.roots(), NOW).await.unwrap();
    assert!(!r.verified && r.verify_error.is_some());
    assert_eq!(r.trust, Trust::Ok, "an expired leaf must not also read as untrusted");
    let fs = tls_findings_at(HOST, 443, &r, NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_expired"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert!(fs[0].message.contains("(1 day ago)"), "{}", fs[0].message);
    assert!(fs[0].recommendation.is_some());
}

#[tokio::test]
async fn a_certificate_not_yet_valid_gets_its_own_finding() {
    let root = Ca::root("Test Root CA");
    let leaf = root.leaf(&[HOST], days(5), days(95));
    let addr = pki::serve(vec![leaf.der], leaf.key).await;

    let r = inspect(addr, &root.roots(), NOW).await.unwrap();
    assert!(!r.verified);
    assert_eq!(r.trust, Trust::Ok);
    assert_eq!(codes(&tls_findings_at(HOST, 443, &r, NOW)), ["ssl_inspection_not_yet_valid"]);
}

#[tokio::test]
async fn expiry_warnings_follow_the_go_thresholds() {
    use time::Duration as D;
    let root = Ca::root("Test Root CA");
    let leaf = root.leaf(&[HOST], days(-90), days(90));
    let not_after = days(90);
    let addr = pki::serve(vec![leaf.der], leaf.key).await;
    let r = inspect(addr, &root.roots(), NOW).await.unwrap();

    let at = |left: D| codes(&tls_findings_at(HOST, 443, &r, not_after - left));
    assert_eq!(at(D::days(31)), ["ssl_inspection_valid"]);
    assert_eq!(at(D::days(30)), ["ssl_inspection_expiring_soon", "ssl_inspection_valid"]);
    assert_eq!(at(D::days(15)), ["ssl_inspection_expiring_soon", "ssl_inspection_valid"]);
    assert_eq!(at(D::days(14) + D::hours(23)), ["ssl_inspection_expiring", "ssl_inspection_valid"]);
    assert_eq!(at(D::days(14)), ["ssl_inspection_expiring", "ssl_inspection_valid"]);
    assert_eq!(at(D::hours(1)), ["ssl_inspection_expiring", "ssl_inspection_valid"]);

    let fs = tls_findings_at(HOST, 443, &r, not_after - D::days(10));
    assert_eq!(find(&fs, "ssl_inspection_expiring").severity, Severity::Warning);
    assert!(find(&fs, "ssl_inspection_expiring").message.contains("(in 10 days)"));
    let fs = tls_findings_at(HOST, 443, &r, not_after - D::days(1));
    assert!(find(&fs, "ssl_inspection_expiring").message.contains("(in 1 day)"));
    let fs = tls_findings_at(HOST, 443, &r, not_after - D::days(20));
    assert_eq!(find(&fs, "ssl_inspection_expiring_soon").severity, Severity::Info);
    let fs = tls_findings_at(HOST, 443, &r, not_after + D::hours(1));
    assert!(find(&fs, "ssl_inspection_expired").message.contains("(1 day ago)"));
    assert_eq!(find(&fs, "ssl_inspection_expired").severity, Severity::Critical);
}

#[tokio::test]
async fn the_soonest_expiry_in_the_chain_is_reported_by_name() {
    let root = Ca::root("Test Root CA");
    let inter = root.intermediate_valid("Test Intermediate", days(-300), days(5));
    let leaf = inter.valid_leaf(&[HOST]);
    let addr = pki::serve(vec![leaf.der, inter.der()], leaf.key).await;

    let r = inspect(addr, &root.roots(), NOW).await.unwrap();
    let fs = tls_findings_at(HOST, 443, &r, NOW);
    let f = find(&fs, "ssl_inspection_expiring");
    assert!(f.message.starts_with("The chain certificate Test Intermediate on example.test:443 expires on "), "{}", f.message);
}

#[tokio::test]
async fn a_wrong_host_is_critical_and_not_valid() {
    let root = Ca::root("Test Root CA");
    let leaf = root.valid_leaf(&["other.test"]);
    let addr = pki::serve(vec![leaf.der], leaf.key).await;

    let r = inspect(addr, &root.roots(), NOW).await.unwrap();
    assert!(!r.hostname_match && !r.verified);
    assert_eq!(r.trust, Trust::Ok);
    assert!(r.verify_error.as_deref().unwrap_or("").contains("other.test"), "{:?}", r.verify_error);
    let fs = tls_findings_at(HOST, 443, &r, NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_hostname_mismatch"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert_eq!(fs[0].message, "The certificate on example.test:443 is for other.test, not example.test.");
}

#[tokio::test]
async fn a_self_signed_certificate_is_not_also_untrusted() {
    let leaf = pki::self_signed(&[HOST]);
    let addr = pki::serve(vec![leaf.der], leaf.key).await;

    let r = inspect(addr, &Ca::root("Some Other Root").roots(), NOW).await.unwrap();
    assert!(r.chain[0].self_signed && r.trust == Trust::SelfSigned && !r.verified, "{r:?}");
    let fs = tls_findings_at(HOST, 443, &r, NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_self_signed"]);
    assert_eq!(fs[0].severity, Severity::Critical);
}

#[tokio::test]
async fn a_missing_intermediate_is_an_incomplete_chain() {
    let root = Ca::root("Test Root CA");
    let inter = root.intermediate("Test Intermediate");
    let leaf = inter.valid_leaf(&[HOST]);
    let addr = pki::serve(vec![leaf.der], leaf.key).await; // intermediate not sent

    let r = inspect(addr, &root.roots(), NOW).await.unwrap();
    assert_eq!((r.chain.len(), r.trust, r.verified), (1, Trust::MissingIntermediate, false), "{r:?}");
    assert!(r.verify_error.is_some());
    let fs = tls_findings_at(HOST, 443, &r, NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_incomplete_chain"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert!(fs[0].message.contains("the server isn't sending its intermediate certificate"));
    assert!(fs[0].message.contains("stops at example.test, issued by Test Intermediate"));
}

#[tokio::test]
async fn a_complete_chain_under_an_unknown_root_is_untrusted() {
    let private = Ca::root("Test Root CA");
    let inter = private.intermediate("Test Intermediate");
    let leaf = inter.valid_leaf(&[HOST]);
    let addr = pki::serve(vec![leaf.der, inter.der()], leaf.key).await;

    let r = inspect(addr, &Ca::root("A Different Root").roots(), NOW).await.unwrap();
    assert_eq!(r.trust, Trust::UnknownAuthority);
    let fs = tls_findings_at(HOST, 443, &r, NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_untrusted"]);
    assert!(fs[0].message.contains("Test Root CA"), "{}", fs[0].message);
    assert_eq!(fs[0].title, "Certificate not trusted");
}

#[tokio::test]
async fn a_chain_that_fails_verification_otherwise_is_invalid() {
    // The intermediate lapsed while the leaf is still in date.
    let root = Ca::root("Test Root CA");
    let inter = root.intermediate_valid("Test Intermediate", days(-300), days(-1));
    let leaf = inter.valid_leaf(&[HOST]);
    let addr = pki::serve(vec![leaf.der, inter.der()], leaf.key).await;

    let r = inspect(addr, &root.roots(), NOW).await.unwrap();
    assert_eq!(r.trust, Trust::Invalid);
    let fs = tls_findings_at(HOST, 443, &r, NOW);
    assert!(codes(&fs).contains(&"ssl_inspection_untrusted"));
    assert_eq!(find(&fs, "ssl_inspection_untrusted").title, "Certificate chain doesn't verify");
}

#[tokio::test]
async fn the_inspection_runs_over_any_connected_stream() {
    // The seam a STARTTLS upgrade reuses: no socket of ours, just a stream.
    let root = Ca::root("Test Root CA");
    let leaf = root.valid_leaf(&[HOST]);
    let (client, server) = tokio::io::duplex(64 * 1024);
    let acceptor = tokio_rustls::TlsAcceptor::from(pki::server_config(vec![leaf.der], leaf.key));
    tokio::spawn(async move {
        let _ = acceptor.accept(server).await;
    });
    let r = inspect_stream(client, HOST, &root.roots(), NOW, WAIT).await.unwrap();
    assert!(r.verified);
}

#[tokio::test]
async fn a_chain_longer_than_the_bound_is_refused() {
    let root = Ca::root("Test Root CA");
    let leaf = root.valid_leaf(&[HOST]);
    let mut chain = vec![leaf.der];
    chain.extend((0..zombo_core::tls::MAX_CHAIN).map(|_| root.der()));
    let addr = pki::serve(chain, leaf.key).await;
    let e = inspect(addr, &root.roots(), NOW).await.unwrap_err();
    assert!(matches!(e, TlsError::Chain(_)), "{e:?}");
}

#[test]
fn an_oversized_certificate_is_refused() {
    let big = vec![0u8; zombo_core::tls::MAX_CERT_BYTES + 1];
    let e = assess(&[CertificateDer::from(big)], HOST, &rustls::RootCertStore::empty(), NOW).unwrap_err();
    assert!(matches!(e, TlsError::Chain(_)), "{e:?}");
}

#[test]
fn garbage_in_place_of_a_certificate_is_an_error_not_a_panic() {
    let e = assess(&[CertificateDer::from(vec![1, 2, 3])], HOST, &rustls::RootCertStore::empty(), NOW).unwrap_err();
    assert!(matches!(e, TlsError::Chain(_)), "{e:?}");
}

#[tokio::test]
async fn a_server_that_never_answers_times_out() {
    let addr = pki::serve_silent().await;
    let began = std::time::Instant::now();
    let e = check_tls_via(addr, HOST, &rustls::RootCertStore::empty(), NOW, Duration::from_millis(300)).await.unwrap_err();
    assert!(matches!(e, TlsError::TimedOut), "{e:?}");
    assert!(began.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_server_that_does_not_speak_tls_is_a_handshake_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Ok((mut tcp, _)) = listener.accept().await {
            let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        }
    });
    let e = inspect(addr, &rustls::RootCertStore::empty(), NOW).await.unwrap_err();
    assert!(matches!(e, TlsError::Handshake(_)), "{e:?}");
}

#[tokio::test]
async fn a_refused_connection_is_a_connect_error() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let e = inspect(addr, &rustls::RootCertStore::empty(), NOW).await.unwrap_err();
    assert!(matches!(e, TlsError::Connect(_)), "{e:?}");
}

#[tokio::test]
async fn an_invalid_server_name_is_rejected_before_connecting() {
    let e = check_tls_via("127.0.0.1:1", "not a name", &rustls::RootCertStore::empty(), NOW, WAIT).await.unwrap_err();
    assert!(matches!(e, TlsError::BadName(_)), "{e:?}");
}

/// An RSA 1024-bit certificate signed with SHA-1, from `openssl req -x509 -newkey rsa:1024 -sha1`.
/// ring refuses such keys, so the server signs with an unrelated key and the
/// handshake, which this tool does not verify, still completes.
fn weak_fixture() -> CertificateDer<'static> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/tls/weak-rsa1024-sha1.pem");
    CertificateDer::from_pem_file(path).unwrap()
}

#[test]
fn the_weak_fixture_parses_as_rsa_1024_with_sha1() {
    let r = assess(&[weak_fixture()], "weak.test", &rustls::RootCertStore::empty(), NOW).unwrap();
    let c = &r.chain[0];
    assert_eq!((c.key.to_string().as_str(), c.signature.as_str(), c.self_signed), ("RSA 1024", "SHA1-RSA", true));
    assert_eq!(c.sans, ["weak.test"]);
}

#[tokio::test]
async fn a_weak_key_and_a_sha1_signature_each_get_a_finding() {
    let unrelated = pki::self_signed(&["unrelated.test"]);
    let addr = pki::serve(vec![weak_fixture()], unrelated.key).await;
    let r = check_tls_via(addr, "weak.test", &rustls::RootCertStore::empty(), NOW, WAIT).await.unwrap();
    let fs = tls_findings_at("weak.test", 443, &r, NOW);
    assert_eq!(find(&fs, "ssl_inspection_weak_key").severity, Severity::Warning);
    assert!(find(&fs, "ssl_inspection_weak_key").message.contains("RSA 1024-bit"));
    assert!(find(&fs, "ssl_inspection_weak_signature").message.contains("SHA1-RSA"));
}
