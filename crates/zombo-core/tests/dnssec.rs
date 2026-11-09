mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{FakeDns, dnssec_zone, rdatas};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RecordType},
};
use zombo_core::{
    Finding, Severity,
    dns::{QueryFlags, exchange_with},
    dnssec::{
        Algorithm, DigestType, Dnskey, DnssecError, DnssecResult, Ds, KeyTag, ResolverStatus, Rrsig, SigWindow,
        check_dnssec, dnssec_findings, dnssec_with, validating_resolvers,
    },
    propagation::Vantage,
};

const T: Duration = Duration::from_millis(500);

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

// exchange_with: the DNSSEC flags reach the wire

async fn ask(s: &FakeDns, n: &str, t: RecordType, dnssec_ok: bool, checking_disabled: bool) -> Message {
    let flags = QueryFlags { recursion_desired: true, dnssec_ok, checking_disabled };
    exchange_with(s.addr, &name(n), t, flags, T).await.unwrap()
}

#[tokio::test]
async fn the_cd_flag_is_sent_when_asked_for() {
    let bogus = FakeDns::start("example.com. 300 IN A 192.0.2.1\n").await.bogus();
    assert_eq!(
        ask(&bogus, "example.com", RecordType::A, true, false).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(
        ask(&bogus, "example.com", RecordType::A, true, true).await.metadata.response_code,
        ResponseCode::NoError
    );
}

#[tokio::test]
async fn the_do_bit_is_sent_when_asked_for() {
    let s = FakeDns::start(&dnssec_zone("cloudflare.com")).await.validating();
    let (with, without) = (
        ask(&s, "cloudflare.com", RecordType::SOA, true, false).await,
        ask(&s, "cloudflare.com", RecordType::SOA, false, false).await,
    );
    assert!(with.answers.iter().any(|r| r.record_type() == RecordType::RRSIG), "{:?}", with.answers);
    assert!(with.metadata.authentic_data);
    assert!(without.answers.iter().all(|r| r.record_type() != RecordType::RRSIG));
    assert!(!without.metadata.authentic_data);
}

// Key tag and DS digest, proven on real zones (testdata/dnssec/*.zone, fetched from the live DNS)

fn keys(zone_text: &str) -> Vec<Dnskey> {
    rdatas(zone_text, RecordType::DNSKEY).iter().map(|r| Dnskey::from_rdata(r).unwrap()).collect()
}
fn ds_set(zone_text: &str) -> Vec<Ds> {
    rdatas(zone_text, RecordType::DS).iter().map(|r| Ds::from_rdata(r).unwrap()).collect()
}

/// (zone, key tag of its KSK, the SHA-256 digest its parent publishes)
const REAL: [(&str, u16, &str); 2] = [
    ("cloudflare.com", 2371, "32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9"),
    ("iana.org", 2234, "005b228ce3dad3486f713ebb9bb6f96a53839bd0e2f5a999d3400e1b7355ce8c"),
];

#[test]
fn a_real_zones_ksk_has_the_key_tag_its_parent_publishes() {
    for (zone, tag, _) in REAL {
        let ksk = keys(&dnssec_zone(zone)).into_iter().find(Dnskey::is_ksk).unwrap();
        assert_eq!(ksk.key_tag, KeyTag(tag), "{zone}");
    }
}

#[test]
fn a_real_ds_matches_its_real_ksk_and_nothing_else() {
    for (zone, _, digest) in REAL {
        let text = dnssec_zone(zone);
        let ds = ds_set(&text).remove(0);
        assert_eq!(ds.digest, data_encoding::HEXLOWER.decode(digest.as_bytes()).unwrap());
        let (ksk, zsk): (Vec<_>, Vec<_>) = keys(&text).into_iter().partition(Dnskey::is_ksk);
        assert!(ds.matches(&name(zone), &ksk[0]), "{zone}");
        assert!(!ds.matches(&name(zone), &zsk[0]), "{zone}: the ZSK is not what the DS points at");
        assert!(ds.matches(&name(&zone.to_uppercase()), &ksk[0]), "{zone}: the owner name is hashed in lowercase");
        assert!(!ds.matches(&name("example.org"), &ksk[0]), "{zone}: the owner name is part of the digest");
    }
}

#[test]
fn one_flipped_digest_byte_breaks_the_match() {
    let text = dnssec_zone("cloudflare.com");
    let mut ds = ds_set(&text).remove(0);
    ds.digest[7] ^= 1;
    let ksk = keys(&text).into_iter().find(Dnskey::is_ksk).unwrap();
    assert!(!ds.matches(&name("cloudflare.com"), &ksk));
}

#[test]
fn the_digest_types_compute_the_published_test_vectors() {
    let hex = |t: DigestType| data_encoding::HEXLOWER.encode(&t.digest(b"abc").unwrap());
    assert_eq!(hex(DigestType::Sha1), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hex(DigestType::Sha256), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex(DigestType::Sha384),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    assert!(DigestType::from_number(3).digest(b"abc").is_none(), "GOST is not computed");
}

// The Check, run against fake servers

const APEX: &str = "cloudflare.com";
const WEB: &str = "cloudflare.com. 300 IN A 192.0.2.1\n";
/// Inside the validity period of the real SOA signature in the fixture.
fn now() -> SystemTime {
    at(CF_START + 3600)
}

/// Run the Check: `parent` is what the recursive resolver knows (its DS), each
/// of `nameservers` is one authoritative server's zone, and `resolvers` are the
/// validating-resolver Vantages.
async fn run_at(parent: &str, nameservers: &[&str], resolvers: Vec<(&str, FakeDns)>, now: SystemTime) -> DnssecResult {
    run_for(APEX, parent, nameservers, resolvers, now).await
}

async fn run_for(
    apex: &str,
    parent: &str,
    nameservers: &[&str],
    resolvers: Vec<(&str, FakeDns)>,
    now: SystemTime,
) -> DnssecResult {
    let rec = FakeDns::start(&format!("{apex}. 300 IN NS ns.{apex}.\n{parent}")).await;
    let ns: Vec<(String, FakeDns)> = fake_nameservers(nameservers).await;
    let ns_v: Vec<Vantage> = ns.iter().map(|(n, s)| Vantage::nameserver(n, s.addr)).collect();
    let res_v: Vec<Vantage> = resolvers.iter().map(|(n, s)| Vantage::resolver(n, "Test", s.addr)).collect();
    dnssec_with(&[rec.addr], &res_v, &ns_v, apex, now, T).await.unwrap()
}

async fn fake_nameservers(zones: &[&str]) -> Vec<(String, FakeDns)> {
    let mut out = vec![];
    for (i, z) in zones.iter().enumerate() {
        out.push((format!("ns{}.{APEX}", i + 1), FakeDns::start(z).await.authoritative()));
    }
    out
}

async fn verdicts(resolvers: Vec<(&str, FakeDns)>) -> Vec<(String, ResolverStatus)> {
    let z = dnssec_zone(APEX);
    run_at(&z, &[&z], resolvers, now()).await.resolvers.into_iter().map(|v| (v.resolver, v.status)).collect()
}

#[tokio::test]
async fn a_validating_resolver_that_sets_ad_says_secure() {
    let v = verdicts(vec![("Good", FakeDns::start(WEB).await.validating())]).await;
    assert_eq!(v, [("Good".to_string(), ResolverStatus::Secure)]);
}

#[tokio::test]
async fn a_resolver_that_does_not_set_ad_says_insecure() {
    let v = verdicts(vec![("Plain", FakeDns::start(WEB).await)]).await;
    assert_eq!(v[0].1, ResolverStatus::Insecure);
}

#[tokio::test]
async fn servfail_that_goes_away_with_cd_is_bogus() {
    let v = verdicts(vec![("Strict", FakeDns::start(WEB).await.bogus())]).await;
    assert_eq!(v[0].1, ResolverStatus::Bogus);
}

#[tokio::test]
async fn servfail_with_cd_too_is_a_plain_dns_failure_not_a_dnssec_one() {
    let v = verdicts(vec![("Broken", FakeDns::start(WEB).await.servfail())]).await;
    assert_eq!(v[0].1, ResolverStatus::Failed);
}

#[tokio::test]
async fn a_resolver_that_does_not_answer_says_no_answer_and_order_is_kept() {
    let v = verdicts(vec![
        ("A", FakeDns::silent().await),
        ("B", FakeDns::start(WEB).await.validating()),
        ("C", FakeDns::start(WEB).await.bogus()),
    ])
    .await;
    assert_eq!(
        v.iter().map(|(n, s)| (n.as_str(), *s)).collect::<Vec<_>>(),
        [("A", ResolverStatus::NoAnswer), ("B", ResolverStatus::Secure), ("C", ResolverStatus::Bogus)]
    );
}

#[tokio::test]
async fn the_real_ds_matches_the_keys_the_real_nameservers_serve() {
    let z = dnssec_zone(APEX);
    let r = run_at(&z, &[&z, &z], vec![], now()).await;
    assert_eq!(r.ds.len(), 1);
    assert!(r.ds[0].matched, "{:?}", r.ds);
    assert_eq!((r.ds[0].ds.key_tag, r.ds[0].ds.digest_type), (KeyTag(2371), DigestType::Sha256));
    for n in &r.nameservers {
        assert!(n.error.is_none() && n.authoritative, "{n:?}");
        assert_eq!(n.dnskeys.iter().map(|k| k.key_tag).collect::<Vec<_>>(), [KeyTag(34505), KeyTag(2371)]);
        assert!(matches!(n.soa_rrsig.as_ref().unwrap().window(now()), SigWindow::Valid { .. }));
    }
}

#[tokio::test]
async fn a_ds_with_no_matching_key_is_not_matched() {
    let z = dnssec_zone(APEX);
    let parent = z.replace("2371 13 2 32996839", "2371 13 2 32996838");
    let r = run_at(&parent, &[&z], vec![], now()).await;
    assert!(!r.ds[0].matched);
}

#[tokio::test]
async fn a_zone_that_serves_no_dnskey_matches_no_ds() {
    let z = dnssec_zone(APEX);
    let unsigned: String =
        z.lines().filter(|l| !l.contains(" DNSKEY ") && !l.contains(" RRSIG ")).collect::<Vec<_>>().join("\n");
    let r = run_at(&z, &[&unsigned], vec![], now()).await;
    assert!(r.nameservers[0].dnskeys.is_empty() && r.nameservers[0].soa_rrsig.is_none());
    assert!(!r.ds[0].matched);
}

#[tokio::test]
async fn nothing_answering_at_all_is_an_error() {
    let z = dnssec_zone(APEX);
    let rec = FakeDns::start(&z).await;
    let down = FakeDns::silent().await;
    let ns = [Vantage::nameserver("ns", down.addr)];
    let res = [Vantage::resolver("R", "Test", down.addr)];
    let err = dnssec_with(&[rec.addr], &res, &ns, APEX, now(), Duration::from_millis(200)).await.unwrap_err();
    assert!(matches!(err, DnssecError::NoneAnswered), "{err}");
}

#[tokio::test]
async fn finds_the_zone_and_its_nameservers_even_through_a_resolver_that_rejects_the_zone() {
    // A validating resolver SERVFAILs on the NS lookup of a broken zone unless CD is set.
    let z = dnssec_zone(APEX);
    let ns = FakeDns::start(&z).await.authoritative();
    let rec =
        FakeDns::start(&format!("{APEX}. 300 IN NS ns1.{APEX}.\nns1.{APEX}. 300 IN A 127.0.0.1\n{z}")).await.bogus();
    let r = check_dnssec(&[rec.addr], &[], &format!("www.{APEX}"), ns.addr.port(), now(), T).await.unwrap();
    assert_eq!(r.apex, APEX);
    assert_eq!(r.nameservers.len(), 1);
    assert!(r.ds[0].matched);
}

// Findings

fn codes(fs: &[Finding]) -> Vec<&str> {
    fs.iter().map(|f| f.code).collect()
}
fn code<'a>(fs: &'a [Finding], c: &str) -> &'a Finding {
    fs.iter().find(|f| f.code == c).unwrap_or_else(|| panic!("no {c} in {:?}", codes(fs)))
}
/// A healthy domain, as the real cloudflare.com data says, with one good resolver.
async fn healthy(now: SystemTime) -> DnssecResult {
    let z = dnssec_zone(APEX);
    run_at(&z, &[&z, &z], vec![("Google", FakeDns::start(WEB).await.validating())], now).await
}

#[tokio::test]
async fn healthy_dnssec_says_so_and_nothing_else() {
    let fs = dnssec_findings(&healthy(now()).await);
    assert_eq!(codes(&fs), ["dnssec_secure"]);
    assert_eq!(fs[0].severity, Severity::Ok);
    assert!(fs[0].message.contains("Google") && fs[0].message.contains("another 2 days"), "{}", fs[0].message);
}

#[tokio::test]
async fn a_resolver_that_rejects_the_domain_is_named_and_the_domain_is_called_unreachable() {
    let z = dnssec_zone(APEX);
    let r = run_at(
        &z,
        &[&z],
        vec![("Strict", FakeDns::start(WEB).await.bogus()), ("Good", FakeDns::start(WEB).await.validating())],
        now(),
    )
    .await;
    let fs = dnssec_findings(&r);
    let f = code(&fs, "dnssec_bogus");
    assert_eq!(f.severity, Severity::Critical);
    assert!(
        f.message.contains("Strict") && !f.message.contains("Good") && f.message.contains("unreachable"),
        "{}",
        f.message
    );
    assert!(!f.message.contains("likely cause"), "no local cause here: {}", f.message);
    assert!(fs.iter().all(|f| f.code != "dnssec_secure"), "{fs:?}");
}

#[tokio::test]
async fn a_ds_that_matches_no_key_is_a_mismatch_and_the_likely_cause_of_the_bogus_verdict() {
    let z = dnssec_zone(APEX);
    let parent = z.replace("2371 13 2 32996839", "2371 13 2 32996838");
    let r = run_at(&parent, &[&z], vec![("Strict", FakeDns::start(WEB).await.bogus())], now()).await;
    let fs = dnssec_findings(&r);
    assert_eq!(code(&fs, "dnssec_ds_mismatch").severity, Severity::Critical);
    assert!(
        code(&fs, "dnssec_ds_mismatch").message.contains("2371")
            && code(&fs, "dnssec_ds_mismatch").message.contains("new provider")
    );
    assert!(
        code(&fs, "dnssec_bogus").message.contains("matches none of the keys"),
        "{}",
        code(&fs, "dnssec_bogus").message
    );
    assert!(fs.iter().all(|f| f.code != "dnssec_ds_without_dnskey"));
}

#[tokio::test]
async fn a_ds_at_the_parent_with_no_dnskey_in_the_zone_is_called_out() {
    let z = dnssec_zone(APEX);
    let unsigned: String =
        z.lines().filter(|l| !l.contains(" DNSKEY ") && !l.contains(" RRSIG ")).collect::<Vec<_>>().join("\n");
    let r = run_at(&z, &[&unsigned], vec![("Strict", FakeDns::start(WEB).await.bogus())], now()).await;
    let fs = dnssec_findings(&r);
    assert_eq!(code(&fs, "dnssec_ds_without_dnskey").severity, Severity::Critical);
    assert!(code(&fs, "dnssec_bogus").message.contains("serves no DNSKEY"));
    assert!(fs.iter().all(|f| f.code != "dnssec_ds_mismatch"), "one cause, not two: {:?}", codes(&fs));
}

#[tokio::test]
async fn a_signature_past_its_expiration_is_critical() {
    let r = healthy(at(CF_END + 2 * 86_400)).await;
    let fs = dnssec_findings(&r);
    let f = code(&fs, "dnssec_signature_expired");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.message.contains("ns1") && f.message.contains("expired 2 days ago"), "{}", f.message);
    assert!(fs.iter().all(|f| f.code != "dnssec_secure"));
}

#[tokio::test]
async fn a_signature_about_to_expire_is_a_warning() {
    // cloudflare.com signs for two days, so "about to expire" is the last quarter of that.
    let fs = dnssec_findings(&healthy(at(CF_END - 3 * 3600)).await);
    let f = code(&fs, "dnssec_signature_expiring");
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.message.contains("expires in 3 hours"), "{}", f.message);
    assert!(fs.iter().all(|f| f.code != "dnssec_signature_expired" && f.code != "dnssec_secure"));
}

/// iana.org signs for three weeks: inception 2026-11-08 16:48:04, expiration 2026-11-29 22:54:07.
const IANA_END: u64 = 1795992847;

async fn iana_at(now: u64) -> Vec<Finding> {
    let z = dnssec_zone("iana.org");
    let web = "iana.org. 300 IN A 192.0.2.1\n";
    dnssec_findings(
        &run_for("iana.org", &z, &[&z], vec![("Google", FakeDns::start(web).await.validating())], at(now)).await,
    )
}

#[tokio::test]
async fn under_three_days_left_on_a_long_signature_is_a_warning() {
    let fs = iana_at(IANA_END - 2 * 86_400).await;
    assert_eq!(code(&fs, "dnssec_signature_expiring").severity, Severity::Warning);
    assert!(code(&fs, "dnssec_signature_expiring").message.contains("expires in 2 days"));
}

#[tokio::test]
async fn more_than_three_days_left_is_fine() {
    assert_eq!(codes(&iana_at(IANA_END - 4 * 86_400).await), ["dnssec_secure"]);
}

#[tokio::test]
async fn a_deprecated_algorithm_is_a_warning_naming_it() {
    let mut r = healthy(now()).await;
    r.nameservers[0].dnskeys[1].algorithm = Algorithm::RsaSha1;
    r.nameservers[1].dnskeys[1].algorithm = Algorithm::RsaSha1;
    let fs = dnssec_findings(&r);
    let f = code(&fs, "dnssec_algorithm_deprecated");
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.message.contains("RSASHA1 (5)"), "{}", f.message);
}

#[tokio::test]
async fn nameservers_serving_different_keys_are_a_warning_listing_each() {
    let z = dnssec_zone(APEX);
    let without_zsk: String = z.lines().filter(|l| !l.contains("DNSKEY 256")).collect::<Vec<_>>().join("\n");
    let r = run_at(&z, &[&z, &without_zsk], vec![("Google", FakeDns::start(WEB).await.validating())], now()).await;
    let fs = dnssec_findings(&r);
    let f = code(&fs, "dnssec_nameservers_disagree");
    assert_eq!(f.severity, Severity::Warning);
    assert!(
        f.message.contains("ns1.cloudflare.com serves keys 34505, 2371")
            && f.message.contains("ns2.cloudflare.com serves key 2371"),
        "{}",
        f.message
    );
    assert!(fs.iter().all(|f| f.code != "dnssec_secure"), "{:?}", codes(&fs));
}

#[tokio::test]
async fn no_ds_and_no_dnskey_is_just_unsigned() {
    let z = dnssec_zone(APEX);
    let plain: String = z
        .lines()
        .filter(|l| !l.contains(" DNSKEY ") && !l.contains(" RRSIG ") && !l.contains(" DS "))
        .collect::<Vec<_>>()
        .join("\n");
    let r = run_at(&plain, &[&plain], vec![("Plain", FakeDns::start(WEB).await)], now()).await;
    let fs = dnssec_findings(&r);
    assert_eq!(codes(&fs), ["dnssec_not_signed"]);
    assert_eq!(fs[0].severity, Severity::Info);
}

#[tokio::test]
async fn keys_with_no_ds_are_signed_but_not_linked() {
    let z = dnssec_zone(APEX);
    let no_ds: String = z.lines().filter(|l| !l.contains(" DS ")).collect::<Vec<_>>().join("\n");
    let r = run_at(&no_ds, &[&z], vec![("Plain", FakeDns::start(WEB).await)], now()).await;
    assert_eq!(codes(&dnssec_findings(&r)), ["dnssec_ds_missing"]);
}

#[tokio::test]
async fn nameservers_that_all_answer_like_a_forwarder_mean_the_network_intercepts_dns() {
    let mut r = healthy(now()).await;
    for n in &mut r.nameservers {
        (n.authoritative, n.recursion_available) = (false, true);
    }
    let fs = dnssec_findings(&r);
    assert_eq!(code(&fs, "dns_network_intercepts").severity, Severity::Warning);
    assert!(fs.iter().all(|f| f.code != "dnssec_secure"));
}

#[test]
fn the_result_serialises_to_json_without_key_material() {
    let ds = Ds::from_rdata(&[0x09, 0x43, 13, 2, 0xab, 0xcd]).unwrap();
    let json = serde_json::to_value(&ds).unwrap();
    assert_eq!(json["key_tag"], 2371);
    assert_eq!(
        (json["algorithm"].as_str(), json["digest_type"].as_str(), json["digest"].as_str()),
        (Some("ECDSAP256SHA256 (13)"), Some("SHA-256"), Some("abcd"))
    );
}

#[test]
fn the_validating_resolvers_are_the_four_verified_ones() {
    let addrs: Vec<String> = validating_resolvers().iter().map(|v| v.address.to_string()).collect();
    assert_eq!(addrs, ["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53", "208.67.222.222:53"]);
}

// RRSIG validity windows

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Wire RDATA of an RRSIG over SOA with these times.
fn rrsig_rdata(inception: u32, expiration: u32) -> Vec<u8> {
    let mut r = 6u16.to_be_bytes().to_vec();
    r.extend([13, 2]);
    r.extend(300u32.to_be_bytes());
    r.extend(expiration.to_be_bytes());
    r.extend(inception.to_be_bytes());
    r.extend(4242u16.to_be_bytes());
    r.extend([7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
    r.extend([1, 2, 3]);
    r
}

fn soa_rrsig(zone_text: &str) -> Rrsig {
    rdatas(zone_text, RecordType::RRSIG)
        .iter()
        .filter_map(|r| Rrsig::from_rdata(r))
        .find(|s| s.type_covered() == RecordType::SOA)
        .unwrap()
}

/// The cloudflare.com SOA signature: valid 2026-11-08 12:36:21 to 2026-11-10 14:36:21 UTC.
const CF_START: u64 = 1794141381;
const CF_END: u64 = 1794321381;

#[test]
fn a_real_rrsig_is_read_and_checked_against_now() {
    let sig = soa_rrsig(&dnssec_zone("cloudflare.com"));
    assert_eq!(
        (sig.key_tag, sig.algorithm, sig.signer.as_str()),
        (KeyTag(34505), Algorithm::EcdsaP256Sha256, "cloudflare.com.")
    );
    assert_eq!((u64::from(sig.inception), u64::from(sig.expiration)), (CF_START, CF_END));
    assert_eq!(sig.window(at(CF_START + 3600)), SigWindow::Valid { expires_in: (CF_END - CF_START - 3600) as u32 });
    assert_eq!(sig.window(at(CF_END)), SigWindow::Valid { expires_in: 0 }, "valid up to and including the expiration");
    assert_eq!(sig.window(at(CF_END + 90)), SigWindow::Expired { ago: 90 });
    assert_eq!(sig.window(at(CF_START - 60)), SigWindow::NotYetValid { starts_in: 60 });
}

#[test]
fn signature_times_are_serial_numbers_that_wrap_in_2106() {
    // Inception just before the 32-bit wrap, expiration just after it: valid across the wrap.
    let sig = Rrsig::from_rdata(&rrsig_rdata(0xffff_ff00, 0x0000_0100)).unwrap();
    assert_eq!(sig.window(at(0xffff_ffc0)), SigWindow::Valid { expires_in: 0x140 });
    assert_eq!(
        sig.window(at(0x1_0000_0010)),
        SigWindow::Valid { expires_in: 0xf0 },
        "after the wrap, a plain comparison calls this not yet valid"
    );
    assert_eq!(sig.window(at(0x1_0000_0200)), SigWindow::Expired { ago: 0x100 });
    assert_eq!(sig.window(at(0xffff_fe00)), SigWindow::NotYetValid { starts_in: 0x100 });
}

#[test]
fn a_truncated_rrsig_is_rejected() {
    let r = rrsig_rdata(1, 2);
    assert!(Rrsig::from_rdata(&r[..10]).is_none());
    assert!(Rrsig::from_rdata(&r[..22]).is_none(), "the signer name is cut off");
}

#[test]
fn algorithm_numbers_round_trip_and_know_which_are_deprecated() {
    for (n, deprecated) in
        [(1, true), (3, true), (5, true), (6, true), (7, true), (12, true), (8, false), (13, false), (15, false)]
    {
        let a = Algorithm::from_number(n);
        assert_eq!((a.number(), a.deprecated()), (n, deprecated), "{a}");
    }
    assert_eq!(Algorithm::from_number(99), Algorithm::Unknown(99));
    assert_eq!(Algorithm::from_number(13).to_string(), "ECDSAP256SHA256 (13)");
}
