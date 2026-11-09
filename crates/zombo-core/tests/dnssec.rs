mod common;

use std::time::Duration;

use common::{FakeDns, dnssec_zone, rdatas};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RecordType},
};
use zombo_core::{
    dns::{QueryFlags, exchange_with},
    dnssec::{Algorithm, DigestType, Dnskey, Ds, KeyTag},
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
    assert_eq!(ask(&bogus, "example.com", RecordType::A, true, false).await.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(ask(&bogus, "example.com", RecordType::A, true, true).await.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn the_do_bit_is_sent_when_asked_for() {
    let s = FakeDns::start(&dnssec_zone("cloudflare.com")).await.validating();
    let (with, without) = (ask(&s, "cloudflare.com", RecordType::SOA, true, false).await, ask(&s, "cloudflare.com", RecordType::SOA, false, false).await);
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
    assert_eq!(hex(DigestType::Sha384), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    assert!(DigestType::from_number(3).digest(b"abc").is_none(), "GOST is not computed");
}

#[test]
fn algorithm_numbers_round_trip_and_know_which_are_deprecated() {
    for (n, deprecated) in [(1, true), (3, true), (5, true), (6, true), (7, true), (12, true), (8, false), (13, false), (15, false)] {
        let a = Algorithm::from_number(n);
        assert_eq!((a.number(), a.deprecated()), (n, deprecated), "{a}");
    }
    assert_eq!(Algorithm::from_number(99), Algorithm::Unknown(99));
    assert_eq!(Algorithm::from_number(13).to_string(), "ECDSAP256SHA256 (13)");
}
