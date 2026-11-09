mod common;

use std::time::Duration;

use common::{FakeDns, dnssec_zone};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RecordType},
};
use zombo_core::dns::{QueryFlags, exchange_with};

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
