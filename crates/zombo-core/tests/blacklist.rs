mod common;
#[path = "common/scripted.rs"]
mod scripted;

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use common::{FakeDns, zone};
use hickory_proto::rr::RecordType;
use scripted::{Reply, a, cname, serve};
use zombo_core::{
    Finding, Severity,
    blacklist::{BlacklistResult, Options, State, blacklist_findings, check_blacklist},
};

const T: Duration = Duration::from_millis(500);

fn zen_listing() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/blacklist/zen_listing.zone");
    std::fs::read_to_string(p).unwrap()
}

fn opts() -> Options {
    Options { query_timeout: T, overall: Duration::from_secs(10) }
}

async fn run_on(server: SocketAddr, target: &str) -> (BlacklistResult, Vec<Finding>) {
    let r = check_blacklist(&[server], target, opts()).await;
    let f = blacklist_findings(target, &r);
    (r, f)
}

async fn run(zone_text: &str, target: &str) -> (BlacklistResult, Vec<Finding>) {
    run_on(FakeDns::start(zone_text).await.addr, target).await
}

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

fn find<'a>(fs: &'a [Finding], code: &str) -> Option<&'a Finding> {
    fs.iter().find(|f| f.code == code)
}

#[tokio::test]
async fn reports_a_listing_with_its_reason_and_delist_link() {
    let (r, fs) = run(&zen_listing(), "203.0.113.7").await;
    let lists = &r.subjects["203.0.113.7"].lists;
    let zen = &lists["Spamhaus ZEN"];
    assert_eq!((zen.state, zen.codes[0].as_str()), (State::Listed, "127.0.0.2"));
    assert!(zen.reason.contains("SBL1"), "{zen:?}");
    assert_eq!(lists["SpamCop"].state, State::Clean);
    assert_eq!(lists.len(), 8);
    assert!(!lists.contains_key("Spamhaus DBL"), "an IP was checked against a domain list");
    let f = find(&fs, "blacklist_listed").expect("a listing finding");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.message.contains("Spamhaus ZEN") && f.message.contains("SBL1") && f.message.contains(": SBL)"), "{}", f.message);
    assert!(f.recommendation.as_deref().unwrap().contains("https://check.spamhaus.org/"));
    assert!(find(&fs, "blacklist_clean").is_none(), "a listed address was also called clean: {:?}", codes(&fs));
}

#[tokio::test]
async fn severity_follows_the_list() {
    let (_, fs) = run("7.113.0.203.psbl.surriel.com. 300 IN A 127.0.0.2\n7.113.0.203.dnsbl-1.uceprotect.net. 300 IN A 127.0.0.2", "203.0.113.7").await;
    let sev = |title: &str| fs.iter().find(|f| f.title == title).map(|f| f.severity);
    assert_eq!(sev("203.0.113.7 listed on PSBL"), Some(Severity::Warning));
    assert_eq!(sev("203.0.113.7 listed on UCEPROTECT Level 1"), Some(Severity::Info));
}

#[tokio::test]
async fn a_refused_query_is_neither_listed_nor_clean() {
    let (r, fs) = run("7.113.0.203.zen.spamhaus.org. 300 IN A 127.255.255.254", "203.0.113.7").await;
    assert_eq!(r.subjects["203.0.113.7"].lists["Spamhaus ZEN"].state, State::Refused);
    assert!(find(&fs, "blacklist_listed").is_none(), "refusal reported as a listing: {fs:?}");
    let f = find(&fs, "blacklist_refused").expect("a refusal finding");
    assert_eq!(f.severity, Severity::Info);
    assert!(f.message.contains("public resolvers"));
    let ok = find(&fs, "blacklist_clean").expect("the other lists answered");
    assert!(ok.message.contains("7 lists"), "the clean count must leave out the refusing list: {}", ok.message);
}

/// Spamhaus answers a query from an open resolver with 127.255.255.x; none of them is a listing.
#[tokio::test]
async fn every_127_255_255_answer_is_a_refusal_not_a_listing() {
    for code in ["127.255.255.1", "127.255.255.252", "127.255.255.254", "127.255.255.255"] {
        let (r, fs) = run(&format!("7.113.0.203.zen.spamhaus.org. 300 IN A {code}"), "203.0.113.7").await;
        let zen = &r.subjects["203.0.113.7"].lists["Spamhaus ZEN"];
        assert_eq!((zen.state, zen.codes.as_slice()), (State::Refused, [code.to_string()].as_slice()), "{code}");
        assert!(find(&fs, "blacklist_listed").is_none(), "{code}: {fs:?}");
    }
}

#[tokio::test]
async fn a_neighbouring_range_is_still_a_listing() {
    for code in ["127.255.254.2", "127.254.255.2", "127.0.0.2"] {
        let (r, _) = run(&format!("7.113.0.203.zen.spamhaus.org. 300 IN A {code}"), "203.0.113.7").await;
        assert_eq!(r.subjects["203.0.113.7"].lists["Spamhaus ZEN"].state, State::Listed, "{code}");
    }
}

#[tokio::test]
async fn a_refusal_wins_over_a_listing_in_the_same_reply() {
    let server = serve(|name, t| match (name, t) {
        ("7.113.0.203.zen.spamhaus.org", RecordType::A) => Reply::Answers(vec![a(name, "127.0.0.2"), a(name, "127.255.255.254")]),
        _ => Reply::NxDomain,
    })
    .await;
    let (r, fs) = run_on(server, "203.0.113.7").await;
    assert_eq!(r.subjects["203.0.113.7"].lists["Spamhaus ZEN"].state, State::Refused);
    assert!(find(&fs, "blacklist_listed").is_none());
}

#[tokio::test]
async fn checks_a_domains_mail_hosts_and_the_domain() {
    let text = format!("{}\nmail.example.com. 300 IN A 203.0.113.7\n{}\nexample.com.dbl.spamhaus.org. 300 IN A 127.0.1.2", zone("example"), zen_listing());
    let (r, fs) = run(&text, "example.com").await;
    let ip = &r.subjects["203.0.113.7"];
    assert_eq!((ip.source.as_str(), ip.lists["Spamhaus ZEN"].state), ("MX mail.example.com", State::Listed));
    assert!(!r.subjects.contains_key("93.184.216.34"), "the domain's own A record was checked although it has MX hosts");
    let dom = &r.subjects["example.com"];
    assert_eq!((dom.lists["Spamhaus DBL"].state, dom.lists["SURBL"].state, dom.lists.len()), (State::Listed, State::Clean, 2));
    assert_eq!(fs.iter().filter(|f| f.code == "blacklist_listed").count(), 2, "one finding per listing: {fs:?}");
    let zen = fs.iter().find(|f| f.title == "203.0.113.7 listed on Spamhaus ZEN").unwrap();
    assert!(zen.message.starts_with("203.0.113.7 (MX mail.example.com) is listed on"), "{}", zen.message);
}

#[tokio::test]
async fn falls_back_to_the_domains_address_without_mx() {
    let (r, _) = run("example.com. 300 IN A 198.51.100.1", "example.com").await;
    assert_eq!(r.subjects["198.51.100.1"].source, "A record of example.com");
}

#[tokio::test]
async fn caps_the_addresses_it_checks() {
    let mut text = "example.com. 300 IN MX 10 mail.example.com.\n".to_string();
    for last in 1..=7 {
        text += &format!("mail.example.com. 300 IN A 198.51.100.{last}\n");
    }
    let (r, _) = run(&text, "example.com").await;
    assert_eq!(r.subjects.len(), 6, "5 addresses plus the domain");
}

#[tokio::test]
async fn warns_when_a_domain_has_no_addresses() {
    let (r, fs) = run("example.com. 300 IN TXT \"v=spf1 -all\"", "example.com").await;
    assert_eq!(r.subjects["example.com"].lists.len(), 2, "the domain lists are still checked");
    assert_eq!(find(&fs, "blacklist_no_addresses").map(|f| f.severity), Some(Severity::Warning));
}

#[tokio::test]
async fn surbls_127_0_0_1_is_a_refusal() {
    let (r, fs) = run("example.com.multi.surbl.org. 300 IN A 127.0.0.1", "example.com").await;
    assert_eq!(r.subjects["example.com"].lists["SURBL"].state, State::Refused);
    assert!(find(&fs, "blacklist_listed").is_none());
}

#[tokio::test]
async fn does_not_check_the_website_of_a_domain_that_takes_no_mail() {
    let (r, fs) = run("example.com. 300 IN MX 0 .\nexample.com. 300 IN A 198.51.100.1", "example.com").await;
    assert!(!r.subjects.contains_key("198.51.100.1"), "a null MX fell back to the A record: {:?}", r.subjects.keys());
    assert!(find(&fs, "blacklist_no_addresses").unwrap().message.contains("null MX"));
}

#[tokio::test]
async fn skips_ipv6_without_calling_it_clean() {
    let (r, fs) = run("", "2001:db8::1").await;
    assert!(r.ipv6 && r.subjects.is_empty());
    assert_eq!(codes(&fs), ["blacklist_ipv6"]);
}

#[tokio::test]
async fn pbl_is_a_policy_warning_not_critical() {
    let (_, fs) = run("7.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.10", "203.0.113.7").await;
    let f = find(&fs, "blacklist_listed").unwrap();
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.message.contains("not an abuse listing") && f.message.contains(": PBL)"), "{}", f.message);
}

#[tokio::test]
async fn a_mixed_pbl_and_sbl_listing_stays_critical() {
    let (_, fs) = run("7.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.10\n7.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.2", "203.0.113.7").await;
    assert_eq!(find(&fs, "blacklist_listed").unwrap().severity, Severity::Critical);
}

#[tokio::test]
async fn timeouts_are_unknown_not_clean() {
    let s = FakeDns::silent().await;
    let started = Instant::now();
    let (r, fs) = run_on(s.addr, "203.0.113.7").await;
    assert_eq!(r.subjects["203.0.113.7"].lists["Spamhaus ZEN"].state, State::Unknown);
    assert!(find(&fs, "blacklist_clean").is_none(), "timeouts called clean: {:?}", codes(&fs));
    assert_eq!(find(&fs, "blacklist_unknown").map(|f| f.severity), Some(Severity::Warning));
    assert!(started.elapsed() < Duration::from_secs(3), "the lists were asked one after another: {:?}", started.elapsed());
}

#[tokio::test]
async fn one_silent_blocklist_does_not_delay_the_others() {
    let server = serve(|name, _| if name.ends_with(".zen.spamhaus.org") { Reply::Silent } else { Reply::NxDomain }).await;
    let started = Instant::now();
    let (r, fs) = run_on(server, "203.0.113.7").await;
    let lists = &r.subjects["203.0.113.7"].lists;
    assert_eq!(lists["Spamhaus ZEN"].state, State::Unknown, "a silent list is unreachable, not clean");
    assert!(lists.iter().filter(|(n, _)| *n != "Spamhaus ZEN").all(|(_, v)| v.state == State::Clean));
    let unknown = find(&fs, "blacklist_unknown").expect("the silent list is reported");
    assert!(unknown.message.contains("Spamhaus ZEN for 203.0.113.7"), "{}", unknown.message);
    assert_eq!(unknown.severity, Severity::Info, "other lists answered");
    assert!(find(&fs, "blacklist_clean").unwrap().message.contains("7 lists"));
    assert!(started.elapsed() < T * 3, "{:?}", started.elapsed());
}

#[tokio::test]
async fn the_overall_deadline_ends_the_wait_and_reports_unanswered_lists() {
    let s = FakeDns::silent().await;
    let o = Options { query_timeout: Duration::from_secs(30), overall: Duration::from_millis(300) };
    let started = Instant::now();
    let r = check_blacklist(&[s.addr], "203.0.113.7", o).await;
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    let lists = &r.subjects["203.0.113.7"].lists;
    assert_eq!(lists.len(), 8);
    assert!(lists.values().all(|v| v.state == State::Unknown && !v.error.is_empty()));
}

#[tokio::test]
async fn a_second_resolver_is_tried_when_the_first_gives_no_answer() {
    let dead = FakeDns::silent().await;
    let live = FakeDns::start(&zen_listing()).await;
    let r = check_blacklist(&[dead.addr, live.addr], "203.0.113.7", Options { query_timeout: Duration::from_millis(200), overall: Duration::from_secs(10) }).await;
    assert_eq!(r.subjects["203.0.113.7"].lists["Spamhaus ZEN"].state, State::Listed);
}

// Hostile replies.

#[tokio::test]
async fn a_reply_with_no_answers_is_clean() {
    let server = serve(|_, _| Reply::Answers(vec![])).await;
    let (r, fs) = run_on(server, "203.0.113.7").await;
    assert!(r.subjects["203.0.113.7"].lists.values().all(|v| v.state == State::Clean));
    assert_eq!(codes(&fs), ["blacklist_clean"]);
}

#[tokio::test]
async fn an_alias_with_no_address_is_unknown_not_clean() {
    let server = serve(|name, t| match t {
        RecordType::A => Reply::Answers(vec![cname(name, "elsewhere.test")]),
        _ => Reply::NxDomain,
    })
    .await;
    let (r, fs) = run_on(server, "203.0.113.7").await;
    let lists = &r.subjects["203.0.113.7"].lists;
    assert!(lists.values().all(|v| v.state == State::Unknown), "{lists:?}");
    assert!(find(&fs, "blacklist_clean").is_none());
}

#[tokio::test]
async fn an_alias_followed_by_a_listing_address_is_a_listing() {
    let server = serve(|name, t| match (name, t) {
        ("7.113.0.203.zen.spamhaus.org", RecordType::A) => Reply::Answers(vec![cname(name, "x.zen.spamhaus.org"), a("x.zen.spamhaus.org", "127.0.0.4")]),
        _ => Reply::NxDomain,
    })
    .await;
    let (r, _) = run_on(server, "203.0.113.7").await;
    assert_eq!(r.subjects["203.0.113.7"].lists["Spamhaus ZEN"].state, State::Listed);
}

#[tokio::test]
async fn an_address_outside_127_8_means_the_resolver_rewrites_answers() {
    let (r, fs) = run("7.113.0.203.zen.spamhaus.org. 300 IN A 192.0.2.1", "203.0.113.7").await;
    let zen = &r.subjects["203.0.113.7"].lists["Spamhaus ZEN"];
    assert_eq!(zen.state, State::Unknown);
    assert!(zen.error.contains("rewriting answers"), "{}", zen.error);
    assert!(find(&fs, "blacklist_listed").is_none());
}

#[tokio::test]
async fn a_flood_of_listing_codes_is_bounded() {
    let server = serve(|name, t| match (name, t) {
        ("7.113.0.203.zen.spamhaus.org", RecordType::A) => Reply::Answers((2..120).map(|i| a(name, &format!("127.0.0.{i}"))).collect()),
        _ => Reply::NxDomain,
    })
    .await;
    let (r, _) = run_on(server, "203.0.113.7").await;
    assert_eq!(r.subjects["203.0.113.7"].lists["Spamhaus ZEN"].codes.len(), 16);
}

#[tokio::test]
async fn a_huge_txt_reason_is_cut_short() {
    let chunk = "A".repeat(250);
    let strings = vec![format!("\"{chunk}\""); 200].join(" "); // 50 KB, which only fits over TCP
    let text = format!("7.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.2\n7.113.0.203.zen.spamhaus.org. 300 IN TXT {strings}");
    let (r, fs) = run(&text, "203.0.113.7").await;
    let zen = &r.subjects["203.0.113.7"].lists["Spamhaus ZEN"];
    assert_eq!(zen.state, State::Listed);
    assert!(zen.reason.ends_with("...") && zen.reason.chars().count() <= 303, "{}", zen.reason.len());
    assert!(find(&fs, "blacklist_listed").unwrap().message.len() < 1000);
}

#[tokio::test]
async fn control_characters_in_a_reason_do_not_reach_the_message() {
    let (r, fs) = run("7.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.2\n7.113.0.203.zen.spamhaus.org. 300 IN TXT \"bad\\007reason\\027x\"", "203.0.113.7").await;
    let zen = &r.subjects["203.0.113.7"].lists["Spamhaus ZEN"];
    assert!(zen.reason.contains("reason") && !zen.reason.chars().any(char::is_control), "{:?}", zen.reason);
    assert!(!find(&fs, "blacklist_listed").unwrap().message.chars().any(char::is_control));
}

#[tokio::test]
async fn a_flood_of_mx_hosts_is_bounded() {
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    let server = serve(move |name, t| match t {
        RecordType::MX if name == "example.com" => Reply::Answers((0..60).map(|i| scripted::mx(name, i, &format!("m{i}.example.com"))).collect()),
        RecordType::A if name.starts_with('m') => {
            counter.fetch_add(1, Ordering::SeqCst);
            Reply::Answers(vec![a(name, "198.51.100.9")])
        }
        _ => Reply::NxDomain,
    })
    .await;
    let (r, _) = run_on(server, "example.com").await;
    assert_eq!(asked.load(Ordering::SeqCst), 10, "only the ten most preferred hosts are resolved");
    assert_eq!(r.subjects.len(), 2, "one distinct address plus the domain");
}

#[tokio::test]
async fn at_most_ten_questions_are_in_flight() {
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    let server = serve(move |name, t| match t {
        RecordType::MX if name == "example.com" => Reply::Answers(vec![scripted::mx(name, 10, "mail.example.com")]),
        RecordType::A if name == "mail.example.com" => Reply::Answers((1..=5).map(|i| a(name, &format!("198.51.100.{i}"))).collect()),
        _ => {
            counter.fetch_add(1, Ordering::SeqCst);
            Reply::Silent
        }
    })
    .await;
    let o = Options { query_timeout: Duration::from_secs(30), overall: Duration::from_millis(400) };
    let r = check_blacklist(&[server], "example.com", o).await;
    assert_eq!(r.subjects.len(), 6);
    assert_eq!(asked.load(Ordering::SeqCst), 10, "42 questions are wanted; only ten may be out at once");
}
