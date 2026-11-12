//! The Port scan Check as the UI runs it. `QUICK` holds real ports and `Timing` real delays, so the
//! tests dial `127.0.0.1`, where a closed port refuses at once. The machine running the tests may
//! have some `QUICK` ports open, so each test first asks the machine which ones answer and expects
//! exactly that. The test that opens 3306 itself skips when it cannot bind it. The tests that
//! dial take one lock, so that none sees another's listener.

use std::{net::SocketAddr, time::Duration};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request},
    ports::{CHECK, QUICK},
};

static LOOPBACK: Mutex<()> = Mutex::const_new(());
const T: Duration = Duration::from_millis(500);

fn rows(o: &Outcome) -> Vec<String> {
    o.facts.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

/// The rows the scan of `127.0.0.1` must give, given which `QUICK` ports answer. A greeting that an
/// open mail or SSH port adds to its row is left out, as it belongs to the software on the machine.
async fn expected_rows(also_open: Option<u16>) -> (Vec<String>, usize) {
    let mut rows = vec!["Addresses probed: 127.0.0.1".to_string()];
    let mut open = 0;
    for p in QUICK {
        let up = Some(p.port) == also_open || TcpStream::connect(("127.0.0.1", p.port)).await.is_ok();
        open += usize::from(up);
        let state = if up { "open" } else { "closed (refused)" };
        rows.push(format!("Port {} {}: {state} on 127.0.0.1", p.port, p.service));
    }
    (rows, open)
}

fn without_banners(rows: &[String]) -> Vec<String> {
    rows.iter().map(|r| r.split(", banner:").next().unwrap_or(r).to_string()).collect()
}

#[tokio::test]
async fn every_quick_port_of_the_loopback_gets_a_row_with_the_state_the_machine_gives_it() {
    let _lock = LOOPBACK.lock().await;
    let (expected, open) = expected_rows(None).await;
    let o = CHECK.run(&Request::system("127.0.0.1", T, &[])).await.unwrap();
    assert_eq!(without_banners(&rows(&o)), expected);
    assert!(o.details.is_empty() && o.details_title.is_empty());
    if open == 0 {
        assert_eq!(found(&o), [("hosting_reachability_unreachable", Severity::Critical)]);
        assert!(o.findings[0].message.contains("every one actively refused"), "{}", o.findings[0].message);
    } else {
        assert_eq!(found(&o).last(), Some(&("hosting_reachability_reachable", Severity::Ok)));
    }
}

#[tokio::test]
async fn an_open_port_is_a_row_and_a_database_port_is_called_out() {
    let _lock = LOOPBACK.lock().await;
    // 3306 is the one QUICK port a user may bind: it is above 1023.
    let Ok(_listener) = TcpListener::bind("127.0.0.1:3306").await else {
        eprintln!("skipped: cannot bind 127.0.0.1:3306");
        return;
    };
    let (expected, _) = expected_rows(Some(3306)).await;
    let o = CHECK.run(&Request::system("127.0.0.1", T, &[])).await.unwrap();
    assert_eq!(without_banners(&rows(&o)), expected);
    assert!(rows(&o).contains(&"Port 3306 MySQL: open on 127.0.0.1".to_string()));
    let codes = found(&o);
    assert!(codes.contains(&("hosting_reachability_database_exposed", Severity::Warning)), "{codes:?}");
    assert_eq!(codes.last(), Some(&("hosting_reachability_reachable", Severity::Ok)));
    assert!(!codes.iter().any(|(c, _)| *c == "hosting_reachability_unreachable"));
}

#[tokio::test]
async fn a_name_that_cannot_resolve_gives_the_resolve_error_text() {
    // A label over 63 bytes is refused by the system resolver before it asks the network.
    let name = format!("{}.example", "a".repeat(64));
    let err = CHECK.run(&Request::system(&name, T, &[])).await.unwrap_err();
    assert!(err.starts_with(&format!("could not resolve {name}: ")), "{err}");
    assert!(!err.ends_with("timed out"), "{err}");
}

#[tokio::test]
async fn a_zero_query_timeout_neither_cuts_the_lookup_short_nor_makes_a_dial_answer_no_answer() {
    let _lock = LOOPBACK.lock().await;
    // Only a stalled lookup would show the 4 s limit, and no local test can stall one: this proves just
    // that a zero query does not turn a local failure into "timed out".
    let name = format!("{}.example", "a".repeat(64));
    let err = CHECK.run(&Request::system(&name, Duration::ZERO, &[])).await.unwrap_err();
    assert!(!err.ends_with("timed out"), "the request's query timeout limited the lookup: {err}");
    // An address needs no lookup, and a zero query still lets every dial answer.
    let o = CHECK.run(&Request::system("127.0.0.1", Duration::ZERO, &[])).await.unwrap();
    assert_eq!(o.facts.len(), 1 + QUICK.len());
    let answered = |f: &Fact| f.value.starts_with("open on 127.0.0.1") || f.value == "closed (refused) on 127.0.0.1";
    assert!(o.facts[1..].iter().all(answered), "{:?}", rows(&o));
}

#[test]
fn the_descriptor_runs_only_on_demand_with_its_own_label_prefix_and_default_limits() {
    assert_eq!(CHECK.label, "Port scan");
    assert!(CHECK.automatic_for.is_empty() && CHECK.is_on_demand() && !CHECK.takes_chosen_port);
    assert_eq!(CHECK.budget, (Duration::from_secs(20), Duration::from_secs(4)));
    assert_eq!(CHECK.owns, ["hosting_reachability_"]);
    assert_eq!(CHECK.blind_spots.len(), 4);
    let brief = CHECK.on_demand.unwrap();
    assert_eq!(brief.run_label, "Run port scan");
    assert!(brief.what.starts_with("Tries to open a connection"));
    assert!(brief.note.unwrap().starts_with("A port that gives no answer is reported as no answer"));
}

#[test]
fn the_brief_lists_the_ports_of_the_quick_table() {
    let list = QUICK.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ");
    let contacts = CHECK.on_demand.unwrap().contacts;
    assert!(contacts.starts_with(&format!("The target's own servers, on TCP ports {list}: ")), "{contacts}");
}

/// Reads the real resolver and the real network. Run on a network that does not intercept DNS:
/// `cargo test -p zombo-core --test check_ports -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_host_gives_a_row_or_the_resolve_error_text() {
    match CHECK.run(&Request::system("example.com", Duration::from_secs(4), &[] as &[SocketAddr])).await {
        Ok(o) => assert!(!o.facts.is_empty()),
        Err(e) => assert!(e.starts_with("could not resolve example.com: "), "{e}"),
    }
}
