#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
//! `zombo run` and `zombo checks` as a person runs them: the real binary, no real network.
use std::process::{Command, Output};

use zombo_core::check::ALL;

fn zombo(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zombo")).args(args).output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

const OLD: [&str; 13] = [
    "delegation",
    "registration",
    "dnssec",
    "email",
    "web",
    "blacklist",
    "rdns",
    "evidence",
    "tls",
    "smtp",
    "caa",
    "ports",
    "propagation",
];

#[test]
fn checks_lists_every_id_in_registry_order() {
    let o = zombo(&["checks"]);
    assert!(o.status.success(), "{o:?}");
    let text = out(&o);
    let ids: Vec<_> = text.lines().map(|l| l.split_whitespace().next().unwrap()).collect();
    assert_eq!(ids, ALL.iter().map(|c| c.id).collect::<Vec<_>>());
    assert_eq!(ids.len(), 11);
    // Both ways to run, and a limit, are readable on the line.
    let smtp = text.lines().find(|l| l.starts_with("smtp")).unwrap();
    assert!(smtp.contains("on demand") && smtp.contains("40s"), "{smtp}");
    let dnssec = text.lines().find(|l| l.starts_with("dnssec")).unwrap();
    assert!(dnssec.contains("automatic") && dnssec.contains("4s") && dnssec.contains("20s"), "{dnssec}");
}

#[test]
fn checks_json_is_an_array_with_the_registry_ids_and_fields() {
    let o = zombo(&["checks", "--json"]);
    assert!(o.status.success(), "{o:?}");
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let rows = v.as_array().unwrap();
    let ids: Vec<_> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ALL.iter().map(|c| c.id).collect::<Vec<_>>());
    let smtp = rows.iter().find(|r| r["id"] == "smtp").unwrap();
    assert_eq!(smtp["label"], "SMTP banner");
    assert_eq!(smtp["automatic"], false);
    assert_eq!(smtp["accepts"], serde_json::json!(["domain", "hostname", "email", "ip"]));
    assert_eq!((smtp["query_secs"].as_f64(), smtp["whole_secs"].as_f64()), (None, Some(40.0)));
    let dnssec = rows.iter().find(|r| r["id"] == "dnssec").unwrap();
    assert_eq!(dnssec["automatic"], true);
}

#[test]
fn the_usage_lists_the_old_subcommands_and_the_new_ones() {
    for args in [&[][..], &["nope"][..]] {
        let o = zombo(args);
        assert!(!o.status.success());
        let e = err(&o);
        for name in OLD.iter().copied().chain(["run", "checks"]) {
            assert!(e.contains(&format!("zombo {name} ")) || e.contains(&format!("zombo {name}\n")), "{name}: {e}");
        }
    }
}

#[test]
fn an_unknown_id_fails_and_lists_the_known_ids() {
    let o = zombo(&["run", "nope", "example.com"]);
    assert!(!o.status.success());
    let e = err(&o);
    assert!(e.starts_with("zombo: unknown check \"nope\""), "{e}");
    for c in ALL {
        assert!(e.contains(c.id), "{}: {e}", c.id);
    }
}

#[test]
fn a_target_the_check_does_not_accept_fails_with_the_reason() {
    let o = zombo(&["run", "dnssec", "192.0.2.1"]);
    assert!(!o.status.success());
    assert_eq!(err(&o), "zombo: dnssec does not run on an IP address\n");
}

#[test]
fn a_port_for_a_check_that_takes_none_fails_with_the_reason() {
    let o = zombo(&["run", "dnssec", "example.com", "--port", "53"]);
    assert!(!o.status.success());
    assert_eq!(err(&o), "zombo: dnssec does not take a port\n");
}

#[test]
fn ports_on_loopback_prints_one_flat_json_object() {
    let o = zombo(&["run", "ports", "127.0.0.1", "--json"]);
    assert!(o.status.success(), "{o:?}");
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let mut keys: Vec<_> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["check", "details", "details_title", "facts", "findings", "target"]);
    assert_eq!((v["check"].as_str(), v["target"].as_str()), (Some("ports"), Some("127.0.0.1")));
    assert!(v["facts"].is_array() && v["details"].is_array() && v["findings"].is_array());
    assert!(v["details_title"].is_string());
}

#[test]
fn ports_on_loopback_prints_the_heading_first_in_text() {
    let o = zombo(&["run", "ports", "127.0.0.1"]);
    assert!(o.status.success(), "{o:?}");
    assert!(out(&o).starts_with("Port scan for 127.0.0.1\n\n"), "{}", out(&o));
}

#[test]
fn a_dead_loopback_resolver_ends_the_run_quickly_with_the_check_named() {
    let t = std::time::Instant::now();
    let o = zombo(&["run", "rdns", "127.0.0.1", "--resolver", "127.0.0.1:1", "--timeout-ms", "200"]);
    assert!(t.elapsed() < std::time::Duration::from_secs(10), "{:?}", t.elapsed());
    // Nothing listens on port 1, so the Check reports a finding: that is an outcome, not a failure.
    assert!(o.status.success(), "{o:?}");
    assert!(out(&o).starts_with("Reverse DNS for 127.0.0.1\n\n"), "{}", out(&o));
    assert!(out(&o).contains("[WARNING]"), "{}", out(&o));
}

#[test]
fn every_flag_of_run_is_accepted_and_an_unknown_one_is_refused() {
    let o = zombo(&[
        "run",
        "dnssec",
        "192.0.2.1",
        "--selector",
        "a",
        "--selector",
        "b",
        "--resolver",
        "127.0.0.1:1",
        "--resolver",
        "127.0.0.2:1",
        "--timeout-ms",
        "5",
        "--json",
    ]);
    // The flags parse; the run then fails on the target, not on an option.
    assert_eq!(err(&o), "zombo: dnssec does not run on an IP address\n");
    let o = zombo(&["run", "dnssec", "example.com", "--bogus"]);
    assert!(!o.status.success());
    assert!(err(&o).starts_with("zombo: unknown option --bogus\nusage: zombo run <id> <target>"), "{}", err(&o));
    for args in [&["run"][..], &["run", "dnssec"][..], &["run", "dnssec", "a.com", "b.com"][..]] {
        let o = zombo(args);
        assert!(!o.status.success());
        assert!(err(&o).starts_with("zombo: usage: zombo run <id> <target>"), "{args:?}: {}", err(&o));
    }
    for args in [&["--port", "x"][..], &["--timeout-ms"][..], &["--resolver", "nope"][..]] {
        let all: Vec<_> = ["run", "dnssec", "example.com"].into_iter().chain(args.iter().copied()).collect();
        assert!(!zombo(&all).status.success(), "{all:?}");
    }
}

/// A UDP socket that records what a run sends to it as its resolver, and never answers.
fn silent_resolver() -> (std::net::SocketAddr, std::sync::mpsc::Receiver<Vec<u8>>) {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, _)) = sock.recv_from(&mut buf) {
            if tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    (addr, rx)
}

fn has(packet: &[u8], needle: &str) -> bool {
    packet.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn selectors_and_resolvers_reach_the_check() {
    let (a, rx_a) = silent_resolver();
    let (b, rx_b) = silent_resolver();
    let (a, b) = (a.to_string(), b.to_string());
    let o = zombo(&[
        "run",
        "email",
        "example.com",
        "--selector",
        "zzfirst",
        "--selector",
        "zzsecond",
        "--resolver",
        &a,
        "--resolver",
        &b,
        "--timeout-ms",
        "300",
    ]);
    drop(o);
    // The recorder threads may lag the exited process by a moment.
    let drain = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
        std::iter::from_fn(move || rx.recv_timeout(std::time::Duration::from_millis(300)).ok()).collect::<Vec<_>>()
    };
    let sent: Vec<_> = drain(rx_a).into_iter().chain(drain(rx_b)).collect();
    assert!(sent.iter().any(|p| has(p, "zzfirst")), "no query for the first selector");
    assert!(sent.iter().any(|p| has(p, "zzsecond")), "no query for the second selector");
    assert!(sent.iter().all(|p| has(p, "example")), "a query for another name");
}

#[test]
fn the_port_and_the_timeout_reach_the_check() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let t = std::time::Instant::now();
    // The listener accepts and never speaks, so the run ends on its limit: the default 8 s one would take far longer than 200 ms.
    let o = zombo(&["run", "tls-port", "127.0.0.1", "--port", &port, "--timeout-ms", "200"]);
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(err(&o), "zombo: timed out\n");
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_ok(), "the run did not dial the chosen port");
}

#[test]
fn a_flag_the_check_does_not_honour_fails_naming_the_flag() {
    let o = zombo(&["run", "blacklist", "127.0.0.2", "--timeout-ms", "300"]);
    assert!(!o.status.success());
    assert_eq!(err(&o), "zombo: blacklist does not take --timeout-ms\n");
    let o = zombo(&["run", "ports", "127.0.0.1", "--resolver", "127.0.0.1:9"]);
    assert!(!o.status.success());
    assert_eq!(err(&o), "zombo: ports does not take --resolver\n");
    let o = zombo(&["run", "rdns", "127.0.0.1", "--selector", "x"]);
    assert_eq!(err(&o), "zombo: rdns does not take --selector\n");
}

#[test]
fn checks_json_lists_the_flags_and_no_query_limit_for_a_check_that_ignores_it() {
    let o = zombo(&["checks", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let rows = v.as_array().unwrap();
    let row = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap();
    assert_eq!(row("email")["flags"], serde_json::json!(["timeout-ms", "resolver", "selector"]));
    assert_eq!(row("tls-port")["flags"], serde_json::json!(["timeout-ms", "port"]));
    assert_eq!(row("smtp")["flags"], serde_json::json!(["resolver", "port"]));
    assert_eq!(row("ports")["flags"], serde_json::json!([]));
    let no_query: Vec<_> =
        rows.iter().filter(|r| r["query_secs"].is_null()).map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(no_query, ["ports", "smtp", "blacklist"]);
    for r in rows {
        let takes_timeout = r["flags"].as_array().unwrap().iter().any(|f| f == "timeout-ms");
        assert_eq!(!r["query_secs"].is_null(), takes_timeout, "{}", r["id"]);
    }
}

#[test]
fn checks_text_shows_the_flags_and_a_dash_for_a_limit_that_does_not_apply() {
    let text = out(&zombo(&["checks"]));
    let line = |id: &str| text.lines().find(|l| l.starts_with(id)).unwrap().to_string();
    assert!(line("email").contains("--timeout-ms --resolver --selector"), "{}", line("email"));
    assert!(line("tls-port").contains("--timeout-ms --port"), "{}", line("tls-port"));
    assert!(line("blacklist").contains("--resolver") && !line("blacklist").contains("--timeout-ms"));
    assert!(!line("blacklist").contains("per query") && !line("ports").contains("per query"));
}

#[test]
fn the_usage_says_a_flag_a_check_does_not_use_is_refused() {
    let e = err(&zombo(&["run"]));
    assert!(e.contains("refused") && e.contains("zombo checks"), "{e}");
}
