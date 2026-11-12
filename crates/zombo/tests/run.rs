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
    assert_eq!((smtp["query_secs"].as_f64(), smtp["whole_secs"].as_f64()), (Some(40.0), Some(40.0)));
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
