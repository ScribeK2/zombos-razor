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
        for name in OLD.iter().copied().chain(["checks"]) {
            assert!(e.contains(&format!("zombo {name} ")) || e.contains(&format!("zombo {name}\n")), "{name}: {e}");
        }
    }
}
