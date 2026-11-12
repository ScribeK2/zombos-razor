use std::collections::HashSet;

use zombo_core::{
    check::{ALL, find},
    target::Kind,
};

#[test]
fn ids_are_non_empty_unique_and_kebab_case() {
    let mut seen = HashSet::new();
    for check in ALL {
        let id = check.id;
        assert!(!id.is_empty(), "{}", check.label);
        assert!(
            id.split('-').all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())),
            "{id} is not kebab-case"
        );
        assert!(seen.insert(id), "{id} appears twice");
    }
}

/// The ids are what a script types after `zombo run`, so a rename is a breaking change.
#[test]
fn the_ids_are_the_published_ones_in_rail_order() {
    let ids: Vec<_> = ALL.iter().map(|c| c.id).collect();
    assert_eq!(
        ids,
        [
            "delegation",
            "dnssec",
            "email",
            "web",
            "tls",
            "registration",
            "rdns",
            "ports",
            "smtp",
            "tls-port",
            "blacklist"
        ]
    );
}

#[test]
fn every_check_accepts_a_kind_and_runs_on_what_it_accepts() {
    for check in ALL {
        assert!(!check.accepts.is_empty(), "{}", check.id);
        for kind in check.automatic_for {
            assert!(check.accepts.contains(kind), "{} runs by itself on a kind it does not accept", check.id);
        }
    }
}

#[test]
fn every_on_demand_check_accepts_an_ip() {
    for check in ALL.iter().filter(|c| c.is_on_demand()) {
        assert!(check.accepts.contains(&Kind::Ip), "{}", check.id);
    }
}

#[test]
fn find_returns_the_descriptor_of_an_id() {
    for check in ALL {
        assert!(std::ptr::eq(find(check.id).expect(check.id), *check), "{}", check.id);
    }
    assert!(find("no-such-check").is_none());
    assert!(find("").is_none());
}
