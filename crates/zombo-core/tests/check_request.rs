#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::time::{Duration, SystemTime};

use zombo_core::check::{Request, Seams};

fn assert_production(s: &Seams<'_>) {
    assert_eq!(s.ns_port, 53);
    assert!(s.validating.is_none());
    assert!(s.machine_resolvers.is_none());
    assert!(s.endpoints.is_none());
    assert!(s.pin.is_none());
    assert!(s.http_port.is_none());
    assert!(s.https_port.is_none());
    let age = SystemTime::now().duration_since(s.now).unwrap_or_default();
    assert!(age < Duration::from_secs(5), "{age:?}");
}

#[test]
fn default_seams_are_the_production_values() {
    assert_production(&Seams::default());
}

#[test]
fn the_system_request_uses_the_default_seams() {
    assert_production(&Request::system("example.com", Duration::from_secs(1), &[]).seams);
}
