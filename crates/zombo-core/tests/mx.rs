#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod common;

use std::time::Duration;

use common::FakeDns;
use zombo_core::resolver::{Mx, Resolver};

async fn mx(zone: &str, name: &str) -> Result<Vec<Mx>, String> {
    let s = FakeDns::start(zone).await;
    Resolver::new(&[s.addr], Duration::from_millis(500)).mx_hosts(name).await
}

fn want(list: &[(u16, &str)]) -> Vec<Mx> {
    list.iter().map(|(p, h)| Mx { preference: *p, host: h.to_string() }).collect()
}

#[tokio::test]
async fn mx_hosts_come_back_lowest_preference_first() {
    let zone = "example.com. 60 IN MX 20 mx2.example.com.\nexample.com. 60 IN MX 10 MX1.Example.com.\nexample.com. 60 IN MX 10 mx0.example.com.\n";
    assert_eq!(
        mx(zone, "example.com").await.unwrap(),
        want(&[(10, "mx0.example.com"), (10, "mx1.example.com"), (20, "mx2.example.com")])
    );
}

#[tokio::test]
async fn a_domain_with_no_mx_has_an_empty_list() {
    assert_eq!(mx("example.com. 60 IN A 192.0.2.1\n", "example.com").await.unwrap(), vec![]);
}

#[tokio::test]
async fn a_null_mx_means_the_domain_takes_no_mail() {
    assert_eq!(mx("example.com. 60 IN MX 0 .\n", "example.com").await.unwrap(), vec![]);
}

#[tokio::test]
async fn a_silent_resolver_is_an_error_not_an_empty_list() {
    let s = FakeDns::silent().await;
    assert!(Resolver::new(&[s.addr], Duration::from_millis(200)).mx_hosts("example.com").await.is_err());
}
