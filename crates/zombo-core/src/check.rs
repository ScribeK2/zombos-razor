//! What every Check hands back, in one shape. The UI shows an `Outcome` without knowing which Check made it.

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    time::{Duration, SystemTime},
};

use crate::{finding::Finding, propagation::Vantage, text::single_line};

/// One line of a Check's data: a label and a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub key: String,
    pub value: String,
}

impl Fact {
    pub fn new(key: impl Into<String>, value: impl AsRef<str>) -> Fact {
        Fact { key: single_line(&key.into()), value: single_line(value.as_ref()) }
    }

    pub fn record(&self) -> String {
        format!("{}: {}", self.key, self.value)
    }
}

/// What one finished Check hands the UI: findings, a short key-value table that
/// stays open, and long data that starts collapsed.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub facts: Vec<Fact>,
    pub details_title: &'static str,
    pub details: Vec<Fact>,
}

impl Outcome {
    /// The lines two runs are compared by.
    pub fn records(&self) -> Vec<String> {
        self.facts.iter().chain(&self.details).map(Fact::record).collect()
    }
}

/// What a Check is asked: the name, how long one query may take, and the resolvers that find its
/// zone. The last four fields are what a test swaps for a fake; production takes them from
/// [`Request::system`]. Each is read by one Check family: the first three by DNSSEC, the last by TLS.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub name: &'a str,
    pub query: Duration,
    pub bootstrap: &'a [SocketAddr],
    /// The port the zone's own nameservers are asked on.
    pub ns_port: u16,
    /// The moment signature validity is judged at.
    pub now: SystemTime,
    /// The validating resolvers to ask. `None` means the Check's own list; `Some(&[])` means ask none.
    pub validating: Option<&'a [Vantage]>,
    /// The port the TLS Checks connect to.
    pub tls_port: u16,
}

impl<'a> Request<'a> {
    /// The real network: port 53, the clock now, the Check's own resolvers.
    pub fn system(name: &'a str, query: Duration, bootstrap: &'a [SocketAddr]) -> Request<'a> {
        Request { name, query, bootstrap, ns_port: 53, now: SystemTime::now(), validating: None, tls_port: 443 }
    }
}

type Running<'a> = Pin<Box<dyn Future<Output = Result<Outcome, String>> + Send + 'a>>;

/// One Check as data: its default limits, the finding-code prefixes it owns, what it cannot see
/// from this machine, and how to run it. A caller needs no knowledge of which Check it holds.
pub struct Check {
    /// Default `(whole, per query)` limits.
    pub budget: (Duration, Duration),
    /// Finding-code prefixes this Check emits.
    pub owns: &'static [&'static str],
    pub blind_spots: &'static [&'static str],
    run: for<'a> fn(&'a Request<'a>) -> Running<'a>,
}

impl Check {
    pub(crate) const fn new(
        budget: (Duration, Duration),
        owns: &'static [&'static str],
        blind_spots: &'static [&'static str],
        run: for<'a> fn(&'a Request<'a>) -> Running<'a>,
    ) -> Check {
        Check { budget, owns, blind_spots, run }
    }

    pub async fn run(&self, request: &Request<'_>) -> Result<Outcome, String> {
        (self.run)(request).await
    }
}
