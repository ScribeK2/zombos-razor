//! What every Check hands back, in one shape. The UI shows an `Outcome` without knowing which Check made it.

use std::{
    borrow::Cow,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    time::{Duration, SystemTime},
};

use crate::{
    finding::Finding, propagation::Vantage, registration::Endpoints, resolver::system_resolvers, target::Kind,
    text::single_line,
};

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
/// zone. The last eight fields are what a test swaps for a fake, or the rep's settings fill in;
/// production takes them from [`Request::system`]. Each is read by one Check family: the first three
/// by DNSSEC (`ns_port` also by Delegation), the fourth by TLS, the fifth by the Checks that ask this
/// machine's resolvers, `proxy` and `endpoints` by Registration, `selectors` by Email.
///
/// Write a literal as `Request { field: x, ..Request::system(..) }`, so that a new field only
/// touches `system` and breaks no caller.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub name: &'a str,
    pub query: Duration,
    pub bootstrap: &'a [SocketAddr],
    /// The port the zone's own nameservers, and its parent zone's, are asked on.
    pub ns_port: u16,
    /// The moment signature validity is judged at.
    pub now: SystemTime,
    /// The validating resolvers to ask. `None` means the Check's own list; `Some(&[])` means ask none.
    pub validating: Option<&'a [Vantage]>,
    /// The port the TLS Checks connect to.
    pub tls_port: u16,
    /// This machine's resolvers. `None` means the Check reads them itself; `Some(&[])` means the machine has none.
    pub machine_resolvers: Option<&'a [SocketAddr]>,
    /// The `http://` or `https://` proxy the Checks that honour one go through. `None` leaves each
    /// Check its own default.
    pub proxy: Option<&'a str>,
    /// Where Registration asks. `None` means the real registries; a test points it at fakes.
    pub endpoints: Option<&'a Endpoints>,
    /// The rep's own DKIM selectors, tried beside the common ones. Empty means only the common ones.
    pub selectors: &'a [String],
}

impl<'a> Request<'a> {
    /// The real network: port 53, the clock now, the Check's own resolvers.
    pub fn system(name: &'a str, query: Duration, bootstrap: &'a [SocketAddr]) -> Request<'a> {
        Request {
            name,
            query,
            bootstrap,
            ns_port: 53,
            now: SystemTime::now(),
            validating: None,
            tls_port: 443,
            machine_resolvers: None,
            proxy: None,
            endpoints: None,
            selectors: &[],
        }
    }
}

impl Request<'_> {
    /// The resolvers of this machine, or the error every Check that needs them gives when it has none.
    pub(crate) fn machine(&self) -> Result<Cow<'_, [SocketAddr]>, String> {
        let resolvers = match self.machine_resolvers {
            Some(r) => Cow::Borrowed(r),
            None => Cow::Owned(system_resolvers()),
        };
        if resolvers.is_empty() { Err("this machine has no DNS resolver configured".into()) } else { Ok(resolvers) }
    }
}

type Running<'a> = Pin<Box<dyn Future<Output = Result<Outcome, String>> + Send + 'a>>;

/// What the rep reads before an on-demand Check runs: what it does, whom it contacts, and the button text.
#[derive(Debug, Clone, Copy)]
pub struct OnDemand {
    pub run_label: &'static str,
    pub what: &'static str,
    pub contacts: &'static str,
    pub note: Option<&'static str>,
}

/// One Check as data: how it is named, when it runs, its default limits, the finding-code prefixes
/// it owns, what it cannot see from this machine, and how to run it. A caller needs no knowledge
/// of which Check it holds.
///
/// Write a descriptor as `Check { label: "X", ..Check::base(run) }`, so that a new field only
/// touches `base` and breaks no descriptor.
pub struct Check {
    /// The name of the Check's section on the rail.
    pub label: &'static str,
    /// The target kinds this Check runs on by itself. Empty means it runs only when the rep asks.
    pub automatic_for: &'static [Kind],
    /// What an on-demand Check tells the rep before it runs. `None` for an automatic Check.
    pub on_demand: Option<OnDemand>,
    /// Default `(whole, per query)` limits.
    pub budget: (Duration, Duration),
    /// Finding-code prefixes this Check emits.
    pub owns: &'static [&'static str],
    pub blind_spots: &'static [&'static str],
    /// True when this Check dials the port the rep picked, not the default. The caller then copies
    /// that port into [`Request::tls_port`].
    pub takes_chosen_port: bool,
    pub(crate) run: for<'a> fn(&'a Request<'a>) -> Running<'a>,
}

impl Check {
    /// A Check that runs by itself on no kind of target, with the default limits and nothing else set.
    pub(crate) const fn base(run: for<'a> fn(&'a Request<'a>) -> Running<'a>) -> Check {
        Check {
            label: "",
            automatic_for: &[],
            on_demand: None,
            budget: (Duration::from_secs(20), Duration::from_secs(4)),
            owns: &[],
            blind_spots: &[],
            takes_chosen_port: false,
            run,
        }
    }

    pub fn is_on_demand(&self) -> bool {
        self.automatic_for.is_empty()
    }

    pub async fn run(&self, request: &Request<'_>) -> Result<Outcome, String> {
        (self.run)(request).await
    }
}
