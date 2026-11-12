//! What every Check hands back, in one shape. The UI shows an `Outcome` without knowing which Check made it.

use std::{
    borrow::Cow,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::{Duration, SystemTime},
};

use crate::{
    finding::Finding,
    propagation::Vantage,
    registration::Endpoints,
    resolver::system_resolvers,
    target::{Kind, parse_target},
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

/// What a Check is asked. The first seven fields are the inputs the UI sets for a run (the CLI
/// sets the same ones); [`Seams`] is where a Check goes, and only tests set it.
///
/// Write a literal as `Request { field: x, ..Request::system(..) }`, so that a new field only
/// touches `system` and breaks no caller.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub name: &'a str,
    /// The kind of target the name came from. It can differ from what parsing `name` gives: the name
    /// of an email target is its domain part, and `bob@mail.example.com` is an email whose name
    /// parses as a host name. SMTP reads it: a domain or an email goes to its MX hosts, the rest is
    /// dialled as typed.
    pub kind: Kind,
    /// How long one query may take. Every Check reads it.
    pub query: Duration,
    /// The resolvers that find the zone of `name`.
    pub bootstrap: &'a [SocketAddr],
    /// The port the Check dials. A Check whose descriptor has `takes_chosen_port` gets the rep's pick;
    /// TLS and SMTP read it.
    pub port: u16,
    /// The `http://` or `https://` proxy the Checks that honour one go through. `None` leaves each
    /// Check its own default. Registration reads it.
    pub proxy: Option<&'a str>,
    /// The rep's own DKIM selectors, tried beside the common ones. Empty means only the common ones.
    /// Email reads it.
    pub selectors: &'a [String],
    /// Where a Check goes. Production leaves this at its default; only tests set it.
    pub seams: Seams<'a>,
}

/// Where a Check goes, which production never sets and tests point at fakes. A new seam touches only
/// this struct and its `Default`.
#[derive(Debug, Clone, Copy)]
pub struct Seams<'a> {
    /// The port the zone's own nameservers, and its parent zone's, are asked on. DNSSEC and Delegation read it.
    pub ns_port: u16,
    /// The moment signature validity is judged at. DNSSEC reads it.
    pub now: SystemTime,
    /// The validating resolvers to ask. `None` means the Check's own list; `Some(&[])` means ask none.
    /// DNSSEC reads it.
    pub validating: Option<&'a [Vantage]>,
    /// This machine's resolvers. `None` means the Check reads them itself; `Some(&[])` means the machine
    /// has none. The Checks that need them fail without one (SMTP instead asks `bootstrap` for the MX
    /// hosts and skips the reverse lookup of the host it reached). Web, Reverse DNS, Blacklist and SMTP read it.
    pub machine_resolvers: Option<&'a [SocketAddr]>,
    /// Where Registration asks. `None` means the real registries; a test points it at fakes. It stays
    /// here, though it names a Registration type, because only a test sets it.
    pub endpoints: Option<&'a Endpoints>,
    /// The address the Web Check connects to instead of resolving its name. `None` means the name's own addresses.
    pub pin: Option<IpAddr>,
    /// The port of plain HTTP the Web Check uses. `None` means 80.
    pub http_port: Option<u16>,
    /// The port of HTTPS the Web Check uses. `None` means 443.
    pub https_port: Option<u16>,
}

impl Default for Seams<'_> {
    /// The production values: port 53, the clock now, and every other seam unset.
    fn default() -> Self {
        Seams {
            ns_port: 53,
            now: SystemTime::now(),
            validating: None,
            machine_resolvers: None,
            endpoints: None,
            pin: None,
            http_port: None,
            https_port: None,
        }
    }
}

impl<'a> Request<'a> {
    /// The real network: the default seams, port 443, and the kind parsing `name` gives (a host name
    /// when it does not parse).
    pub fn system(name: &'a str, query: Duration, bootstrap: &'a [SocketAddr]) -> Request<'a> {
        Request {
            name,
            kind: parse_target(name).map_or(Kind::Hostname, |t| t.kind),
            query,
            bootstrap,
            port: 443,
            proxy: None,
            selectors: &[],
            seams: Seams::default(),
        }
    }
}

impl Request<'_> {
    /// The resolvers of this machine, possibly none.
    pub(crate) fn machine_or_none(&self) -> Cow<'_, [SocketAddr]> {
        match self.seams.machine_resolvers {
            Some(r) => Cow::Borrowed(r),
            None => Cow::Owned(system_resolvers()),
        }
    }

    /// The resolvers of this machine, or the error every Check that needs them gives when it has none.
    pub(crate) fn machine(&self) -> Result<Cow<'_, [SocketAddr]>, String> {
        let resolvers = self.machine_or_none();
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
    /// that port into [`Request::port`]. A Check that leaves it false is handed the default.
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
