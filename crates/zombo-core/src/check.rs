//! What every Check hands back, in one shape. The UI shows an `Outcome` without knowing which Check made it.

use std::{
    borrow::Cow,
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::{Duration, SystemTime},
};

use serde::Serialize;

use crate::{
    blacklist, delegation, dnssec, email_auth,
    finding::{Finding, Severity},
    ports,
    propagation::{Vantage, default_resolvers},
    rdns,
    registration::{self, Endpoints},
    resolver::system_resolvers,
    smtp,
    target::{Kind, Target, parse_target},
    text::single_line,
    tls, web,
};

/// One line of a Check's data: a label and a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, Default, Serialize)]
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

    /// The outcome as plain text: the facts, then the details under their title, then the findings
    /// worst-first as the Check ordered them. The groups are separated by one blank line.
    pub fn to_text(&self) -> String {
        self.text_blocks().join("\n\n")
    }

    fn text_blocks(&self) -> Vec<String> {
        let facts = self.facts.iter().map(Fact::record).collect::<Vec<_>>().join("\n");
        let details = if self.details.is_empty() {
            String::new()
        } else {
            let rows = self.details.iter().map(|d| format!("  {}", d.record()));
            std::iter::once(self.details_title.to_string()).chain(rows).collect::<Vec<_>>().join("\n")
        };
        let findings = self.findings.iter().map(finding_text).collect::<Vec<_>>().join("\n");
        [facts, details, findings].into_iter().filter(|b| !b.is_empty()).collect()
    }
}

fn finding_text(f: &Finding) -> String {
    let tag = match f.severity {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "WARNING",
        Severity::Critical => "CRITICAL",
    };
    let line = format!("[{tag}] {}: {}", f.title, f.message);
    match &f.recommendation {
        Some(r) => format!("{line}\n        {r}"),
        None => line,
    }
}

/// What a Check is asked. The first eight fields are the inputs a run is given (the UI sets all but `resolvers`); [`Seams`] is where a Check goes, and only tests set it.
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
    /// How long one query may take. Ports, SMTP and Blacklist keep their own limits and do not read it.
    pub query: Duration,
    /// The resolvers that find the zone of `name`. Delegation, Email and DNSSEC read it.
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
    /// The resolvers to ask instead of the defaults. Empty means the defaults. A seam still wins over
    /// it. Reverse DNS, Blacklist and SMTP ask them in place of this machine's resolvers, and
    /// DNSSEC asks them in place of its validating list. Delegation, Email and DNSSEC find the zone
    /// through `bootstrap`, which the runner sets to these, and so does TLS for its CAA join. Web reads
    /// only a seam. Registration and Ports read nothing here.
    /// The UI leaves it empty.
    pub resolvers: &'a [SocketAddr],
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
            resolvers: &[],
            seams: Seams::default(),
        }
    }
}

impl Request<'_> {
    /// The resolvers of this machine, possibly none.
    pub(crate) fn machine_or_none(&self) -> Cow<'_, [SocketAddr]> {
        match self.seams.machine_resolvers {
            Some(r) => Cow::Borrowed(r),
            None if !self.resolvers.is_empty() => Cow::Borrowed(self.resolvers),
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

/// A flag of `zombo run` that only some Checks read. Port is not one: `takes_chosen_port` governs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunFlag {
    /// `Request::query`.
    Timeout,
    /// `Request::resolvers`, and `bootstrap`, which the runner sets from it.
    Resolver,
    /// `Request::selectors`.
    Selector,
}

impl RunFlag {
    /// The flag's name without its dashes.
    pub fn name(self) -> &'static str {
        match self {
            RunFlag::Timeout => "timeout-ms",
            RunFlag::Resolver => "resolver",
            RunFlag::Selector => "selector",
        }
    }
}

/// One Check as data: how it is named, when it runs, its default limits, the finding-code prefixes
/// it owns, what it cannot see from this machine, and how to run it. A caller needs no knowledge
/// of which Check it holds.
///
/// Write a descriptor as `Check { label: "X", ..Check::base(run) }`, so that a new field only
/// touches `base` and breaks no descriptor.
pub struct Check {
    /// The name the CLI knows this Check by: kebab-case, unique among [`ALL`].
    pub id: &'static str,
    /// The target kinds this Check can run on, by itself or when the rep asks.
    pub accepts: &'static [Kind],
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
    /// The port this Check dials when the caller picks none.
    pub default_port: u16,
    /// The flags of a run this Check reads. A run that sets any other is refused, so no flag does
    /// nothing in silence. List a flag only after finding the line of `run` that reads it.
    pub honours: &'static [RunFlag],
    pub(crate) run: for<'a> fn(&'a Request<'a>) -> Running<'a>,
}

impl Check {
    /// A Check that runs by itself on no kind of target, with the default limits and nothing else set.
    pub(crate) const fn base(run: for<'a> fn(&'a Request<'a>) -> Running<'a>) -> Check {
        Check {
            id: "",
            accepts: &[],
            label: "",
            automatic_for: &[],
            on_demand: None,
            budget: (Duration::from_secs(20), Duration::from_secs(4)),
            owns: &[],
            blind_spots: &[],
            takes_chosen_port: false,
            default_port: 443,
            honours: &[RunFlag::Timeout],
            run,
        }
    }

    pub fn is_on_demand(&self) -> bool {
        self.automatic_for.is_empty()
    }

    /// The name this Check runs on for the target: the domain part of an email address, an IP address
    /// as typed where the Check accepts one, else the name as typed. `None` when the Check does not
    /// accept the kind of the target.
    pub fn subject(&self, target: &Target) -> Option<String> {
        if !self.accepts.contains(&target.kind) {
            return None;
        }
        match target.kind {
            Kind::Email => target.value.split_once('@').map(|(_, domain)| domain.to_string()),
            _ => Some(target.value.clone()),
        }
    }

    pub async fn run(&self, request: &Request<'_>) -> Result<Outcome, String> {
        (self.run)(request).await
    }
}

/// Every Check, in the order of the rail.
pub static ALL: &[&Check] = &[
    &delegation::CHECK,
    &dnssec::CHECK,
    &email_auth::CHECK,
    &web::CHECK,
    &tls::CHECK,
    &registration::CHECK,
    &rdns::CHECK,
    &ports::CHECK,
    &smtp::CHECK,
    &tls::ON_PORT,
    &blacklist::CHECK,
];

pub fn find(id: &str) -> Option<&'static Check> {
    ALL.iter().copied().find(|c| c.id == id)
}

/// What a caller says about one run. Write it as `RunArgs { port: Some(25), ..RunArgs::new(text) }`, so
/// that a new field breaks no caller. Only tests set `seams`.
#[derive(Debug, Clone, Copy)]
pub struct RunArgs<'a> {
    /// What the rep typed: a domain, host name, IP address or email address.
    pub target: &'a str,
    /// The limit of one query. `None` means the Check's own.
    pub timeout: Option<Duration>,
    /// The resolvers to ask instead of the defaults. See [`Request::resolvers`].
    pub resolvers: &'a [SocketAddr],
    /// The port to dial. Only a Check with `takes_chosen_port` accepts one.
    pub port: Option<u16>,
    pub selectors: &'a [String],
    pub seams: Seams<'a>,
}

impl<'a> RunArgs<'a> {
    pub fn new(target: &'a str) -> RunArgs<'a> {
        RunArgs { target, timeout: None, resolvers: &[], port: None, selectors: &[], seams: Seams::default() }
    }
}

/// Why a run did not give an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    UnknownId(String),
    /// The text of the target that did not parse.
    BadTarget(String),
    NotAccepted {
        check: &'static str,
        kind: Kind,
    },
    /// An option this Check does not take.
    BadOption(String),
    TimedOut,
    /// The Check's own error text.
    Failed(String),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::UnknownId(id) => {
                let ids: Vec<_> = ALL.iter().map(|c| c.id).collect();
                write!(f, "unknown check \"{id}\"; the checks are {}", ids.join(", "))
            }
            RunError::BadTarget(text) | RunError::BadOption(text) | RunError::Failed(text) => f.write_str(text),
            RunError::NotAccepted { check, kind } => {
                let kind = match kind {
                    Kind::Domain => "a domain",
                    Kind::Hostname => "a host name",
                    Kind::Ip => "an IP address",
                    Kind::Email => "an email address",
                };
                write!(f, "{check} does not run on {kind}")
            }
            RunError::TimedOut => f.write_str("the check ran out of time"),
        }
    }
}

impl std::error::Error for RunError {}

/// A finished run: which Check, on what, and what it found.
#[derive(Debug, Clone)]
pub struct Report {
    pub id: &'static str,
    pub label: &'static str,
    /// The name the Check ran on: the domain part of an email address, else the target as parsed.
    pub subject: String,
    pub outcome: Outcome,
}

impl Report {
    /// A heading line, then [`Outcome::to_text`].
    pub fn to_text(&self) -> String {
        let heading = format!("{} for {}", self.label, self.subject);
        std::iter::once(heading).chain(self.outcome.text_blocks()).collect::<Vec<_>>().join("\n\n")
    }
}

/// The whole limit of a run: the Check's own, or five queries' worth of an explicit timeout when that
/// is more.
// ponytail: five is a guess. A Check that asks more than five queries in a row still ends at this limit and
// reports `TimedOut`; give the descriptor a query count if one does.
fn whole_limit(budget_whole: Duration, timeout: Option<Duration>) -> Duration {
    timeout.map_or(budget_whole, |t| budget_whole.max(t.saturating_mul(5)))
}

/// The first flag the run sets that the Check does not read.
fn unhonoured(check: &Check, args: &RunArgs<'_>) -> Option<RunFlag> {
    let set = [
        (RunFlag::Timeout, args.timeout.is_some()),
        (RunFlag::Resolver, !args.resolvers.is_empty()),
        (RunFlag::Selector, !args.selectors.is_empty()),
    ];
    set.into_iter().find(|(flag, set)| *set && !check.honours.contains(flag)).map(|(flag, _)| flag)
}

/// Run the Check with this id as the UI does: parse the target, derive its subject, and give the
/// Check its limits.
pub async fn run_by_id(id: &str, args: &RunArgs<'_>) -> Result<Report, RunError> {
    let check = find(id).ok_or_else(|| RunError::UnknownId(id.to_string()))?;
    let target = parse_target(args.target).map_err(RunError::BadTarget)?;
    let subject = check.subject(&target).ok_or(RunError::NotAccepted { check: check.id, kind: target.kind })?;
    if let Some(flag) = unhonoured(check, args) {
        return Err(RunError::BadOption(format!("{} does not take --{}", check.id, flag.name())));
    }
    if args.port.is_some() && !check.takes_chosen_port {
        return Err(RunError::BadOption(format!("{} does not take a port", check.id)));
    }
    let defaults: Vec<SocketAddr>;
    let bootstrap = if args.resolvers.is_empty() {
        defaults = default_resolvers().iter().map(|r| r.address).collect();
        &defaults[..]
    } else {
        args.resolvers
    };
    let query = args.timeout.unwrap_or(check.budget.1);
    let request = Request {
        kind: target.kind,
        selectors: args.selectors,
        resolvers: args.resolvers,
        port: args.port.unwrap_or(check.default_port),
        seams: args.seams,
        ..Request::system(&subject, query, bootstrap)
    };
    let outcome = tokio::time::timeout(whole_limit(check.budget.0, args.timeout), check.run(&request))
        .await
        .map_err(|_| RunError::TimedOut)?
        .map_err(RunError::Failed)?;
    Ok(Report { id: check.id, label: check.label, subject, outcome })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_timeout_stretches_the_whole_limit_to_five_queries_and_never_shrinks_it() {
        let whole = Duration::from_secs(20);
        assert_eq!(whole_limit(whole, None), whole);
        assert_eq!(whole_limit(whole, Some(Duration::from_secs(1))), whole);
        assert_eq!(whole_limit(whole, Some(Duration::from_secs(10))), Duration::from_secs(50));
    }

    use RunFlag::{Resolver, Selector, Timeout};

    const FLAGS: [RunFlag; 3] = [Timeout, Resolver, Selector];

    #[test]
    fn every_check_honours_exactly_the_flags_its_code_reads() {
        let honours: Vec<_> = ALL.iter().map(|c| (c.id, c.honours)).collect();
        assert_eq!(
            honours,
            [
                ("delegation", &[Timeout, Resolver][..]),
                ("dnssec", &[Timeout, Resolver]),
                ("email", &[Timeout, Resolver, Selector]),
                ("web", &[Timeout]),
                ("tls", &[Timeout, Resolver]),
                ("registration", &[Timeout]),
                ("rdns", &[Timeout, Resolver]),
                ("ports", &[]),
                ("smtp", &[Resolver]),
                ("tls-port", &[Timeout]),
                ("blacklist", &[Resolver]),
            ]
        );
    }

    /// The flag check alone, with no query, for every Check and every flag: exactly the flags a Check
    /// does not honour come back. `run_by_id` runs the same function before it asks anything.
    #[test]
    fn a_flag_is_refused_exactly_when_the_check_does_not_honour_it() {
        let (addr, words) = (["127.0.0.1:9".parse().unwrap()], ["x".to_string()]);
        for check in ALL {
            for flag in FLAGS {
                let args = match flag {
                    Timeout => RunArgs { timeout: Some(Duration::from_millis(1)), ..RunArgs::new("127.0.0.1") },
                    Resolver => RunArgs { resolvers: &addr, ..RunArgs::new("127.0.0.1") },
                    Selector => RunArgs { selectors: &words, ..RunArgs::new("127.0.0.1") },
                };
                let want = (!check.honours.contains(&flag)).then_some(flag);
                assert_eq!(unhonoured(check, &args), want, "{} {flag:?}", check.id);
            }
            assert_eq!(unhonoured(check, &RunArgs::new("127.0.0.1")), None, "{}", check.id);
        }
    }

    fn t(value: &str, kind: Kind) -> crate::target::Target {
        crate::target::Target { value: value.into(), kind }
    }

    #[test]
    fn the_subject_is_the_name_the_check_runs_on_or_none_when_it_does_not_accept_the_kind() {
        let on = |id: &str, value: &str, kind| find(id).unwrap().subject(&t(value, kind));
        assert_eq!(on("dnssec", "example.com", Kind::Domain).as_deref(), Some("example.com"));
        assert_eq!(on("dnssec", "www.example.com", Kind::Hostname).as_deref(), Some("www.example.com"));
        assert_eq!(on("dnssec", "bob@mail.example.com", Kind::Email).as_deref(), Some("mail.example.com"));
        assert_eq!(on("email", "bob@example.com", Kind::Email).as_deref(), Some("example.com"));
        assert_eq!(on("dnssec", "192.0.2.1", Kind::Ip), None);
        assert_eq!(on("rdns", "192.0.2.1", Kind::Ip).as_deref(), Some("192.0.2.1"));
        assert_eq!(on("rdns", "bob@example.com", Kind::Email).as_deref(), Some("example.com"));
    }
}
