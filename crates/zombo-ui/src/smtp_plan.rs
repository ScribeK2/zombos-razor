//! Which host the SMTP Check dials. A domain's mail goes to its MX hosts, so the Check asks for
//! them first and runs against the most preferred host that answers. A host name or an IP
//! address is dialled as typed. No UI here: the dialling itself is injected.

use std::future::Future;

use zombo_core::{
    resolver::{Mx, Resolver},
    smtp::{Reach, SmtpResult},
    target::Kind,
};

use crate::outcome::Fact;

/// The ports a rep can pick, in the order the field shows them.
pub const PORTS: [u16; 3] = [25, 587, 465];

/// Hosts tried before giving up on finding one that answers. Each silent host costs a connect timeout.
const MAX_TRIES: usize = 3;

/// What the shell asks the Check to do, taken from the tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub port: u16,
    pub via_mx: bool,
}

impl Request {
    pub fn new(kind: Kind, port: u16) -> Request {
        Request { port, via_mx: matches!(kind, Kind::Domain | Kind::Email) }
    }
}

impl Default for Request {
    fn default() -> Self {
        Request { port: PORTS[0], via_mx: false }
    }
}

/// How the dialled host was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The name was dialled as typed.
    Typed,
    /// The domain has no MX record, so its own name was dialled (RFC 5321 implicit MX).
    NoMx,
    /// The MX lookup failed, so the name was dialled instead.
    LookupFailed(String),
    /// The Nth entry of the MX list, 0 for the most preferred.
    Mx(usize),
    /// No tried MX host answered, so the report is about the most preferred one.
    MxSilent,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub mx: Vec<Mx>,
    pub host: String,
    pub source: Source,
    pub result: SmtpResult,
}

fn answered(r: &SmtpResult) -> bool {
    r.reach == Reach::Answered
}

/// Resolve MX first when `req` asks for it, then dial hosts in preference order until one answers.
pub async fn run<F, Fut>(name: &str, req: Request, resolver: &Resolver, dial: F) -> Plan
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = SmtpResult>,
{
    let direct = |source: Source, mx: Vec<Mx>| async {
        let result = dial(name.to_string()).await;
        Plan { mx, host: name.to_string(), source, result }
    };
    if !req.via_mx {
        return direct(Source::Typed, vec![]).await;
    }
    let mx = match resolver.mx_hosts(name).await {
        Err(e) => return direct(Source::LookupFailed(e), vec![]).await,
        Ok(mx) if mx.is_empty() => return direct(Source::NoMx, vec![]).await,
        Ok(mx) => mx,
    };
    let (source, host, result) = pick(&mx, dial).await;
    Plan { mx, host, source, result }
}

/// Dial the hosts of a non-empty MX list in order and stop at the first that answers. When none
/// does, the result is the most preferred host's.
async fn pick<F, Fut>(mx: &[Mx], dial: F) -> (Source, String, SmtpResult)
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = SmtpResult>,
{
    let mut first: Option<SmtpResult> = None;
    for (i, m) in mx.iter().take(MAX_TRIES).enumerate() {
        let result = dial(m.host.clone()).await;
        if answered(&result) {
            return (Source::Mx(i), m.host.clone(), result);
        }
        first.get_or_insert(result);
    }
    match (first, mx.first()) {
        (Some(result), Some(m)) => (Source::MxSilent, m.host.clone(), result),
        _ => unreachable!("pick is called with a non-empty MX list"),
    }
}

/// The lines that say where the Check went and why, shown above the server's own answer.
pub fn facts(p: &Plan) -> Vec<Fact> {
    let mut out: Vec<Fact> = p.mx.iter().map(|m| Fact::new("MX", format!("{} {}", m.preference, m.host))).collect();
    let chosen = match &p.source {
        Source::Typed => return out,
        Source::NoMx => format!("{}, the name itself: the domain has no MX record", p.host),
        Source::LookupFailed(e) => format!("{}, the name itself: the MX lookup failed ({e})", p.host),
        Source::Mx(0) => format!("{}, the most preferred MX host", p.host),
        Source::Mx(_) => format!("{}, the most preferred MX host that answered", p.host),
        Source::MxSilent => format!("{}, the most preferred MX host: none of the first {MAX_TRIES} answered", p.host),
    };
    out.push(Fact::new("Dialled", chosen));
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use zombo_core::smtp::{SmtpOptions, check_smtp};

    use super::*;

    /// A real result from a local port nobody listens on, with the reach set by the test.
    async fn result(host: &str, reach: Reach) -> SmtpResult {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut r = check_smtp("127.0.0.1", port, &SmtpOptions::for_port(port)).await;
        r.host = host.to_string();
        r.reach = reach;
        r
    }

    fn mx(list: &[(u16, &str)]) -> Vec<Mx> {
        list.iter().map(|(p, h)| Mx { preference: *p, host: h.to_string() }).collect()
    }

    #[test]
    fn a_domain_goes_through_mx_and_the_rest_dial_directly() {
        assert!(Request::new(Kind::Domain, 25).via_mx);
        assert!(Request::new(Kind::Email, 25).via_mx);
        assert!(!Request::new(Kind::Hostname, 25).via_mx);
        assert!(!Request::new(Kind::Ip, 587).via_mx);
        assert_eq!(Request::new(Kind::Ip, 587).port, 587);
    }

    #[test]
    fn the_three_ports_are_offered_with_25_first() {
        assert_eq!(PORTS, [25, 587, 465]);
    }

    #[tokio::test]
    async fn a_plan_lists_the_mx_hosts_and_names_the_chosen_one() {
        let p = Plan {
            mx: mx(&[(10, "mx1.example.com"), (20, "mx2.example.com")]),
            host: "mx2.example.com".into(),
            source: Source::Mx(1),
            result: result("mx2.example.com", Reach::Answered).await,
        };
        let f = facts(&p);
        assert_eq!(f[0], Fact::new("MX", "10 mx1.example.com"));
        assert_eq!(f[1], Fact::new("MX", "20 mx2.example.com"));
        assert_eq!(f[2], Fact::new("Dialled", "mx2.example.com, the most preferred MX host that answered"));
    }

    #[tokio::test]
    async fn a_typed_name_adds_no_lines() {
        let p = Plan {
            mx: vec![],
            host: "mail.example.com".into(),
            source: Source::Typed,
            result: result("mail.example.com", Reach::Answered).await,
        };
        assert!(facts(&p).is_empty());
    }

    #[tokio::test]
    async fn each_fallback_says_why_the_name_itself_was_dialled() {
        let r = result("example.com", Reach::NoAnswer).await;
        let mk = |source| facts(&Plan { mx: vec![], host: "example.com".into(), source, result: r.clone() });
        assert!(mk(Source::NoMx)[0].value.contains("no MX record"));
        assert!(mk(Source::LookupFailed("timed out".into()))[0].value.contains("MX lookup failed (timed out)"));
    }

    fn dial_with(
        answering: &'static [&'static str],
        log: std::sync::Arc<Mutex<Vec<String>>>,
    ) -> impl Fn(String) -> std::pin::Pin<Box<dyn Future<Output = SmtpResult>>> {
        move |h: String| {
            log.lock().unwrap().push(h.clone());
            let reach = if answering.contains(&h.as_str()) { Reach::Answered } else { Reach::NoAnswer };
            Box::pin(async move { result(&h, reach).await })
        }
    }

    #[tokio::test]
    async fn the_most_preferred_host_that_answers_is_chosen_and_later_hosts_are_not_dialled() {
        let list = mx(&[(10, "mx1.example.com"), (20, "mx2.example.com"), (30, "mx3.example.com")]);
        let log = Default::default();
        let (source, host, r) =
            pick(&list, dial_with(&["mx2.example.com", "mx3.example.com"], std::sync::Arc::clone(&log))).await;
        assert_eq!((source, host.as_str(), r.reach), (Source::Mx(1), "mx2.example.com", Reach::Answered));
        assert_eq!(*log.lock().unwrap(), ["mx1.example.com", "mx2.example.com"]);
    }

    #[tokio::test]
    async fn when_no_host_answers_the_report_is_about_the_most_preferred_one() {
        let list =
            mx(&[(10, "mx1.example.com"), (20, "mx2.example.com"), (30, "mx3.example.com"), (40, "mx4.example.com")]);
        let log = Default::default();
        let (source, host, _) = pick(&list, dial_with(&[], std::sync::Arc::clone(&log))).await;
        assert_eq!((source, host.as_str()), (Source::MxSilent, "mx1.example.com"));
        assert_eq!(log.lock().unwrap().len(), MAX_TRIES);
    }

    #[tokio::test]
    async fn direct_dialling_never_asks_for_mx() {
        let dialled = Mutex::new(vec![]);
        let resolver = Resolver::new(&[], std::time::Duration::from_millis(10));
        let plan = run("mail.example.com", Request::new(Kind::Hostname, 25), &resolver, |h| {
            dialled.lock().unwrap().push(h.clone());
            async move { result(&h, Reach::Answered).await }
        })
        .await;
        assert_eq!(*dialled.lock().unwrap(), ["mail.example.com"]);
        assert_eq!(plan.source, Source::Typed);
    }

    #[tokio::test]
    async fn a_failed_mx_lookup_falls_back_to_the_name_and_says_so() {
        let resolver = Resolver::new(&[], std::time::Duration::from_millis(10));
        let plan = run("example.com", Request::new(Kind::Domain, 25), &resolver, |h| async move {
            result(&h, Reach::NoAnswer).await
        })
        .await;
        assert!(matches!(plan.source, Source::LookupFailed(_)));
        assert_eq!(plan.host, "example.com");
    }
}
