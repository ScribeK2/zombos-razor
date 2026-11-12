//! SMTP banner and STARTTLS Check for one mail host: read the greeting, ask
//! what the server offers, upgrade to TLS and report the certificate. The Check
//! never sends mail: it stops at QUIT (or, after the handshake, QUIT over TLS).
//!
//! Everything the server sends is untrusted, so every line, reply and wait is
//! bounded (see `reply`). The network is injectable through `check_smtp_via`.

mod findings;
mod plan;
pub(crate) mod reply;

use std::{io, net::IpAddr, time::Duration};

use rustls::RootCertStore;
use serde::Serialize;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};

use crate::{
    check::{Check, OnDemand, Outcome, Request, RunFlag},
    rdns::{RdnsResult, check_rdns},
    resolver::Resolver,
    target::Kind,
    tls::{TlsResult, inspect_stream_keep, public_roots},
};
pub use findings::{smtp_findings, smtp_findings_at};
pub use plan::PORTS;
use reply::Conn;
pub use reply::{Extensions, MAX_LINE, MAX_REPLY_LINES, Reply, ReplyError, banner_host};

/// The SMTP banner row: the greeting, what the server offers, STARTTLS and the certificate, on the
/// request's `port`. A domain or an email (the request's `kind`) goes to its MX hosts, most
/// preferred first, and the first of three that answers is reported; a host name or an IP address
/// is dialled as typed. The MX lookup asks this machine's resolvers (the `bootstrap` ones when it
/// has none) with a 5 s limit, the reverse lookup of the address reached takes 3 s, and the
/// request's `query` is not used: each step has its own limit.
pub static CHECK: Check = Check {
    label: "SMTP banner",
    id: "smtp",
    accepts: &[Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip],
    on_demand: Some(OnDemand {
        run_label: "Run SMTP banner check",
        what: "Connects to the target's mail port, reads the greeting, lists what the server offers and tries STARTTLS. It sends no mail.",
        contacts: "For a domain, its MX hosts, most preferred first (up to 3 are tried), on the port you pick below. For a host name or an IP address, that name or address on the port. This machine's resolver looks up the MX records, the name and the reverse name of the address.",
        note: Some(
            "Port 25 is often blocked outbound on home and cloud networks. A host that gives no answer is reported as no answer, not as down. Ports 587 and 465 are the submission ports.",
        ),
    }),
    budget: (Duration::from_secs(40), Duration::from_secs(40)),
    owns: &["smtp_"],
    blind_spots: &[
        "Whether the server accepts mail from you: no mail is sent.",
        "Recipient-side filtering of mail it does accept.",
        "MX hosts after the first three tried.",
        "Whether this network blocks the port, when there is no answer.",
    ],
    takes_chosen_port: true,
    default_port: 25,
    honours: &[RunFlag::Resolver],
    ..Check::base(|request| Box::pin(async move { Ok(run(request).await) }))
};

async fn run(request: &Request<'_>) -> Outcome {
    let resolvers = request.machine_or_none();
    let asked = if resolvers.is_empty() { request.bootstrap } else { &resolvers[..] };
    let port = request.port;
    let plan = plan::run(
        request.name,
        plan::Request::new(request.kind, port),
        &Resolver::new(asked, Duration::from_secs(5)),
        |host| async move { check_smtp(&host, port, &SmtpOptions::for_port(port)).await },
    )
    .await;
    let r = &plan.result;
    let mut expect = vec![];
    if plan.host.parse::<IpAddr>().is_err() {
        expect.push(plan.host.clone());
    }
    if let (Some(ip), Reach::Answered, false) = (r.peer, r.reach, resolvers.is_empty())
        && let RdnsResult::Ip { ptrs, .. } = check_rdns(&resolvers, &ip.to_string(), Duration::from_secs(3)).await
    {
        expect.extend(ptrs.into_iter().map(|p| p.name));
    }
    let mut outcome = findings::outcome(r, &expect);
    let mut facts = plan::facts(&plan);
    facts.append(&mut outcome.facts);
    outcome.facts = facts;
    outcome
}

/// How the TLS starts: after a STARTTLS command (ports 25 and 587) or at once (port 465).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Starttls,
    Implicit,
}

impl Mode {
    pub fn for_port(port: u16) -> Mode {
        if port == 465 { Mode::Implicit } else { Mode::Starttls }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub connect: Duration,
    /// How long the server has for one reply, or for one command to be written.
    pub step: Duration,
    /// The whole Check, DNS lookup included.
    pub overall: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing { connect: Duration::from_secs(5), step: Duration::from_secs(10), overall: Duration::from_secs(30) }
    }
}

#[derive(Debug, Clone)]
pub struct SmtpOptions {
    pub mode: Mode,
    /// The name sent in EHLO. It must pass `valid_ehlo_name`.
    pub ehlo_name: String,
    pub timing: Timing,
}

impl SmtpOptions {
    pub fn for_port(port: u16) -> Self {
        SmtpOptions { mode: Mode::for_port(port), ehlo_name: "zombo.invalid".into(), timing: Timing::default() }
    }
}

/// A host name or address literal made of characters that cannot break the command line.
pub fn valid_ehlo_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '[' | ']' | ':'))
}

/// What happened at the TCP level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    Answered,
    /// Nothing came back in time: a firewall, a dead host, or a network that blocks the port.
    NoAnswer,
    /// Actively refused: the host is up and nothing listens on the port.
    Refused,
    NoRoute,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Setup,
    Connect,
    Greeting,
    Ehlo,
    /// The TLS handshake of an implicit-TLS port.
    Tls,
    Starttls,
    /// After the handshake.
    Session,
    Overall,
}

#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    pub stage: Stage,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Banner {
    pub code: u16,
    /// The first line, control characters replaced.
    pub text: String,
    /// The host name the greeting opens with, when it opens with one.
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Starttls {
    /// Implicit TLS has no STARTTLS command.
    NotApplicable,
    /// The dialogue ended before STARTTLS could be tried.
    NotAttempted,
    NotOffered,
    Refused {
        code: u16,
        text: String,
    },
    /// The server said go ahead and the handshake failed.
    HandshakeFailed(String),
    Upgraded,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmtpResult {
    pub host: String,
    pub port: u16,
    pub mode: Mode,
    pub reach: Reach,
    /// The address connected to.
    pub peer: Option<IpAddr>,
    pub banner: Option<Banner>,
    /// What EHLO offered before any TLS (or, on an implicit-TLS port, inside it).
    pub extensions: Option<Extensions>,
    pub starttls: Starttls,
    pub tls: Option<TlsResult>,
    /// What a second EHLO offered after STARTTLS.
    pub extensions_after_tls: Option<Extensions>,
    pub failure: Option<Failure>,
}

impl SmtpResult {
    fn new(host: &str, port: u16, mode: Mode) -> Self {
        SmtpResult {
            host: host.into(),
            port,
            mode,
            reach: Reach::NoAnswer,
            peer: None,
            banner: None,
            extensions: None,
            starttls: if mode == Mode::Implicit { Starttls::NotApplicable } else { Starttls::NotAttempted },
            tls: None,
            extensions_after_tls: None,
            failure: None,
        }
    }

    fn fail(&mut self, stage: Stage, message: impl ToString) {
        self.failure.get_or_insert(Failure { stage, message: message.to_string() });
    }
}

fn classify(e: &io::Error) -> Reach {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => Reach::Refused,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => Reach::NoRoute,
        io::ErrorKind::TimedOut => Reach::NoAnswer,
        _ => Reach::Failed,
    }
}

/// Check `host:port` against the bundled public roots, as of now.
pub async fn check_smtp(host: &str, port: u16, o: &SmtpOptions) -> SmtpResult {
    check_smtp_via((host, port), host, port, o, &public_roots(), OffsetDateTime::now_utc()).await
}

/// Connect to `addr` (a name is resolved with the system resolver) and run the
/// Check for the mail host `host`, the name the certificate must cover. The
/// connect, the dialogue and the handshake all count against `o.timing.overall`,
/// and what was learned before it ran out is kept.
pub async fn check_smtp_via(
    addr: impl tokio::net::ToSocketAddrs,
    host: &str,
    port: u16,
    o: &SmtpOptions,
    roots: &RootCertStore,
    now: OffsetDateTime,
) -> SmtpResult {
    let mut r = SmtpResult::new(host, port, o.mode);
    if !valid_ehlo_name(&o.ehlo_name) {
        r.reach = Reach::Failed;
        r.fail(Stage::Setup, "the EHLO name has characters that are not allowed");
        return r;
    }
    if timeout(o.timing.overall, session(&mut r, addr, host, o, roots, now)).await.is_err() {
        if r.reach == Reach::NoAnswer {
            r.fail(Stage::Connect, "no answer in time");
        } else {
            r.fail(
                Stage::Overall,
                format!("the Check stopped after {} s: the server was too slow", o.timing.overall.as_secs().max(1)),
            );
        }
    }
    r
}

async fn session(
    r: &mut SmtpResult,
    addr: impl tokio::net::ToSocketAddrs,
    host: &str,
    o: &SmtpOptions,
    roots: &RootCertStore,
    now: OffsetDateTime,
) {
    let t = o.timing;
    let tcp = match timeout(t.connect, TcpStream::connect(addr)).await {
        Err(_) => return r.fail(Stage::Connect, "no answer in time"),
        Ok(Err(e)) => {
            r.reach = classify(&e);
            return r.fail(Stage::Connect, crate::text::printable(&e.to_string()));
        }
        Ok(Ok(s)) => s,
    };
    r.reach = Reach::Answered;
    r.peer = tcp.peer_addr().ok().map(|a| a.ip());

    if o.mode == Mode::Implicit {
        let (tls, result) = match inspect_stream_keep(tcp, host, roots, now, t.step).await {
            Ok(ok) => ok,
            Err(e) => return r.fail(Stage::Tls, e),
        };
        r.tls = Some(result);
        let mut c = Conn::new(tls);
        if greet(&mut c, r, o).await {
            quit(&mut c, t).await;
        }
        return;
    }

    let mut c = Conn::new(tcp);
    if !greet(&mut c, r, o).await {
        return;
    }
    let offered = r.extensions.as_ref().is_some_and(|e| e.starttls);
    if !offered {
        r.starttls = Starttls::NotOffered;
        return quit(&mut c, t).await;
    }
    let answer = match c.send("STARTTLS", t.step).await {
        Ok(()) => c.reply(t.step).await,
        Err(e) => Err(e),
    };
    match answer {
        Ok(rep) if rep.code == 220 => {}
        Ok(rep) => {
            r.starttls = Starttls::Refused { code: rep.code, text: rep.lines.first().cloned().unwrap_or_default() };
            return quit(&mut c, t).await;
        }
        Err(e) => return r.fail(Stage::Starttls, e),
    }
    let tcp = match c.into_stream() {
        Ok(s) => s,
        Err(n) => {
            return r.fail(
                Stage::Starttls,
                format!("the server sent {n} bytes after its STARTTLS reply and before the handshake"),
            );
        }
    };
    let (tls, result) = match inspect_stream_keep(tcp, host, roots, now, t.step).await {
        Ok(ok) => ok,
        Err(e) => {
            r.starttls = Starttls::HandshakeFailed(e.to_string());
            return;
        }
    };
    r.starttls = Starttls::Upgraded;
    r.tls = Some(result);
    let mut c = Conn::new(tls);
    match ehlo(&mut c, o).await {
        Ok(rep) if rep.code == 250 => r.extensions_after_tls = Some(Extensions::parse(&rep.lines)),
        Ok(_) => {}
        Err(e) => return r.fail(Stage::Session, e),
    }
    quit(&mut c, t).await;
}

async fn ehlo<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Conn<S>, o: &SmtpOptions) -> Result<Reply, ReplyError> {
    c.send(&format!("EHLO {}", o.ehlo_name), o.timing.step).await?;
    c.reply(o.timing.step).await
}

/// The greeting and EHLO. True when the dialogue can go on.
async fn greet<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Conn<S>, r: &mut SmtpResult, o: &SmtpOptions) -> bool {
    let banner = match c.reply(o.timing.step).await {
        Ok(b) => b,
        Err(e) => {
            r.fail(Stage::Greeting, e);
            return false;
        }
    };
    let text = banner.lines.first().cloned().unwrap_or_default();
    r.banner = Some(Banner { code: banner.code, hostname: banner_host(&text), text });
    if banner.code != 220 {
        return false;
    }
    match ehlo(c, o).await {
        Ok(rep) if rep.code == 250 => {
            r.extensions = Some(Extensions::parse(&rep.lines));
            true
        }
        Ok(rep) => {
            r.fail(
                Stage::Ehlo,
                format!("the server answered EHLO with {} {}", rep.code, rep.lines.first().map_or("", String::as_str)),
            );
            false
        }
        Err(e) => {
            r.fail(Stage::Ehlo, e);
            false
        }
    }
}

/// Politely end the session. Failures here change nothing.
async fn quit<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Conn<S>, t: Timing) {
    if c.send("QUIT", t.step).await.is_ok() {
        let _ = c.reply(t.step.min(Duration::from_secs(2))).await;
    }
}
