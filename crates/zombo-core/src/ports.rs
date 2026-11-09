//! TCP port test: which well-known service ports of a host accept a
//! connection. Ported from the Go `hosting_reachability` Check.

use std::{
    borrow::Cow,
    collections::HashSet,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use serde::Serialize;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::Semaphore, task::JoinSet};

use crate::{
    finding::{Finding, Severity},
    text::strip,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ServicePort {
    pub port: u16,
    pub service: &'static str,
}

const fn sp(port: u16, service: &'static str) -> ServicePort {
    ServicePort { port, service }
}

/// The services a rep asks about first.
pub const QUICK: &[ServicePort] = &[
    sp(80, "HTTP"),
    sp(443, "HTTPS"),
    sp(25, "SMTP"),
    sp(587, "Submission"),
    sp(993, "IMAPS"),
    sp(22, "SSH"),
    sp(21, "FTP"),
    sp(3306, "MySQL"),
];

/// The ports a hosting, mail or database server commonly listens on.
pub const FULL: &[ServicePort] = &[
    sp(20, "FTP data"),
    sp(21, "FTP"),
    sp(22, "SSH"),
    sp(25, "SMTP"),
    sp(53, "DNS"),
    sp(80, "HTTP"),
    sp(110, "POP3"),
    sp(143, "IMAP"),
    sp(443, "HTTPS"),
    sp(465, "SMTPS"),
    sp(587, "Submission"),
    sp(993, "IMAPS"),
    sp(995, "POP3S"),
    sp(1433, "MS SQL"),
    sp(2082, "cPanel"),
    sp(2083, "cPanel SSL"),
    sp(2086, "WHM"),
    sp(2087, "WHM SSL"),
    sp(2095, "Webmail"),
    sp(2096, "Webmail SSL"),
    sp(2222, "SSH alt / DirectAdmin"),
    sp(3306, "MySQL"),
    sp(3389, "RDP"),
    sp(5432, "PostgreSQL"),
    sp(6379, "Redis"),
    sp(8080, "HTTP alt"),
    sp(8443, "HTTPS alt / Plesk"),
    sp(8888, "HTTP alt"),
    sp(10000, "Webmin"),
    sp(27017, "MongoDB"),
];

/// Plain-text protocols that greet the client first, so a short read shows the software.
const BANNER_PORTS: &[u16] = &[21, 22, 25, 110, 143, 587, 2222];
const DATABASE_PORTS: &[u16] = &[1433, 3306, 5432, 6379, 27017];
const BANNER_BYTES: usize = 256;

/// A port the rep named that is not in the table.
pub fn service_for(port: u16) -> ServicePort {
    FULL.iter().copied().find(|s| s.port == port).unwrap_or(sp(port, "TCP"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    /// Actively refused: the server is up and nothing listens.
    Closed,
    /// No answer in time, or a firewall dropped or rejected it.
    Filtered,
    /// This machine's network has no route to the address (for example no IPv6).
    NoRoute,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortProbe {
    pub address: IpAddr,
    pub port: u16,
    pub service: &'static str,
    pub state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortsResult {
    /// What was probed: the first IPv4 address and, if this machine has IPv6, the first IPv6 address.
    pub addresses: Vec<IpAddr>,
    pub ports: Vec<PortProbe>,
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub dial: Duration,
    pub banner: Duration,
    /// How many connection attempts run at once.
    pub parallel: usize,
}

impl Default for Timing {
    fn default() -> Self {
        Timing { dial: Duration::from_secs(2), banner: Duration::from_millis(500), parallel: 16 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PortsError {
    #[error("could not resolve {0}: {1}")]
    Resolve(String, String),
    #[error(
        "{0} has no address this machine can reach (it has only IPv6 addresses and this machine has no IPv6 route)"
    )]
    NoUsableAddress(String),
}

/// The first IPv4 address and, when `ipv6` is true, the first IPv6 address.
pub fn select_addresses(all: &[IpAddr], ipv6: bool) -> Vec<IpAddr> {
    let v4 = all.iter().copied().find(IpAddr::is_ipv4);
    let v6 = all.iter().copied().find(IpAddr::is_ipv6).filter(|_| ipv6);
    v4.into_iter().chain(v6).collect()
}

/// Whether this machine can route to the IPv6 internet. A connected UDP socket
/// sends nothing; connecting only asks the kernel for a route.
pub async fn has_ipv6() -> bool {
    let Ok(s) = tokio::net::UdpSocket::bind("[::]:0").await else { return false };
    s.connect("[2001:4860:4860::8888]:53").await.is_ok()
}

/// Resolve a host name with the system resolver, or take an IP as it is.
pub async fn resolve_target(target: &str, timeout: Duration) -> Result<Vec<IpAddr>, PortsError> {
    if let Ok(ip) = target.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let fail = |e: String| PortsError::Resolve(target.to_string(), e);
    let found = tokio::time::timeout(timeout, tokio::net::lookup_host((target, 0)))
        .await
        .map_err(|_| fail("timed out".into()))?
        .map_err(|e| fail(e.to_string()))?;
    let all: Vec<IpAddr> = found.map(|a| a.ip()).collect();
    let picked = select_addresses(&all, has_ipv6().await);
    if picked.is_empty() && !all.is_empty() {
        return Err(PortsError::NoUsableAddress(target.to_string()));
    }
    Ok(picked)
}

fn classify(e: &io::Error) -> PortState {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => PortState::Closed,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => PortState::NoRoute,
        _ => PortState::Filtered,
    }
}

/// The first line of a greeting, printable characters only: it comes from the network.
pub(crate) fn clean_banner(raw: &[u8]) -> Option<String> {
    let line = strip(String::from_utf8_lossy(raw).split('\n').next().unwrap_or("")).replace('\u{fffd}', "");
    let line = line.trim();
    (!line.is_empty()).then(|| line.to_string())
}

async fn probe_one<C, F>(connect: &C, address: IpAddr, port: u16, t: Timing) -> (PortState, Option<String>)
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<TcpStream>>,
{
    let mut stream = match tokio::time::timeout(t.dial, connect(SocketAddr::new(address, port))).await {
        Err(_) => return (PortState::Filtered, None),
        Ok(Err(e)) => return (classify(&e), None),
        Ok(Ok(s)) => s,
    };
    if !BANNER_PORTS.contains(&port) {
        return (PortState::Open, None);
    }
    let mut buf = [0u8; BANNER_BYTES];
    let n = tokio::time::timeout(t.banner, stream.read(&mut buf)).await.ok().and_then(Result::ok).unwrap_or(0);
    (PortState::Open, clean_banner(buf.get(..n).unwrap_or_default()))
}

/// Dial every port on every address, at most `t.parallel` at a time, using
/// `connect` to open the connection. Tests inject a `connect` that fakes a host.
pub async fn probe_with<C, F>(connect: C, addresses: &[IpAddr], ports: &[ServicePort], t: Timing) -> PortsResult
where
    C: Fn(SocketAddr) -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<TcpStream>> + Send + 'static,
{
    let mut out: Vec<PortProbe> = addresses
        .iter()
        .flat_map(|&address| {
            ports.iter().map(move |p| PortProbe {
                address,
                port: p.port,
                service: p.service,
                state: PortState::Filtered,
                banner: None,
            })
        })
        .collect();
    let (connect, gate) = (Arc::new(connect), Arc::new(Semaphore::new(t.parallel.max(1))));
    let mut set = JoinSet::new();
    for (i, p) in out.iter().enumerate() {
        let (connect, gate, address, port) = (connect.clone(), gate.clone(), p.address, p.port);
        set.spawn(async move {
            let _slot = gate.acquire().await;
            (i, probe_one(&*connect, address, port, t).await)
        });
    }
    while let Some(done) = set.join_next().await {
        if let Ok((i, (state, banner))) = done
            && let Some(p) = out.get_mut(i)
        {
            p.state = state;
            p.banner = banner;
        }
    }
    PortsResult { addresses: addresses.to_vec(), ports: out }
}

/// Dial the ports on real TCP. Every attempt is bounded by `t.dial` and at most
/// `t.parallel` run at once, so the whole sweep is bounded too.
pub async fn probe(addresses: &[IpAddr], ports: &[ServicePort], t: Timing) -> PortsResult {
    probe_with(TcpStream::connect, addresses, ports, t).await
}

fn finding(
    code: &'static str,
    severity: Severity,
    title: &'static str,
    message: String,
    recommendation: Option<&'static str>,
) -> Finding {
    Finding { code, severity, title: Cow::Borrowed(title), message, recommendation: recommendation.map(Cow::Borrowed) }
}

/// The Go `hosting_reachability` findings.
pub fn ports_findings(target: &str, r: &PortsResult) -> Vec<Finding> {
    use PortState::*;
    if r.addresses.is_empty() {
        return vec![finding(
            "hosting_reachability_no_address",
            Severity::Critical,
            "No address to probe",
            format!("{target} has no A or AAAA record, so there is no server to reach."),
            Some("Add an A record pointing at the hosting server, or check the DNS Lookup for this name."),
        )];
    }
    let mut open_ports: HashSet<u16> = HashSet::new();
    let mut open_on: HashSet<(IpAddr, u16)> = HashSet::new();
    let mut services: Vec<String> = vec![];
    let (mut closed, mut filtered, mut no_route) = (0, 0, 0);
    for p in &r.ports {
        match p.state {
            Open => {
                if open_ports.insert(p.port) {
                    services.push(format!("{} ({})", p.service, p.port));
                }
                open_on.insert((p.address, p.port));
            }
            Closed => closed += 1,
            NoRoute => no_route += 1,
            Filtered => filtered += 1,
        }
    }
    // The addresses on which none of `ports` is open: a site open over IPv6
    // only still fails for most visitors.
    let lacking = |ports: &[u16]| {
        r.addresses
            .iter()
            .filter(|a| !ports.iter().any(|p| open_on.contains(&(**a, *p))))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" and ")
    };
    let addrs = r.addresses.iter().map(ToString::to_string).collect::<Vec<_>>().join(" and ");

    // Outbound mail ports are blocked by many networks and hosting providers, so silence on
    // only those ports says nothing about the server.
    const OUTBOUND_MAIL: [u16; 4] = [25, 465, 587, 2525];
    if open_ports.is_empty() && filtered > 0 && closed == 0 && r.ports.iter().all(|p| OUTBOUND_MAIL.contains(&p.port)) {
        return vec![finding(
            "hosting_reachability_mail_filtered",
            Severity::Info,
            "No answer on the mail ports",
            format!(
                "{addrs} did not answer on the mail ports probed. Many networks and hosting providers block outbound mail connections, so this may be the network doing the probing and not the server."
            ),
            Some("Re-run from a network that allows outbound mail, or check the server's own mail logs."),
        )];
    }
    if open_ports.is_empty() {
        let mut msg = format!("None of the probed ports on {addrs} accepted a connection");
        let mut rec = "Check that the server is up and that its firewall allows these services.";
        if filtered == 0 && no_route == 0 {
            msg += "; every one actively refused, so the server is up but nothing is listening.";
            rec = "Check that the web, mail and other services are running on the server.";
        } else if closed == 0 && filtered == 0 {
            msg += ": this network has no route to it.";
            rec = "Your own connection may lack a route (e.g. no IPv6); re-run from another network.";
        } else {
            msg +=
                &format!(" ({closed} refused, {filtered} got no answer, {no_route} had no route from this network).");
        }
        return vec![finding(
            "hosting_reachability_unreachable",
            Severity::Critical,
            "Host unreachable",
            msg,
            Some(rec),
        )];
    }

    let mut out = vec![];
    let (no_web, no_tls) = (lacking(&[80, 443]), lacking(&[443]));
    if !no_web.is_empty() {
        out.push(finding(
            "hosting_reachability_web_closed",
            Severity::Warning,
            "Web ports closed",
            format!("Neither HTTP (80) nor HTTPS (443) is open on {no_web}, so a website there won't load."),
            Some("If this server should host a site, check the web server is running and the firewall allows 80 and 443."),
        ));
    } else if !no_tls.is_empty() {
        out.push(finding(
            "hosting_reachability_no_https",
            Severity::Warning,
            "No HTTPS",
            format!("HTTP (80) is open but HTTPS (443) is not on {no_tls}, so visitors can't load the site securely."),
            Some("Enable HTTPS on the web server (e.g. a free Let's Encrypt certificate) and open port 443."),
        ));
    }
    let no_smtp = lacking(&[25]);
    if !no_smtp.is_empty() {
        let mut msg = format!(
            "SMTP (25) did not accept a connection on {no_smtp}, so this server can't receive mail directly. Many ISPs and networks block outbound port 25, so the cause may be your own network rather than the server."
        );
        if open_ports.contains(&587) || open_ports.contains(&465) {
            msg += " Mail submission is open, so the server does run mail.";
        }
        out.push(finding(
            "hosting_reachability_smtp_closed",
            Severity::Info,
            "SMTP port closed",
            msg,
            Some("If this server should receive mail, re-run from another network before changing anything on the server."),
        ));
    }
    let dbs: Vec<String> = DATABASE_PORTS
        .iter()
        .filter(|p| open_ports.contains(p))
        .filter_map(|p| r.ports.iter().find(|x| x.port == *p).map(|x| format!("{} ({p})", x.service)))
        .collect();
    if !dbs.is_empty() {
        out.push(finding(
            "hosting_reachability_database_exposed",
            Severity::Warning,
            "Database open to the internet",
            format!(
                "{} accepts connections from anywhere, which invites brute-force and exploit attempts.",
                dbs.join(", ")
            ),
            Some("Firewall database ports to the hosts that need them, or bind the database to localhost."),
        ));
    }
    out.push(finding(
        "hosting_reachability_reachable",
        Severity::Ok,
        "Reachable",
        format!("{addrs} answers on {}.", services.join(", ")),
        None,
    ));
    out
}
