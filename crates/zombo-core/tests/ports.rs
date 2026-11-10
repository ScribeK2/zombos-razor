#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The TCP port test against fake hosts made of local listeners. The Go
//! `hosting_reachability` scenarios, with the dial injected as in the Go tests.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use zombo_core::{
    Finding, Severity,
    ports::{
        FULL, PortProbe, PortState, PortsResult, QUICK, ServicePort, Timing, ports_findings, probe_with,
        resolve_target, select_addresses, service_for,
    },
};

const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const V6: &str = "2001:db8::10";

fn fast() -> Timing {
    Timing { dial: Duration::from_millis(150), banner: Duration::from_millis(150), parallel: 16 }
}

/// A host whose `open` ports are local listeners that send their banner on
/// accept, `filtered` ports never answer, and every other port refuses.
struct FakeHost {
    local: HashMap<u16, SocketAddr>,
    filtered: Vec<u16>,
    refused: SocketAddr,
}

async fn fake_host(open: &[(u16, &'static [u8])], filtered: &[u16]) -> Arc<FakeHost> {
    let refused = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let mut local = HashMap::new();
    for &(port, banner) in open {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        local.insert(port, l.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let _ = c.write_all(banner).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    }
    Arc::new(FakeHost { local, filtered: filtered.to_vec(), refused })
}

impl FakeHost {
    async fn dial(&self, to: SocketAddr) -> io::Result<TcpStream> {
        if self.filtered.contains(&to.port()) {
            std::future::pending::<()>().await;
        }
        TcpStream::connect(self.local.get(&to.port()).copied().unwrap_or(self.refused)).await
    }
}

async fn run(host: &Arc<FakeHost>, addrs: &[IpAddr], ports: &[ServicePort]) -> PortsResult {
    let host = host.clone();
    probe_with(
        move |a| {
            let h = host.clone();
            async move { h.dial(a).await }
        },
        addrs,
        ports,
        fast(),
    )
    .await
}

fn port(r: &PortsResult, n: u16) -> &PortProbe {
    r.ports.iter().find(|p| p.port == n).unwrap_or_else(|| panic!("no port {n}"))
}

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

const WEB_AND_MAIL: &[(u16, &[u8])] = &[
    (80, b""),
    (443, b""),
    (25, b"220 mx.example.com ESMTP Postfix\r\n250 more\r\n"),
    (22, b"SSH-2.0-OpenSSH_9.6\r\n"),
];

#[tokio::test]
async fn the_quick_sweep_classifies_each_port() {
    let r = run(&fake_host(WEB_AND_MAIL, &[]).await, &[V4], QUICK).await;
    assert_eq!(r.ports.len(), 8);
    assert_eq!((port(&r, 443).state, port(&r, 443).service), (PortState::Open, "HTTPS"));
    assert_eq!((port(&r, 21).state, port(&r, 21).service), (PortState::Closed, "FTP"));
    assert_eq!(port(&r, 25).banner.as_deref(), Some("220 mx.example.com ESMTP Postfix"));
    assert_eq!(port(&r, 22).banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
    assert_eq!(port(&r, 80).banner, None);
    assert_eq!(codes(&ports_findings("example.com", &r)), ["hosting_reachability_reachable"]);
}

#[tokio::test]
async fn the_full_table_has_the_hosting_ports() {
    assert!(FULL.len() >= 25);
    assert_eq!(service_for(2083).service, "cPanel SSL");
    assert_eq!(service_for(31337).service, "TCP");
    let host = fake_host(&[(80, b""), (443, b""), (25, b""), (5432, b""), (2083, b"")], &[]).await;
    let r = run(&host, &[V4], FULL).await;
    assert_eq!(port(&r, 2083).state, PortState::Open);
    let fs = ports_findings("example.com", &r);
    assert_eq!(
        fs.iter().find(|f| f.code == "hosting_reachability_database_exposed").map(|f| f.severity),
        Some(Severity::Warning)
    );
}

#[tokio::test]
async fn a_port_that_never_answers_is_filtered_within_the_dial_timeout() {
    let r = run(&fake_host(WEB_AND_MAIL, &[3306]).await, &[V4], QUICK).await;
    assert_eq!(port(&r, 3306).state, PortState::Filtered);
}

#[tokio::test]
async fn an_unroutable_address_is_no_route_not_filtered() {
    let r =
        probe_with(|_| async { Err(io::Error::from(io::ErrorKind::NetworkUnreachable)) }, &[V4], QUICK, fast()).await;
    assert!(r.ports.iter().all(|p| p.state == PortState::NoRoute));
    let fs = ports_findings("example.com", &r);
    assert_eq!(codes(&fs), ["hosting_reachability_unreachable"]);
    assert!(fs[0].message.contains("this network has no route to it"), "{}", fs[0].message);
}

#[tokio::test]
async fn a_sweep_stays_within_the_parallel_bound_and_the_time_bound() {
    let (now, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let t = Timing { dial: Duration::from_millis(100), banner: Duration::from_millis(100), parallel: 4 };
    let began = Instant::now();
    let (n, p) = (now.clone(), peak.clone());
    let r = probe_with(
        move |_| {
            let (n, p) = (n.clone(), p.clone());
            async move {
                let cur = n.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                n.fetch_sub(1, Ordering::SeqCst);
                Err(io::Error::from(io::ErrorKind::ConnectionRefused))
            }
        },
        &[V4],
        FULL,
        t,
    )
    .await;
    assert_eq!(r.ports.len(), FULL.len());
    assert!(peak.load(Ordering::SeqCst) <= 4, "peak {}", peak.load(Ordering::SeqCst));
    assert!(peak.load(Ordering::SeqCst) >= 2, "the sweep should run in parallel");
    assert!(began.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_hostile_banner_is_one_clean_short_line() {
    let hostile: &'static [u8] = b"\x1b[31mSSH-2.0-evil\x07\xff\xfe\x00 tail\r\nsecond line\r\n";
    let host = fake_host(&[(22, hostile)], &[]).await;
    let r = run(&host, &[V4], &[service_for(22)]).await;
    let banner = port(&r, 22).banner.clone().unwrap();
    assert_eq!(banner, "[31mSSH-2.0-evil tail");
    assert!(!banner.chars().any(char::is_control));

    static LONG: [u8; 4096] = [b'A'; 4096];
    let host = fake_host(&[(22, &LONG)], &[]).await;
    let r = run(&host, &[V4], &[service_for(22)]).await;
    assert_eq!(port(&r, 22).banner.as_deref().map(str::len), Some(256));
}

#[tokio::test]
async fn a_server_that_stays_silent_is_open_without_a_banner() {
    let host = fake_host(&[(22, b"")], &[]).await;
    let r = run(&host, &[V4], &[service_for(22)]).await;
    assert_eq!((port(&r, 22).state, port(&r, 22).banner.clone()), (PortState::Open, None));
}

#[test]
fn only_the_first_address_of_each_family_is_probed() {
    let a = |s: &str| s.parse::<IpAddr>().unwrap();
    let all = [a("2001:db8::1"), a("192.0.2.1"), a("192.0.2.2"), a("2001:db8::2")];
    assert_eq!(select_addresses(&all, true), [a("192.0.2.1"), a("2001:db8::1")]);
    assert_eq!(select_addresses(&all, false), [a("192.0.2.1")]);
    assert!(select_addresses(&[a("2001:db8::1")], false).is_empty());
}

#[tokio::test]
async fn an_ip_target_is_probed_as_it_is_and_localhost_resolves() {
    assert_eq!(resolve_target("192.0.2.10", Duration::from_secs(1)).await.unwrap(), [V4]);
    assert_eq!(
        resolve_target("[2001:db8::10]", Duration::from_secs(1)).await.unwrap(),
        [V6.parse::<IpAddr>().unwrap()]
    );
    assert!(
        resolve_target("localhost", Duration::from_secs(2)).await.unwrap().contains(&IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
}

fn result(addrs: &[&str], probes: &[(&str, u16, &'static str, PortState)]) -> PortsResult {
    PortsResult {
        addresses: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        ports: probes
            .iter()
            .map(|&(a, port, service, state)| PortProbe {
                address: a.parse().unwrap(),
                port,
                service,
                state,
                banner: None,
            })
            .collect(),
    }
}

use PortState::{Closed, Filtered, NoRoute, Open};

#[test]
fn no_address_is_critical() {
    let fs = ports_findings("bare.example.com", &result(&[], &[]));
    assert_eq!(codes(&fs), ["hosting_reachability_no_address"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert_eq!(fs[0].message, "bare.example.com has no A or AAAA record, so there is no server to reach.");
}

#[test]
fn nothing_open_is_unreachable_and_says_why() {
    let v4 = "192.0.2.10";
    let refused = result(&[v4], &[(v4, 80, "HTTP", Closed), (v4, 443, "HTTPS", Closed)]);
    let fs = ports_findings("example.com", &refused);
    assert_eq!(codes(&fs), ["hosting_reachability_unreachable"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert!(fs[0].message.contains("every one actively refused"));
    let mixed = result(&[v4], &[(v4, 80, "HTTP", Closed), (v4, 443, "HTTPS", Filtered), (v4, 25, "SMTP", NoRoute)]);
    assert!(
        ports_findings("example.com", &mixed)[0]
            .message
            .contains("(1 refused, 1 got no answer, 1 had no route from this network).")
    );
}

#[test]
fn web_mail_and_database_findings() {
    let v4 = "192.0.2.10";
    let fs = ports_findings(
        "example.com",
        &result(
            &[v4],
            &[(v4, 22, "SSH", Open), (v4, 3306, "MySQL", Open), (v4, 80, "HTTP", Closed), (v4, 443, "HTTPS", Closed)],
        ),
    );
    let sev = |c: &str| fs.iter().find(|f| f.code == c).map(|f| f.severity);
    assert_eq!(sev("hosting_reachability_web_closed"), Some(Severity::Warning));
    assert_eq!(sev("hosting_reachability_smtp_closed"), Some(Severity::Info));
    assert_eq!(sev("hosting_reachability_database_exposed"), Some(Severity::Warning));
    assert_eq!(sev("hosting_reachability_reachable"), Some(Severity::Ok));
    assert!(
        fs.iter()
            .find(|f| f.code == "hosting_reachability_database_exposed")
            .unwrap()
            .message
            .starts_with("MySQL (3306) accepts")
    );

    let fs = ports_findings(
        "example.com",
        &result(&[v4], &[(v4, 80, "HTTP", Open), (v4, 443, "HTTPS", Closed), (v4, 25, "SMTP", Open)]),
    );
    assert_eq!(
        fs.iter().find(|f| f.code == "hosting_reachability_no_https").map(|f| f.severity),
        Some(Severity::Warning)
    );
    assert!(!codes(&fs).contains(&"hosting_reachability_web_closed"));
    let fs = ports_findings(
        "example.com",
        &result(
            &[v4],
            &[
                (v4, 80, "HTTP", Open),
                (v4, 443, "HTTPS", Open),
                (v4, 25, "SMTP", Closed),
                (v4, 587, "Submission", Open),
            ],
        ),
    );
    assert!(
        fs.iter()
            .find(|f| f.code == "hosting_reachability_smtp_closed")
            .unwrap()
            .message
            .ends_with("Mail submission is open, so the server does run mail.")
    );
}

#[test]
fn each_address_is_judged_on_its_own() {
    // HTTPS open over IPv4 must not hide that IPv6 lacks it.
    let (v4, v6) = ("192.0.2.10", V6);
    let r = result(
        &[v4, v6],
        &[
            (v4, 80, "HTTP", Open),
            (v4, 443, "HTTPS", Open),
            (v4, 25, "SMTP", Open),
            (v6, 80, "HTTP", NoRoute),
            (v6, 443, "HTTPS", NoRoute),
            (v6, 25, "SMTP", NoRoute),
        ],
    );
    let fs = ports_findings("dual.example.com", &r);
    let web = fs.iter().find(|f| f.code == "hosting_reachability_web_closed").expect("web_closed");
    assert!(web.message.contains(V6) && !web.message.contains(v4), "{}", web.message);
    assert!(
        fs.iter()
            .find(|f| f.code == "hosting_reachability_reachable")
            .unwrap()
            .message
            .starts_with("192.0.2.10 and 2001:db8::10 answers on")
    );
}

#[test]
fn only_mail_ports_with_no_answer_blames_the_probing_network_not_the_server() {
    // Many networks and hosting providers block outbound SMTP: silence on 25 alone says nothing about the server.
    let v4 = "192.0.2.10";
    let r = result(&[v4], &[(v4, 25, "SMTP", Filtered)]);
    let fs = ports_findings("mail.example.com", &r);
    assert_eq!(codes(&fs), ["hosting_reachability_mail_filtered"], "{fs:?}");
    assert_eq!(fs[0].severity, Severity::Info);
    assert!(fs[0].message.contains("block outbound"), "{}", fs[0].message);
}

#[test]
fn mail_ports_that_are_refused_still_say_the_server_is_up() {
    let v4 = "192.0.2.10";
    let r = result(&[v4], &[(v4, 25, "SMTP", Closed), (v4, 587, "Submission", Closed)]);
    assert_eq!(codes(&ports_findings("mail.example.com", &r)), ["hosting_reachability_unreachable"]);
}

#[test]
fn silence_on_web_ports_is_still_unreachable() {
    let v4 = "192.0.2.10";
    let r = result(&[v4], &[(v4, 80, "HTTP", Filtered), (v4, 25, "SMTP", Filtered)]);
    assert_eq!(codes(&ports_findings("example.com", &r)), ["hosting_reachability_unreachable"]);
}
