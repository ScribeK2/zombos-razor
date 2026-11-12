//! Every fact a rail section has, frozen as literals. It reads only the public interface, so it
//! must pass unchanged however the facts are stored (a table in the UI or a Check descriptor).

use std::time::Duration;

use zombo_core::target::Kind;
use zombo_ui::{blind_spots, checks, ondemand, section::Section, settings_model::budget};

struct Row {
    section: Section,
    label: &'static str,
    position: usize,
    on_demand: bool,
    watchable: bool,
    wired: bool,
    /// The target kinds the section runs on by itself.
    automatic_for: &'static [Kind],
    /// `(whole, query)` in milliseconds with no setting.
    default_budget: (u128, u128),
    /// The same with a 30 second timeout setting.
    budget_at_30s: (u128, u128),
    blind_spots: &'static [&'static str],
    /// `(what, contacts, note)` of the on-demand brief.
    brief: Option<(&'static str, &'static str, Option<&'static str>)>,
    run_label: Option<&'static str>,
}

const ROWS: [Row; 13] = [
    Row {
        section: Section::Summary,
        label: "Summary",
        position: 0,
        on_demand: false,
        watchable: false,
        wired: false,
        automatic_for: &[],
        default_budget: (20000, 4000),
        budget_at_30s: (30000, 6000),
        blind_spots: &[],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Dns,
        label: "DNS",
        position: 1,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Domain, Kind::Hostname, Kind::Email],
        default_budget: (20000, 4000),
        budget_at_30s: (30000, 6000),
        blind_spots: &[
            "The registrar account: who controls the domain, and a change saved there but not yet published.",
            "The host's own resolver, and its cache or hosts file. Only the This machine row shows this machine's.",
            "Answers given only to some networks (split-horizon DNS) or regions beyond the resolvers asked.",
            "The DNS provider's panel: records saved there but not yet served.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Delegation,
        label: "Delegation",
        position: 2,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Domain, Kind::Email],
        default_budget: (20000, 4000),
        budget_at_30s: (30000, 6000),
        blind_spots: &[
            "The registrar account where the nameservers are set.",
            "Nameservers that answer only some networks: a server that is silent here may answer elsewhere.",
            "Why a nameserver is lame: its configuration and logs are on its own host.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Dnssec,
        label: "DNSSEC",
        position: 3,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Domain, Kind::Email],
        default_budget: (20000, 4000),
        budget_at_30s: (30000, 6000),
        blind_spots: &[
            "The signing keys and how the DNS provider stores and rolls them.",
            "The DS record upload at the registrar: only what the parent zone serves now is read.",
            "Resolvers beyond the four asked: a resolver with an old trust anchor can disagree.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Email,
        label: "Email",
        position: 4,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Domain, Kind::Email],
        default_budget: (25000, 4000),
        budget_at_30s: (30000, 4800),
        blind_spots: &[
            "Recipient-side filtering: spam filters, quarantine and allow lists decide delivery after DNS passes.",
            "Mail that was really sent: DMARC reports and mail logs hold that, DNS does not.",
            "DKIM keys under a selector this Check did not try.",
            "The settings inside the sending service's own console.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Web,
        label: "Web",
        position: 5,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Domain, Kind::Hostname, Kind::Email],
        default_budget: (12000, 10000),
        budget_at_30s: (30000, 25000),
        blind_spots: &[
            "Application logs and errors behind the page.",
            "The CDN's origin server: the Check sees what the CDN returns, not what is behind it.",
            "Pages behind a login, and content that JavaScript builds.",
            "How the site answers other regions or networks than this one.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Tls,
        label: "TLS",
        position: 6,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Domain, Kind::Hostname, Kind::Email],
        default_budget: (10000, 8000),
        budget_at_30s: (30000, 24000),
        blind_spots: &[
            "Other ports: the TLS on a port Check asks for those.",
            "Protocol versions below TLS 1.2: this tool speaks only 1.2 and 1.3.",
            "Cipher suites the server accepts but did not choose.",
            "Revocation at the CA: only an OCSP response stapled by the server is seen.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Registration,
        label: "Registration",
        position: 7,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Domain, Kind::Hostname, Kind::Email],
        default_budget: (15000, 12000),
        budget_at_30s: (30000, 24000),
        blind_spots: &[
            "The registrar account: ownership contact, locks, billing and auto-renew.",
            "Contact details hidden by a privacy service.",
            "Changes the registry has not yet published to RDAP or WHOIS.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Rdns,
        label: "Reverse DNS",
        position: 8,
        on_demand: false,
        watchable: true,
        wired: true,
        automatic_for: &[Kind::Ip],
        default_budget: (20000, 4000),
        budget_at_30s: (30000, 6000),
        blind_spots: &[
            "The hosting provider's panel, where the PTR record is set.",
            "Reverse names published only to some networks.",
            "Whether a mail server's greeting name matches its PTR: only the DNS side is read.",
        ],
        brief: None,
        run_label: None,
    },
    Row {
        section: Section::Ports,
        label: "Port scan",
        position: 9,
        on_demand: true,
        watchable: false,
        wired: true,
        automatic_for: &[],
        default_budget: (20000, 4000),
        budget_at_30s: (30000, 4000),
        blind_spots: &[
            "UDP services: only TCP ports are tried.",
            "Ports outside the quick list.",
            "Whether a firewall that allows only some source addresses is hiding a service from this machine.",
            "Whether this network or the target blocks a port that gives no answer.",
        ],
        brief: Some((
            "Tries to open a connection to the common service ports and reports which ones answer.",
            "The target's own servers, on TCP ports 80, 443, 25, 587, 993, 22, 21, 3306: its first IPv4 address, and its first IPv6 address if this machine has IPv6. This machine's resolver looks up the name first.",
            Some(
                "A port that gives no answer is reported as no answer, not as down: many networks block outbound mail ports.",
            ),
        )),
        run_label: Some("Run port scan"),
    },
    Row {
        section: Section::Smtp,
        label: "SMTP banner",
        position: 10,
        on_demand: true,
        watchable: false,
        wired: true,
        automatic_for: &[],
        default_budget: (40000, 40000),
        budget_at_30s: (40000, 40000),
        blind_spots: &[
            "Whether the server accepts mail from you: no mail is sent.",
            "Recipient-side filtering of mail it does accept.",
            "MX hosts after the first three tried.",
            "Whether this network blocks the port, when there is no answer.",
        ],
        brief: Some((
            "Connects to the target's mail port, reads the greeting, lists what the server offers and tries STARTTLS. It sends no mail.",
            "For a domain, its MX hosts, most preferred first (up to 3 are tried), on the port you pick below. For a host name or an IP address, that name or address on the port. This machine's resolver looks up the MX records, the name and the reverse name of the address.",
            Some(
                "Port 25 is often blocked outbound on home and cloud networks. A host that gives no answer is reported as no answer, not as down. Ports 587 and 465 are the submission ports.",
            ),
        )),
        run_label: Some("Run SMTP banner check"),
    },
    Row {
        section: Section::TlsPort,
        label: "TLS on a port",
        position: 11,
        on_demand: true,
        watchable: false,
        wired: true,
        automatic_for: &[],
        default_budget: (10000, 8000),
        budget_at_30s: (30000, 8000),
        blind_spots: &[
            "Services that start TLS after a plain greeting (STARTTLS): the SMTP banner check covers those.",
            "A server that requires a client certificate.",
            "Protocol versions below TLS 1.2, and revocation at the CA.",
        ],
        brief: Some((
            "Opens a TLS connection to one port of the target and reads the certificate and protocol it presents. It sends no mail and no web request.",
            "The target's own server, on the port you pick below: its first address, found by this machine's resolver. The target sees one TLS handshake.",
            Some(
                "Port 443 is the website. Mail servers present their own certificate on 465, 993 and 995. A server that starts TLS with STARTTLS on 25 or 587 is checked in the SMTP banner check.",
            ),
        )),
        run_label: Some("Run TLS check"),
    },
    Row {
        section: Section::Blacklist,
        label: "Blacklist",
        position: 12,
        on_demand: true,
        watchable: false,
        wired: true,
        automatic_for: &[],
        default_budget: (25000, 25000),
        budget_at_30s: (30000, 25000),
        blind_spots: &[
            "Lists that are not in the table this Check asks.",
            "Private block lists inside the receiving company.",
            "Whether a listing changes delivery: the receiving server decides.",
            "The sending reputation of the domain's mail history.",
        ],
        brief: Some((
            "Asks public blocklists whether the target's address, or a domain and its mail hosts, are listed for spam.",
            "This machine's resolver, which sends 10 questions per address to the blocklist operators' DNS servers (Spamhaus, SpamCop, Barracuda and others). They see the address or domain asked about. Nothing connects to the target.",
            None,
        )),
        run_label: Some("Run blacklist check"),
    },
];

const AUTOMATIC_ORDER: [(Kind, &[Section]); 4] = [
    (
        Kind::Domain,
        &[
            Section::Dns,
            Section::Delegation,
            Section::Dnssec,
            Section::Email,
            Section::Web,
            Section::Tls,
            Section::Registration,
        ],
    ),
    (Kind::Hostname, &[Section::Dns, Section::Web, Section::Tls, Section::Registration]),
    (
        Kind::Email,
        &[
            Section::Dns,
            Section::Delegation,
            Section::Dnssec,
            Section::Email,
            Section::Web,
            Section::Tls,
            Section::Registration,
        ],
    ),
    (Kind::Ip, &[Section::Rdns]),
];

#[test]
fn the_rail_has_these_thirteen_sections_in_this_order() {
    assert_eq!(Section::ALL.len(), 13);
    for (i, row) in ROWS.iter().enumerate() {
        assert_eq!(Section::ALL[i], row.section, "slot {i}");
        assert_eq!(row.section.index(), i, "{:?}", row.section);
        assert_eq!(Section::at(i), Some(row.section));
    }
    assert_eq!(Section::at(13), None);
}

#[test]
fn the_first_on_demand_slot_is_the_ninth_and_holds_the_port_scan() {
    assert_eq!(Section::FIRST_ON_DEMAND, 9);
    assert_eq!(Section::at(Section::FIRST_ON_DEMAND), Some(Section::Ports));
}

#[test]
fn every_section_keeps_its_facts() {
    for row in &ROWS {
        let s = row.section;
        assert_eq!(s.label(), row.label, "{s:?} label");
        assert_eq!(s.index(), row.position, "{s:?} position");
        assert_eq!(s.is_on_demand(), row.on_demand, "{s:?} on demand");
        assert_eq!(checks::watchable(s), row.watchable, "{s:?} watchable");
        assert_eq!(checks::wired(s), row.wired, "{s:?} wired");
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            assert_eq!(
                checks::automatic(kind).contains(&s),
                row.automatic_for.contains(&kind),
                "{s:?} automatic for {kind:?}"
            );
        }
        let b = budget(s, None);
        assert_eq!((b.whole.as_millis(), b.query.as_millis()), row.default_budget, "{s:?} default budget");
        let b = budget(s, Some(Duration::from_secs(30)));
        assert_eq!((b.whole.as_millis(), b.query.as_millis()), row.budget_at_30s, "{s:?} budget at 30 s");
        assert_eq!(blind_spots::lines(s), row.blind_spots, "{s:?} blind spots");
        let brief = ondemand::brief(s);
        assert_eq!(brief.as_ref().map(|b| (b.what.as_str(), b.contacts.as_str(), b.note)), row.brief, "{s:?} brief");
        assert_eq!(ondemand::run_label(s), row.run_label, "{s:?} run label");
    }
}

#[test]
fn the_automatic_checks_run_in_this_order_for_each_kind() {
    for (kind, order) in AUTOMATIC_ORDER {
        assert_eq!(checks::automatic(kind), order, "{kind:?}");
    }
}
