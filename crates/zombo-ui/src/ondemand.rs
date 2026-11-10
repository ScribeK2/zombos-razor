use zombo_core::{blacklist::DNSBLS, ports::QUICK, target::Kind};

use crate::{section::Section, status::CheckState};

/// What an on-demand Check will do, shown before the rep runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brief {
    pub what: String,
    pub contacts: String,
    pub note: Option<&'static str>,
}

/// The Checks a rep can ask for on this kind of target. They never start by themselves.
pub fn on_demand(kind: Kind) -> &'static [Section] {
    match kind {
        Kind::Domain | Kind::Hostname | Kind::Email | Kind::Ip => {
            &[Section::Ports, Section::Smtp, Section::TlsPort, Section::Blacklist]
        }
    }
}

pub fn runnable(kind: Kind, section: Section) -> bool {
    on_demand(kind).contains(&section)
}

/// Once a result exists the description card shrinks to one line, unless the rep opened it.
pub fn collapsed(state: &CheckState, open: bool) -> bool {
    !open && matches!(state, CheckState::Done { .. } | CheckState::Failed { .. } | CheckState::TimedOut)
}

pub fn run_label(section: Section) -> Option<&'static str> {
    match section {
        Section::Ports => Some("Run port scan"),
        Section::Smtp => Some("Run SMTP banner check"),
        Section::TlsPort => Some("Run TLS check"),
        Section::Blacklist => Some("Run blacklist check"),
        _ => None,
    }
}

pub fn brief(section: Section) -> Option<Brief> {
    let brief = |what: &str, contacts: String, note: &'static str| Brief {
        what: what.into(),
        contacts,
        note: Some(note).filter(|n| !n.is_empty()),
    };
    match section {
        Section::Ports => {
            let ports = QUICK.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ");
            Some(brief(
                "Tries to open a connection to the common service ports and reports which ones answer.",
                format!("The target's own servers, on TCP ports {ports}: its first IPv4 address, and its first IPv6 address if this machine has IPv6. This machine's resolver looks up the name first."),
                "A port that gives no answer is reported as no answer, not as down: many networks block outbound mail ports.",
            ))
        }
        Section::Smtp => Some(brief(
            "Connects to the target's mail port, reads the greeting, lists what the server offers and tries STARTTLS. It sends no mail.",
            "For a domain, its MX hosts, most preferred first (up to 3 are tried), on the port you pick below. For a host name or an IP address, that name or address on the port. This machine's resolver looks up the MX records, the name and the reverse name of the address.".into(),
            "Port 25 is often blocked outbound on home and cloud networks. A host that gives no answer is reported as no answer, not as down. Ports 587 and 465 are the submission ports.",
        )),
        Section::TlsPort => Some(brief(
            "Opens a TLS connection to one port of the target and reads the certificate and protocol it presents. It sends no mail and no web request.",
            "The target's own server, on the port you pick below: its first address, found by this machine's resolver. The target sees one TLS handshake.".into(),
            "Port 443 is the website. Mail servers present their own certificate on 465, 993 and 995. A server that starts TLS with STARTTLS on 25 or 587 is checked in the SMTP banner check.",
        )),
        Section::Blacklist => Some(brief(
            "Asks public blocklists whether the target's address, or a domain and its mail hosts, are listed for spam.",
            format!(
                "This machine's resolver, which sends {} questions per address to the blocklist operators' DNS servers (Spamhaus, SpamCop, Barracuda and others). They see the address or domain asked about. Nothing connects to the target.",
                DNSBLS.len()
            ),
            "",
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_kind_can_ask_for_the_four_checks() {
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            assert_eq!(
                on_demand(kind),
                [Section::Ports, Section::Smtp, Section::TlsPort, Section::Blacklist],
                "{kind:?}"
            );
        }
    }

    #[test]
    fn exactly_the_on_demand_sections_have_a_brief_and_a_run_label() {
        for s in Section::ALL {
            assert_eq!(brief(s).is_some(), s.is_on_demand(), "{s:?}");
            assert_eq!(run_label(s).is_some(), s.is_on_demand(), "{s:?}");
            assert_eq!(runnable(Kind::Domain, s), s.is_on_demand(), "{s:?}");
        }
    }

    #[test]
    fn the_card_collapses_only_after_a_result_and_only_until_it_is_opened() {
        let done = CheckState::Done { problems: 0 };
        for s in [CheckState::NotRun, CheckState::Running] {
            assert!(!collapsed(&s, false), "{s:?}");
        }
        for s in [done.clone(), CheckState::Failed { reason: "x".into() }, CheckState::TimedOut] {
            assert!(collapsed(&s, false), "{s:?}");
            assert!(!collapsed(&s, true), "{s:?} opened");
        }
    }

    #[test]
    fn the_brief_names_the_servers_it_will_contact() {
        let ports = brief(Section::Ports).unwrap();
        assert!(ports.contacts.contains("25") && ports.contacts.contains("3306"));
        assert!(brief(Section::Smtp).unwrap().contacts.contains("MX hosts"));
        assert!(brief(Section::TlsPort).unwrap().contacts.contains("on the port you pick"));
        assert!(brief(Section::Blacklist).unwrap().contacts.contains("Nothing connects to the target"));
    }
}
