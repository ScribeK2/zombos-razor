use zombo_core::{blacklist::DNSBLS, ports::QUICK, target::Kind};

use crate::section::Section;

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
        Kind::Domain | Kind::Hostname | Kind::Email | Kind::Ip => &[Section::Ports, Section::Smtp, Section::Blacklist],
    }
}

pub fn runnable(kind: Kind, section: Section) -> bool {
    on_demand(kind).contains(&section)
}

pub fn run_label(section: Section) -> Option<&'static str> {
    match section {
        Section::Ports => Some("Run port scan"),
        Section::Smtp => Some("Run SMTP banner check"),
        Section::Blacklist => Some("Run blacklist check"),
        _ => None,
    }
}

pub fn brief(section: Section) -> Option<Brief> {
    let brief = |what: &str, contacts: String, note: &'static str| Brief { what: what.into(), contacts, note: Some(note).filter(|n| !n.is_empty()) };
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
            "The target's server on port 25, dialled by the name you typed. This machine's resolver looks up the name and the reverse name of the address.".into(),
            "This build does not look up MX records first and the port is fixed at 25. For a domain whose mail is hosted elsewhere, open the mail host's name as the target.",
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
    fn every_target_kind_can_ask_for_the_three_checks() {
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            assert_eq!(on_demand(kind), [Section::Ports, Section::Smtp, Section::Blacklist], "{kind:?}");
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
    fn the_brief_names_the_servers_it_will_contact() {
        let ports = brief(Section::Ports).unwrap();
        assert!(ports.contacts.contains("25") && ports.contacts.contains("3306"));
        assert!(brief(Section::Smtp).unwrap().contacts.contains("port 25"));
        assert!(brief(Section::Blacklist).unwrap().contacts.contains("Nothing connects to the target"));
    }
}
