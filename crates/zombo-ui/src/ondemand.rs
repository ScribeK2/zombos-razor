use zombo_core::target::Kind;

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
    section.check()?.on_demand.map(|d| d.run_label)
}

pub fn brief(section: Section) -> Option<Brief> {
    section.check()?.on_demand.map(|d| Brief { what: d.what.into(), contacts: d.contacts.into(), note: d.note })
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
