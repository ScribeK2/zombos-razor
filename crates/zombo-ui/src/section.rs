use zombo_core::{blacklist, check::Check, delegation, dnssec, email_auth, ports, rdns, registration, smtp, tls, web};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Summary,
    Dns,
    Delegation,
    Dnssec,
    Email,
    Web,
    Tls,
    Registration,
    Rdns,
    Ports,
    Smtp,
    TlsPort,
    Blacklist,
}

enum Home {
    Literal(&'static str),
    Check(&'static Check),
}

impl Section {
    pub const ALL: [Section; 13] = [
        Section::Summary,
        Section::Dns,
        Section::Delegation,
        Section::Dnssec,
        Section::Email,
        Section::Web,
        Section::Tls,
        Section::Registration,
        Section::Rdns,
        Section::Ports,
        Section::Smtp,
        Section::TlsPort,
        Section::Blacklist,
    ];

    /// Ctrl+9 jumps here: the first of the Checks that only run when asked.
    pub const FIRST_ON_DEMAND: usize = 9;

    pub fn label(self) -> &'static str {
        match self.home() {
            Home::Literal(label) => label,
            Home::Check(check) => check.label,
        }
    }

    /// The Check behind this section, or `None` for the two sections that are not one Check:
    /// the Summary and DNS propagation.
    pub(crate) fn check(self) -> Option<&'static Check> {
        match self.home() {
            Home::Literal(_) => None,
            Home::Check(check) => Some(check),
        }
    }

    /// Where a section gets its facts. Every variant is named here, with no wildcard, so a new
    /// section does not compile until it says whether it has a Check.
    fn home(self) -> Home {
        match self {
            Section::Summary => Home::Literal("Summary"),
            Section::Dns => Home::Literal("DNS"),
            Section::Delegation => Home::Check(&delegation::CHECK),
            Section::Dnssec => Home::Check(&dnssec::CHECK),
            Section::Email => Home::Check(&email_auth::CHECK),
            Section::Web => Home::Check(&web::CHECK),
            Section::Tls => Home::Check(&tls::CHECK),
            Section::Registration => Home::Check(&registration::CHECK),
            Section::TlsPort => Home::Check(&tls::ON_PORT),
            Section::Rdns => Home::Check(&rdns::CHECK),
            Section::Ports => Home::Check(&ports::CHECK),
            Section::Smtp => Home::Check(&smtp::CHECK),
            Section::Blacklist => Home::Check(&blacklist::CHECK),
        }
    }

    pub fn is_on_demand(self) -> bool {
        self.check().is_some_and(Check::is_on_demand)
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&s| s == self).unwrap_or(0)
    }

    pub fn at(index: usize) -> Option<Section> {
        Self::ALL.get(index).copied()
    }

    pub fn step(self, delta: isize) -> Section {
        crate::cycle::step(&Self::ALL, self, delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stepping_wraps_in_both_directions() {
        assert_eq!(Section::Blacklist.step(1), Section::Summary);
        assert_eq!(Section::Summary.step(-1), Section::Blacklist);
        assert_eq!(Section::Smtp.step(1), Section::TlsPort);
        assert_eq!(Section::Dns.step(1), Section::Delegation);
    }

    #[test]
    fn rail_order_matches_the_design() {
        let labels: Vec<_> = Section::ALL.iter().map(|s| s.label()).collect();
        assert_eq!(
            labels,
            [
                "Summary",
                "DNS",
                "Delegation",
                "DNSSEC",
                "Email",
                "Web",
                "TLS",
                "Registration",
                "Reverse DNS",
                "Port scan",
                "SMTP banner",
                "TLS on a port",
                "Blacklist"
            ]
        );
    }

    #[test]
    fn the_ninth_slot_is_the_first_on_demand_check() {
        assert_eq!(Section::at(7), Some(Section::Registration));
        assert_eq!(Section::at(Section::FIRST_ON_DEMAND), Some(Section::Ports));
        assert_eq!(Section::at(13), None);
    }

    #[test]
    fn every_section_but_the_summary_and_dns_is_behind_a_descriptor() {
        let behind: Vec<_> = Section::ALL.iter().filter(|s| s.check().is_some()).collect();
        assert_eq!(
            behind,
            [
                &Section::Delegation,
                &Section::Dnssec,
                &Section::Email,
                &Section::Web,
                &Section::Tls,
                &Section::Registration,
                &Section::Rdns,
                &Section::Ports,
                &Section::Smtp,
                &Section::TlsPort,
                &Section::Blacklist
            ]
        );
        assert!(std::ptr::eq(Section::Tls.check().unwrap(), &tls::CHECK));
        assert!(std::ptr::eq(Section::TlsPort.check().unwrap(), &tls::ON_PORT));
    }

    #[test]
    fn exactly_the_last_four_are_on_demand() {
        let on: Vec<_> = Section::ALL.iter().filter(|s| s.is_on_demand()).map(|s| s.index()).collect();
        assert_eq!(on, [9, 10, 11, 12]);
    }

    /// The one guard that the UI and the core registry cannot drift: the UI runs a section on a
    /// kind exactly when its descriptor accepts the kind, and every descriptor is in `ALL`.
    #[test]
    fn the_registry_matches_what_the_rail_runs() {
        use zombo_core::{
            check::ALL,
            target::{Kind, parse_target},
        };

        let targets: Vec<_> = ["example.com", "www.example.com", "bob@example.com", "192.0.2.1"]
            .iter()
            .map(|raw| parse_target(raw).unwrap())
            .collect();
        let kinds: Vec<Kind> = targets.iter().map(|t| t.kind).collect();
        assert_eq!(kinds, [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip]);
        for section in Section::ALL {
            let Some(check) = section.check() else { continue };
            assert!(ALL.iter().any(|c| std::ptr::eq(*c, check)), "{section:?} is missing from ALL");
            for target in &targets {
                assert_eq!(
                    crate::checks::name_for(section, target).is_some(),
                    check.accepts.contains(&target.kind),
                    "{section:?} on {:?}",
                    target.kind
                );
            }
        }
        assert_eq!(ALL.len(), Section::ALL.iter().filter(|s| s.check().is_some()).count());
    }
}
