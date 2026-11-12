use zombo_core::{check::Check, dnssec, tls};

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
        match self {
            Section::Summary => "Summary",
            Section::Dns => "DNS",
            Section::Delegation => "Delegation",
            Section::Dnssec => "DNSSEC",
            Section::Email => "Email",
            Section::Web => "Web",
            Section::Tls => "TLS",
            Section::Registration => "Registration",
            Section::Rdns => "Reverse DNS",
            Section::Ports => "Port scan",
            Section::Smtp => "SMTP banner",
            Section::TlsPort => "TLS on a port",
            Section::Blacklist => "Blacklist",
        }
    }

    /// The Check behind this section when it is a migrated one: the section then holds no Check
    /// knowledge of its own. `None` for the rest, until each moves behind a descriptor.
    pub(crate) fn check(self) -> Option<&'static Check> {
        match self {
            Section::Dnssec => Some(&dnssec::CHECK),
            Section::Tls => Some(&tls::CHECK),
            Section::TlsPort => Some(&tls::ON_PORT),
            _ => None,
        }
    }

    pub fn is_on_demand(self) -> bool {
        matches!(self, Section::Ports | Section::Smtp | Section::TlsPort | Section::Blacklist)
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
    fn only_dnssec_and_the_two_tls_rows_are_behind_a_descriptor_so_far() {
        let behind: Vec<_> = Section::ALL.iter().filter(|s| s.check().is_some()).collect();
        assert_eq!(behind, [&Section::Dnssec, &Section::Tls, &Section::TlsPort]);
        assert!(std::ptr::eq(Section::Tls.check().unwrap(), &tls::CHECK));
        assert!(std::ptr::eq(Section::TlsPort.check().unwrap(), &tls::ON_PORT));
    }

    #[test]
    fn exactly_the_last_four_are_on_demand() {
        let on: Vec<_> = Section::ALL.iter().filter(|s| s.is_on_demand()).map(|s| s.index()).collect();
        assert_eq!(on, [9, 10, 11, 12]);
    }
}
