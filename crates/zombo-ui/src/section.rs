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
    Ports,
    Smtp,
    Blacklist,
}

impl Section {
    pub const ALL: [Section; 11] = [
        Section::Summary,
        Section::Dns,
        Section::Delegation,
        Section::Dnssec,
        Section::Email,
        Section::Web,
        Section::Tls,
        Section::Registration,
        Section::Ports,
        Section::Smtp,
        Section::Blacklist,
    ];

    /// Ctrl+9 jumps here: the first of the Checks that only run when asked.
    pub const FIRST_ON_DEMAND: usize = 8;

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
            Section::Ports => "Port scan",
            Section::Smtp => "SMTP banner",
            Section::Blacklist => "Blacklist",
        }
    }

    pub fn is_on_demand(self) -> bool {
        matches!(self, Section::Ports | Section::Smtp | Section::Blacklist)
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&s| s == self).unwrap_or(0)
    }

    pub fn at(index: usize) -> Option<Section> {
        Self::ALL.get(index).copied()
    }

    pub fn step(self, delta: isize) -> Section {
        let n = Self::ALL.len() as isize;
        Self::ALL[(self.index() as isize + delta).rem_euclid(n) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stepping_wraps_in_both_directions() {
        assert_eq!(Section::Blacklist.step(1), Section::Summary);
        assert_eq!(Section::Summary.step(-1), Section::Blacklist);
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
                "Port scan",
                "SMTP banner",
                "Blacklist"
            ]
        );
    }

    #[test]
    fn the_ninth_slot_is_the_first_on_demand_check() {
        assert_eq!(Section::at(7), Some(Section::Registration));
        assert_eq!(Section::at(Section::FIRST_ON_DEMAND), Some(Section::Ports));
        assert_eq!(Section::at(11), None);
    }

    #[test]
    fn exactly_the_last_three_are_on_demand() {
        let on: Vec<_> = Section::ALL.iter().filter(|s| s.is_on_demand()).map(|s| s.index()).collect();
        assert_eq!(on, [8, 9, 10]);
    }
}
