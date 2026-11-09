#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Summary,
    Dns,
    Delegation,
    Dnssec,
    Email,
    Web,
    Tls,
    Registration,
}

impl Section {
    pub const ALL: [Section; 8] = [
        Section::Summary,
        Section::Dns,
        Section::Delegation,
        Section::Dnssec,
        Section::Email,
        Section::Web,
        Section::Tls,
        Section::Registration,
    ];

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
        }
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
        assert_eq!(Section::Registration.step(1), Section::Summary);
        assert_eq!(Section::Summary.step(-1), Section::Registration);
        assert_eq!(Section::Dns.step(1), Section::Delegation);
    }

    #[test]
    fn rail_order_matches_the_design() {
        let labels: Vec<_> = Section::ALL.iter().map(|s| s.label()).collect();
        assert_eq!(labels, ["Summary", "DNS", "Delegation", "DNSSEC", "Email", "Web", "TLS", "Registration"]);
    }

    #[test]
    fn at_rejects_the_ninth_slot() {
        assert_eq!(Section::at(7), Some(Section::Registration));
        assert_eq!(Section::at(8), None);
    }
}
