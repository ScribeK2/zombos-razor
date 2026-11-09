/// The record types the propagation Check asks every resolver for. SOA is asked of
/// nameservers only and CAA not at all, so neither can be compared across resolvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordKind {
    #[default]
    A,
    Aaaa,
    Mx,
    Ns,
    Txt,
    Cname,
}

impl RecordKind {
    pub const ALL: [RecordKind; 6] =
        [RecordKind::A, RecordKind::Aaaa, RecordKind::Mx, RecordKind::Ns, RecordKind::Txt, RecordKind::Cname];

    pub fn code(self) -> &'static str {
        match self {
            RecordKind::A => "A",
            RecordKind::Aaaa => "AAAA",
            RecordKind::Mx => "MX",
            RecordKind::Ns => "NS",
            RecordKind::Txt => "TXT",
            RecordKind::Cname => "CNAME",
        }
    }

    pub fn step(self, delta: isize) -> RecordKind {
        let i = Self::ALL.iter().position(|&k| k == self).unwrap_or(0) as isize;
        Self::ALL[(i + delta).rem_euclid(Self::ALL.len() as isize) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_a_and_stepping_wraps() {
        assert_eq!(RecordKind::default(), RecordKind::A);
        assert_eq!(RecordKind::A.step(-1), RecordKind::Cname);
        assert_eq!(RecordKind::Cname.step(1), RecordKind::A);
        assert_eq!(RecordKind::Txt.step(1).code(), "CNAME");
    }

    #[test]
    fn every_code_is_a_key_the_core_answers_with() {
        let core: Vec<String> = zombo_core::propagation::Scope::All.types().iter().map(|t| t.to_string()).collect();
        for k in RecordKind::ALL {
            assert!(core.iter().any(|c| c == k.code()), "{} is not asked by Scope::All", k.code());
        }
    }
}
