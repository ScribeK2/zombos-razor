use std::borrow::Cow;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// Sort key for worst first: `Critical` is 0 and `Ok` is the largest.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::Warning => 1,
            Severity::Info => 2,
            Severity::Ok => 3,
        }
    }
}

/// A conclusion with a severity, derived from one Lookup.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    /// Usually a fixed sentence; a runtime string where the title carries a value.
    pub title: Cow<'static, str>,
    pub message: String,
    pub recommendation: Option<Cow<'static, str>>,
}

#[cfg(test)]
mod tests {
    use super::Severity::{Critical, Info, Ok, Warning};

    #[test]
    fn severity_sorts_worst_first_critical_warning_info_ok() {
        let mut all = [Ok, Info, Warning, Critical];
        all.sort_by_key(|s| s.rank());
        assert_eq!(all, [Critical, Warning, Info, Ok]);
        let ranks: Vec<u8> = all.iter().map(|s| s.rank()).collect();
        assert!(ranks.windows(2).all(|w| w[0] < w[1]), "{ranks:?}");
    }
}
