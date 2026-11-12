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

impl Finding {
    /// A Finding with no recommendation. Chain [`Finding::recommend`] to add one.
    #[must_use]
    pub fn new(
        code: &'static str,
        severity: Severity,
        title: impl Into<Cow<'static, str>>,
        message: String,
    ) -> Finding {
        Finding { code, severity, title: title.into(), message, recommendation: None }
    }

    /// Sets the recommendation, from a `&'static str`, a `String` or a `Cow`.
    #[must_use]
    pub fn recommend(mut self, text: impl Into<Cow<'static, str>>) -> Finding {
        self.recommendation = Some(text.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::Finding;
    use super::Severity::{Critical, Info, Ok, Warning};

    #[test]
    fn new_leaves_the_recommendation_empty() {
        let f = Finding::new("dns_example", Warning, "Title", "Message".to_string());
        assert_eq!(f.code, "dns_example");
        assert_eq!(f.severity, Warning);
        assert_eq!(f.message, "Message");
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn new_takes_a_static_or_an_owned_title() {
        let fixed = Finding::new("dns_example", Info, "Fixed", String::new());
        assert!(matches!(fixed.title, Cow::Borrowed("Fixed")));
        let port = 25;
        let owned = Finding::new("dns_example", Info, format!("Port {port}"), String::new());
        assert!(matches!(&owned.title, Cow::Owned(t) if t == "Port 25"));
    }

    #[test]
    fn recommend_keeps_a_static_str_borrowed() {
        let f = Finding::new("dns_example", Info, "T", String::new()).recommend("Do this.");
        assert!(matches!(f.recommendation, Some(Cow::Borrowed("Do this."))));
    }

    #[test]
    fn recommend_owns_a_string() {
        let f = Finding::new("dns_example", Info, "T", String::new()).recommend(format!("Do {}.", "this"));
        assert!(matches!(&f.recommendation, Some(Cow::Owned(t)) if t == "Do this."));
    }

    #[test]
    fn recommend_takes_a_cow_as_it_is() {
        let borrowed: Cow<'static, str> = Cow::Borrowed("Static.");
        let owned: Cow<'static, str> = Cow::Owned("Owned.".to_string());
        let a = Finding::new("dns_example", Info, "T", String::new()).recommend(borrowed);
        let b = Finding::new("dns_example", Info, "T", String::new()).recommend(owned);
        assert!(matches!(a.recommendation, Some(Cow::Borrowed("Static."))));
        assert!(matches!(&b.recommendation, Some(Cow::Owned(t)) if t == "Owned."));
    }

    #[test]
    fn severity_sorts_worst_first_critical_warning_info_ok() {
        let mut all = [Ok, Info, Warning, Critical];
        all.sort_by_key(|s| s.rank());
        assert_eq!(all, [Critical, Warning, Info, Ok]);
        let ranks: Vec<u8> = all.iter().map(|s| s.rank()).collect();
        assert!(ranks.windows(2).all(|w| w[0] < w[1]), "{ranks:?}");
    }
}
