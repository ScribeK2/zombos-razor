use std::collections::HashSet;

use crate::section::Section;

/// Which collapsed rows are open. The state belongs to one tab and one section, so opening
/// "All records" in one tab leaves every other tab as it was. Rows start collapsed.
#[derive(Debug, Default)]
pub struct OpenState {
    open: HashSet<(String, Section, &'static str)>,
}

impl OpenState {
    fn key(target: &str, section: Section, id: &'static str) -> (String, Section, &'static str) {
        (target.to_string(), section, id)
    }

    pub fn is_open(&self, target: &str, section: Section, id: &'static str) -> bool {
        self.open.contains(&Self::key(target, section, id))
    }

    pub fn toggle(&mut self, target: &str, section: Section, id: &'static str) {
        let key = Self::key(target, section, id);
        if !self.open.remove(&key) {
            self.open.insert(key);
        }
    }

    /// Closing a tab drops its state, like the rest of its results.
    pub fn keep_targets(&mut self, alive: impl Fn(&str) -> bool) {
        self.open.retain(|(target, ..)| alive(target));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_start_collapsed_and_toggle() {
        let mut s = OpenState::default();
        assert!(!s.is_open("a.com", Section::Dns, "records"));
        s.toggle("a.com", Section::Dns, "records");
        assert!(s.is_open("a.com", Section::Dns, "records"));
        s.toggle("a.com", Section::Dns, "records");
        assert!(!s.is_open("a.com", Section::Dns, "records"));
    }

    #[test]
    fn state_is_kept_per_tab_and_per_section() {
        let mut s = OpenState::default();
        s.toggle("a.com", Section::Dns, "records");
        assert!(!s.is_open("b.com", Section::Dns, "records"));
        assert!(!s.is_open("a.com", Section::Email, "records"));
        assert!(!s.is_open("a.com", Section::Dns, "nameservers"));
    }

    #[test]
    fn a_closed_tab_forgets_its_rows() {
        let mut s = OpenState::default();
        s.toggle("a.com", Section::Dns, "records");
        s.toggle("b.com", Section::Dns, "records");
        s.keep_targets(|t| t == "b.com");
        assert!(!s.is_open("a.com", Section::Dns, "records"));
        assert!(s.is_open("b.com", Section::Dns, "records"));
    }
}
