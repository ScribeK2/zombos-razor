use std::collections::BTreeSet;

pub use zombo_core::check::{Fact, Outcome};

use crate::{
    diagnosis::{ordered, problems},
    status::CheckState,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    pub fn summary(&self) -> String {
        match (self.added.len(), self.removed.len()) {
            (0, 0) => "no change".into(),
            (a, 0) => format!("{a} added"),
            (0, r) => format!("{r} removed"),
            (a, r) => format!("{r} removed, {a} added"),
        }
    }
}

/// Lines in `now` but not in `before` are added, and the reverse are removed. Order is
/// the order of the run each line came from, so output is stable.
pub fn diff(before: &[String], now: &[String]) -> Diff {
    let old: BTreeSet<&str> = before.iter().map(String::as_str).collect();
    let new: BTreeSet<&str> = now.iter().map(String::as_str).collect();
    let mut seen = BTreeSet::new();
    let pick = |from: &[String], not_in: &BTreeSet<&str>, seen: &mut BTreeSet<String>| -> Vec<String> {
        from.iter().filter(|l| !not_in.contains(l.as_str()) && seen.insert((*l).clone())).cloned().collect()
    };
    let added = pick(now, &old, &mut seen);
    seen.clear();
    let removed = pick(before, &new, &mut seen);
    Diff { added, removed }
}

/// The records of the last finished run, and what changed against the one before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    baseline: Option<Vec<String>>,
    pub changes: Option<Diff>,
}

impl History {
    pub fn settle(&mut self, records: Vec<String>) {
        self.changes = self.baseline.as_deref().map(|b| diff(b, &records));
        self.baseline = Some(records);
    }

    pub fn records(&self) -> Option<&[String]> {
        self.baseline.as_deref()
    }
}

pub enum CheckEvent {
    Started,
    Finished(Box<Result<Outcome, String>>),
    TimedOut,
    /// The rep stopped it. The Check goes back to not run, with a note, and is not a failure.
    Cancelled,
}

/// A Check that answers once: the five states, its Outcome, and its change history.
#[derive(Debug, Clone)]
pub struct Run {
    pub state: CheckState,
    pub outcome: Outcome,
    pub history: History,
    pub cancelled: bool,
}

impl Run {
    pub fn new() -> Run {
        Run { state: CheckState::NotRun, outcome: Outcome::default(), history: History::default(), cancelled: false }
    }

    pub fn apply(&mut self, event: CheckEvent) {
        match event {
            CheckEvent::Started => {
                self.state = CheckState::Running;
                self.outcome = Outcome::default();
                self.cancelled = false;
            }
            CheckEvent::Cancelled => {
                if self.state == CheckState::Running {
                    self.state = CheckState::NotRun;
                    self.cancelled = true;
                }
            }
            CheckEvent::TimedOut => {
                if self.state == CheckState::Running {
                    self.state = CheckState::TimedOut;
                }
            }
            CheckEvent::Finished(result) => {
                if self.state != CheckState::Running {
                    return;
                }
                match *result {
                    Ok(mut o) => {
                        o.findings = ordered(&o.findings);
                        self.history.settle(o.records());
                        self.state = CheckState::Done { problems: problems(&o.findings) };
                        self.outcome = o;
                    }
                    Err(reason) => self.state = CheckState::Failed { reason },
                }
            }
        }
    }
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use zombo_core::{Finding, Severity};

    use super::*;

    fn lines(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    fn outcome(facts: &[(&str, &str)]) -> Outcome {
        Outcome { facts: facts.iter().map(|(k, v)| Fact::new(*k, v)).collect(), ..Outcome::default() }
    }

    fn run_with(facts: &[(&str, &str)]) -> CheckEvent {
        CheckEvent::Finished(Box::new(Ok(outcome(facts))))
    }

    #[test]
    fn diff_lists_what_was_added_and_what_was_removed() {
        let d = diff(&lines(&["a", "b", "c"]), &lines(&["b", "c", "d", "e"]));
        assert_eq!(d, Diff { added: lines(&["d", "e"]), removed: lines(&["a"]) });
        assert_eq!(d.summary(), "1 removed, 2 added");
    }

    #[test]
    fn identical_runs_have_an_empty_diff() {
        let d = diff(&lines(&["a", "b"]), &lines(&["b", "a"]));
        assert!(d.is_empty());
        assert_eq!(d.summary(), "no change");
    }

    #[test]
    fn a_changed_value_is_one_removal_and_one_addition() {
        let d = diff(&lines(&["TXT: old"]), &lines(&["TXT: new"]));
        assert_eq!((d.added, d.removed), (lines(&["TXT: new"]), lines(&["TXT: old"])));
    }

    #[test]
    fn a_repeated_line_is_reported_once() {
        let d = diff(&lines(&[]), &lines(&["x", "x"]));
        assert_eq!(d.added, lines(&["x"]));
    }

    #[test]
    fn the_first_run_has_nothing_to_compare_with() {
        let mut r = Run::new();
        r.apply(CheckEvent::Started);
        r.apply(run_with(&[("MX", "mail.example.com")]));
        assert_eq!(r.history.changes, None);
    }

    #[test]
    fn a_rerun_compares_with_the_previous_finished_run() {
        let mut r = Run::new();
        for facts in [&[("NS", "a")][..], &[("NS", "a"), ("NS", "b")][..]] {
            r.apply(CheckEvent::Started);
            r.apply(run_with(facts));
        }
        assert_eq!(r.history.changes, Some(Diff { added: lines(&["NS: b"]), removed: vec![] }));
    }

    #[test]
    fn a_failed_run_does_not_replace_the_run_to_compare_with() {
        let mut r = Run::new();
        r.apply(CheckEvent::Started);
        r.apply(run_with(&[("NS", "a")]));
        r.apply(CheckEvent::Started);
        r.apply(CheckEvent::Finished(Box::new(Err("no answer".into()))));
        assert!(matches!(r.state, CheckState::Failed { .. }));
        r.apply(CheckEvent::Started);
        r.apply(run_with(&[("NS", "b")]));
        assert_eq!(r.history.changes, Some(Diff { added: lines(&["NS: b"]), removed: lines(&["NS: a"]) }));
    }

    #[test]
    fn findings_settle_worst_first_and_count_problems() {
        let f = |sev, code: &'static str| Finding::new(code, sev, code, String::new());
        let mut r = Run::new();
        r.apply(CheckEvent::Started);
        r.apply(CheckEvent::Finished(Box::new(Ok(Outcome {
            findings: vec![f(Severity::Ok, "o"), f(Severity::Critical, "c")],
            ..Outcome::default()
        }))));
        assert_eq!(r.outcome.findings[0].code, "c");
        assert_eq!(r.state, CheckState::Done { problems: 1 });
    }

    #[test]
    fn a_cancelled_check_is_not_run_with_a_note_and_not_failed() {
        let mut r = Run::new();
        r.apply(CheckEvent::Started);
        r.apply(CheckEvent::Cancelled);
        assert_eq!((r.state.clone(), r.cancelled), (CheckState::NotRun, true));
        r.apply(run_with(&[("a", "b")]));
        assert_eq!(r.state, CheckState::NotRun, "a result that arrives after the cancel is dropped");
        r.apply(CheckEvent::Started);
        assert!(!r.cancelled, "running again clears the note");
    }

    #[test]
    fn cancelling_a_check_that_is_not_running_changes_nothing() {
        let mut r = Run::new();
        r.apply(CheckEvent::Started);
        r.apply(run_with(&[("a", "b")]));
        r.apply(CheckEvent::Cancelled);
        assert_eq!((r.state.clone(), r.cancelled), (CheckState::Done { problems: 0 }, false));
    }

    #[test]
    fn a_late_result_after_a_timeout_is_ignored() {
        let mut r = Run::new();
        r.apply(CheckEvent::Started);
        r.apply(CheckEvent::TimedOut);
        r.apply(run_with(&[("a", "b")]));
        assert_eq!(r.state, CheckState::TimedOut);
    }

    #[test]
    fn control_characters_never_reach_the_screen() {
        assert_eq!(Fact::new("k\u{7}", "v\u{1b}[31m").record(), "k : v [31m");
    }
}
