use std::time::{Duration, Instant};

use crate::{
    outcome::{Diff, diff},
    section::Section,
    workspace::relative,
};

/// How long a Watch waits between runs of its Check.
pub const INTERVAL: Duration = Duration::from_secs(60);

/// A request to re-run one Check until its answer changes. It holds no clock: every
/// method that needs the time takes it as an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    pub target: String,
    pub section: Section,
    baseline: Option<Vec<String>>,
    started: Instant,
    pub last_run: Option<Instant>,
}

/// What ended a Watch: the answer it was watching is not the answer any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stopped {
    pub target: String,
    pub section: Section,
    pub changes: Diff,
}

impl Stopped {
    pub fn message(&self) -> String {
        format!("{} {} changed: {}. The Watch stopped.", self.target, self.section.label(), self.changes.summary())
    }
}

#[derive(Debug, Default)]
pub struct Watches {
    list: Vec<Watch>,
}

impl Watches {
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn is_watching(&self, target: &str, section: Section) -> bool {
        self.list.iter().any(|w| w.target == target && w.section == section)
    }

    /// Start watching. `current` is the answer on screen now, which later runs are compared with.
    pub fn start(&mut self, target: &str, section: Section, current: Option<Vec<String>>, now: Instant) {
        if self.is_watching(target, section) {
            return;
        }
        self.list.push(Watch { target: target.into(), section, baseline: current, started: now, last_run: None });
    }

    pub fn stop(&mut self, target: &str, section: Section) {
        self.list.retain(|w| !(w.target == target && w.section == section));
    }

    pub fn keep_targets(&mut self, alive: impl Fn(&str) -> bool) {
        self.list.retain(|w| alive(&w.target));
    }

    /// The Watches whose next run is due. A run that is still going is the caller's to skip.
    pub fn due(&self, now: Instant) -> Vec<(String, Section)> {
        self.list
            .iter()
            .filter(|w| now.saturating_duration_since(w.last_run.unwrap_or(w.started)) >= INTERVAL)
            .map(|w| (w.target.clone(), w.section))
            .collect()
    }

    /// A run of the Check finished. `records` is `None` when it failed or timed out: that
    /// counts as a run, so a failing Check is retried at the interval and not every tick,
    /// but it never counts as a change. A change stops the Watch and returns why.
    pub fn finished(
        &mut self,
        target: &str,
        section: Section,
        records: Option<&[String]>,
        now: Instant,
    ) -> Option<Stopped> {
        let at = self.list.iter().position(|w| w.target == target && w.section == section)?;
        let w = self.list.get_mut(at)?;
        w.last_run = Some(now);
        let records = records?;
        match &w.baseline {
            None => {
                w.baseline = Some(records.to_vec());
                None
            }
            Some(before) => {
                let changes = diff(before, records);
                if changes.is_empty() {
                    return None;
                }
                let w = self.list.remove(at);
                Some(Stopped { target: w.target, section: w.section, changes })
            }
        }
    }

    pub fn status_lines(&self, now: Instant) -> Vec<String> {
        self.list
            .iter()
            .map(|w| {
                let last = match w.last_run {
                    Some(t) => format!("last run {}", relative(now.saturating_duration_since(t))),
                    None => "not run yet".into(),
                };
                format!("Watching {} {} \u{b7} {last} \u{b7} stops on change", w.target, w.section.label())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    fn secs(base: Instant, s: u64) -> Instant {
        base + Duration::from_secs(s)
    }

    fn watching(base: Instant, records: &[&str]) -> Watches {
        let mut w = Watches::default();
        w.start("example.com", Section::Dns, Some(lines(records)), base);
        w
    }

    #[test]
    fn a_watch_is_due_once_the_interval_has_passed() {
        let t0 = Instant::now();
        let w = watching(t0, &["A: 1.1.1.1"]);
        assert!(w.due(secs(t0, 59)).is_empty());
        assert_eq!(w.due(secs(t0, 60)), [("example.com".to_string(), Section::Dns)]);
    }

    #[test]
    fn the_interval_counts_from_the_last_run() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["A: 1.1.1.1"]);
        w.finished("example.com", Section::Dns, Some(&lines(&["A: 1.1.1.1"])), secs(t0, 70));
        assert!(w.due(secs(t0, 120)).is_empty());
        assert_eq!(w.due(secs(t0, 130)).len(), 1);
    }

    #[test]
    fn an_unchanged_answer_keeps_the_watch_going() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["A: 1.1.1.1", "A: 2.2.2.2"]);
        let stopped =
            w.finished("example.com", Section::Dns, Some(&lines(&["A: 2.2.2.2", "A: 1.1.1.1"])), secs(t0, 60));
        assert_eq!(stopped, None);
        assert!(w.is_watching("example.com", Section::Dns));
    }

    #[test]
    fn a_changed_answer_stops_the_watch_and_says_what_changed() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["TXT: old"]);
        let stopped = w.finished("example.com", Section::Dns, Some(&lines(&["TXT: new"])), secs(t0, 60)).unwrap();
        assert_eq!(stopped.changes, Diff { added: lines(&["TXT: new"]), removed: lines(&["TXT: old"]) });
        assert_eq!(stopped.message(), "example.com DNS changed: 1 removed, 1 added. The Watch stopped.");
        assert!(!w.is_watching("example.com", Section::Dns));
        assert!(w.due(secs(t0, 600)).is_empty());
    }

    #[test]
    fn one_added_record_alone_is_a_change() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["NS: a"]);
        assert!(w.finished("example.com", Section::Dns, Some(&lines(&["NS: a", "NS: b"])), secs(t0, 60)).is_some());
    }

    #[test]
    fn a_failed_run_is_not_a_change_and_is_not_retried_every_tick() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["A: 1.1.1.1"]);
        assert_eq!(w.finished("example.com", Section::Dns, None, secs(t0, 60)), None);
        assert!(w.is_watching("example.com", Section::Dns));
        assert!(w.due(secs(t0, 61)).is_empty());
        assert_eq!(w.due(secs(t0, 120)).len(), 1);
    }

    #[test]
    fn without_a_baseline_the_first_finished_run_becomes_it() {
        let t0 = Instant::now();
        let mut w = Watches::default();
        w.start("example.com", Section::Registration, None, t0);
        assert_eq!(
            w.finished("example.com", Section::Registration, Some(&lines(&["Registrar: a"])), secs(t0, 60)),
            None
        );
        assert!(
            w.finished("example.com", Section::Registration, Some(&lines(&["Registrar: b"])), secs(t0, 120)).is_some()
        );
    }

    #[test]
    fn a_result_for_something_not_watched_does_nothing() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["A: 1"]);
        assert_eq!(w.finished("other.com", Section::Dns, Some(&lines(&["A: 2"])), t0), None);
        assert_eq!(w.finished("example.com", Section::Web, Some(&lines(&["A: 2"])), t0), None);
        assert!(w.is_watching("example.com", Section::Dns));
    }

    #[test]
    fn starting_twice_keeps_one_watch_and_stop_removes_it() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["A: 1"]);
        w.start("example.com", Section::Dns, Some(lines(&["A: 9"])), secs(t0, 5));
        assert_eq!(w.status_lines(t0).len(), 1);
        w.stop("example.com", Section::Dns);
        assert!(w.is_empty());
    }

    #[test]
    fn the_status_line_names_target_check_and_last_run() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["A: 1"]);
        assert_eq!(w.status_lines(t0), ["Watching example.com DNS \u{b7} not run yet \u{b7} stops on change"]);
        w.finished("example.com", Section::Dns, Some(&lines(&["A: 1"])), secs(t0, 60));
        assert_eq!(
            w.status_lines(secs(t0, 72)),
            ["Watching example.com DNS \u{b7} last run 12 s ago \u{b7} stops on change"]
        );
    }

    #[test]
    fn watches_for_closed_tabs_are_dropped() {
        let t0 = Instant::now();
        let mut w = watching(t0, &["A: 1"]);
        w.start("b.com", Section::Web, None, t0);
        w.keep_targets(|t| t == "b.com");
        assert!(!w.is_watching("example.com", Section::Dns));
        assert!(w.is_watching("b.com", Section::Web));
    }
}
