use std::time::{Duration, Instant};

use zombo_core::target::parse_target;

use crate::{diagnosis::Tab, section::Section};

pub const RECENT_LIMIT: usize = 8;

#[derive(Debug, Clone)]
pub struct Recent {
    pub value: String,
    pub at: Instant,
}

pub fn relative(elapsed: Duration) -> String {
    let s = elapsed.as_secs();
    match s {
        0..=4 => "just now".into(),
        5..=59 => format!("{s} s ago"),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86400),
    }
}

#[derive(Debug, Default)]
pub struct Workspace {
    pub tabs: Vec<Tab>,
    pub active: Option<usize>,
    pub recent: Vec<Recent>,
    pub recent_selected: usize,
}

impl Workspace {
    pub fn current(&self) -> Option<&Tab> {
        self.active.and_then(|i| self.tabs.get(i))
    }

    pub fn current_mut(&mut self) -> Option<&mut Tab> {
        self.active.and_then(|i| self.tabs.get_mut(i))
    }

    pub fn is_empty_state(&self) -> bool {
        self.active.is_none()
    }

    pub fn submit(&mut self, typed: &str, now: Instant) -> Result<usize, String> {
        let raw = if typed.trim().is_empty() {
            match self.recent.get(self.recent_selected) {
                Some(r) if self.active.is_none() => r.value.clone(),
                _ => return Err("enter a domain, host, IP or email address".into()),
            }
        } else {
            typed.to_string()
        };
        let target = parse_target(&raw)?;
        self.recent.retain(|r| r.value != target.value);
        self.recent.insert(0, Recent { value: target.value.clone(), at: now });
        self.recent.truncate(RECENT_LIMIT);
        self.recent_selected = 0;
        let index = match self.tabs.iter().position(|t| t.target.value == target.value) {
            Some(i) => i,
            None => {
                self.tabs.push(Tab::new(target));
                self.tabs.len() - 1
            }
        };
        self.active = Some(index);
        Ok(index)
    }

    pub fn new_tab(&mut self) {
        self.active = None;
    }

    pub fn close_active(&mut self) {
        let Some(i) = self.active else { return };
        self.tabs.remove(i);
        self.active = if self.tabs.is_empty() { None } else { Some(i.min(self.tabs.len() - 1)) };
    }

    pub fn select_tab(&mut self, index: usize) {
        if index < self.tabs.len() {
            self.active = Some(index);
        }
    }

    pub fn step_tab(&mut self, delta: isize) {
        let n = self.tabs.len() as isize;
        if n == 0 {
            return;
        }
        let from = self.active.map(|i| i as isize).unwrap_or(if delta > 0 { -1 } else { 0 });
        self.active = Some((from + delta).rem_euclid(n) as usize);
    }

    pub fn jump(&mut self, index: usize) {
        if let (Some(tab), Some(section)) = (self.current_mut(), Section::at(index)) {
            tab.section = section;
        }
    }

    pub fn step_section(&mut self, delta: isize) {
        if let Some(tab) = self.current_mut() {
            tab.section = tab.section.step(delta);
        }
    }

    pub fn step_record(&mut self, delta: isize) {
        if let Some(tab) = self.current_mut() {
            tab.record = tab.record.step(delta);
        }
    }

    pub fn move_recent(&mut self, delta: isize) {
        let n = self.recent.len() as isize;
        if n > 0 {
            self.recent_selected = (self.recent_selected as isize + delta).clamp(0, n - 1) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws_with(targets: &[&str]) -> Workspace {
        let mut ws = Workspace::default();
        let now = Instant::now();
        for t in targets {
            ws.submit(t, now).unwrap();
        }
        ws
    }

    #[test]
    fn submitting_a_target_opens_a_tab_classified_by_zombo_core() {
        let ws = ws_with(&["https://Example.COM/path"]);
        let tab = ws.current().unwrap();
        assert_eq!(tab.target.value, "example.com");
        assert_eq!(ws.tabs.len(), 1);
    }

    #[test]
    fn a_bad_target_is_an_error_message_and_opens_nothing() {
        let mut ws = Workspace::default();
        assert!(ws.submit("not a target!", Instant::now()).is_err());
        assert!(ws.submit("   ", Instant::now()).is_err());
        assert!(ws.tabs.is_empty());
        assert!(ws.is_empty_state());
    }

    #[test]
    fn the_same_target_reuses_its_tab() {
        let mut ws = ws_with(&["example.com", "example.org"]);
        let i = ws.submit("example.com", Instant::now()).unwrap();
        assert_eq!((i, ws.tabs.len(), ws.active), (0, 2, Some(0)));
    }

    #[test]
    fn recent_targets_are_newest_first_deduplicated_and_capped_at_eight() {
        let names: Vec<String> = (0..10).map(|i| format!("site{i}.example.com")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut ws = ws_with(&refs);
        assert_eq!(ws.recent.len(), RECENT_LIMIT);
        assert_eq!(ws.recent[0].value, "site9.example.com");
        ws.submit("site5.example.com", Instant::now()).unwrap();
        assert_eq!(ws.recent[0].value, "site5.example.com");
        assert_eq!(ws.recent.iter().filter(|r| r.value == "site5.example.com").count(), 1);
    }

    #[test]
    fn an_empty_box_runs_the_selected_recent_target_in_the_empty_state_only() {
        let mut ws = ws_with(&["a.example.com", "b.example.com"]);
        ws.new_tab();
        ws.move_recent(1);
        let i = ws.submit("", Instant::now()).unwrap();
        assert_eq!(ws.tabs[i].target.value, "a.example.com");
        assert!(ws.submit("", Instant::now()).is_err());
    }

    #[test]
    fn the_recent_selection_stays_inside_the_list() {
        let mut ws = ws_with(&["a.example.com", "b.example.com"]);
        ws.move_recent(-5);
        assert_eq!(ws.recent_selected, 0);
        ws.move_recent(9);
        assert_eq!(ws.recent_selected, 1);
    }

    #[test]
    fn closing_the_last_tab_returns_to_the_empty_state() {
        let mut ws = ws_with(&["a.example.com", "b.example.com"]);
        ws.close_active();
        assert_eq!(ws.active, Some(0));
        ws.close_active();
        assert!(ws.is_empty_state());
        ws.close_active();
        assert!(ws.tabs.is_empty());
    }

    #[test]
    fn closing_a_tab_drops_its_results() {
        let mut ws = ws_with(&["a.example.com", "b.example.com"]);
        ws.select_tab(0);
        ws.close_active();
        assert_eq!(ws.tabs.len(), 1);
        assert_eq!(ws.tabs[0].target.value, "b.example.com");
    }

    #[test]
    fn tabs_cycle_and_a_new_tab_shows_the_empty_state() {
        let mut ws = ws_with(&["a.example.com", "b.example.com", "c.example.com"]);
        ws.step_tab(1);
        assert_eq!(ws.active, Some(0));
        ws.step_tab(-1);
        assert_eq!(ws.active, Some(2));
        ws.new_tab();
        assert!(ws.is_empty_state());
        ws.step_tab(1);
        assert_eq!(ws.active, Some(0));
    }

    #[test]
    fn jump_and_step_move_the_section_of_the_active_tab_only() {
        let mut ws = ws_with(&["a.example.com", "b.example.com"]);
        ws.jump(4);
        assert_eq!(ws.current().unwrap().section, Section::Email);
        ws.jump(8);
        assert_eq!(ws.current().unwrap().section, Section::Email);
        ws.step_section(1);
        assert_eq!(ws.current().unwrap().section, Section::Web);
        assert_eq!(ws.tabs[0].section, Section::Dns);
        ws.new_tab();
        ws.jump(0);
        ws.step_section(1);
    }

    #[test]
    fn relative_time_reads_naturally() {
        assert_eq!(relative(Duration::from_secs(2)), "just now");
        assert_eq!(relative(Duration::from_secs(12)), "12 s ago");
        assert_eq!(relative(Duration::from_secs(180)), "3 min ago");
        assert_eq!(relative(Duration::from_secs(7300)), "2 h ago");
        assert_eq!(relative(Duration::from_secs(200_000)), "2 d ago");
    }
}
