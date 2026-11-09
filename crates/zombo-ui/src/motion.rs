//! Motion, as DESIGN.md decides it. Pure: durations, the on/off switch, easing and the small
//! state machines that turn elapsed time into a color or an opacity. The window layer only
//! asks these functions what to draw at this instant.

use std::{collections::HashMap, process::Command, time::{Duration, Instant}};

pub const PRESS_AND_HOVER: Duration = Duration::from_millis(80);
pub const RESULT_FADE_IN: Duration = Duration::from_millis(100);
pub const TOAST_IN: Duration = Duration::from_millis(150);
pub const TOAST_OUT: Duration = Duration::from_millis(120);
/// How far a toast rises while it fades in, in logical pixels.
pub const TOAST_RISE: f32 = 8.0;
/// Nothing animates longer than this.
pub const LONGEST: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Motion {
    pub enabled: bool,
}

impl Default for Motion {
    fn default() -> Self {
        Motion { enabled: true }
    }
}

impl Motion {
    /// The duration to use for `d`: zero when the system turned animations off.
    pub fn duration(self, d: Duration) -> Duration {
        if self.enabled { d.min(LONGEST) } else { Duration::ZERO }
    }

    /// How far along an animation of length `d` is after `elapsed`, from 0.0 to 1.0, eased out.
    pub fn progress(self, elapsed: Duration, d: Duration) -> f32 {
        let d = self.duration(d);
        if d.is_zero() {
            return 1.0;
        }
        let t = (elapsed.as_secs_f32() / d.as_secs_f32()).clamp(0.0, 1.0);
        1.0 - (1.0 - t).powi(3)
    }

    pub fn running(self, elapsed: Duration, d: Duration) -> bool {
        elapsed < self.duration(d)
    }

    /// The palette opens instantly, always.
    pub const PALETTE: Duration = Duration::ZERO;

    /// Read from the output of `gsettings get org.gnome.desktop.interface enable-animations`
    /// or of the XDG settings portal call. Unreadable means motion stays on.
    pub fn from_setting(output: Option<&str>) -> Motion {
        Motion { enabled: output.and_then(parse_enable_animations).unwrap_or(true) }
    }
}

fn parse_enable_animations(out: &str) -> Option<bool> {
    let out = out.trim().to_ascii_lowercase();
    if out.contains("false") {
        Some(false)
    } else if out.contains("true") {
        Some(true)
    } else {
        None
    }
}

/// Ask the desktop. gsettings first, then the XDG settings portal. Blocking, so call it off the
/// UI thread.
pub fn read_system_motion() -> Motion {
    let run = |cmd: &str, args: &[&str]| Command::new(cmd).args(args).output().ok().filter(|o| o.status.success()).and_then(|o| String::from_utf8(o.stdout).ok());
    let out = run("gsettings", &["get", "org.gnome.desktop.interface", "enable-animations"]).or_else(|| {
        run(
            "gdbus",
            &[
                "call", "--session", "--dest", "org.freedesktop.portal.Desktop", "--object-path", "/org/freedesktop/portal/desktop",
                "--method", "org.freedesktop.portal.Settings.Read", "org.gnome.desktop.interface", "enable-animations",
            ],
        )
    });
    Motion::from_setting(out.as_deref())
}

pub fn lerp_rgb(from: u32, to: u32, t: f32) -> u32 {
    let ch = |shift: u32| {
        let (a, b) = (((from >> shift) & 0xFF) as f32, ((to >> shift) & 0xFF) as f32);
        ((a + (b - a) * t.clamp(0.0, 1.0)).round() as u32) << shift
    };
    ch(16) | ch(8) | ch(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Rest,
    Hover,
    Press,
}

#[derive(Debug, Clone, Copy)]
struct Transition {
    from: Level,
    to: Level,
    since: Instant,
}

/// Hover and press feedback for many controls, keyed by a small id. A control that moves to a
/// new level blends from the level it was showing toward the new one over 80 ms.
#[derive(Debug, Default)]
pub struct Feedback<K: std::hash::Hash + Eq> {
    states: HashMap<K, Transition>,
}

impl<K: std::hash::Hash + Eq> Feedback<K> {
    pub fn new() -> Self {
        Feedback { states: HashMap::new() }
    }

    pub fn set(&mut self, key: K, level: Level, now: Instant) {
        let shown = self.states.get(&key).map(|t| (t.from, t.to, t.since));
        let (from, to) = match shown {
            Some((_, to, _)) if to == level => return,
            Some((_, to, _)) => (to, level),
            None => (Level::Rest, level),
        };
        self.states.insert(key, Transition { from, to, since: now });
    }

    /// The color to draw now, given the color of each level.
    pub fn color(&self, key: &K, now: Instant, motion: Motion, rest: u32, hover: u32, press: u32) -> u32 {
        let pick = |l: Level| match l {
            Level::Rest => rest,
            Level::Hover => hover,
            Level::Press => press,
        };
        match self.states.get(key) {
            None => rest,
            Some(t) => lerp_rgb(pick(t.from), pick(t.to), motion.progress(now.saturating_duration_since(t.since), PRESS_AND_HOVER)),
        }
    }

    pub fn animating(&self, now: Instant, motion: Motion) -> bool {
        self.states.values().any(|t| motion.running(now.saturating_duration_since(t.since), PRESS_AND_HOVER))
    }
}

/// An opacity that restarts from zero whenever its key changes: results fade in when a
/// section is opened or its Check finishes.
#[derive(Debug)]
pub struct Fade<K: PartialEq> {
    shown: Option<(K, Instant)>,
}

impl<K: PartialEq> Default for Fade<K> {
    fn default() -> Self {
        Fade { shown: None }
    }
}

impl<K: PartialEq> Fade<K> {
    pub fn opacity(&mut self, key: K, now: Instant, motion: Motion) -> f32 {
        if self.shown.as_ref().is_none_or(|(k, _)| *k != key) {
            self.shown = Some((key, now));
        }
        let since = self.shown.as_ref().map_or(now, |(_, t)| *t);
        motion.progress(now.saturating_duration_since(since), RESULT_FADE_IN)
    }

    pub fn animating(&self, now: Instant, motion: Motion) -> bool {
        self.shown.as_ref().is_some_and(|(_, t)| motion.running(now.saturating_duration_since(*t), RESULT_FADE_IN))
    }
}

/// Where a toast is at `age` since it appeared, and `left` since it started to leave (if it did):
/// its opacity, and how many pixels below its resting place it is. `None` once it is gone.
pub fn toast_frame(motion: Motion, age: Duration, left: Option<Duration>) -> Option<(f32, f32)> {
    if let Some(left) = left {
        if !motion.running(left, TOAST_OUT) {
            return None;
        }
        let p = 1.0 - motion.progress(left, TOAST_OUT);
        return Some((p, TOAST_RISE * (1.0 - p)));
    }
    let p = motion.progress(age, TOAST_IN);
    Some((p, TOAST_RISE * (1.0 - p)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON: Motion = Motion { enabled: true };
    const OFF: Motion = Motion { enabled: false };
    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn the_durations_are_the_ones_in_the_design() {
        assert_eq!(PRESS_AND_HOVER, MS(80));
        assert_eq!(RESULT_FADE_IN, MS(100));
        assert_eq!(TOAST_IN, MS(150));
        assert_eq!(TOAST_OUT, MS(120));
        assert_eq!(Motion::PALETTE, Duration::ZERO);
    }

    #[test]
    fn nothing_animates_longer_than_200_ms() {
        for d in [PRESS_AND_HOVER, RESULT_FADE_IN, TOAST_IN, TOAST_OUT] {
            assert!(ON.duration(d) <= MS(200));
        }
        assert_eq!(ON.duration(MS(900)), MS(200));
    }

    #[test]
    fn motion_off_means_zero_duration_and_instant_progress() {
        assert_eq!(OFF.duration(TOAST_IN), Duration::ZERO);
        assert_eq!(OFF.progress(MS(0), TOAST_IN), 1.0);
        assert!(!OFF.running(MS(0), TOAST_IN));
    }

    #[test]
    fn progress_runs_from_zero_to_one_and_stays() {
        assert_eq!(ON.progress(MS(0), RESULT_FADE_IN), 0.0);
        let mid = ON.progress(MS(50), RESULT_FADE_IN);
        assert!(mid > 0.0 && mid < 1.0);
        assert_eq!(ON.progress(MS(100), RESULT_FADE_IN), 1.0);
        assert_eq!(ON.progress(MS(5000), RESULT_FADE_IN), 1.0);
    }

    #[test]
    fn the_system_setting_decides_and_unreadable_means_on() {
        assert!(!Motion::from_setting(Some("false\n")).enabled);
        assert!(!Motion::from_setting(Some("(<<false>>,)")).enabled);
        assert!(Motion::from_setting(Some("true\n")).enabled);
        assert!(Motion::from_setting(Some("(<<true>>,)")).enabled);
        assert!(Motion::from_setting(Some("no such schema")).enabled);
        assert!(Motion::from_setting(None).enabled);
    }

    #[test]
    fn colors_blend_between_two_levels() {
        assert_eq!(lerp_rgb(0x000000, 0xFFFFFF, 0.0), 0x000000);
        assert_eq!(lerp_rgb(0x000000, 0xFFFFFF, 1.0), 0xFFFFFF);
        assert_eq!(lerp_rgb(0x102030, 0x304050, 0.5), 0x203040);
    }

    #[test]
    fn hover_blends_over_80_ms_and_press_follows() {
        let t0 = Instant::now();
        let mut fb = Feedback::new();
        let (rest, hover, press) = (0x111111, 0x222222, 0x333333);
        assert_eq!(fb.color(&"a", t0, ON, rest, hover, press), rest);
        fb.set("a", Level::Hover, t0);
        assert_eq!(fb.color(&"a", t0, ON, rest, hover, press), rest);
        let mid = fb.color(&"a", t0 + MS(40), ON, rest, hover, press);
        assert!(mid > rest && mid < hover);
        assert_eq!(fb.color(&"a", t0 + MS(80), ON, rest, hover, press), hover);
        assert!(fb.animating(t0 + MS(40), ON));
        assert!(!fb.animating(t0 + MS(80), ON));
        fb.set("a", Level::Press, t0 + MS(100));
        assert_eq!(fb.color(&"a", t0 + MS(180), ON, rest, hover, press), press);
    }

    #[test]
    fn feedback_is_instant_when_motion_is_off() {
        let t0 = Instant::now();
        let mut fb = Feedback::new();
        fb.set("a", Level::Hover, t0);
        assert_eq!(fb.color(&"a", t0, OFF, 1, 0xFFFFFF, 3), 0xFFFFFF);
        assert!(!fb.animating(t0, OFF));
    }

    #[test]
    fn the_same_level_does_not_restart_the_blend() {
        let t0 = Instant::now();
        let mut fb = Feedback::new();
        fb.set("a", Level::Hover, t0);
        fb.set("a", Level::Hover, t0 + MS(40));
        let mid = fb.color(&"a", t0 + MS(40), ON, 0, 0xFF, 0);
        assert!(mid > 0 && mid < 0xFF, "{mid:#x}");
        assert_eq!(fb.color(&"a", t0 + MS(80), ON, 0, 0xFF, 0), 0xFF);
    }

    #[test]
    fn results_fade_in_again_only_when_the_key_changes() {
        let t0 = Instant::now();
        let mut f = Fade::default();
        assert_eq!(f.opacity("dns:running", t0, ON), 0.0);
        assert_eq!(f.opacity("dns:running", t0 + MS(100), ON), 1.0);
        assert_eq!(f.opacity("dns:done", t0 + MS(150), ON), 0.0);
        assert!(f.animating(t0 + MS(160), ON));
        assert_eq!(f.opacity("dns:done", t0 + MS(260), ON), 1.0);
        assert_eq!(Fade::default().opacity("x", t0, OFF), 1.0);
    }

    #[test]
    fn a_toast_rises_in_150_ms_and_leaves_in_120_ms() {
        let (o0, y0) = toast_frame(ON, MS(0), None).unwrap();
        assert_eq!((o0, y0), (0.0, TOAST_RISE));
        assert_eq!(toast_frame(ON, MS(150), None), Some((1.0, 0.0)));
        let (o, _) = toast_frame(ON, MS(5000), Some(MS(60))).unwrap();
        assert!(o > 0.0 && o < 1.0);
        assert_eq!(toast_frame(ON, MS(5000), Some(MS(120))), None);
    }

    #[test]
    fn a_toast_just_appears_and_vanishes_when_motion_is_off() {
        assert_eq!(toast_frame(OFF, MS(0), None), Some((1.0, 0.0)));
        assert_eq!(toast_frame(OFF, MS(0), Some(MS(0))), None);
    }
}
