//! The update flow without a window: when to ask, what the rep skipped, and what the prompt shows.
//! The disk keeps a timestamp and one skipped version in the state directory (ADR-0004: no results).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zombo_core::update::{self, Available, Target, UpdateError, Version};

use crate::config::{self, Dirs};

pub const INTERVAL_SECS: i64 = 24 * 60 * 60;

pub fn state_file(dirs: &Dirs) -> PathBuf {
    dirs.state.join("update.toml")
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateState {
    /// Seconds since the Unix epoch of the last attempt.
    pub checked_at: Option<i64>,
    pub skipped: Option<String>,
}

impl UpdateState {
    /// A missing, unreadable or broken file is an empty state: the worst case is one extra check.
    pub fn load(path: &Path) -> UpdateState {
        config::read_capped(path).ok().flatten().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        config::write_atomic(path, &toml::to_string(self).unwrap_or_default())
    }

    /// At most once a day. A stamp far in the future (the clock moved back) does not block for ever.
    pub fn due(&self, now: i64) -> bool {
        self.checked_at
            .is_none_or(|at| now.saturating_sub(at) >= INTERVAL_SECS || at.saturating_sub(now) > INTERVAL_SECS)
    }

    pub fn wants(&self, version: &Version) -> bool {
        self.skipped.as_deref() != Some(version.to_string().as_str())
    }
}

/// Whether this run can update at all, and if not, why the settings pane says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    NotAnAppImage,
    NoSigningKey,
    Ready,
}

pub fn availability(target: Option<&Target>, release_build: bool) -> Availability {
    match target {
        None => Availability::NotAnAppImage,
        Some(_) if !update::available_in(release_build) => Availability::NoSigningKey,
        Some(_) => Availability::Ready,
    }
}

/// A newer version the rep may take. `can_install` is false when the AppImage's directory is not writable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub rel: Available,
    pub can_install: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    Idle,
    Prompt(Offer),
    Applying(Offer),
    Restart(Offer),
    Failed(Offer, String),
}

impl Stage {
    pub fn offer(&self) -> Option<&Offer> {
        match self {
            Stage::Idle => None,
            Stage::Prompt(o) | Stage::Applying(o) | Stage::Restart(o) | Stage::Failed(o, _) => Some(o),
        }
    }
}

/// The background half of the flow. Records the attempt before asking, so a crash or an offline
/// start never turns into a retry on every launch. Errors are silent: no prompt is the answer.
pub fn background_check(
    setting: bool,
    target: Option<&Target>,
    state_path: &Path,
    now: i64,
    check: impl FnOnce() -> Result<Option<Available>, UpdateError>,
) -> Option<Offer> {
    let target = target.filter(|_| setting)?;
    let mut state = UpdateState::load(state_path);
    if !state.due(now) {
        return None;
    }
    state.checked_at = Some(now);
    state.save(state_path).ok()?;
    let rel = check().ok()??;
    state.wants(&rel.version).then_some(Offer { rel, can_install: target.writable })
}

/// "Skip this version": remember it, keeping the last check time.
pub fn skip(state_path: &Path, version: &Version) -> Result<(), String> {
    let mut state = UpdateState::load(state_path);
    state.skipped = Some(version.to_string());
    state.save(state_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, os::unix::fs::PermissionsExt};
    use zombo_core::update::Endpoints;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zombo-upd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn release(tag: &str) -> Available {
        let a = |n: &str| format!(r#"{{"name":"{n}","browser_download_url":"https://h/{n}","size":1}}"#);
        let json = format!(
            r#"[{{"tag_name":"{tag}","draft":false,"prerelease":false,"body":"n","html_url":"https://h/r","assets":[{},{},{}]}}]"#,
            a("z.AppImage"),
            a("SHA256SUMS"),
            a("SHA256SUMS.minisig")
        );
        let current = Version::parse("1.0.0").unwrap();
        update::select(json.as_bytes(), &current, &Endpoints::real(&current)).unwrap().unwrap()
    }

    fn target(writable: bool) -> Target {
        Target { path: "/x/App.AppImage".into(), writable }
    }

    #[test]
    fn a_check_is_due_once_a_day() {
        let s = |at| UpdateState { checked_at: Some(at), skipped: None };
        assert!(UpdateState::default().due(1_000));
        assert!(!s(1_000).due(1_000 + INTERVAL_SECS - 1));
        assert!(s(1_000).due(1_000 + INTERVAL_SECS));
        assert!(s(10 * INTERVAL_SECS).due(0), "a stamp from the future does not block for ever");
        assert!(!s(1_000 + 60).due(1_000), "a small clock step back still waits");
    }

    #[test]
    fn the_state_is_a_private_file_that_round_trips_and_a_broken_one_is_empty() {
        let dir = tmp("state");
        let path = dir.join("update.toml");
        assert_eq!(UpdateState::load(&path), UpdateState::default());
        let s = UpdateState { checked_at: Some(5), skipped: Some("1.4.0".into()) };
        s.save(&path).unwrap();
        assert_eq!(UpdateState::load(&path), s);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&path, "garbage = [").unwrap();
        assert_eq!(UpdateState::load(&path), UpdateState::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_an_enabled_appimage_asks_and_only_once_a_day() {
        let dir = tmp("ask");
        let path = dir.join("update.toml");
        let asked = Cell::new(0);
        let ask = |setting, t: Option<&Target>, now| {
            background_check(setting, t, &path, now, || {
                asked.set(asked.get() + 1);
                Ok(Some(release("v1.4.0")))
            })
        };
        assert!(ask(true, None, 100).is_none(), "not an AppImage");
        assert!(ask(false, Some(&target(true)), 100).is_none(), "switched off");
        assert_eq!(asked.get(), 0);
        let offer = ask(true, Some(&target(true)), 100).unwrap();
        assert!(offer.can_install);
        assert_eq!(offer.rel.version.to_string(), "1.4.0");
        assert!(ask(true, Some(&target(true)), 100 + 60).is_none(), "asked an hour ago");
        assert_eq!(asked.get(), 1);
        assert!(!ask(true, Some(&target(false)), 100 + INTERVAL_SECS).unwrap().can_install);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_check_still_counts_as_the_days_attempt_and_shows_nothing() {
        let dir = tmp("fail");
        let path = dir.join("update.toml");
        let r = background_check(true, Some(&target(true)), &path, 7, || Err(UpdateError::TimedOut));
        assert!(r.is_none());
        assert_eq!(UpdateState::load(&path).checked_at, Some(7));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_skipped_version_is_not_offered_again_but_a_newer_one_is() {
        let dir = tmp("skip");
        let path = dir.join("update.toml");
        skip(&path, &Version::parse("1.4.0").unwrap()).unwrap();
        let ask = |now, tag: &str| background_check(true, Some(&target(true)), &path, now, || Ok(Some(release(tag))));
        assert!(ask(0, "v1.4.0").is_none());
        assert!(ask(INTERVAL_SECS, "v1.5.0").is_some());
        assert_eq!(UpdateState::load(&path).skipped.as_deref(), Some("1.4.0"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn availability_says_why_updates_are_off() {
        let t = target(true);
        assert_eq!(availability(None, false), Availability::NotAnAppImage);
        assert_eq!(availability(Some(&t), true), Availability::NoSigningKey, "the test key is embedded");
        assert_eq!(availability(Some(&t), false), Availability::Ready);
    }
}
