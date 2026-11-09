use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use zombo_core::target::parse_target;

use crate::{
    settings_model::{self, MAX_FILE_BYTES, Settings},
    workspace::{RECENT_LIMIT, Recent},
};

const APP_DIR: &str = "zombo-razor";

/// The two directories this app writes to. Nothing else on disk is ever touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    pub config: PathBuf,
    pub state: PathBuf,
}

impl Dirs {
    /// XDG rules: a variable counts only when it holds an absolute path.
    pub fn from_vars(config_home: Option<&str>, state_home: Option<&str>, home: Option<&str>) -> Option<Dirs> {
        let abs = |v: Option<&str>| v.map(PathBuf::from).filter(|p| p.is_absolute());
        let home = abs(home);
        let config = abs(config_home).or_else(|| home.as_ref().map(|h| h.join(".config")))?;
        let state = abs(state_home).or_else(|| home.as_ref().map(|h| h.join(".local/state")))?;
        Some(Dirs { config: config.join(APP_DIR), state: state.join(APP_DIR) })
    }

    pub fn from_env() -> Option<Dirs> {
        let var = |k: &str| std::env::var(k).ok();
        Dirs::from_vars(var("XDG_CONFIG_HOME").as_deref(), var("XDG_STATE_HOME").as_deref(), var("HOME").as_deref())
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    pub fn recent_file(&self) -> PathBuf {
        self.state.join("recent.toml")
    }
}

/// `Ok(None)` when the file does not exist. A directory, a pipe or an oversized file is an error,
/// and is never opened for reading beyond the cap.
fn read_capped(path: &Path) -> Result<Option<String>, String> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.is_file() {
        return Err("it is not a regular file".into());
    }
    if meta.len() > MAX_FILE_BYTES as u64 {
        return Err(settings_model::LoadError::TooLarge.to_string());
    }
    let mut bytes = vec![];
    File::open(path)
        .and_then(|f| f.take(MAX_FILE_BYTES as u64 + 1).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(settings_model::LoadError::TooLarge.to_string());
    }
    String::from_utf8(bytes).map(Some).map_err(|_| settings_model::LoadError::NotText.to_string())
}

/// Write a temp file beside the target (mode 0600), then rename it over the target.
/// A new directory gets mode 0700. A reader sees the old file or the new one, never half of one.
fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let dir = path.parent().ok_or("the file has no directory")?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("the file has no name")?;
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
        .and_then(|()| fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot write {}: {e}", path.display())
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentEntry {
    pub name: String,
    /// Seconds since the Unix epoch. This and the name are all the disk keeps (ADR-0004).
    pub at: i64,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RecentFile {
    recent: Vec<RecentEntry>,
}

pub fn parse_recent(text: &str) -> Result<Vec<RecentEntry>, String> {
    if text.len() > MAX_FILE_BYTES {
        return Err(settings_model::LoadError::TooLarge.to_string());
    }
    let f: RecentFile = toml::from_str(text).map_err(|e| e.to_string().replace('\n', " "))?;
    if f.recent.len() > RECENT_LIMIT {
        return Err(format!("at most {RECENT_LIMIT} recent targets"));
    }
    for e in &f.recent {
        match parse_target(&e.name) {
            Ok(t) if t.value == e.name => {}
            _ => {
                return Err(format!(
                    "{:?} is not a target name",
                    e.name.chars().filter(|c| !c.is_control()).take(40).collect::<String>()
                ));
            }
        }
        if e.at < 0 {
            return Err("a time is before 1970".into());
        }
    }
    Ok(f.recent)
}

pub fn recent_to_toml(entries: &[RecentEntry]) -> String {
    toml::to_string(&RecentFile { recent: entries.to_vec() }).unwrap_or_default()
}

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The recent list as the workspace holds it: the wall-clock time becomes an age.
pub fn to_recent(entries: &[RecentEntry], now_unix: i64, now: Instant) -> Vec<Recent> {
    entries
        .iter()
        .map(|e| {
            let age = Duration::from_secs(now_unix.saturating_sub(e.at).max(0) as u64);
            Recent { value: e.name.clone(), at: now.checked_sub(age).unwrap_or(now) }
        })
        .collect()
}

pub fn from_recent(recent: &[Recent], now_unix: i64, now: Instant) -> Vec<RecentEntry> {
    recent
        .iter()
        .map(|r| RecentEntry {
            name: r.value.clone(),
            at: now_unix.saturating_sub(now.saturating_duration_since(r.at).as_secs() as i64),
        })
        .collect()
}

/// What is on disk, as this run sees it. A file that is present but broken is never written
/// by the app on its own: the app runs on defaults and tells the rep.
#[derive(Debug)]
pub struct Config {
    dirs: Option<Dirs>,
    pub settings: Settings,
    pub settings_problem: Option<String>,
    pub recent: Vec<RecentEntry>,
    pub recent_problem: Option<String>,
}

impl Config {
    pub fn load(dirs: Option<Dirs>) -> Config {
        let mut c = Config {
            dirs: dirs.clone(),
            settings: Settings::default(),
            settings_problem: None,
            recent: vec![],
            recent_problem: None,
        };
        let Some(dirs) = dirs else { return c };
        match read_capped(&dirs.settings_file())
            .and_then(|t| t.map(|t| settings_model::parse(&t).map_err(|e| e.to_string())).transpose())
        {
            Ok(s) => c.settings = s.unwrap_or_default(),
            Err(e) => c.settings_problem = Some(e),
        }
        match read_capped(&dirs.recent_file()).and_then(|t| t.map(|t| parse_recent(&t)).transpose()) {
            Ok(r) => c.recent = r.unwrap_or_default(),
            Err(e) => c.recent_problem = Some(e),
        }
        c
    }

    pub fn settings_path(&self) -> Option<PathBuf> {
        self.dirs.as_ref().map(Dirs::settings_file)
    }

    /// The only writer of `config.toml`, and it runs only when the rep saves. A broken file is
    /// copied to `config.toml.bak` first, so the text the rep wrote is never lost.
    pub fn save_settings(&mut self, settings: Settings) -> Result<(), String> {
        let path = self.settings_path().ok_or("no home directory: set XDG_CONFIG_HOME or HOME")?;
        if self.settings_problem.is_some() {
            let mut bak = path.clone().into_os_string();
            bak.push(".bak");
            fs::rename(&path, &bak).map_err(|e| format!("cannot keep a copy of the broken file: {e}"))?;
        }
        write_atomic(&path, &settings_model::to_toml(&settings))?;
        self.settings = settings;
        self.settings_problem = None;
        Ok(())
    }

    /// Called on each Diagnosis. A broken `recent.toml` is left alone: the list stays in memory only.
    pub fn save_recent(&mut self, entries: Vec<RecentEntry>) -> Result<(), String> {
        self.recent = entries;
        if self.recent_problem.is_some() {
            return Ok(());
        }
        let Some(dirs) = &self.dirs else { return Ok(()) };
        write_atomic(&dirs.recent_file(), &recent_to_toml(&self.recent))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!("zombo-config-test-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn dirs(&self) -> Dirs {
            Dirs::from_vars(
                Some(self.0.join("cfg").to_str().unwrap()),
                Some(self.0.join("state").to_str().unwrap()),
                None,
            )
            .unwrap()
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn sample() -> Settings {
        Settings { timeout: Some(Duration::from_secs(30)), selectors: vec!["s1".into()], ..Settings::default() }
    }

    #[test]
    fn xdg_variables_win_when_absolute_and_home_is_the_fallback() {
        let d = Dirs::from_vars(Some("/x/cfg"), Some("/x/state"), Some("/home/u")).unwrap();
        assert_eq!(
            (d.settings_file(), d.recent_file()),
            ("/x/cfg/zombo-razor/config.toml".into(), "/x/state/zombo-razor/recent.toml".into())
        );
        let d = Dirs::from_vars(None, None, Some("/home/u")).unwrap();
        assert_eq!(
            (d.settings_file(), d.recent_file()),
            ("/home/u/.config/zombo-razor/config.toml".into(), "/home/u/.local/state/zombo-razor/recent.toml".into())
        );
        let d = Dirs::from_vars(Some("relative/cfg"), Some(""), Some("/home/u")).unwrap();
        assert_eq!(d.settings_file(), PathBuf::from("/home/u/.config/zombo-razor/config.toml"));
        assert_eq!(Dirs::from_vars(None, None, None), None);
        assert_eq!(Dirs::from_vars(None, None, Some("rel")), None);
    }

    #[test]
    fn a_missing_file_means_defaults_and_no_problem() {
        let t = Tmp::new("missing");
        let c = Config::load(Some(t.dirs()));
        assert_eq!(
            (c.settings, c.settings_problem, c.recent, c.recent_problem),
            (Settings::default(), None, vec![], None)
        );
        assert!(!t.dirs().config.exists(), "loading creates nothing");
    }

    #[test]
    fn saving_writes_a_private_file_in_a_private_new_directory_and_loading_reads_it_back() {
        let t = Tmp::new("save");
        let mut c = Config::load(Some(t.dirs()));
        c.save_settings(sample()).unwrap();
        let file = t.dirs().settings_file();
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&t.dirs().config), 0o700);
        assert_eq!(Config::load(Some(t.dirs())).settings, sample());
        let leftovers: Vec<_> = fs::read_dir(&t.dirs().config).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(leftovers, ["config.toml"], "no temp file stays behind");
    }

    #[test]
    fn saving_replaces_the_file_in_one_rename() {
        let t = Tmp::new("atomic");
        let mut c = Config::load(Some(t.dirs()));
        c.save_settings(sample()).unwrap();
        let before = fs::metadata(t.dirs().settings_file()).unwrap();
        c.save_settings(Settings { timeout: Some(Duration::from_secs(60)), ..sample() }).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            before.ino(),
            fs::metadata(t.dirs().settings_file()).unwrap().ino(),
            "a new inode means the file was swapped, not rewritten in place"
        );
        assert_eq!(mode(&t.dirs().settings_file()), 0o600);
    }

    #[test]
    fn a_broken_file_falls_back_to_defaults_with_the_error_and_is_not_touched_by_loading() {
        let t = Tmp::new("broken");
        let file = t.dirs().settings_file();
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "timeout_seconds = 999\ntheme = 1\n").unwrap();
        let c = Config::load(Some(t.dirs()));
        assert_eq!(c.settings, Settings::default());
        assert!(c.settings_problem.as_deref().is_some_and(|p| p.contains("theme")), "{:?}", c.settings_problem);
        assert_eq!(fs::read_to_string(&file).unwrap(), "timeout_seconds = 999\ntheme = 1\n");
    }

    #[test]
    fn a_broken_settings_file_survives_as_a_copy_when_the_rep_saves_over_it() {
        let t = Tmp::new("bak");
        let file = t.dirs().settings_file();
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "not toml at all = = =").unwrap();
        let mut c = Config::load(Some(t.dirs()));
        assert!(c.settings_problem.is_some());
        c.save_settings(sample()).unwrap();
        assert_eq!(fs::read_to_string(file.with_extension("toml.bak")).unwrap(), "not toml at all = = =");
        assert_eq!(c.settings_problem, None);
        assert_eq!(Config::load(Some(t.dirs())).settings, sample());
    }

    #[test]
    fn a_broken_recent_file_is_never_overwritten_by_a_diagnosis() {
        let t = Tmp::new("recent-broken");
        let file = t.dirs().recent_file();
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "[[recent]]\nname = \"bad name!\"\nat = 1\n").unwrap();
        let mut c = Config::load(Some(t.dirs()));
        assert!(c.recent_problem.is_some() && c.recent.is_empty());
        c.save_recent(vec![RecentEntry { name: "example.com".into(), at: 5 }]).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "[[recent]]\nname = \"bad name!\"\nat = 1\n");
        assert_eq!(c.recent.len(), 1, "the list still works in memory");
    }

    #[test]
    fn recent_targets_hold_only_a_name_and_a_time_and_round_trip() {
        let t = Tmp::new("recent");
        let mut c = Config::load(Some(t.dirs()));
        let entries: Vec<RecentEntry> =
            (0..8).map(|i| RecentEntry { name: format!("site{i}.example.com"), at: 1_700_000_000 + i }).collect();
        c.save_recent(entries.clone()).unwrap();
        let file = t.dirs().recent_file();
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&t.dirs().state), 0o700);
        assert_eq!(Config::load(Some(t.dirs())).recent, entries);
        let text = fs::read_to_string(&file).unwrap();
        assert!(
            text.lines()
                .filter(|l| !l.is_empty())
                .all(|l| l.starts_with("name") || l.starts_with("at") || l == "[[recent]]"),
            "{text}"
        );
    }

    #[test]
    fn a_recent_file_is_validated_like_a_settings_file() {
        let ok = "[[recent]]\nname = \"example.com\"\nat = 5\n";
        assert_eq!(parse_recent(ok).unwrap().len(), 1);
        assert_eq!(parse_recent("").unwrap(), vec![]);
        let nine = ok.repeat(9);
        assert!(parse_recent(&nine).is_err());
        for bad in [
            "[[recent]]\nname = \"Example.COM\"\nat = 5\n",
            "[[recent]]\nname = \"\"\nat = 5\n",
            "[[recent]]\nname = \"a b\"\nat = 5\n",
            "[[recent]]\nname = \"example.com\"\nat = -1\n",
            "[[recent]]\nname = \"example.com\"\n",
            "[[recent]]\nname = \"example.com\"\nat = 5\nextra = 1\n",
            "other = 1\n",
            "[[recent]]\nname = \"\u{1b}[31m\"\nat = 5\n",
        ] {
            assert!(parse_recent(bad).is_err(), "{bad:?}");
        }
        let huge = " ".repeat(MAX_FILE_BYTES + 1);
        assert!(parse_recent(&huge).is_err());
    }

    #[test]
    fn a_file_over_the_cap_or_not_text_or_not_a_file_is_a_problem_and_not_a_panic() {
        let t = Tmp::new("hostile");
        let file = t.dirs().settings_file();
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, vec![b'#'; MAX_FILE_BYTES + 1]).unwrap();
        assert!(Config::load(Some(t.dirs())).settings_problem.unwrap().contains("larger"));
        fs::write(&file, [0xff, 0xfe, 0x00]).unwrap();
        assert!(Config::load(Some(t.dirs())).settings_problem.unwrap().contains("not text"));
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        assert!(Config::load(Some(t.dirs())).settings_problem.unwrap().contains("regular file"));
    }

    #[test]
    fn with_no_home_nothing_is_written_and_saving_the_settings_says_why() {
        let mut c = Config::load(None);
        assert!(c.save_settings(sample()).unwrap_err().contains("HOME"));
        assert!(c.save_recent(vec![]).is_ok());
    }

    #[test]
    fn a_recent_list_keeps_its_ages_across_the_conversion() {
        let now = Instant::now();
        let entries = vec![
            RecentEntry { name: "a.example.com".into(), at: 1_000 - 90 },
            RecentEntry { name: "b.example.com".into(), at: 5_000 },
        ];
        let recent = to_recent(&entries, 1_000, now);
        assert_eq!(now.duration_since(recent[0].at), Duration::from_secs(90));
        assert_eq!(recent[1].at, now, "a time in the future counts as now");
        let back = from_recent(&recent, 1_000, now);
        assert_eq!((back[0].at, back[1].at), (910, 1_000));
        assert_eq!(back[0].name, "a.example.com");
    }
}
