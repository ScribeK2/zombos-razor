//! Makes a bare AppImage show its icon in the taskbar, dock and Activities.
//!
//! GNOME and KDE match a window to its icon only through an installed `.desktop` file named after
//! the window's app id. An AppImage installs nothing, so this module copies the entry and the icon
//! out of the mounted image into the user's data directory, with `Exec=` pointing at the AppImage.

use std::{
    fs,
    path::{Path, PathBuf},
};

const ID: &str = "io.github.scribek2.zombos-razor";

/// XDG rules: `XDG_DATA_HOME` counts only when it is an absolute path, else `$HOME/.local/share`.
pub fn data_home(xdg_data_home: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
    let abs = |v: &str| Path::new(v).is_absolute().then(|| PathBuf::from(v));
    xdg_data_home.and_then(abs).or_else(|| home.and_then(abs).map(|h| h.join(".local/share")))
}

/// Installs or refreshes the entry and the icon. Returns `true` when a file changed.
/// Running it twice in a row changes nothing the second time. `appdir` is the mounted image.
pub fn ensure(appimage: &Path, appdir: &Path, data_home: &Path) -> Result<bool, String> {
    let exec = exec_line(appimage)?;
    let template = appdir.join(format!("usr/share/applications/{ID}.desktop"));
    let template = fs::read_to_string(&template).map_err(|e| format!("cannot read {}: {e}", template.display()))?;
    let entry = template
        .lines()
        .map(|l| if l.starts_with("Exec=") { exec.clone() } else { l.to_string() })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let icon = appdir.join(format!("usr/share/icons/hicolor/256x256/apps/{ID}.png"));
    let icon = fs::read(&icon).map_err(|e| format!("cannot read {}: {e}", icon.display()))?;
    let a = put(&data_home.join(format!("applications/{ID}.desktop")), entry.as_bytes())?;
    let b = put(&data_home.join(format!("icons/hicolor/256x256/apps/{ID}.png")), &icon)?;
    Ok(a || b)
}

/// A quoted `Exec=` line. A path with a character that needs a second layer of escaping is refused.
fn exec_line(appimage: &Path) -> Result<String, String> {
    let p = appimage.to_str().ok_or("the AppImage path is not valid UTF-8")?;
    if p.chars().any(|c| zombo_core::text::is_unsafe_char(c) || matches!(c, '"' | '`' | '$' | '\\' | '%')) {
        return Err(format!("the AppImage path {p:?} has a character a desktop entry cannot quote"));
    }
    Ok(format!("Exec=\"{p}\""))
}

fn put(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    if fs::read(path).is_ok_and(|old| old == bytes) {
        return Ok(false);
    }
    let dir = path.parent().ok_or("the file has no directory")?;
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{ID}.{}.tmp", std::process::id()));
    fs::write(&tmp, bytes).and_then(|()| fs::rename(&tmp, path)).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot write {}: {e}", path.display())
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!("zombo-launcher-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn image(root: &Path) -> PathBuf {
        let apps = root.join("usr/share/applications");
        let icons = root.join("usr/share/icons/hicolor/256x256/apps");
        fs::create_dir_all(&apps).unwrap();
        fs::create_dir_all(&icons).unwrap();
        fs::write(apps.join(format!("{ID}.desktop")), "[Desktop Entry]\nName=Z\nExec=zombo-razor\nIcon=x\n").unwrap();
        fs::write(icons.join(format!("{ID}.png")), b"png-bytes").unwrap();
        root.to_path_buf()
    }

    fn desktop(data: &Path) -> String {
        fs::read_to_string(data.join(format!("applications/{ID}.desktop"))).unwrap()
    }

    #[test]
    fn the_entry_runs_the_appimage_and_the_icon_is_copied() {
        let t = Tmp::new("install");
        let appdir = image(&t.0.join("mnt"));
        let data = t.0.join("data");
        assert!(ensure(Path::new("/home/me/My Apps/Z.AppImage"), &appdir, &data).unwrap());
        assert_eq!(desktop(&data), "[Desktop Entry]\nName=Z\nExec=\"/home/me/My Apps/Z.AppImage\"\nIcon=x\n");
        assert_eq!(fs::read(data.join(format!("icons/hicolor/256x256/apps/{ID}.png"))).unwrap(), b"png-bytes");
    }

    #[test]
    fn a_second_run_changes_nothing_and_a_moved_appimage_rewrites_the_entry() {
        let t = Tmp::new("again");
        let appdir = image(&t.0.join("mnt"));
        let data = t.0.join("data");
        let app = Path::new("/opt/Z.AppImage");
        assert!(ensure(app, &appdir, &data).unwrap());
        assert!(!ensure(app, &appdir, &data).unwrap());
        assert!(ensure(Path::new("/opt/new/Z.AppImage"), &appdir, &data).unwrap());
        assert!(desktop(&data).contains("Exec=\"/opt/new/Z.AppImage\""));
    }

    #[test]
    fn a_path_that_cannot_be_quoted_is_refused_and_writes_nothing() {
        let t = Tmp::new("refuse");
        let appdir = image(&t.0.join("mnt"));
        let data = t.0.join("data");
        for bad in ["/o/a\"b.AppImage", "/o/a$b.AppImage", "/o/a%b.AppImage", "/o/a\\b.AppImage", "/o/a\nb.AppImage"] {
            assert!(ensure(Path::new(bad), &appdir, &data).is_err(), "{bad:?}");
        }
        assert!(!data.exists());
    }

    #[test]
    fn a_missing_template_is_an_error() {
        let t = Tmp::new("missing");
        assert!(ensure(Path::new("/o/Z.AppImage"), &t.0, &t.0.join("data")).is_err());
    }

    #[test]
    fn the_data_home_follows_the_xdg_rules() {
        assert_eq!(data_home(Some("/x/data"), Some("/h")), Some(PathBuf::from("/x/data")));
        assert_eq!(data_home(Some("rel"), Some("/h")), Some(PathBuf::from("/h/.local/share")));
        assert_eq!(data_home(None, Some("/h")), Some(PathBuf::from("/h/.local/share")));
        assert_eq!(data_home(None, None), None);
    }
}
