//! GPUI starts a headless platform when no display variable is set, so the app would run
//! forever with no window. Check the environment first and say what is missing.

pub const NO_DISPLAY: &str = "zombo-razor: no display found.\n\
Zombo's Razor needs a Wayland or X11 session. Neither WAYLAND_DISPLAY nor DISPLAY is set.\n\
Start it from a desktop session, not from a bare terminal or over SSH without a forwarded display.";

fn set(v: Option<&str>) -> bool {
    v.is_some_and(|s| !s.trim().is_empty())
}

pub fn has_display(wayland: Option<&str>, x11: Option<&str>) -> bool {
    set(wayland) || set(x11)
}

pub fn has_display_in_env() -> bool {
    has_display(std::env::var("WAYLAND_DISPLAY").ok().as_deref(), std::env::var("DISPLAY").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_variable_means_no_display() {
        assert!(!has_display(None, None));
    }

    #[test]
    fn empty_or_blank_values_do_not_count() {
        assert!(!has_display(Some(""), Some("  ")));
    }

    #[test]
    fn either_variable_is_enough() {
        assert!(has_display(Some("wayland-1"), None));
        assert!(has_display(None, Some(":0")));
    }
}
