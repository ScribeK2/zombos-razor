use std::process::Command;

/// Radius of the window corners and the size of the soft shadow's margin, in logical pixels.
pub const CORNER_RADIUS: f32 = 12.0;
pub const SHADOW_MARGIN: f32 = 12.0;
/// Width of the invisible strip along each edge that starts a resize, when the compositor
/// already draws the shadow and the window has no margin of its own.
pub const EDGE_BAND: f32 = 6.0;
pub const GRIP_SIZE: f32 = 16.0;

/// Where the window stands, as GPUI reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowState {
    pub client_decorated: bool,
    pub tiled: bool,
    pub maximized: bool,
    pub fullscreen: bool,
}

/// What the client draws around the window content.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Chrome {
    /// Transparent margin around the content that holds the shadow and the resize zone.
    pub margin: f32,
    pub shadow: bool,
    pub rounded: bool,
    /// Resize zone width, measured from the window edge inward.
    pub band: f32,
    /// A visible grip in the bottom-right corner.
    pub grip: bool,
}

impl Chrome {
    pub const NONE: Chrome = Chrome { margin: 0.0, shadow: false, rounded: false, band: 0.0, grip: false };

    /// Maximized, fullscreen and tiled windows get nothing: they fill their space and the
    /// compositor owns their edges. A floating window with a compositor shadow gets only the
    /// resize zone and the grip, so the shadow is not doubled. Otherwise it gets its own.
    pub fn decide(state: WindowState, compositor_shadow: bool) -> Chrome {
        if !state.client_decorated || state.tiled || state.maximized || state.fullscreen {
            return Chrome::NONE;
        }
        if compositor_shadow {
            Chrome { margin: 0.0, shadow: false, rounded: false, band: EDGE_BAND, grip: true }
        } else {
            Chrome { margin: SHADOW_MARGIN, shadow: true, rounded: true, band: SHADOW_MARGIN, grip: true }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    Top,
    TopRight,
    Right,
    BottomRight,
    Bottom,
    BottomLeft,
    Left,
    TopLeft,
}

/// The edge or corner a point on the window is in, with `band` as the zone width.
pub fn edge_at(x: f32, y: f32, width: f32, height: f32, band: f32) -> Option<Edge> {
    if band <= 0.0 {
        return None;
    }
    let (left, right) = (x < band, x > width - band);
    let (top, bottom) = (y < band, y > height - band);
    match (left, right, top, bottom) {
        (true, _, true, _) => Some(Edge::TopLeft),
        (_, true, true, _) => Some(Edge::TopRight),
        (true, _, _, true) => Some(Edge::BottomLeft),
        (_, true, _, true) => Some(Edge::BottomRight),
        (_, _, true, _) => Some(Edge::Top),
        (_, _, _, true) => Some(Edge::Bottom),
        (true, ..) => Some(Edge::Left),
        (_, true, ..) => Some(Edge::Right),
        _ => None,
    }
}

/// Whether the compositor draws a shadow for a client-decorated window. Only Hyprland is
/// asked: it can be configured either way. Other desktops are assumed not to draw one for
/// client-decorated windows. An unreadable Hyprland setting counts as "draws", so a shadow
/// is never doubled.
pub fn compositor_draws_shadow(hyprland: bool, hypr_option_json: Option<&str>) -> bool {
    hyprland && hypr_option_json.and_then(parse_hypr_bool).unwrap_or(true)
}

/// `hyprctl getoption <name> -j` prints `{"option": "...", "bool": false, "set": true}`, or
/// `"int": 0` on other versions.
fn parse_hypr_bool(json: &str) -> Option<bool> {
    let after = ["\"bool\"", "\"int\""].iter().find_map(|k| json.split(k).nth(1))?;
    let value = after.trim_start().strip_prefix(':')?.trim_start();
    if value.starts_with("true") || value.starts_with('1') {
        Some(true)
    } else if value.starts_with("false") || value.starts_with('0') {
        Some(false)
    } else {
        None
    }
}

/// Read once: the answer cannot change while the window is open.
pub fn detect_compositor_shadow() -> bool {
    static DRAWN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DRAWN.get_or_init(read_compositor_shadow)
}

fn read_compositor_shadow() -> bool {
    let hyprland = std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some();
    let json = hyprland
        .then(|| Command::new("hyprctl").args(["getoption", "decoration:shadow:enabled", "-j"]).output().ok())
        .flatten()
        .and_then(|o| String::from_utf8(o.stdout).ok());
    compositor_draws_shadow(hyprland, json.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOATING: WindowState = WindowState { client_decorated: true, tiled: false, maximized: false, fullscreen: false };

    #[test]
    fn a_floating_window_without_a_compositor_shadow_draws_its_own() {
        let c = Chrome::decide(FLOATING, false);
        assert!(c.shadow && c.rounded && c.grip);
        assert_eq!((c.margin, c.band), (SHADOW_MARGIN, SHADOW_MARGIN));
    }

    #[test]
    fn a_compositor_shadow_is_not_doubled() {
        let c = Chrome::decide(FLOATING, true);
        assert!(!c.shadow && c.margin == 0.0);
        assert!(c.grip && c.band == EDGE_BAND);
    }

    #[test]
    fn maximized_tiled_and_fullscreen_windows_get_no_shadow_and_no_handle() {
        for state in [
            WindowState { maximized: true, ..FLOATING },
            WindowState { tiled: true, ..FLOATING },
            WindowState { fullscreen: true, ..FLOATING },
        ] {
            for compositor in [false, true] {
                assert_eq!(Chrome::decide(state, compositor), Chrome::NONE);
            }
        }
    }

    #[test]
    fn a_server_decorated_window_gets_nothing() {
        assert_eq!(Chrome::decide(WindowState { client_decorated: false, ..FLOATING }, false), Chrome::NONE);
    }

    #[test]
    fn edges_and_corners_are_found_inside_the_band() {
        let at = |x, y| edge_at(x, y, 100.0, 80.0, 6.0);
        assert_eq!(at(50.0, 2.0), Some(Edge::Top));
        assert_eq!(at(50.0, 78.0), Some(Edge::Bottom));
        assert_eq!(at(2.0, 40.0), Some(Edge::Left));
        assert_eq!(at(98.0, 40.0), Some(Edge::Right));
        assert_eq!(at(2.0, 2.0), Some(Edge::TopLeft));
        assert_eq!(at(98.0, 2.0), Some(Edge::TopRight));
        assert_eq!(at(2.0, 78.0), Some(Edge::BottomLeft));
        assert_eq!(at(98.0, 78.0), Some(Edge::BottomRight));
        assert_eq!(at(50.0, 40.0), None);
    }

    #[test]
    fn no_band_means_no_edge() {
        assert_eq!(edge_at(0.0, 0.0, 100.0, 80.0, 0.0), None);
    }

    #[test]
    fn hyprland_shadow_setting_is_read_and_defaults_to_drawn() {
        let off = r#"{"option": "decoration:shadow:enabled", "int": 0, "set": true}"#;
        let on = r#"{"option": "decoration:shadow:enabled", "int": 1, "set": true}"#;
        let real_off = r#"{"option": "decoration:shadow:enabled", "bool": false, "set": true }"#;
        let real_on = r#"{"option": "decoration:shadow:enabled", "bool": true, "set": true }"#;
        assert!(!compositor_draws_shadow(true, Some(real_off)));
        assert!(compositor_draws_shadow(true, Some(real_on)));
        assert!(!compositor_draws_shadow(true, Some(off)));
        assert!(compositor_draws_shadow(true, Some(on)));
        assert!(compositor_draws_shadow(true, None));
        assert!(compositor_draws_shadow(true, Some("garbage")));
        assert!(!compositor_draws_shadow(false, Some(on)));
    }
}
