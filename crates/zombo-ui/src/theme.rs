pub const BG_100: u32 = 0x0B0B0C;
pub const BG_200: u32 = 0x111113;
pub const GRAY_100: u32 = 0x17171A;
pub const GRAY_200: u32 = 0x1D1D21;
pub const GRAY_300: u32 = 0x25252A;
pub const GRAY_400: u32 = 0x2E2E34;
pub const GRAY_500: u32 = 0x3A3A41;
pub const GRAY_600: u32 = 0x6B6B74;
pub const GRAY_800: u32 = 0x8F8F99;
pub const GRAY_900: u32 = 0xA1A1AA;
pub const GRAY_1000: u32 = 0xEDEDEF;
pub const ACCENT: u32 = 0x5B8DEF;
pub const OK: u32 = 0x3FB27F;
pub const INFO: u32 = 0x5B8DEF;
pub const WARNING: u32 = 0xE5A93D;
pub const CRITICAL: u32 = 0xF06A6E;

pub const RADIUS_SMALL: f32 = 6.0;
pub const RADIUS_LARGE: f32 = 12.0;

pub const TITLE_BAR_HEIGHT: f32 = 44.0;
pub const OMNIBOX_HEIGHT: f32 = 32.0;
pub const TAB_STRIP_HEIGHT: f32 = 32.0;
pub const RAIL_WIDTH: f32 = 248.0;
pub const RAIL_ITEM_HEIGHT: f32 = 32.0;
pub const ROW_HEIGHT: f32 = 28.0;
pub const STATUS_BAR_HEIGHT: f32 = 28.0;
pub const PANE_PADDING: f32 = 16.0;
pub const FINDING_GAP: f32 = 8.0;

pub const FONT_SANS: &str = "Geist";
pub const FONT_MONO: &str = "Geist Mono";

pub const TEXT_CAPTION: f32 = 12.0;
pub const TEXT_LABEL: f32 = 13.0;
pub const TEXT_BODY: f32 = 14.0;
pub const TEXT_VERDICT: f32 = 28.0;

#[cfg(test)]
const TEXT_ON_ACTIVE_STEP: &[(u32, u32)] = &[
    (GRAY_1000, BG_100),
    (GRAY_1000, GRAY_300),
    (GRAY_900, GRAY_300),
    (GRAY_800, GRAY_300),
    (GRAY_900, BG_200),
    (CRITICAL, GRAY_300),
    (WARNING, GRAY_300),
    (OK, GRAY_300),
    (INFO, GRAY_300),
];

#[cfg(test)]
fn contrast(a: u32, b: u32) -> f64 {
    let luminance = |c: u32| {
        let channel = |shift: u32| {
            let v = ((c >> shift) & 0xFF) as f64 / 255.0;
            if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0)
    };
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_tokens_reach_aa_on_the_active_step() {
        for &(fg, bg) in TEXT_ON_ACTIVE_STEP {
            assert!(contrast(fg, bg) >= 4.5, "{fg:06X} on {bg:06X} is {:.2}", contrast(fg, bg));
        }
    }

    #[test]
    fn control_boundary_token_reaches_3_to_1() {
        assert!(contrast(GRAY_600, BG_200) >= 3.0);
        assert!(contrast(GRAY_600, GRAY_100) >= 3.0);
    }
}
