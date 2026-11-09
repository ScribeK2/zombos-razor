//! Sizes the shell derives from the data it shows.

/// The key column of a data table starts here, as the design's 200 px.
pub const KEY_MIN: f32 = 200.;
/// Past this a key wraps instead of pushing the values aside.
pub const KEY_MAX: f32 = 360.;
/// An average label-size character, a little generous so that a key never wraps by a hair.
const CHAR_PX: f32 = 7.2;
/// The row's own gap to the value column.
const PAD_PX: f32 = 4.;

/// One width for every key of a table, wide enough for the longest key.
pub fn key_column<'a>(keys: impl IntoIterator<Item = &'a str>) -> f32 {
    let longest = keys.into_iter().map(|k| k.chars().count()).max().unwrap_or(0);
    (longest as f32 * CHAR_PX + PAD_PX).clamp(KEY_MIN, KEY_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_keys_keep_the_design_width() {
        assert_eq!(key_column(["MX", "SPF"]), KEY_MIN);
        assert_eq!(key_column([]), KEY_MIN);
    }

    #[test]
    fn a_long_key_widens_the_column_to_fit_it() {
        let key = "198.51.100.5 (address, mail host of example.com)";
        let w = key_column(["MX", key]);
        assert!(w > KEY_MIN && w >= key.chars().count() as f32 * 7., "{w}");
    }

    #[test]
    fn a_very_long_key_is_capped_so_the_value_keeps_its_room() {
        assert_eq!(key_column(["x".repeat(200).as_str()]), KEY_MAX);
    }
}
