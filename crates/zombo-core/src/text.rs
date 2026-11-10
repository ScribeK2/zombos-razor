//! The one policy for text that came from the network and is about to reach a Finding or the UI.
//!
//! `char::is_control` is not enough: it lets bidirectional overrides and invisible format
//! characters through, so a registrar name can read backwards or hide a word. Every module
//! cleans text here and nowhere else (`tests/text_policy.rs` enforces it).
//!
//! U+200D (zero width joiner) is kept on purpose. Emoji sequences (a family, a flag with a
//! modifier) and some scripts need it to render as typed. The other zero width characters hide
//! text and are unsafe. Legitimate right-to-left letters (Arabic, Hebrew) are not touched: only
//! the control characters that reorder them are.

use std::borrow::Cow;

const REPLACEMENT: char = '\u{fffd}';

/// True for controls, bidirectional controls, and invisible format characters.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00ad}' // soft hyphen
            | '\u{061c}' // Arabic letter mark
            | '\u{200b}'..='\u{200c}' // zero width space, zero width non-joiner
            | '\u{200e}'..='\u{200f}' // left-to-right and right-to-left marks
            | '\u{2028}'..='\u{2029}' // line and paragraph separators
            | '\u{202a}'..='\u{202e}' // embeddings and overrides
            | '\u{2060}'..='\u{2064}' // word joiner and invisible operators
            | '\u{2066}'..='\u{2069}' // isolates
            | '\u{feff}' // byte order mark, zero width no-break space
            | '\u{e0000}'..='\u{e007f}' // tag characters
        )
}

/// Each unsafe character becomes U+FFFD.
pub fn printable(s: &str) -> String {
    printable_cow(s).into_owned()
}

/// Like [`printable`], and borrows when nothing changes.
pub fn printable_cow(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_unsafe_char) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(s.chars().map(|c| if is_unsafe_char(c) { REPLACEMENT } else { c }).collect())
}

/// Each unsafe character is removed.
pub fn strip(s: &str) -> String {
    s.chars().filter(|c| !is_unsafe_char(*c)).collect()
}

/// Each unsafe character (tabs and newlines included) becomes a space, and a run of spaces
/// becomes one space.
pub fn single_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let c = if is_unsafe_char(c) { ' ' } else { c };
        if c != ' ' || !out.ends_with(' ') {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNSAFE: &[(&str, char)] = &[
        ("NUL", '\u{0}'),
        ("escape", '\u{1b}'),
        ("newline", '\n'),
        ("tab", '\t'),
        ("DEL", '\u{7f}'),
        ("C1 control", '\u{85}'),
        ("soft hyphen", '\u{ad}'),
        ("Arabic letter mark", '\u{61c}'),
        ("zero width space", '\u{200b}'),
        ("zero width non-joiner", '\u{200c}'),
        ("left-to-right mark", '\u{200e}'),
        ("right-to-left mark", '\u{200f}'),
        ("line separator", '\u{2028}'),
        ("paragraph separator", '\u{2029}'),
        ("left-to-right embedding", '\u{202a}'),
        ("right-to-left embedding", '\u{202b}'),
        ("pop directional formatting", '\u{202c}'),
        ("left-to-right override", '\u{202d}'),
        ("right-to-left override", '\u{202e}'),
        ("word joiner", '\u{2060}'),
        ("function application", '\u{2061}'),
        ("invisible times", '\u{2062}'),
        ("invisible separator", '\u{2063}'),
        ("invisible plus", '\u{2064}'),
        ("left-to-right isolate", '\u{2066}'),
        ("right-to-left isolate", '\u{2067}'),
        ("first strong isolate", '\u{2068}'),
        ("pop directional isolate", '\u{2069}'),
        ("byte order mark", '\u{feff}'),
        ("tag begin", '\u{e0000}'),
        ("tag space", '\u{e0020}'),
        ("cancel tag", '\u{e007f}'),
    ];

    const SAFE: &[(&str, &str)] = &[
        ("Latin", "Zombo's Razor, Zürich ñ"),
        ("Cyrillic", "Пример Регистратор"),
        ("Arabic", "مثال المسجل"),
        ("Hebrew", "דוגמה רשם"),
        ("CJK", "例え 注册商 한국어"),
        ("emoji", "ok \u{1f600} \u{1f44d}\u{1f3fd}"),
        ("emoji ZWJ family", "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}"),
        ("ordinary space", "a b"),
        ("noncharacter", "a\u{fdd0}b"),
        ("private use", "a\u{e000}b"),
        ("replacement mark", "a\u{fffd}b"),
        ("tag range neighbours", "a\u{dfff0}\u{e0080}b"),
    ];

    #[test]
    fn every_unsafe_class_is_unsafe() {
        for (name, c) in UNSAFE {
            assert!(is_unsafe_char(*c), "{name} U+{:04X}", *c as u32);
            assert_eq!(printable(&format!("a{c}b")), "a\u{fffd}b", "{name}");
            assert_eq!(strip(&format!("a{c}b")), "ab", "{name}");
            assert_eq!(single_line(&format!("a{c}b")), "a b", "{name}");
        }
    }

    #[test]
    fn ordinary_text_survives_every_helper() {
        for (name, s) in SAFE {
            assert!(!s.chars().any(is_unsafe_char), "{name}");
            assert_eq!(printable(s), *s, "{name}");
            assert_eq!(strip(s), *s, "{name}");
            assert_eq!(single_line(s), *s, "{name}");
            assert!(matches!(printable_cow(s), Cow::Borrowed(_)), "{name}");
        }
    }

    #[test]
    fn zero_width_joiner_is_kept_so_emoji_sequences_render() {
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
        assert!(!is_unsafe_char('\u{200d}'));
        assert_eq!(printable(family), family);
        assert_eq!(strip(family), family);
    }

    #[test]
    fn right_to_left_letters_stay_and_the_override_goes() {
        assert_eq!(strip("\u{202e}\u{5d3}\u{5d5}\u{5d2}"), "\u{5d3}\u{5d5}\u{5d2}");
    }

    #[test]
    fn printable_cow_borrows_when_clean_and_owns_when_not() {
        assert!(matches!(printable_cow("plain"), Cow::Borrowed(_)));
        assert_eq!(printable_cow("a\u{200b}b"), "a\u{fffd}b");
    }

    #[test]
    fn single_line_collapses_runs() {
        assert_eq!(single_line("a \n\t\r\n  b"), "a b");
    }
}
