#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! Hostile text for the UI's pure input functions: pasted evidence and the settings file.

use std::time::{Duration, Instant};

use zombo_ui::{
    evidence_model::{display_text, sniff},
    settings_model,
};

fn nasty() -> Vec<String> {
    vec![
        String::new(),
        "\0".repeat(1 << 20),
        "\r\n".repeat(200_000),
        (0u8..32).map(char::from).collect::<String>() + "\u{7f}\u{85}\u{202e}\u{feff}",
        "Received: ".repeat(100_000),
        "\u{fffd}".repeat(100_000),
        "😀\n".repeat(100_000),
        "[".repeat(100_000),
        "a = ".repeat(100_000),
        "[a]\n".repeat(100_000),
        "a = \"".to_string() + &"x".repeat(1 << 20),
        "resolver = \"\u{0}\"\ntimeout_seconds = 99999999999999999999\n".into(),
        "resolver = [".repeat(10_000),
        "x = 1e999999999\ny = 0x\nz = 1979-05-27T07:32:00-99:99\n".into(),
    ]
}

#[test]
fn pure_text_functions_survive_nasty_text_in_bounded_time() {
    for t in nasty() {
        let start = Instant::now();
        let _ = sniff(&t);
        let shown = display_text(&t);
        assert!(!shown.chars().any(|c| c.is_control() && c != '\n'), "control character survived");
        if let Err(e) = settings_model::parse(&t) {
            assert!(!e.to_string().chars().any(char::is_control), "control character in {e}");
        }
        assert!(start.elapsed() < Duration::from_secs(5), "took {:?}", start.elapsed());
    }
}

#[test]
fn bidirectional_and_invisible_characters_never_reach_displayed_text() {
    let bad = |s: &str| s.contains('\u{202e}') || s.contains('\u{200b}');
    assert!(!bad(&display_text("pasted \u{202e}evil\u{200b}")));
    let n = zombo_ui::notice::watch_notice(&settings_model::Settings::default(), "example.com\u{202e} \u{200b}changed")
        .unwrap();
    assert!(!bad(&n.1), "{:?}", n.1);
    let e = settings_model::parse("resolvers = [\"1.2.3\u{202e}.4\u{200b}\"]")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(e.contains("1.2.3") && !bad(&e), "{e:?}");
}
