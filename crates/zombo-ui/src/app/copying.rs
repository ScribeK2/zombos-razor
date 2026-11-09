//! Putting Diagnosis text on the clipboard. The text itself comes from `zombo_ui::copy`.

use super::*;
use zombo_ui::copy::{self, Format};

impl Shell {
    pub(super) fn copy_current(&mut self, format: Format, cx: &mut Context<Self>) {
        if self.ws.current_evidence().is_some() {
            if format == Format::Json {
                self.toast = Some((
                    "JSON copy works on a Diagnosis tab. Use Ctrl+Shift+C for Markdown here.".into(),
                    Instant::now(),
                ));
            } else {
                self.copy_evidence(format == Format::Whole, cx);
            }
            return;
        }
        let Some(tab) = self.ws.current() else {
            self.toast = Some(("Enter a target first, then copy its results.".into(), Instant::now()));
            return;
        };
        let (text, message) = copy::build(tab, format);
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.toast = Some((message, Instant::now()));
    }

    pub(super) fn copy_value(&mut self, value: &str, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(zombo_core::text::strip(value)));
        self.toast = Some(("Copied the value.".into(), Instant::now()));
        cx.notify();
    }
}
