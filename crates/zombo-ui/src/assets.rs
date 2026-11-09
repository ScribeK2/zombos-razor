use std::borrow::Cow;

use gpui_kit::{AssetSource, Result, SharedString};

const HEAD: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="#fff" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round">"##;

const SHAPES: &[(&str, &str)] = &[
    ("ring", r#"<circle cx="8" cy="8" r="6"/>"#),
    ("dashed", r#"<circle cx="8" cy="8" r="6" stroke-dasharray="5 3.4"/>"#),
    ("check", r#"<circle cx="8" cy="8" r="6.5"/><path d="M5 8.2l2 2 4-4.4"/>"#),
    ("info", r#"<circle cx="8" cy="8" r="6.5"/><path d="M8 7.2v4M8 4.6v.1" stroke-width="1.8"/>"#),
    ("triangle", r#"<path d="M8 2.2l6.2 11H1.8z"/><path d="M8 6.6v3.2M8 11.6v.1" stroke-width="1.8"/>"#),
    ("octagon", r#"<path d="M5.2 1.8h5.6l3.4 3.4v5.6l-3.4 3.4H5.2L1.8 10.8V5.2z"/><path d="M5.8 5.8l4.4 4.4M10.2 5.8l-4.4 4.4"/>"#),
    ("clock", r#"<circle cx="8" cy="8" r="6.5"/><path d="M8 4.6V8l2.4 1.6"/>"#),
    ("search", r#"<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/>"#),
    ("close", r#"<path d="M4 4l8 8M12 4l-8 8"/>"#),
    ("minimize", r#"<path d="M3.5 8h9"/>"#),
    ("maximize", r#"<rect x="3.5" y="3.5" width="9" height="9" rx="1"/>"#),
    ("chevron", r#"<path d="M6 4l4 4-4 4"/>"#),
];

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        let name = path.strip_prefix("icons/").and_then(|p| p.strip_suffix(".svg"));
        Ok(SHAPES
            .iter()
            .find(|(n, _)| Some(*n) == name)
            .map(|(_, body)| Cow::Owned(format!("{HEAD}{body}</svg>").into_bytes())))
    }

    fn list(&self, _path: &str) -> Result<Vec<SharedString>> {
        Ok(SHAPES.iter().map(|(n, _)| format!("icons/{n}.svg").into()).collect())
    }
}

pub const FONTS: [&[u8]; 2] = [include_bytes!("../assets/Geist.ttf"), include_bytes!("../assets/GeistMono.ttf")];
