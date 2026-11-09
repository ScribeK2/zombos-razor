mod app;
mod assets;
mod settings;
mod update_ui;

use std::{
    any::Any,
    borrow::Cow,
    panic::{AssertUnwindSafe, catch_unwind, set_hook},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::Instant,
};

use gpui_kit::component::theme::{Theme, ThemeMode};
use gpui_kit::*;

const APP_ID: &str = "io.github.scribek2.zombos-razor";

fn describe(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown failure".into())
}

fn launch(started: Instant) {
    gpui_kit::application().with_assets(assets::Assets).run(move |cx| {
        gpui_kit::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);
        if let Err(e) = cx.text_system().add_fonts(assets::FONTS.iter().map(|f| Cow::Borrowed(*f)).collect()) {
            eprintln!("zombo-razor: the bundled fonts did not load, using system fonts: {e}");
        }
        let options = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: Some("Zombo's Razor".into()),
                appears_transparent: true,
                traffic_light_position: None,
            }),
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(None, size(px(1280.), px(800.)), cx))),
            window_decorations: Some(WindowDecorations::Client),
            window_background: if zombo_ui::chrome::detect_compositor_shadow() {
                WindowBackgroundAppearance::Opaque
            } else {
                WindowBackgroundAppearance::Transparent
            },
            app_id: Some(APP_ID.into()),
            window_min_size: Some(size(px(720.), px(480.))),
            ..Default::default()
        };
        if let Err(e) =
            gpui_kit::open_window(options, cx, |window, cx| cx.new(|cx| app::Shell::new(started, window, cx)))
        {
            eprintln!("zombo-razor: cannot open the window: {e}");
            cx.quit();
        }
    });
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("zombo-razor {}", zombo_core::VERSION);
        return ExitCode::SUCCESS;
    }
    if !zombo_ui::session::has_display_in_env() {
        eprintln!("{}", zombo_ui::session::NO_DISPLAY);
        return ExitCode::FAILURE;
    }
    let started = Instant::now();
    let panic_text = Arc::new(Mutex::new(None::<String>));
    let sink = panic_text.clone();
    set_hook(Box::new(move |info| {
        if let Ok(mut slot) = sink.lock() {
            slot.get_or_insert_with(|| info.to_string());
        }
    }));
    match catch_unwind(AssertUnwindSafe(|| launch(started))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(payload) => {
            let detail = panic_text.lock().ok().and_then(|s| s.clone()).unwrap_or_else(|| describe(payload.as_ref()));
            eprintln!(
                "zombo-razor: the window system could not start.\n\
                 Zombo's Razor needs a Wayland or X11 session with a graphics driver (Vulkan or OpenGL) and an input seat.\n\
                 Detail: {detail}"
            );
            ExitCode::FAILURE
        }
    }
}
