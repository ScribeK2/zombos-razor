//! The client-drawn window frame: soft shadow, rounded corners, resize strips and the grip.
//! `zombo_ui::chrome` decides what to draw; this only turns that into elements.

use gpui_kit::prelude::*;
use gpui_kit::*;
use zombo_ui::{
    chrome::{self, Chrome, Edge, WindowState},
    theme as t,
};

fn resize_edge(e: Edge) -> ResizeEdge {
    match e {
        Edge::Top => ResizeEdge::Top,
        Edge::TopRight => ResizeEdge::TopRight,
        Edge::Right => ResizeEdge::Right,
        Edge::BottomRight => ResizeEdge::BottomRight,
        Edge::Bottom => ResizeEdge::Bottom,
        Edge::BottomLeft => ResizeEdge::BottomLeft,
        Edge::Left => ResizeEdge::Left,
        Edge::TopLeft => ResizeEdge::TopLeft,
    }
}

fn cursor(e: Edge) -> CursorStyle {
    match e {
        Edge::Top | Edge::Bottom => CursorStyle::ResizeUpDown,
        Edge::Left | Edge::Right => CursorStyle::ResizeLeftRight,
        Edge::TopLeft | Edge::BottomRight => CursorStyle::ResizeUpLeftDownRight,
        Edge::TopRight | Edge::BottomLeft => CursorStyle::ResizeUpRightDownLeft,
    }
}

pub fn current(window: &Window) -> Chrome {
    let (client_decorated, tiled) = match window.window_decorations() {
        Decorations::Client { tiling } => (true, tiling.is_tiled()),
        Decorations::Server => (false, false),
    };
    let state =
        WindowState { client_decorated, tiled, maximized: window.is_maximized(), fullscreen: window.is_fullscreen() };
    Chrome::decide(state, chrome::detect_compositor_shadow())
}

fn strip(id: &'static str, e: Edge, band: f32) -> Stateful<Div> {
    let s =
        div().id(id).absolute().occlude().cursor(cursor(e)).on_mouse_down(MouseButton::Left, move |_, window, cx| {
            cx.stop_propagation();
            window.start_window_resize(resize_edge(e));
        });
    let b = px(band);
    match e {
        Edge::Top => s.top_0().left(b).right(b).h(b),
        Edge::Bottom => s.bottom_0().left(b).right(b).h(b),
        Edge::Left => s.left_0().top(b).bottom(b).w(b),
        Edge::Right => s.right_0().top(b).bottom(b).w(b),
        Edge::TopLeft => s.top_0().left_0().size(b),
        Edge::TopRight => s.top_0().right_0().size(b),
        Edge::BottomLeft => s.bottom_0().left_0().size(b),
        Edge::BottomRight => s.bottom_0().right_0().size(b),
    }
}

pub fn frame(window: &mut Window, content: impl IntoElement) -> impl IntoElement {
    let c = current(window);
    window.set_client_inset(px(c.margin));
    let shadow = vec![BoxShadow {
        color: hsla(0., 0., 0., 0.45),
        offset: point(px(0.), px(2.)),
        blur_radius: px(c.margin),
        spread_radius: px(0.),
        inset: false,
    }];
    let inner = div()
        .relative()
        .size_full()
        .overflow_hidden()
        .when(c.rounded, |s| s.rounded(px(chrome::CORNER_RADIUS)).border_1().border_color(rgb(t::GRAY_400)))
        .when(c.shadow, |s| s.shadow(shadow))
        .child(content);
    let grip = c.grip.then(|| {
        svg()
            .path("icons/grip.svg")
            .absolute()
            .right(px(2.))
            .bottom(px(2.))
            .size(px(chrome::GRIP_SIZE - 4.))
            .text_color(rgb(t::GRAY_600))
    });
    div().relative().size_full().p(px(c.margin)).child(inner.children(grip)).when(c.band > 0.0, |s| {
        let band = c.band;
        s.children([
            strip("rz-top", Edge::Top, band),
            strip("rz-bottom", Edge::Bottom, band),
            strip("rz-left", Edge::Left, band),
            strip("rz-right", Edge::Right, band),
            strip("rz-tl", Edge::TopLeft, band),
            strip("rz-tr", Edge::TopRight, band),
            strip("rz-bl", Edge::BottomLeft, band),
            strip("rz-br", Edge::BottomRight, band.max(chrome::GRIP_SIZE)),
        ])
    })
}
