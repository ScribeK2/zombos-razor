use std::path::PathBuf;

use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::prelude::*;
use gpui_kit::*;
use zombo_ui::{
    settings_model::{Draft, Field, FieldError, Settings, split_list},
    theme as t,
};

pub enum PaneEvent {
    Save(Settings),
    Close,
}

/// The settings pane (DESIGN.md, "Settings"): the five fields and nothing else.
pub struct SettingsPane {
    inputs: [(Field, Entity<InputState>); 4],
    notifications: bool,
    check_updates: bool,
    /// Only an AppImage can update itself, so only an AppImage shows the control.
    can_update: bool,
    errors: Vec<FieldError>,
    save_error: Option<String>,
    file_problem: Option<String>,
    path: Option<PathBuf>,
    save_focus: FocusHandle,
    cancel_focus: FocusHandle,
}

impl EventEmitter<PaneEvent> for SettingsPane {}

const PROXY_RULE: &str = "The proxy applies to the Registration Check only. The Web Check ignores it on purpose: it must show what the site does from this machine, not what a proxy relays. Empty means use HTTP_PROXY and HTTPS_PROXY from the environment.";
const RESOLVER_RULE: &str = "Added to the ten public resolvers (Google, Cloudflare, Quad9, OpenDNS, Level3, DNS.SB, AdGuard, Yandex, 114DNS, CleanBrowsing) in the DNS propagation Check. The queries hold the target's name and nothing else. Separate with commas or spaces; a port is optional (192.0.2.53:5353).";
const UPDATE_RULE: &str = "Asks GitHub once a day whether a newer version exists. Nothing about you or your lookups is sent. A newer version is downloaded only after you click Update, and its signature is checked first.";
const APPLY_RULE: &str =
    "Changes apply to the next run of a Check. A Check that is running keeps the settings it started with.";

impl SettingsPane {
    pub fn new(
        current: &Settings,
        can_update: bool,
        file_problem: Option<String>,
        path: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let d = Draft::from(current);
        let input = |text: String, placeholder: &'static str, window: &mut Window, cx: &mut Context<Self>| {
            cx.new(|cx| {
                let mut state = InputState::new(window, cx).placeholder(placeholder);
                state.set_value(text, window, cx);
                state
            })
        };
        let inputs = [
            (Field::Resolvers, input(d.resolvers.join(", "), "9.9.9.10, 192.0.2.53:5353", window, cx)),
            (Field::Selectors, input(d.selectors.join(", "), "selector1, acme2024", window, cx)),
            (Field::Timeout, input(d.timeout, "each Check's own limit", window, cx)),
            (Field::Proxy, input(d.proxy, "http://proxy.example:3128", window, cx)),
        ];
        inputs[0].1.update(cx, |i, cx| i.focus(window, cx));
        SettingsPane {
            inputs,
            notifications: current.notifications,
            check_updates: current.check_updates,
            can_update,
            errors: vec![],
            save_error: None,
            file_problem,
            path,
            save_focus: cx.focus_handle().tab_stop(true),
            cancel_focus: cx.focus_handle().tab_stop(true),
        }
    }

    pub fn set_save_error(&mut self, message: String, cx: &mut Context<Self>) {
        self.save_error = Some(message);
        cx.notify();
    }

    fn text(&self, field: Field, cx: &App) -> String {
        self.inputs.iter().find(|(f, _)| *f == field).map(|(_, i)| i.read(cx).value().to_string()).unwrap_or_default()
    }

    fn save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let draft = Draft {
            resolvers: split_list(&self.text(Field::Resolvers, cx)),
            selectors: split_list(&self.text(Field::Selectors, cx)),
            timeout: self.text(Field::Timeout, cx),
            proxy: self.text(Field::Proxy, cx),
            notifications: self.notifications,
            check_updates: self.check_updates,
        };
        match draft.validate() {
            Ok(settings) => {
                self.errors.clear();
                self.save_error = None;
                cx.emit(PaneEvent::Save(settings));
            }
            Err(errors) => {
                if let Some((_, first)) = self.inputs.iter().find(|(f, _)| errors.iter().any(|e| e.field == *f)) {
                    first.update(cx, |i, cx| i.focus(window, cx));
                }
                self.errors = errors;
                cx.notify();
            }
        }
    }

    fn field(&self, field: Field, help: &'static str, window: &Window, cx: &App) -> impl IntoElement {
        let state = self.inputs.iter().find(|(f, _)| *f == field).map(|(_, i)| i.clone());
        let Some(state) = state else { return div() };
        let focused = state.read(cx).focus_handle(cx).is_focused(window);
        let error = self.errors.iter().find(|e| e.field == field).map(|e| e.message.clone());
        let border = if error.is_some() {
            t::CRITICAL
        } else if focused {
            t::ACCENT
        } else {
            t::GRAY_600
        };
        div()
            .flex()
            .flex_col()
            .gap(px(4.))
            .child(div().text_size(px(t::TEXT_LABEL)).font_weight(FontWeight::MEDIUM).child(field.label()))
            .child(
                div()
                    .h(px(t::OMNIBOX_HEIGHT))
                    .flex()
                    .items_center()
                    .px(px(10.))
                    .bg(color(t::GRAY_100))
                    .border_1()
                    .border_color(color(border))
                    .when(focused, |s| s.shadow(vec![ring()]))
                    .rounded(px(t::RADIUS_SMALL))
                    .font_family(t::FONT_MONO)
                    .text_size(px(t::TEXT_LABEL))
                    .text_color(color(t::GRAY_1000))
                    .child(
                        div().flex_1().child(
                            Input::new(&state)
                                .appearance(false)
                                .bordered(false)
                                .focus_bordered(false)
                                .aria_label(field.label()),
                        ),
                    ),
            )
            .when_some(error, |s, message| {
                s.child(
                    div()
                        .id(field.label())
                        .text_size(px(t::TEXT_LABEL))
                        .text_color(color(t::CRITICAL))
                        .role(Role::Alert)
                        .aria_label(format!("{}: {message}", field.label()))
                        .child(message),
                )
            })
            .child(div().text_size(px(t::TEXT_CAPTION)).line_height(px(16.)).text_color(color(t::GRAY_900)).child(help))
    }

    fn button(
        &self,
        id: &'static str,
        label: &'static str,
        aria: &'static str,
        focus: &FocusHandle,
        cx: &mut Context<Self>,
        act: fn(&mut Self, &mut Window, &mut Context<Self>),
    ) -> impl IntoElement {
        div()
            .id(id)
            .track_focus(focus)
            .h(px(28.))
            .px(px(16.))
            .flex()
            .items_center()
            .rounded(px(t::RADIUS_SMALL))
            .border_1()
            .border_color(color(t::GRAY_500))
            .bg(color(t::GRAY_300))
            .text_size(px(t::TEXT_LABEL))
            .font_weight(FontWeight::MEDIUM)
            .cursor_pointer()
            .hover(|s| s.bg(color(t::GRAY_200)))
            .focus_visible(|mut s| {
                s.box_shadow = Some(vec![ring()]);
                s.border_color = Some(color(t::ACCENT).into());
                s
            })
            .role(Role::Button)
            .aria_label(aria)
            .on_click(cx.listener(move |this, _, window, cx| act(this, window, cx)))
            .on_key_down(cx.listener(move |this, ev: &KeyDownEvent, window, cx| {
                if matches!(ev.keystroke.key.as_str(), "enter" | "space") {
                    cx.stop_propagation();
                    act(this, window, cx);
                }
            }))
            .child(label)
    }
}

fn color(c: u32) -> Rgba {
    rgb(c)
}

fn ring() -> BoxShadow {
    BoxShadow {
        color: color(t::ACCENT).into(),
        offset: point(px(0.), px(0.)),
        blur_radius: px(0.),
        spread_radius: px(1.),
        inset: false,
    }
}

impl Render for SettingsPane {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let location = self
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "No home directory: settings cannot be saved".into());
        let notifications = self.notifications;
        let check_updates = self.check_updates;
        div()
            .absolute()
            .size_full()
            .flex()
            .justify_center()
            .items_start()
            .pt(px(32.))
            .pb(px(32.))
            .bg(rgba(0x00000066))
            .on_mouse_down(MouseButton::Left, cx.listener(|_, _, _, cx| cx.emit(PaneEvent::Close)))
            .child(
                div()
                    .id("settings-dialog")
                    .w(px(600.))
                    .max_h_full()
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap(px(16.))
                    .p(px(24.))
                    .bg(color(t::GRAY_100))
                    .border_1()
                    .border_color(color(t::GRAY_500))
                    .rounded(px(t::RADIUS_LARGE))
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .role(Role::Dialog)
                    .aria_label("Settings")
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(4.))
                            .child(div().text_size(px(20.)).line_height(px(28.)).font_weight(FontWeight::SEMIBOLD).child("Settings"))
                            .child(div().text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_900)).font_family(t::FONT_MONO).child(location)),
                    )
                    .when_some(self.file_problem.clone(), |s, problem| {
                        let text = format!("The settings file has an error, so these are the defaults: {problem}. The file is not changed until you save; saving keeps a copy as config.toml.bak.");
                        s.child(div().id("file-problem").text_size(px(t::TEXT_LABEL)).text_color(color(t::CRITICAL)).role(Role::Alert).aria_label(text.clone()).child(text))
                    })
                    .child(self.field(Field::Resolvers, RESOLVER_RULE, window, cx))
                    .child(self.field(Field::Selectors, "Tried in addition to the common selectors in the Email Check. At most 20, each a DNS label such as acme2024 or mail.k1.", window, cx))
                    .child(self.field(Field::Timeout, "Whole seconds from 1 to 120. Empty keeps each Check's own limit. Port scan, SMTP banner and Blacklist never get less than their own limit.", window, cx))
                    .child(self.field(Field::Proxy, PROXY_RULE, window, cx))
                    .child(
                        Checkbox::new("notifications")
                            .checked(notifications)
                            .label("Send a desktop notification when a Watch stops")
                            .accessibility_label("Send a desktop notification when a Watch stops")
                            .on_click(cx.listener(|this, checked: &bool, _, cx| {
                                this.notifications = *checked;
                                cx.notify();
                            })),
                    )
                    .when(self.can_update, |s| {
                        s.child(
                            Checkbox::new("check-updates")
                                .checked(check_updates)
                                .label("Check for updates once a day")
                                .accessibility_label("Check for updates once a day")
                                .on_click(cx.listener(|this, checked: &bool, _, cx| {
                                    this.check_updates = *checked;
                                    cx.notify();
                                })),
                        )
                        .child(div().text_size(px(t::TEXT_CAPTION)).line_height(px(16.)).text_color(color(t::GRAY_900)).child(UPDATE_RULE))
                    })
                    .child(div().text_size(px(t::TEXT_CAPTION)).line_height(px(16.)).text_color(color(t::GRAY_900)).child(APPLY_RULE))
                    .when_some(self.save_error.clone(), |s, e| s.child(div().id("save-error").text_size(px(t::TEXT_LABEL)).text_color(color(t::CRITICAL)).role(Role::Alert).aria_label(e.clone()).child(e)))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(self.button("settings-save", "Save", "Save settings", &self.save_focus.clone(), cx, |this, window, cx| this.save(window, cx)))
                            .child(self.button("settings-cancel", "Cancel", "Close settings without saving", &self.cancel_focus.clone(), cx, |_, _, cx| cx.emit(PaneEvent::Close)))
                            .child(div().text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child("Esc closes")),
                    ),
            )
    }
}
