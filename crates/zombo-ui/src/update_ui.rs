//! The update prompt: a card in the top right corner, never a modal, so a rep typing a target is not
//! interrupted. Buttons are tab stops, and Esc on any of them means Later.

use std::path::PathBuf;

use gpui_kit::prelude::*;
use gpui_kit::*;
use zombo_core::update::{self, Endpoints, Target, Version};
use zombo_ui::{
    config::{self, Dirs},
    theme as t,
    update_model::{self, Availability, Offer, Stage},
};

const BUTTONS: usize = 3;

pub struct UpdateCard {
    stage: Stage,
    target: Option<Target>,
    state_path: Option<PathBuf>,
    endpoints: Endpoints,
    focus: Vec<FocusHandle>,
    copied: bool,
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

impl UpdateCard {
    /// Starts the daily check in the background. Nothing here waits on the disk or the network.
    pub fn new(check_updates: bool, dirs: Option<&Dirs>, cx: &mut Context<Self>) -> Self {
        let version =
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|| Version::parse("0.0.0").expect("literal"));
        let endpoints = Endpoints::real(&version);
        let state_path = dirs.map(update_model::state_file);
        let (ep, v, path) = (endpoints.clone(), version.clone(), state_path.clone());
        cx.spawn(async move |this, cx| {
            let job = cx.background_executor().spawn(async move {
                let target = Target::detect(std::env::var_os("APPIMAGE").as_deref());
                let offer = path.and_then(|p| {
                    update_model::background_check(check_updates, target.as_ref(), &p, config::unix_now(), || {
                        update::check(&ep, &v)
                    })
                });
                (target, offer)
            });
            let (target, offer) = job.await;
            let _ = this.update(cx, |card, cx| {
                card.target = target;
                if let Some(offer) = offer {
                    card.stage = Stage::Prompt(offer);
                }
                cx.notify();
            });
        })
        .detach();
        UpdateCard {
            stage: Stage::Idle,
            target: None,
            state_path,
            endpoints,
            focus: (0..BUTTONS).map(|_| cx.focus_handle().tab_stop(true)).collect(),
            copied: false,
        }
    }

    pub fn availability(&self) -> Availability {
        update_model::availability(self.target.as_ref(), !cfg!(debug_assertions))
    }

    fn later(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.stage, Stage::Applying(_)) {
            self.stage = Stage::Idle;
            self.copied = false;
            cx.notify();
        }
    }

    fn skip(&mut self, cx: &mut Context<Self>) {
        if let (Some(offer), Some(path)) = (self.stage.offer(), &self.state_path) {
            let _ = update_model::skip(path, &offer.rel.version);
        }
        self.later(cx);
    }

    fn install(&mut self, cx: &mut Context<Self>) {
        let offer = match &self.stage {
            Stage::Prompt(o) | Stage::Failed(o, _) if o.can_install => o.clone(),
            _ => return,
        };
        let Some(target) = self.target.clone() else { return };
        self.stage = Stage::Applying(offer.clone());
        let ep = self.endpoints.clone();
        cx.spawn(async move |this, cx| {
            let rel = offer.rel.clone();
            let result = cx
                .background_executor()
                .spawn(async move { update::install(&ep, &rel, &target.path).map_err(|e| e.to_string()) })
                .await;
            let _ = this.update(cx, |card, cx| {
                card.stage = match result {
                    Ok(()) => Stage::Restart(offer),
                    Err(reason) => Stage::Failed(offer, reason),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn restart(&mut self, cx: &mut Context<Self>) {
        let (Stage::Restart(offer), Some(target)) = (&self.stage, &self.target) else { return };
        let error = update::restart(&target.path);
        self.stage = Stage::Failed(offer.clone(), format!("the new version is installed but did not start: {error}"));
        cx.notify();
    }

    fn copy(&mut self, text: String, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.copied = true;
        cx.notify();
    }

    fn button(
        &self,
        slot: usize,
        label: &'static str,
        aria: String,
        cx: &mut Context<Self>,
        act: fn(&mut Self, &mut Context<Self>),
    ) -> impl IntoElement {
        div()
            .id(("update-button", slot))
            .track_focus(&self.focus[slot])
            .h(px(28.))
            .px(px(12.))
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
            .on_click(cx.listener(move |this, _, _, cx| act(this, cx)))
            .on_key_down(cx.listener(move |this, ev: &KeyDownEvent, _, cx| {
                if matches!(ev.keystroke.key.as_str(), "enter" | "space") {
                    cx.stop_propagation();
                    act(this, cx);
                }
            }))
            .child(label)
    }

    fn body(&mut self, offer: &Offer, cx: &mut Context<Self>) -> (String, Vec<AnyElement>) {
        let v = &offer.rel.version;
        let name = format!("Zombo's Razor {v}");
        let mut buttons = vec![];
        let headline = match &self.stage {
            Stage::Prompt(_) if offer.can_install => {
                buttons.push(
                    self.button(0, "Update", format!("Update to {v} and restart"), cx, |c, cx| c.install(cx))
                        .into_any_element(),
                );
                format!("{name} is available. Update and restart?")
            }
            Stage::Prompt(_) => {
                let label = if self.copied { "Copied" } else { "Copy link" };
                buttons.push(
                    self.button(0, label, "Copy the release page address".into(), cx, |c, cx| {
                        if let Stage::Prompt(o) = &c.stage {
                            let url = o.rel.page_url.clone();
                            c.copy(url, cx);
                        }
                    })
                    .into_any_element(),
                );
                format!("{name} is available. Download the new version from {}", offer.rel.page_url)
            }
            Stage::Applying(_) => format!("Downloading and checking {name}..."),
            Stage::Restart(_) => {
                buttons.push(
                    self.button(0, "Restart", format!("Restart into {v}"), cx, |c, cx| c.restart(cx))
                        .into_any_element(),
                );
                format!("{name} is installed. Restart now?")
            }
            Stage::Failed(_, reason) => {
                if offer.can_install {
                    buttons.push(
                        self.button(0, "Try again", "Try the update again".into(), cx, |c, cx| c.install(cx))
                            .into_any_element(),
                    );
                }
                format!("The update did not install: {reason}. The current version is untouched.")
            }
            Stage::Idle => String::new(),
        };
        if !matches!(self.stage, Stage::Applying(_)) {
            buttons
                .push(self.button(1, "Later", "Ask again tomorrow".into(), cx, |c, cx| c.later(cx)).into_any_element());
        }
        if matches!(self.stage, Stage::Prompt(_)) {
            buttons.push(
                self.button(2, "Skip this version", format!("Skip version {v}"), cx, |c, cx| c.skip(cx))
                    .into_any_element(),
            );
        }
        (headline, buttons)
    }
}

impl Render for UpdateCard {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(offer) = self.stage.offer().cloned() else { return div().into_any_element() };
        let (headline, buttons) = self.body(&offer, cx);
        let notes = matches!(self.stage, Stage::Prompt(_)).then(|| offer.rel.notes.clone()).filter(|n| !n.is_empty());
        div()
            .id("update-card")
            .absolute()
            .top(px(t::TITLE_BAR_HEIGHT + 8.))
            .right(px(16.))
            .w(px(420.))
            .flex()
            .flex_col()
            .gap(px(8.))
            .p(px(12.))
            .bg(color(t::GRAY_100))
            .border_1()
            .border_color(color(t::GRAY_500))
            .rounded(px(t::RADIUS_LARGE))
            .text_size(px(t::TEXT_LABEL))
            .role(Role::Dialog)
            .aria_label(headline.clone())
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, _, cx| {
                if ev.keystroke.key == "escape" {
                    cx.stop_propagation();
                    this.later(cx);
                }
            }))
            .child(div().font_weight(FontWeight::MEDIUM).child(headline))
            .when_some(notes, |s, n| {
                s.child(
                    div().text_size(px(t::TEXT_CAPTION)).line_height(px(16.)).text_color(color(t::GRAY_900)).child(n),
                )
            })
            .child(div().flex().items_center().gap(px(8.)).children(buttons))
            .into_any_element()
    }
}
