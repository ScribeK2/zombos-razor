//! The Evidence tab: paste pane, rail and result sections. The pasted text lives in the text
//! area entity in `Shell::pastes` and nowhere else, and it is dropped with its tab.

use std::time::SystemTime;

use gpui_kit::component::input::{InputEvent, Textarea};

use super::*;
use ev::{Kind, Stage};

const ANALYSIS_DEADLINE: Duration = Duration::from_secs(20);
const PASTE_HEIGHT: f32 = 320.;
const KEY_WIDTH: f32 = 240.;

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn button(id: &'static str, label: &str, hint: Option<&str>, primary: bool) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(28.))
        .px(px(12.))
        .flex()
        .items_center()
        .gap(px(8.))
        .border_1()
        .border_color(color(if primary { t::ACCENT } else { t::GRAY_500 }))
        .rounded(px(t::RADIUS_SMALL))
        .bg(color(t::GRAY_100))
        .text_size(px(t::TEXT_LABEL))
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .hover(|s| s.bg(color(t::GRAY_200)))
        .active(|s| s.bg(color(t::GRAY_300)))
        .focus_visible(focus_ring)
        .role(Role::Button)
        .aria_label(label.to_string())
        .child(label.to_string())
        .when_some(hint, |s, h| s.child(kbd(h)))
}

fn value_color(key: &str, value: &str) -> u32 {
    if !matches!(key, "SPF" | "DKIM" | "DMARC" | "Composite authentication") {
        return t::GRAY_1000;
    }
    match value {
        "pass" => t::OK,
        "fail" | "permerror" => t::CRITICAL,
        "softfail" | "temperror" | "policy" => t::WARNING,
        _ => t::GRAY_1000,
    }
}

impl Shell {
    pub(super) fn open_evidence(&mut self, kind: Kind, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.ws.open_evidence(kind, unix_secs());
        let state = cx.new(|cx| TextareaState::new(window, cx).placeholder("Paste here with Ctrl+V"));
        cx.subscribe_in(&state, window, move |this, state, ev: &InputEvent, window, cx| {
            match ev {
                InputEvent::Change => this.refresh_suggestion(id, state, cx),
                // The text area binds Ctrl+Enter itself, ahead of the window's key handler.
                InputEvent::PressEnter { secondary: true, .. } => {
                    this.analyse_pasted(window, cx);
                    cx.notify();
                }
                _ => {}
            }
        })
        .detach();
        state.update(cx, |s, cx| s.focus(window, cx));
        self.pastes.insert(id, state);
        self.error = None;
        self.set_omnibox("", window, cx);
    }

    fn refresh_suggestion(&mut self, id: u64, state: &Entity<TextareaState>, cx: &mut Context<Self>) {
        let text = state.read(cx).value();
        if let Some(tab) = self.ws.evidence_mut_for(id) {
            tab.suggest(&text);
            tab.notice = None;
        }
        cx.notify();
    }

    pub(super) fn drop_closed_pastes(&mut self) {
        let alive: HashSet<u64> = self.ws.tabs.iter().filter_map(Slot::evidence).map(|e| e.id).collect();
        self.pastes.retain(|id, _| alive.contains(id));
    }

    pub(super) fn analyse_pasted(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(tab) = self.ws.current_evidence() else { return };
        let (id, kind) = (tab.id, tab.kind);
        if !matches!(tab.stage, Stage::Paste) {
            return;
        }
        let Some(state) = self.pastes.get(&id) else { return };
        let text = state.read(cx).value().to_string();
        let notice = if text.trim().is_empty() { Some("Paste some text first.".to_string()) } else { ev::check_size(text.len()).err() };
        if let (Some(n), Some(tab)) = (notice, self.ws.evidence_mut_for(id)) {
            tab.notice = Some(n);
            return;
        }
        if let Some(tab) = self.ws.evidence_mut_for(id) {
            tab.stage = Stage::Analysing;
            tab.notice = None;
        }
        let mut rx = runtime::stream(move |tx| async move {
            let job = tokio::task::spawn_blocking(move || ev::analyse(kind, &text));
            let result = match tokio::time::timeout(ANALYSIS_DEADLINE, job).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => Err("The analysis stopped unexpectedly. Try a smaller part of the text.".to_string()),
                Err(_) => Err("The analysis took too long and was given up. Try a smaller part of the text.".to_string()),
            };
            let _ = tx.send(result);
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Some(result) = rx.recv().await {
                this.update_in(cx, |app, window, cx| app.finish_analysis(id, result, window, cx)).ok();
            }
        })
        .detach();
    }

    fn finish_analysis(&mut self, id: u64, result: Result<ev::Report, String>, window: &mut Window, cx: &mut Context<Self>) {
        let Some(tab) = self.ws.evidence_mut_for(id) else { return };
        match result {
            Ok(report) => {
                tab.section = ev::sections(tab.kind)[0];
                tab.stage = Stage::Done(Box::new(report));
                self.pastes.remove(&id);
                window.focus(&self.root_focus, cx);
            }
            Err(message) => {
                tab.stage = Stage::Paste;
                tab.notice = Some(message);
            }
        }
        cx.notify();
    }

    pub(super) fn copy_evidence(&mut self, all: bool, cx: &mut Context<Self>) {
        let Some(tab) = self.ws.current_evidence() else {
            self.toast = Some(("Copying as Markdown works on Evidence tabs for now.".into(), Instant::now()));
            return;
        };
        let text = match (all, tab.report()) {
            (_, None) => None,
            (true, Some(_)) => ev::evidence_markdown(tab),
            (false, Some(r)) => Some(ev::section_markdown(r, tab.section)),
        };
        let message = match (&text, all) {
            (None, _) => "Nothing to copy yet. Analyse the pasted text first.".to_string(),
            (Some(_), true) => "Copied the whole Evidence as Markdown.".to_string(),
            (Some(_), false) => format!("Copied the {} section as Markdown.", tab.section.label()),
        };
        if let Some(text) = text {
            cx.write_to_clipboard(ClipboardItem::new_string(text));
        }
        self.toast = Some((message, Instant::now()));
    }

    pub(super) fn evidence_rail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(tab) = self.ws.current_evidence() else { return div().id("none") };
        let items = ev::sections(tab.kind).iter().enumerate().map(|(i, &section)| {
            let state = tab.state(section);
            let selected = tab.section == section;
            div()
                .id(("ev-rail", i))
                .track_focus(&self.rail_focus[i])
                .h(px(t::RAIL_ITEM_HEIGHT))
                .px(px(8.))
                .flex()
                .items_center()
                .gap(px(8.))
                .rounded(px(t::RADIUS_SMALL))
                .border_1()
                .border_color(color(t::BG_200))
                .text_size(px(t::TEXT_BODY))
                .text_color(color(if selected { t::GRAY_1000 } else { t::GRAY_900 }))
                .when(selected, |s| s.bg(color(t::GRAY_300)))
                .hover(|s| s.bg(color(t::GRAY_200)))
                .focus_visible(focus_ring)
                .cursor_pointer()
                .role(Role::Tab)
                .aria_selected(selected)
                .aria_label(format!("{}: {}", section.label(), state.label()))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.ws.jump(i);
                    cx.notify();
                }))
                .on_key_down(cx.listener(move |this, ev: &KeyDownEvent, _, cx| {
                    if matches!(ev.keystroke.key.as_str(), "enter" | "space") {
                        this.ws.jump(i);
                        cx.notify();
                    }
                }))
                .child(glyph(state.glyph(), 16.))
                .child(div().flex_1().child(section.label()))
                .child(div().max_w(px(132.)).truncate().text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_900)).child(state.label()))
        });
        div()
            .id("ev-rail")
            .w(px(t::RAIL_WIDTH))
            .flex_none()
            .flex()
            .flex_col()
            .gap(px(2.))
            .p(px(8.))
            .bg(color(t::BG_200))
            .role(Role::TabList)
            .aria_label("Evidence sections")
            .child(div().px(px(8.)).pt(px(4.)).pb(px(4.)).text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child(tab.kind.label().to_uppercase()))
            .children(items)
    }

    pub(super) fn evidence_pane(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(tab) = self.ws.current_evidence() else { return div().id("none") };
        let body = match tab.report() {
            Some(report) => self.evidence_results(tab, report, cx).into_any_element(),
            None => self.paste_pane(tab, cx).into_any_element(),
        };
        div()
            .id("ev-pane")
            .flex_1()
            .min_w_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(16.))
            .px(px(24.))
            .py(px(t::PANE_PADDING))
            .role(Role::Main)
            .aria_label(format!("{} evidence", tab.kind.label()))
            .child(body)
    }

    fn paste_pane(&self, tab: &ev::EvidenceTab, cx: &mut Context<Self>) -> Div {
        let id = tab.id;
        let Some(state) = self.pastes.get(&id) else { return div() };
        let bytes = state.read(cx).text().len();
        let analysing = matches!(tab.stage, Stage::Analysing);
        let weak = cx.entity().downgrade();
        let paste_state = state.clone();
        let on_paste = move |item: &ClipboardItem, window: &mut Window, cx: &mut gpui_kit::App| -> bool {
            let Some(text) = item.text() else { return false };
            let total = paste_state.read(cx).text().len() + text.len();
            if let Err(message) = ev::check_size(total) {
                weak.update(cx, |app, cx| {
                    if let Some(tab) = app.ws.evidence_mut_for(id) {
                        tab.notice = Some(message);
                    }
                    cx.notify();
                })
                .ok();
                return true;
            }
            paste_state.update(cx, |s, cx| s.replace(ev::display_text(&text), window, cx));
            let all = paste_state.read(cx).value();
            weak.update(cx, |app, cx| {
                if let Some(tab) = app.ws.evidence_mut_for(id) {
                    tab.suggest(&all);
                    tab.notice = None;
                }
                cx.notify();
            })
            .ok();
            true
        };
        let hint = match (tab.suggested, bytes) {
            (_, 0) => format!("Paste {}, then press Ctrl+Enter.", tab.kind.noun()),
            (Some(s), _) if s == tab.kind => format!("This looks like {}.", s.noun()),
            (Some(s), _) => format!("This looks like {}. You chose {}.", s.noun(), tab.kind.noun()),
            (None, _) => "I cannot tell what this is. Choose a kind below.".to_string(),
        };
        let kinds = div().id("ev-kinds").flex().gap(px(4.)).role(Role::TabList).aria_label("Kind of evidence").children(Kind::ALL.iter().enumerate().map(|(i, &kind)| {
            let on = kind == tab.kind;
            div()
                .id(("ev-kind", i))
                .h(px(28.))
                .px(px(10.))
                .flex()
                .items_center()
                .rounded(px(t::RADIUS_SMALL))
                .border_1()
                .border_color(color(if on { t::ACCENT } else { t::GRAY_400 }))
                .bg(color(if on { t::GRAY_300 } else { t::GRAY_100 }))
                .text_color(color(if on { t::GRAY_1000 } else { t::GRAY_900 }))
                .text_size(px(t::TEXT_LABEL))
                .cursor_pointer()
                .hover(|s| s.bg(color(t::GRAY_200)))
                .focus_visible(focus_ring)
                .role(Role::Tab)
                .aria_selected(on)
                .aria_label(format!("Analyse as {}", kind.noun()))
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(tab) = this.ws.evidence_mut_for(id) {
                        tab.choose(kind);
                    }
                    cx.notify();
                }))
                .child(kind.label())
        }));
        div()
            .w_full()
            .max_w(px(900.))
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().text_size(px(t::TEXT_VERDICT)).line_height(px(36.)).font_weight(FontWeight::SEMIBOLD).child(format!("Analyse pasted {}", tab.kind.label().to_lowercase())))
            .child(
                div()
                    .text_size(px(t::TEXT_BODY))
                    .text_color(color(t::GRAY_900))
                    .child("The text stays in memory. It is never saved and is dropped when you close this tab."),
            )
            .child(
                div()
                    .w_full()
                    .font_family(t::FONT_MONO)
                    .text_size(px(t::TEXT_LABEL))
                    .child(Textarea::new(state).h(px(PASTE_HEIGHT)).aria_label("Pasted text to analyse").on_paste(on_paste)),
            )
            .child(div().id("ev-hint").role(Role::Status).aria_label(hint.clone()).text_size(px(t::TEXT_LABEL)).text_color(color(t::GRAY_900)).child(hint))
            .when_some(tab.notice.clone(), |s, n| {
                s.child(
                    div()
                        .id("ev-notice")
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .text_size(px(t::TEXT_BODY))
                        .text_color(color(t::CRITICAL))
                        .role(Role::Alert)
                        .aria_label(n.clone())
                        .child(glyph(Glyph::Octagon, 16.))
                        .child(div().flex_1().min_w_0().child(n)),
                )
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(12.))
                    .child(kinds)
                    .child(button("ev-analyse", if analysing { "Analysing" } else { "Analyse" }, Some("Ctrl Enter"), true).on_click(cx.listener(|this, _, window, cx| {
                        this.analyse_pasted(window, cx);
                        cx.notify();
                    })))
                    .child(div().text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child(format!("{} KiB of 1 MiB", bytes.div_ceil(1024)))),
            )
    }

    fn evidence_results(&self, tab: &ev::EvidenceTab, report: &ev::Report, cx: &mut Context<Self>) -> Div {
        let section = tab.section;
        let v = ev::view(report, section);
        let finding_views = v.findings.iter().enumerate().map(|(i, f)| self.finding_card(i, f));
        let copy = |id: &'static str, label: &'static str, hint: &'static str, all: bool, cx: &mut Context<Self>| {
            button(id, label, Some(hint), false).on_click(cx.listener(move |this, _, _, cx| {
                this.copy_evidence(all, cx);
                cx.notify();
            }))
        };
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(
                div()
                    .id("ev-verdict")
                    .w_full()
                    .min_w_0()
                    .flex()
                    .flex_wrap()
                    .justify_between()
                    .items_end()
                    .gap_x(px(24.))
                    .gap_y(px(8.))
                    .role(Role::Group)
                    .aria_label(format!("{}: {}. {}", section.label(), v.word, v.why))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(280.))
                            .flex()
                            .flex_col()
                            .child(div().flex().items_center().gap(px(12.)).text_size(px(t::TEXT_VERDICT)).line_height(px(36.)).font_weight(FontWeight::SEMIBOLD).child(glyph(v.glyph, 24.)).child(v.word.clone()))
                            .child(div().max_w(px(640.)).text_size(px(t::TEXT_BODY)).line_height(px(20.)).text_color(color(t::GRAY_900)).child(v.why.clone())),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .gap(px(8.))
                            .child(copy("ev-copy-section", "Copy section", "Ctrl Shift C", false, cx))
                            .child(copy("ev-copy-all", "Copy all", "Ctrl Alt C", true, cx)),
                    ),
            )
            .when(!v.findings.is_empty(), |s| {
                s.child(div().id("ev-findings").w_full().min_w_0().flex().flex_col().gap(px(t::FINDING_GAP)).role(Role::List).aria_label("Findings").children(finding_views))
            })
            .when(!v.rows.is_empty(), |s| {
                s.child(self.evidence_rows("ev-table", &format!("{} data", section.label()), &v.rows, cx).bg(color(t::GRAY_100)))
            })
            .children(v.disclosures.iter().map(|d| self.evidence_disclosure(d, cx)))
    }

    fn evidence_rows(&self, id: &'static str, title: &str, rows: &[zombo_ui::outcome::Fact], cx: &mut Context<Self>) -> Stateful<Div> {
        div()
            .id(id)
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .border_1()
            .border_color(color(t::GRAY_400))
            .rounded(px(t::RADIUS_SMALL))
            .overflow_hidden()
            .role(Role::Table)
            .aria_label(title.to_string())
            .children(rows.iter().enumerate().map(|(i, f)| {
                let value = f.value.clone();
                div()
                    .id((id, i))
                    .min_h(px(t::ROW_HEIGHT))
                    .px(px(12.))
                    .py(px(4.))
                    .flex()
                    .gap(px(12.))
                    .when(i > 0, |s| s.border_t_1().border_color(color(t::GRAY_400)))
                    .text_size(px(t::TEXT_LABEL))
                    .cursor_pointer()
                    .hover(|s| s.bg(color(t::GRAY_200)))
                    .role(Role::Row)
                    .aria_label(format!("{}: {}. Click to copy the value.", f.key.trim(), f.value))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(value.clone()));
                        this.toast = Some(("Copied the value.".into(), Instant::now()));
                        cx.notify();
                    }))
                    .child(div().w(px(KEY_WIDTH)).flex_none().text_color(color(t::GRAY_900)).child(f.key.clone()))
                    .child(div().flex_1().min_w_0().font_family(t::FONT_MONO).text_color(color(value_color(&f.key, &f.value))).child(f.value.clone()))
            }))
    }

    fn evidence_disclosure(&self, d: &ev::Disclosure, cx: &mut Context<Self>) -> Div {
        let open = self.open.contains(d.id);
        let id = d.id;
        let n = d.rows.len();
        let summary = format!("{n} {}", if n == 1 { "line" } else { "lines" });
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap(px(8.))
            .child(
                div()
                    .id((id, 9999usize))
                    .h(px(32.))
                    .px(px(12.))
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .bg(color(t::GRAY_100))
                    .border_1()
                    .border_color(color(t::GRAY_400))
                    .rounded(px(t::RADIUS_SMALL))
                    .cursor_pointer()
                    .hover(|s| s.bg(color(t::GRAY_200)))
                    .focus_visible(focus_ring)
                    .role(Role::Button)
                    .aria_expanded(open)
                    .aria_label(format!("{}, {summary}", d.title))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if !this.open.remove(id) {
                            this.open.insert(id);
                        }
                        cx.notify();
                    }))
                    .child(icon("icons/chevron.svg", 12., t::GRAY_800).when(open, |s| s.with_transformation(Transformation::rotate(radians(std::f32::consts::FRAC_PI_2)))))
                    .child(div().text_size(px(t::TEXT_LABEL)).font_weight(FontWeight::SEMIBOLD).child(d.title.clone()))
                    .child(div().text_size(px(t::TEXT_LABEL)).text_color(color(t::GRAY_900)).child(summary)),
            )
            .when(open, |s| s.child(self.evidence_rows(id, &d.title, &d.rows, cx).bg(color(t::GRAY_100))))
    }
}
