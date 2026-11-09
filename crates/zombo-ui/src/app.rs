use std::{collections::HashSet, time::{Duration, Instant}};

use gpui_kit::component::input::{Input, InputState};
use gpui_kit::prelude::*;
use gpui_kit::*;
use zombo_ui::{
    checks, diagnosis as dg,
    keys::{self, Action, Mode, Press},
    ondemand,
    outcome::{CheckEvent, Fact},
    record::RecordKind,
    runtime,
    section::Section,
    status::Glyph,
    theme as t,
    watch::Watches,
    workspace::{Workspace, relative},
};
use zombo_core::Severity;

const FINDING_HANDLES: usize = 64;
const TOAST_FOR: Duration = Duration::from_secs(8);

pub struct Shell {
    ws: Workspace,
    input: Entity<InputState>,
    root_focus: FocusHandle,
    pane_focus: FocusHandle,
    rail_focus: Vec<FocusHandle>,
    finding_focus: Vec<FocusHandle>,
    palette: Option<usize>,
    open: HashSet<&'static str>,
    watches: Watches,
    toast: Option<(String, Instant)>,
    sheet: bool,
    error: Option<String>,
    started: Instant,
    rendered: bool,
}

fn color(c: u32) -> Rgba {
    rgb(c)
}

fn glyph_color(g: Glyph) -> u32 {
    match g {
        Glyph::Check => t::OK,
        Glyph::Info => t::INFO,
        Glyph::Triangle => t::WARNING,
        Glyph::Octagon => t::CRITICAL,
        Glyph::Clock => t::WARNING,
        Glyph::Ring | Glyph::Dashed => t::GRAY_800,
    }
}

fn severity_color(s: Severity) -> u32 {
    glyph_color(dg::severity_glyph(s))
}

fn icon(path: &'static str, size: f32, c: u32) -> Svg {
    svg().path(path).size(px(size)).flex_none().text_color(color(c))
}

fn glyph(g: Glyph, size: f32) -> Svg {
    icon(g.asset(), size, glyph_color(g))
}

fn ring_shadow() -> Vec<BoxShadow> {
    vec![BoxShadow {
        color: color(t::ACCENT).into(),
        offset: point(px(0.), px(0.)),
        blur_radius: px(0.),
        spread_radius: px(1.),
        inset: false,
    }]
}

fn focus_ring(mut s: StyleRefinement) -> StyleRefinement {
    s.box_shadow = Some(ring_shadow());
    s.border_color = Some(color(t::ACCENT).into());
    s
}

fn kbd(text: &str) -> Div {
    div()
        .px(px(5.))
        .h(px(16.))
        .flex()
        .items_center()
        .rounded(px(4.))
        .border_1()
        .border_color(color(t::GRAY_500))
        .text_color(color(t::GRAY_900))
        .font_family(t::FONT_MONO)
        .text_size(px(11.))
        .child(text.to_string())
}

impl Shell {
    pub fn new(started: Instant, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("domain, host, IP or email"));
        input.update(cx, |i, cx| i.focus(window, cx));
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |app, cx| app.tick(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        Shell {
            ws: Workspace::default(),
            input,
            root_focus: cx.focus_handle(),
            pane_focus: cx.focus_handle(),
            rail_focus: Section::ALL.iter().map(|_| cx.focus_handle().tab_stop(true)).collect(),
            finding_focus: (0..FINDING_HANDLES).map(|_| cx.focus_handle().tab_stop(true)).collect(),
            palette: None,
            open: HashSet::new(),
            watches: Watches::default(),
            toast: None,
            sheet: false,
            error: None,
            started,
            rendered: false,
        }
    }

    fn mode(&self, window: &Window, cx: &gpui_kit::App) -> Mode {
        if self.palette.is_some() {
            Mode::Palette
        } else if self.sheet {
            Mode::Sheet
        } else if self.input.read(cx).focus_handle(cx).is_focused(window) {
            Mode::Omnibox
        } else {
            Mode::Browse
        }
    }

    fn typed(&self, cx: &gpui_kit::App) -> String {
        self.input.read(cx).value().to_string()
    }

    fn set_omnibox(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        let text = text.to_string();
        self.input.update(cx, |i, cx| i.set_value(text, window, cx));
    }

    fn sync_omnibox(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.ws.current().map(|t| t.target.value.clone()).unwrap_or_default();
        self.set_omnibox(&text, window, cx);
    }

    fn focus_omnibox(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.input.update(cx, |i, cx| i.focus(window, cx));
    }

    fn start_section(&mut self, section: Section, cx: &mut Context<Self>) {
        let Some(key) = self.ws.current().map(|t| t.target.value.clone()) else { return };
        self.start_section_for(&key, section, cx);
    }

    fn start_section_for(&mut self, key: &str, section: Section, cx: &mut Context<Self>) {
        let Some(tab) = self.ws.tabs.iter().find(|t| t.target.value == key) else { return };
        if tab.state(section) == zombo_ui::status::CheckState::Running || !checks::wired(section) {
            return;
        }
        if section.is_on_demand() && !ondemand::runnable(tab.target.kind, section) {
            return;
        }
        let key = key.to_string();
        let Some(name) = checks::name_for(section, &tab.target) else { return };
        if section == Section::Dns {
            let mut rx = runtime::stream(move |tx| checks::run_propagation(name, tx));
            cx.spawn(async move |this, cx| {
                while let Some(event) = rx.recv().await {
                    let key = key.clone();
                    if this
                        .update(cx, |app, cx| {
                            if let Some(tab) = app.ws.tabs.iter_mut().find(|t| t.target.value == key) {
                                tab.propagation.apply(&key, event);
                                cx.notify();
                            }
                            app.after_run(&key, Section::Dns);
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .detach();
            return;
        }
        if let Some(tab) = self.ws.tabs.iter_mut().find(|t| t.target.value == key) {
            tab.run_mut(section).apply(CheckEvent::Started);
        }
        let mut rx = runtime::stream(move |tx| checks::run_section(section, name, tx));
        cx.spawn(async move |this, cx| {
            while let Some(event) = rx.recv().await {
                let key = key.clone();
                if this
                    .update(cx, |app, cx| {
                        if let Some(tab) = app.ws.tabs.iter_mut().find(|t| t.target.value == key) {
                            tab.run_mut(section).apply(event);
                            cx.notify();
                        }
                        app.after_run(&key, section);
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    fn after_run(&mut self, key: &str, section: Section) {
        let Some(settled) = self.ws.tabs.iter().find(|t| t.target.value == key).and_then(|t| t.settled(section)) else { return };
        let now = Instant::now();
        if let Some(stopped) = self.watches.finished(key, section, settled.as_deref(), now) {
            self.toast = Some((stopped.message(), now));
        }
    }

    fn tick(&mut self, cx: &mut Context<Self>) {
        let now = Instant::now();
        let alive: Vec<String> = self.ws.tabs.iter().map(|t| t.target.value.clone()).collect();
        self.watches.keep_targets(|t| alive.iter().any(|a| a == t));
        for (target, section) in self.watches.due(now) {
            self.start_section_for(&target, section, cx);
        }
        if self.toast.as_ref().is_some_and(|(_, at)| now.duration_since(*at) > TOAST_FOR) {
            self.toast = None;
        }
        if !self.watches.is_empty() || self.toast.is_some() {
            cx.notify();
        }
    }

    fn toggle_watch(&mut self) {
        let Some(tab) = self.ws.current() else { return };
        let (target, section) = (tab.target.value.clone(), tab.section);
        if section == Section::Summary || !checks::wired(section) {
            return;
        }
        if self.watches.is_watching(&target, section) {
            self.watches.stop(&target, section);
        } else {
            self.watches.start(&target, section, tab.records(section), Instant::now());
        }
    }

    fn start_automatic(&mut self, cx: &mut Context<Self>) {
        let Some(kind) = self.ws.current().map(|t| t.target.kind) else { return };
        for &section in checks::automatic(kind) {
            self.start_section(section, cx);
        }
    }

    fn perform(&mut self, action: Action, window: &mut Window, cx: &mut Context<Self>) {
        match action {
            Action::FocusOmnibox => self.focus_omnibox(window, cx),
            Action::Submit => {
                if let Some(selected) = self.palette.take() {
                    let entries = keys::entries();
                    if let Some(e) = entries.get(selected) {
                        self.perform(e.action, window, cx);
                    }
                } else {
                    let typed = self.typed(cx);
                    match self.ws.submit(&typed, Instant::now()) {
                        Ok(_) => {
                            self.error = None;
                            self.sync_omnibox(window, cx);
                            self.start_automatic(cx);
                            window.focus(&self.root_focus, cx);
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
            }
            Action::Palette => self.palette = if self.palette.is_some() { None } else { Some(0) },
            Action::Rerun => {
                match self.ws.current().map(|t| t.section) {
                    Some(Section::Summary) => self.start_automatic(cx),
                    Some(section) => self.start_section(section, cx),
                    None => {}
                }
            }
            Action::Run(section) => match self.ws.current().map(|t| t.target.kind) {
                None => self.toast = Some(("Enter a target first, then run this Check.".into(), Instant::now())),
                Some(kind) if !ondemand::runnable(kind, section) => {
                    self.toast = Some((format!("The {} Check does not apply to this target.", section.label()), Instant::now()))
                }
                Some(_) => {
                    self.ws.jump(section.index());
                    self.start_section(section, cx);
                }
            },
            Action::ToggleWatch => self.toggle_watch(),
            Action::NextRecord | Action::PrevRecord => {
                if self.ws.current().is_some_and(|t| t.section == Section::Dns) {
                    self.ws.step_record(if action == Action::NextRecord { 1 } else { -1 });
                }
            }
            Action::Jump(n) => self.ws.jump(n),
            Action::PrevSection => self.ws.step_section(-1),
            Action::NextSection => self.ws.step_section(1),
            Action::NewTab => {
                self.ws.new_tab();
                self.error = None;
                self.set_omnibox("", window, cx);
                self.focus_omnibox(window, cx);
            }
            Action::CloseTab => {
                self.ws.close_active();
                self.sync_omnibox(window, cx);
                if self.ws.is_empty_state() {
                    self.focus_omnibox(window, cx);
                }
            }
            Action::NextTab | Action::PrevTab => {
                self.ws.step_tab(if action == Action::NextTab { 1 } else { -1 });
                self.sync_omnibox(window, cx);
            }
            Action::Cheatsheet => self.sheet = !self.sheet,
            Action::Dismiss => {
                if self.palette.is_some() || self.sheet {
                    self.palette = None;
                    self.sheet = false;
                } else {
                    window.focus(&self.root_focus, cx);
                }
            }
            Action::MoveUp | Action::MoveDown => {
                let delta: isize = if action == Action::MoveUp { -1 } else { 1 };
                match self.palette {
                    Some(sel) => {
                        let n = keys::entries().len() as isize;
                        self.palette = Some((sel as isize + delta).clamp(0, n - 1) as usize);
                    }
                    None => self.ws.move_recent(delta),
                }
            }
        }
        cx.notify();
    }

    fn on_key(&mut self, ev: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        let k = &ev.keystroke;
        let press = Press { key: &k.key, ctrl: k.modifiers.control, alt: k.modifiers.alt, shift: k.modifiers.shift };
        let mode = self.mode(window, cx);
        if let Some(action) = keys::action_for(mode, self.ws.is_empty_state(), press) {
            cx.stop_propagation();
            self.perform(action, window, cx);
        }
    }

    fn title_bar(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.input.read(cx).focus_handle(cx).is_focused(window);
        let control = |id: &'static str, path: &'static str, label: &'static str| {
            div()
                .id(id)
                .size(px(28.))
                .flex()
                .items_center()
                .justify_center()
                .rounded(px(t::RADIUS_SMALL))
                .cursor_pointer()
                .hover(|s| s.bg(color(t::GRAY_200)))
                .active(|s| s.bg(color(t::GRAY_300)))
                .role(Role::Button)
                .aria_label(label)
                .child(icon(path, 16., t::GRAY_900))
        };
        div()
            .h(px(t::TITLE_BAR_HEIGHT))
            .flex_none()
            .flex()
            .items_center()
            .px(px(8.))
            .pl(px(16.))
            .bg(color(t::BG_200))
            .on_mouse_down(MouseButton::Left, |_, window, _| window.start_window_move())
            .child(
                div()
                    .w(px(220.))
                    .text_size(px(t::TEXT_LABEL))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(color(t::GRAY_900))
                    .child("Zombo's Razor"),
            )
            .child(
                div().flex_1().flex().justify_center().child(
                    div()
                        .w_full()
                        .max_w(px(640.))
                        .h(px(t::OMNIBOX_HEIGHT))
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .px(px(10.))
                        .bg(color(t::GRAY_100))
                        .border_1()
                        .border_color(color(if focused { t::ACCENT } else { t::GRAY_600 }))
                        .when(focused, |s| s.shadow(ring_shadow()))
                        .rounded(px(t::RADIUS_SMALL))
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .child(icon("icons/search.svg", 16., t::GRAY_600))
                        .child(
                            div()
                                .flex_1()
                                .font_family(t::FONT_MONO)
                                .text_size(px(t::TEXT_LABEL))
                                .text_color(color(t::GRAY_1000))
                                .child(Input::new(&self.input).appearance(false).bordered(false).focus_bordered(false).aria_label("Target: domain, host, IP or email")),
                        )
                        .child(kbd("Ctrl L"))
                        .child(kbd("Enter")),
                ),
            )
            .child(
                div()
                    .w(px(220.))
                    .flex()
                    .justify_end()
                    .gap(px(4.))
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child(control("min", "icons/minimize.svg", "Minimize").on_click(|_, window, _| window.minimize_window()))
                    .child(control("max", "icons/maximize.svg", "Maximize").on_click(|_, window, _| window.zoom_window()))
                    .child(control("close", "icons/close.svg", "Close").on_click(|_, _, cx| cx.quit())),
            )
    }

    fn tab_strip(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tabs = self.ws.tabs.iter().enumerate().map(|(i, tab)| {
            let active = self.ws.active == Some(i);
            div()
                .id(("tab", i))
                .h(px(28.))
                .px(px(12.))
                .flex()
                .items_center()
                .gap(px(8.))
                .rounded_t(px(t::RADIUS_SMALL))
                .cursor_pointer()
                .text_size(px(t::TEXT_LABEL))
                .font_family(t::FONT_MONO)
                .text_color(color(if active { t::GRAY_1000 } else { t::GRAY_900 }))
                .when(active, |s| s.bg(color(t::BG_100)).border_1().border_color(color(t::GRAY_400)).border_b_0())
                .hover(|s| s.bg(color(t::GRAY_200)))
                .role(Role::Tab)
                .aria_label(format!("Tab {} of {}: {}", i + 1, self.ws.tabs.len(), tab.target.value))
                .aria_selected(active)
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.ws.select_tab(i);
                    this.sync_omnibox(window, cx);
                    cx.notify();
                }))
                .child(tab.target.value.clone())
                .child(
                    div()
                        .id(("tab-close", i))
                        .size(px(16.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .role(Role::Button)
                        .aria_label(format!("Close tab {}", tab.target.value))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            cx.stop_propagation();
                            this.ws.select_tab(i);
                            this.perform(Action::CloseTab, window, cx);
                        }))
                        .child(icon("icons/close.svg", 12., t::GRAY_800)),
                )
        });
        div()
            .h(px(t::TAB_STRIP_HEIGHT))
            .flex_none()
            .flex()
            .items_end()
            .gap(px(2.))
            .px(px(8.))
            .bg(color(t::BG_200))
            .border_b_1()
            .border_color(color(t::GRAY_400))
            .children(tabs)
            .child(
                div()
                    .id("new-tab")
                    .h(px(28.))
                    .px(px(10.))
                    .flex()
                    .items_center()
                    .text_color(color(t::GRAY_800))
                    .cursor_pointer()
                    .role(Role::Button)
                    .aria_label("New tab")
                    .on_click(cx.listener(|this, _, window, cx| this.perform(Action::NewTab, window, cx)))
                    .child("+"),
            )
    }

    fn empty_state(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let rows = self.ws.recent.iter().enumerate().map(|(i, r)| {
            let selected = i == self.ws.recent_selected;
            let value = r.value.clone();
            div()
                .id(("recent", i))
                .h(px(t::ROW_HEIGHT))
                .px(px(12.))
                .flex()
                .items_center()
                .justify_between()
                .rounded(px(t::RADIUS_SMALL))
                .border_1()
                .border_color(color(if selected { t::ACCENT } else { t::BG_100 }))
                .when(selected, |s| s.bg(color(t::GRAY_200)))
                .cursor_pointer()
                .role(Role::ListItem)
                .aria_label(format!("Recent target {}, {}", r.value, relative(r.at.elapsed())))
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.set_omnibox(&value, window, cx);
                    this.perform(Action::Submit, window, cx);
                }))
                .child(div().font_family(t::FONT_MONO).text_size(px(t::TEXT_LABEL)).child(r.value.clone()))
                .child(div().text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_900)).child(relative(r.at.elapsed())))
        });
        let hints = [("Ctrl L", "focus the omnibox"), ("Enter", "run the Diagnosis"), ("Ctrl K", "command palette"), ("?", "shortcut cheat sheet")];
        div()
            .flex_1()
            .flex()
            .justify_center()
            .pt(px(72.))
            .child(
                div()
                    .w(px(520.))
                    .flex()
                    .flex_col()
                    .gap(px(24.))
                    .when_some(self.error.clone(), |s, e| {
                        s.child(
                            div()
                                .id("error")
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .text_size(px(t::TEXT_BODY))
                                .text_color(color(t::CRITICAL))
                                .role(Role::Alert)
                                .aria_label(e.clone())
                                .child(glyph(Glyph::Octagon, 16.))
                                .child(e),
                        )
                    })
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(4.))
                            .child(
                                div()
                                    .pb(px(4.))
                                    .text_size(px(t::TEXT_CAPTION))
                                    .text_color(color(t::GRAY_900))
                                    .child(if self.ws.recent.is_empty() { "NO RECENT TARGETS YET" } else { "RECENT" }),
                            )
                            .children(rows),
                    )
                    .child(div().flex().flex_col().gap(px(8.)).children(hints.map(|(k, text)| {
                        div()
                            .flex()
                            .items_center()
                            .gap(px(12.))
                            .text_size(px(t::TEXT_LABEL))
                            .text_color(color(t::GRAY_800))
                            .child(div().w(px(56.)).child(kbd(k)))
                            .child(text)
                    }))),
            )
    }

    fn rail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(tab) = self.ws.current() else { return div().id("none") };
        let heading = |text: &'static str| {
            div().px(px(8.)).pt(px(12.)).pb(px(4.)).text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child(text)
        };
        let items = Section::ALL.iter().enumerate().map(|(i, &section)| {
            let state = tab.state(section);
            let selected = tab.section == section;
            let g = state.glyph();
            let group = match i {
                1 => Some("CHECKS"),
                Section::FIRST_ON_DEMAND => Some("ON DEMAND"),
                _ => None,
            };
            let item = div()
                .id(("rail", i))
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
                .child(glyph(g, 16.))
                .child(div().flex_1().child(section.label()))
                .child(
                    div()
                        .max_w(px(132.))
                        .truncate()
                        .text_size(px(t::TEXT_CAPTION))
                        .text_color(color(t::GRAY_900))
                        .child(state.label()),
                );
            div().flex().flex_col().when_some(group, |s, g| s.child(heading(g))).child(item)
        });
        div()
            .id("rail")
            .w(px(t::RAIL_WIDTH))
            .flex_none()
            .flex()
            .flex_col()
            .gap(px(2.))
            .p(px(8.))
            .bg(color(t::BG_200))
            .role(Role::TabList)
            .aria_label("Sections")
            .children(items)
    }

    fn pane(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(tab) = self.ws.current() else { return div().id("none") };
        let section = tab.section;
        let verdict = tab.verdict(section);
        let state = tab.state(section);
        let findings = tab.findings(section);
        let counts = dg::counts(&findings);
        let show_chips = !findings.is_empty();
        let watchable = section != Section::Summary && checks::wired(section) && state != zombo_ui::status::CheckState::NotRun;
        let watching = self.watches.is_watching(&tab.target.value, section);
        let finding_views = findings.iter().enumerate().map(|(i, f)| {
            let c = severity_color(f.severity);
            let label = dg::finding_label(f);
            div()
                .id(("finding", i))
                .w_full()
                .min_w_0()
                .track_focus(&self.finding_focus[i.min(FINDING_HANDLES - 1)])
                .flex()
                .gap(px(12.))
                .items_start()
                .px(px(12.))
                .py(px(10.))
                .bg(color(t::GRAY_100))
                .border_1()
                .border_color(color(t::GRAY_400))
                .rounded(px(t::RADIUS_SMALL))
                .focus_visible(|s| focus_ring(s).bg(color(t::GRAY_200)))
                .role(Role::ListItem)
                .aria_label(label)
                .child(
                    div()
                        .w(px(96.))
                        .flex_none()
                        .flex()
                        .items_center()
                        .gap(px(6.))
                        .h(px(20.))
                        .text_size(px(t::TEXT_CAPTION))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(color(c))
                        .child(glyph(dg::severity_glyph(f.severity), 16.))
                        .child(dg::severity_word(f.severity).to_uppercase()),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap(px(2.))
                        .child(div().text_size(px(t::TEXT_BODY)).line_height(px(20.)).font_weight(FontWeight::MEDIUM).child(f.title.to_string()))
                        .when(!f.message.is_empty(), |s| {
                            s.child(div().text_size(px(t::TEXT_LABEL)).line_height(px(18.)).text_color(color(t::GRAY_900)).child(f.message.clone()))
                        })
                        .when_some(f.recommendation.clone(), |s, r| {
                            s.child(div().text_size(px(t::TEXT_LABEL)).line_height(px(18.)).text_color(color(t::GRAY_800)).child(r.to_string()))
                        }),
                )
        });
        let brief = ondemand::brief(section);
        let run_label = ondemand::run_label(section);
        let can_run = brief.is_some() && !state.can_retry() && state != zombo_ui::status::CheckState::Running;
        div()
            .id("pane")
            .track_focus(&self.pane_focus)
            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, window, cx| window.focus(&this.pane_focus, cx)))
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, window, cx| {
                let plain_enter = ev.keystroke.key == "enter" && !ev.keystroke.modifiers.modified();
                if let Some(section) = this.ws.current().map(|t| t.section).filter(|s| plain_enter && s.is_on_demand()) {
                    cx.stop_propagation();
                    this.perform(Action::Run(section), window, cx);
                }
            }))
            .flex_1()
            .min_w_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(16.))
            .px(px(24.))
            .py(px(t::PANE_PADDING))
            .role(Role::Main)
            .aria_label(format!("{} section", section.label()))
            .child(
                div()
                    .id("verdict")
                    .w_full()
                    .min_w_0()
                    .flex()
                    .flex_wrap()
                    .justify_between()
                    .items_end()
                    .gap_x(px(24.))
                    .gap_y(px(8.))
                    .role(Role::Group)
                    .aria_label(format!("Verdict: {}. {}", verdict.word, verdict.why))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(280.))
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(12.))
                                    .text_size(px(t::TEXT_VERDICT))
                                    .line_height(px(36.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(glyph(tab.verdict_glyph(section), 24.))
                                    .child(verdict.word.clone()),
                            )
                            .child(
                                div()
                                    .max_w(px(640.))
                                    .text_size(px(t::TEXT_BODY))
                                    .line_height(px(20.))
                                    .text_color(color(t::GRAY_900))
                                    .child(verdict.why.clone()),
                            ),
                    )
                    .child(div().flex().flex_none().items_center().gap(px(8.)).when(watchable, |s| s.child(self.watch_button(watching, cx))).when(show_chips, |s| {
                        s.child(div().flex().flex_none().gap(px(8.)).children(counts.map(|(sev, n)| {
                            div()
                                .id(("chip", dg::severity_rank(sev) as usize))
                                .flex()
                                .items_center()
                                .gap(px(6.))
                                .px(px(10.))
                                .py(px(2.))
                                .rounded(px(999.))
                                .border_1()
                                .border_color(color(t::GRAY_400))
                                .bg(color(t::GRAY_100))
                                .text_size(px(t::TEXT_LABEL))
                                .aria_label(format!("{n} {}", dg::severity_word(sev).to_lowercase()))
                                .child(glyph(dg::severity_glyph(sev), 16.))
                                .child(div().font_weight(FontWeight::SEMIBOLD).child(n.to_string()))
                                .child(dg::severity_word(sev).to_lowercase())
                        })))
                    })),
            )
            .when_some(brief, |s, b| {
                s.child(
                    div()
                        .id("on-demand")
                        .w_full()
                        .max_w(px(720.))
                        .flex()
                        .flex_col()
                        .gap(px(8.))
                        .p(px(16.))
                        .bg(color(t::GRAY_100))
                        .border_1()
                        .border_color(color(t::GRAY_400))
                        .rounded(px(t::RADIUS_SMALL))
                        .role(Role::Group)
                        .aria_label("What this Check will do")
                        .child(div().text_size(px(t::TEXT_BODY)).line_height(px(20.)).child(b.what))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(2.))
                                .child(div().text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child("SERVERS IT CONTACTS"))
                                .child(div().text_size(px(t::TEXT_LABEL)).line_height(px(18.)).text_color(color(t::GRAY_900)).child(b.contacts)),
                        )
                        .when_some(b.note, |s, n| s.child(div().text_size(px(t::TEXT_LABEL)).line_height(px(18.)).text_color(color(t::GRAY_800)).child(n)))
                        .when(can_run, |s| {
                            s.child(
                                div()
                                    .id("run")
                                    .h(px(28.))
                                    .px(px(12.))
                                    .flex()
                                    .items_center()
                                    .gap(px(8.))
                                    .self_start()
                                    .border_1()
                                    .border_color(color(t::ACCENT))
                                    .rounded(px(t::RADIUS_SMALL))
                                    .bg(color(t::GRAY_100))
                                    .text_size(px(t::TEXT_LABEL))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .cursor_pointer()
                                    .hover(|s| s.bg(color(t::GRAY_200)))
                                    .active(|s| s.bg(color(t::GRAY_300)))
                                    .focus_visible(focus_ring)
                                    .role(Role::Button)
                                    .aria_label(run_label.unwrap_or("Run this Check"))
                                    .on_click(cx.listener(move |this, _, window, cx| this.perform(Action::Run(section), window, cx)))
                                    .child(if state == zombo_ui::status::CheckState::NotRun { run_label.unwrap_or("Run") } else { "Run again" })
                                    .child(kbd("Enter")),
                            )
                        }),
                )
            })
            .when(state.can_retry(), |s| {
                s.child(
                    div()
                        .id("retry")
                        .w(px(120.))
                        .h(px(28.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .gap(px(6.))
                        .border_1()
                        .border_color(color(t::GRAY_500))
                        .rounded(px(t::RADIUS_SMALL))
                        .bg(color(t::GRAY_100))
                        .text_size(px(t::TEXT_CAPTION))
                        .cursor_pointer()
                        .hover(|s| s.bg(color(t::GRAY_200)))
                        .active(|s| s.bg(color(t::GRAY_300)))
                        .focus_visible(focus_ring)
                        .role(Role::Button)
                        .aria_label("Retry this Check")
                        .on_click(cx.listener(|this, _, window, cx| this.perform(Action::Rerun, window, cx)))
                        .child("Retry")
                        .child(kbd("Ctrl R")),
                )
            })
            .when(!findings.is_empty(), |s| {
                s.child(
                    div()
                        .id("findings")
                        .w_full()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap(px(t::FINDING_GAP))
                        .role(Role::List)
                        .aria_label("Findings")
                        .children(finding_views),
                )
            })
            .when(section == Section::Dns, |s| s.child(self.resolver_table(tab, cx)))
            .when(section != Section::Dns && section != Section::Summary, |s| s.child(self.facts(tab, section, cx)))
            .when_some(tab.history(section).and_then(|h| h.changes.clone()), |s, d| s.child(self.changes_view(d, cx)))
    }

    fn watch_button(&self, watching: bool, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("watch")
            .h(px(28.))
            .px(px(10.))
            .flex()
            .items_center()
            .gap(px(6.))
            .border_1()
            .border_color(color(if watching { t::ACCENT } else { t::GRAY_500 }))
            .rounded(px(t::RADIUS_SMALL))
            .bg(color(if watching { t::GRAY_300 } else { t::GRAY_100 }))
            .text_size(px(t::TEXT_CAPTION))
            .cursor_pointer()
            .hover(|s| s.bg(color(t::GRAY_200)))
            .active(|s| s.bg(color(t::GRAY_300)))
            .focus_visible(focus_ring)
            .role(Role::Button)
            .aria_label(if watching { "Stop watching this Check" } else { "Watch this Check until its answer changes" })
            .on_click(cx.listener(|this, _, _, cx| {
                this.toggle_watch();
                cx.notify();
            }))
            .child(if watching { "Watching" } else { "Watch" })
            .child(kbd("W"))
    }

    fn disclosure(&self, id: &'static str, title: String, summary: String, lines: Vec<(String, String, u32)>, cx: &mut Context<Self>) -> Div {
        let open = self.open.contains(id);
        let body = lines.into_iter().enumerate().map(|(i, (k, v, c))| {
            div()
                .id((id, i))
                .min_h(px(t::ROW_HEIGHT))
                .px(px(12.))
                .py(px(4.))
                .flex()
                .gap(px(12.))
                .border_t_1()
                .border_color(color(t::GRAY_400))
                .text_size(px(t::TEXT_LABEL))
                .role(Role::Row)
                .aria_label(format!("{k} {v}"))
                .child(div().w(px(200.)).flex_none().text_color(color(t::GRAY_900)).child(k))
                .child(div().flex_1().min_w_0().font_family(t::FONT_MONO).text_color(color(c)).child(v))
        });
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .bg(color(t::GRAY_100))
            .border_1()
            .border_color(color(t::GRAY_400))
            .rounded(px(t::RADIUS_SMALL))
            .overflow_hidden()
            .child(
                div()
                    .id((id, 9999usize))
                    .h(px(32.))
                    .px(px(12.))
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .cursor_pointer()
                    .hover(|s| s.bg(color(t::GRAY_200)))
                    .focus_visible(focus_ring)
                    .role(Role::Button)
                    .aria_expanded(open)
                    .aria_label(format!("{title}, {summary}"))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if !this.open.remove(id) {
                            this.open.insert(id);
                        }
                        cx.notify();
                    }))
                    .child(icon("icons/chevron.svg", 12., t::GRAY_800).when(open, |s| s.with_transformation(Transformation::rotate(radians(std::f32::consts::FRAC_PI_2)))))
                    .child(div().text_size(px(t::TEXT_LABEL)).font_weight(FontWeight::SEMIBOLD).child(title))
                    .child(div().text_size(px(t::TEXT_LABEL)).text_color(color(t::GRAY_900)).child(summary)),
            )
            .when(open, |s| s.children(body))
    }

    fn facts(&self, tab: &dg::Tab, section: Section, cx: &mut Context<Self>) -> Div {
        let Some(run) = tab.runs.get(&section) else { return div() };
        let o = &run.outcome;
        let rows = |f: &[Fact]| f.iter().map(|f| (f.key.clone(), f.value.clone(), t::GRAY_1000)).collect::<Vec<_>>();
        let open_rows = rows(&o.facts);
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap(px(8.))
            .when(!open_rows.is_empty(), |s| {
                s.child(div().text_size(px(t::TEXT_LABEL)).font_weight(FontWeight::SEMIBOLD).child(format!("{} data", section.label())))
                    .child(
                        div()
                            .id("facts")
                            .w_full()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .bg(color(t::GRAY_100))
                            .border_1()
                            .border_color(color(t::GRAY_400))
                            .rounded(px(t::RADIUS_SMALL))
                            .overflow_hidden()
                            .role(Role::Table)
                            .aria_label(format!("{} data", section.label()))
                            .children(open_rows.into_iter().enumerate().map(|(i, (k, v, c))| {
                                let shown = if i > 0 && o.facts[i - 1].key == k { String::new() } else { k.clone() };
                                div()
                                    .id(("fact", i))
                                    .min_h(px(t::ROW_HEIGHT))
                                    .px(px(12.))
                                    .py(px(4.))
                                    .flex()
                                    .gap(px(12.))
                                    .when(i > 0, |s| s.border_t_1().border_color(color(t::GRAY_400)))
                                    .text_size(px(t::TEXT_LABEL))
                                    .role(Role::Row)
                                    .aria_label(format!("{k}: {v}"))
                                    .child(div().w(px(200.)).flex_none().text_color(color(t::GRAY_900)).child(shown))
                                    .child(div().flex_1().min_w_0().font_family(t::FONT_MONO).text_color(color(c)).child(v))
                            })),
                    )
            })
            .when(!o.details.is_empty(), |s| {
                let n = o.details.len();
                s.child(self.disclosure("details", o.details_title.to_string(), format!("{n} {}", if n == 1 { "line" } else { "lines" }), rows(&o.details), cx))
            })
    }

    fn changes_view(&self, d: zombo_ui::outcome::Diff, cx: &mut Context<Self>) -> Div {
        let lines = d
            .removed
            .iter()
            .map(|l| ("removed".to_string(), l.clone(), t::CRITICAL))
            .chain(d.added.iter().map(|l| ("added".to_string(), l.clone(), t::OK)))
            .collect();
        self.disclosure("changes", "Changed since the previous run".into(), d.summary(), lines, cx)
    }

    fn resolver_table(&self, tab: &dg::Tab, cx: &mut Context<Self>) -> impl IntoElement {
        let rows = tab.propagation.view(tab.record);
        let cell = |w: Option<f32>| {
            let c = div().px(px(12.)).truncate();
            match w {
                Some(w) => c.w(px(w)).flex_none(),
                None => c.flex_1().min_w_0(),
            }
        };
        let header = div()
            .h(px(24.))
            .flex()
            .items_center()
            .bg(color(t::BG_200))
            .text_size(px(t::TEXT_CAPTION))
            .font_weight(FontWeight::MEDIUM)
            .text_color(color(t::GRAY_900))
            .child(cell(Some(150.)).child("Resolver"))
            .child(cell(Some(140.)).child("Location"))
            .child(cell(None).child(format!("{} answer", tab.record.code())))
            .child(cell(Some(70.)).child("TTL"))
            .child(cell(Some(100.)).child("Status"));
        let body = rows.iter().enumerate().map(|(i, r)| {
            let status_color = match r.status {
                dg::RowStatus::Truth | dg::RowStatus::Match => t::OK,
                dg::RowStatus::Stale => t::WARNING,
                dg::RowStatus::NoAnswer => t::CRITICAL,
                dg::RowStatus::Answered => t::GRAY_900,
            };
            div()
                .id(("row", i))
                .w_full()
                .min_w_0()
                .h(px(t::ROW_HEIGHT))
                .flex()
                .items_center()
                .border_t_1()
                .border_color(color(t::GRAY_400))
                .font_family(t::FONT_MONO)
                .text_size(px(t::TEXT_LABEL))
                .when(r.status == dg::RowStatus::Stale, |s| s.bg(color(0x1A1812)))
                .role(Role::Row)
                .aria_label(r.label())
                .child(cell(Some(150.)).child(r.resolver.clone()))
                .child(cell(Some(140.)).child(r.location.clone()))
                .child(cell(None).child(r.answer.clone()))
                .child(cell(Some(70.)).child(r.ttl.map(|t| t.to_string()).unwrap_or_default()))
                .child(
                    cell(Some(100.))
                        .text_size(px(t::TEXT_CAPTION))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(color(status_color))
                        .child(r.status.label().to_uppercase()),
                )
        });
        let heading = match (&tab.propagation.state, rows.len()) {
            (zombo_ui::status::CheckState::NotRun, _) => "Propagation by resolver: not run".to_string(),
            (_, 0) => "Propagation by resolver: waiting for the first answer".to_string(),
            (_, n) => format!("Propagation by resolver: {n} answers"),
        };
        let switcher = div()
            .id("record-types")
            .flex()
            .flex_wrap()
            .gap(px(4.))
            .role(Role::TabList)
            .aria_label("Record type")
            .children(RecordKind::ALL.iter().enumerate().map(|(i, &kind)| {
                let on = kind == tab.record;
                div()
                    .id(("rtype", i))
                    .h(px(28.))
                    .px(px(10.))
                    .flex()
                    .items_center()
                    .rounded(px(t::RADIUS_SMALL))
                    .border_1()
                    .border_color(color(if on { t::ACCENT } else { t::GRAY_400 }))
                    .bg(color(if on { t::GRAY_300 } else { t::GRAY_100 }))
                    .text_color(color(if on { t::GRAY_1000 } else { t::GRAY_900 }))
                    .font_family(t::FONT_MONO)
                    .text_size(px(t::TEXT_LABEL))
                    .cursor_pointer()
                    .hover(|s| s.bg(color(t::GRAY_200)))
                    .active(|s| s.bg(color(t::GRAY_300)))
                    .role(Role::Tab)
                    .aria_selected(on)
                    .aria_label(format!("Compare {} records", kind.code()))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(tab) = this.ws.current_mut() {
                            tab.record = kind;
                        }
                        cx.notify();
                    }))
                    .child(kind.code())
            }))
            .child(div().h(px(28.)).flex().items_center().gap(px(6.)).pl(px(8.)).text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child(kbd("[")).child(kbd("]")).child("switch"));
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap(px(8.))
            .child(div().text_size(px(t::TEXT_LABEL)).font_weight(FontWeight::SEMIBOLD).child(heading))
            .child(switcher)
            .when(!rows.is_empty(), |s| {
                s.child(
                    div()
                        .id("table")
                        .w_full()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .bg(color(t::GRAY_100))
                        .border_1()
                        .border_color(color(t::GRAY_400))
                        .rounded(px(t::RADIUS_SMALL))
                        .overflow_hidden()
                        .role(Role::Table)
                        .aria_label("Propagation by resolver")
                        .child(header)
                        .children(body),
                )
            })
    }

    fn status_bar(&self) -> impl IntoElement {
        let lines = self.watches.status_lines(Instant::now());
        let watch_text = match lines.as_slice() {
            [] => "No active Watches".to_string(),
            [one] => one.clone(),
            [first, rest @ ..] => format!("{first} (+{} more)", rest.len()),
        };
        let hint = |k: &'static str, text: &'static str| {
            div().flex().items_center().gap(px(6.)).child(kbd(k)).child(text)
        };
        div()
            .id("status")
            .h(px(t::STATUS_BAR_HEIGHT))
            .flex_none()
            .flex()
            .items_center()
            .gap(px(16.))
            .px(px(16.))
            .bg(color(t::BG_200))
            .border_t_1()
            .border_color(color(t::GRAY_400))
            .text_size(px(t::TEXT_CAPTION))
            .text_color(color(t::GRAY_900))
            .role(Role::Status)
            .aria_label("Status bar")
            .child(div().flex_1().min_w_0().truncate().child(watch_text))
            .child(hint("Ctrl K", "palette"))
            .child(hint("?", "shortcuts"))
    }

    fn overlay(&self, title: &'static str, selected: Option<usize>, cx: &mut Context<Self>) -> impl IntoElement {
        let entries = keys::entries();
        let rows = entries.into_iter().enumerate().map(|(i, e)| {
            let sel = selected == Some(i);
            div()
                .id(("entry", i))
                .h(px(t::ROW_HEIGHT))
                .px(px(12.))
                .flex()
                .items_center()
                .justify_between()
                .rounded(px(t::RADIUS_SMALL))
                .border_1()
                .border_color(color(if sel { t::ACCENT } else { t::GRAY_100 }))
                .when(sel, |s| s.bg(color(t::GRAY_300)))
                .text_size(px(t::TEXT_LABEL))
                .role(Role::ListItem)
                .aria_label(format!("{}, shortcut {}", e.label, e.shortcut))
                .when(selected.is_some(), |s| {
                    let action = e.action;
                    s.cursor_pointer().hover(|s| s.bg(color(t::GRAY_200))).on_click(cx.listener(move |this, _, window, cx| {
                        this.palette = None;
                        this.perform(action, window, cx);
                    }))
                })
                .child(e.label)
                .child(kbd(&e.shortcut))
        });
        div()
            .absolute()
            .size_full()
            .flex()
            .justify_center()
            .items_start()
            .pt(px(96.))
            .bg(rgba(0x00000066))
            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                this.palette = None;
                this.sheet = false;
                cx.notify();
            }))
            .child(
                div()
                    .id("dialog")
                    .w(px(520.))
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .p(px(8.))
                    .bg(color(t::GRAY_100))
                    .border_1()
                    .border_color(color(t::GRAY_500))
                    .rounded(px(t::RADIUS_LARGE))
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .role(Role::Dialog)
                    .aria_label(title)
                    .child(div().px(px(12.)).py(px(6.)).text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_900)).child(title.to_uppercase()))
                    .children(rows),
            )
    }
}

impl Render for Shell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if !self.rendered {
            self.rendered = true;
            eprintln!("first render {:?} after main()", self.started.elapsed());
        }
        let body = if self.ws.is_empty_state() {
            div().flex_1().flex().flex_col().child(self.empty_state(cx).into_any_element())
        } else {
            div().flex_1().min_h_0().flex().child(self.rail(cx)).child(self.pane(cx))
        };
        div()
            .id("root")
            .key_context("Zombo")
            .track_focus(&self.root_focus)
            .capture_key_down(cx.listener(|this, ev: &KeyDownEvent, window, cx| this.on_key(ev, window, cx)))
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(color(t::BG_100))
            .text_color(color(t::GRAY_1000))
            .font_family(t::FONT_SANS)
            .text_size(px(t::TEXT_BODY))
            .line_height(px(20.))
            .child(self.title_bar(window, cx))
            .when(!self.ws.tabs.is_empty(), |s| s.child(self.tab_strip(cx)))
            .child(body)
            .child(self.status_bar())
            .when_some(self.toast.clone(), |s, (text, _)| {
                s.child(
                    div()
                        .id("toast")
                        .absolute()
                        .bottom(px(t::STATUS_BAR_HEIGHT + 12.))
                        .right(px(16.))
                        .w(px(420.))
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .px(px(12.))
                        .py(px(8.))
                        .bg(color(t::GRAY_100))
                        .border_1()
                        .border_color(color(t::GRAY_500))
                        .rounded(px(t::RADIUS_LARGE))
                        .text_size(px(t::TEXT_LABEL))
                        .cursor_pointer()
                        .role(Role::Alert)
                        .aria_label(text.clone())
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.toast = None;
                            cx.notify();
                        }))
                        .child(glyph(Glyph::Info, 16.))
                        .child(div().flex_1().min_w_0().child(text)),
                )
            })
            .when(self.palette.is_some(), |s| s.child(self.overlay("Command palette", self.palette, cx)))
            .when(self.sheet, |s| s.child(self.overlay("Keyboard shortcuts", None, cx)))
    }
}
