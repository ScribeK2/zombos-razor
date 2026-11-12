use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use crate::settings::{PaneEvent, SettingsPane};
use crate::update_ui::UpdateCard;
use gpui_kit::component::input::{Input, InputEvent, InputState, TextareaState};
use gpui_kit::prelude::*;
use gpui_kit::*;
use zombo_core::Severity;
use zombo_ui::{
    checks,
    config::{self, Config, Dirs},
    copy::Format,
    diagnosis as dg, evidence_model as ev,
    keys::{self, Action, Mode, Press},
    layout,
    motion::{self, Fade, Feedback, Level, Motion},
    notice, ondemand,
    open_state::OpenState,
    outcome::{CheckEvent, Fact},
    record::RecordKind,
    runtime,
    section::Section,
    status::Glyph,
    theme as t,
    watch::Watches,
    workspace::{Slot, Workspace, relative},
};

mod copying;
mod evidence;
mod frame;
mod ondemand_ui;

const FINDING_HANDLES: usize = 64;
const DISCLOSURES: [&str; 5] = ["nameservers", "records", "details", "changes", "blind"];
const TOAST_FOR: Duration = Duration::from_secs(8);

pub struct Shell {
    ws: Workspace,
    input: Entity<InputState>,
    port_input: Entity<InputState>,
    root_focus: FocusHandle,
    pane_focus: FocusHandle,
    rail_focus: Vec<FocusHandle>,
    finding_focus: Vec<FocusHandle>,
    action_focus: Vec<FocusHandle>,
    palette: Option<usize>,
    open: HashSet<&'static str>,
    tab_open: OpenState,
    row_focus: Vec<FocusHandle>,
    nav_rows: Vec<FocusHandle>,
    nav: Option<zombo_ui::focus_nav::Stop>,
    jobs: HashMap<(String, Section), runtime::Cancel>,
    motion: Motion,
    fx: Feedback<(&'static str, usize)>,
    fade: Fade<(String, Section, &'static str)>,
    pane_opacity: f32,
    toast_leave: Option<Instant>,
    watches: Watches,
    pastes: HashMap<u64, Entity<TextareaState>>,
    toast: Option<(String, Instant)>,
    sheet: bool,
    error: Option<String>,
    config: Config,
    settings: Option<Entity<SettingsPane>>,
    update: Entity<UpdateCard>,
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

const WORDMARK_H: f32 = 18.;
const WORDMARK_W: f32 = WORDMARK_H * 1095. / 180.;

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
        let port_input = cx.new(|cx| InputState::new(window, cx).placeholder("other port"));
        cx.subscribe_in(&port_input, window, |this, input, ev: &InputEvent, window, cx| match ev {
            InputEvent::Change => {
                let text = input.read(cx).value().to_string();
                if let Some(tab) = this.ws.current_mut() {
                    tab.tls_port.typed(&text);
                }
                cx.notify();
            }
            InputEvent::PressEnter { .. } => this.perform(Action::Run(Section::TlsPort), window, cx),
            _ => {}
        })
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |app, cx| app.tick(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            let motion = cx.background_executor().spawn(async { zombo_ui::motion::read_system_motion() }).await;
            let _ = this.update(cx, |app, cx| {
                app.motion = motion;
                cx.notify();
            });
        })
        .detach();
        let config = Config::load(Dirs::from_env());
        let dirs = Dirs::from_env();
        let update = cx.new(|cx| UpdateCard::new(config.settings.check_updates, dirs.as_ref(), cx));
        let ws = Workspace {
            recent: config::to_recent(&config.recent, config::unix_now(), Instant::now()),
            ..Workspace::default()
        };
        let toast = [("config.toml", &config.settings_problem), ("recent.toml", &config.recent_problem)]
            .into_iter()
            .filter_map(|(file, p)| {
                p.as_ref()
                    .map(|p| format!("{file} has an error: {p}. The app runs without it and leaves the file as it is."))
            })
            .next()
            .map(|text| (text, Instant::now()));
        Shell {
            ws,
            input,
            port_input,
            root_focus: cx.focus_handle(),
            pane_focus: cx.focus_handle(),
            rail_focus: Section::ALL.iter().map(|_| cx.focus_handle().tab_stop(true)).collect(),
            finding_focus: (0..FINDING_HANDLES).map(|_| cx.focus_handle().tab_stop(true)).collect(),
            action_focus: (0..FINDING_HANDLES).map(|_| cx.focus_handle().tab_stop(true)).collect(),
            palette: None,
            open: HashSet::new(),
            motion: Motion::default(),
            fx: Feedback::new(),
            fade: Fade::default(),
            pane_opacity: 1.0,
            toast_leave: None,
            tab_open: OpenState::default(),
            row_focus: DISCLOSURES.iter().map(|_| cx.focus_handle().tab_stop(true)).collect(),
            nav_rows: (0..FINDING_HANDLES).map(|_| cx.focus_handle().tab_stop(true)).collect(),
            nav: None,
            jobs: HashMap::new(),
            watches: Watches::default(),
            pastes: HashMap::new(),
            toast,
            sheet: false,
            error: None,
            config,
            settings: None,
            update,
            started,
            rendered: false,
        }
    }

    fn mode(&self, window: &Window, cx: &gpui_kit::App) -> Mode {
        if self.settings.is_some() {
            Mode::Settings
        } else if self.palette.is_some() {
            Mode::Palette
        } else if self.sheet {
            Mode::Sheet
        } else if self.input.read(cx).focus_handle(cx).is_focused(window) {
            Mode::Omnibox
        } else if self.port_input.read(cx).focus_handle(cx).is_focused(window)
            || self.pastes.values().any(|p| p.read(cx).focus_handle(cx).is_focused(window))
        {
            Mode::Paste
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
        self.sync_port_input(window, cx);
    }

    fn sync_port_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let port = self.ws.current().map(|t| t.tls_port.text().to_string()).unwrap_or_default();
        self.port_input.update(cx, |i, cx| i.set_value(port, window, cx));
    }

    fn focus_omnibox(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.input.update(cx, |i, cx| i.focus(window, cx));
    }

    fn start_section(&mut self, section: Section, cx: &mut Context<Self>) {
        let Some(key) = self.ws.current().map(|t| t.target.value.clone()) else { return };
        self.start_section_for(&key, section, cx);
    }

    fn start_section_for(&mut self, key: &str, section: Section, cx: &mut Context<Self>) {
        let Some(tab) = self.ws.tabs.iter().filter_map(Slot::diagnosis).find(|t| t.target.value == key) else { return };
        if tab.state(section) == zombo_ui::status::CheckState::Running || !checks::wired(section) {
            return;
        }
        if section.is_on_demand() && !ondemand::runnable(tab.target.kind, section) {
            return;
        }
        let key = key.to_string();
        let Some(name) = checks::name_for(section, &tab.target) else { return };
        let (kind, port) = (tab.target.kind, tab.chosen_port(section));
        if section == Section::Dns {
            let settings = self.config.settings.clone();
            let (mut rx, cancel) = runtime::stream(move |tx| checks::run_propagation(name, settings, tx));
            self.jobs.insert((key.clone(), Section::Dns), cancel);
            cx.spawn(async move |this, cx| {
                while let Some(event) = rx.recv().await {
                    let key = key.clone();
                    if this
                        .update(cx, |app, cx| {
                            if let Some(tab) = app.ws.diagnosis_mut_for(&key) {
                                let target = tab.target.clone();
                                tab.propagation.apply(&target, event);
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
        let port = match port {
            Ok(p) => p,
            Err(e) => {
                self.toast = Some((e.into(), Instant::now()));
                return;
            }
        };
        if let Some(tab) = self.ws.diagnosis_mut_for(&key) {
            tab.run_mut(section).apply(CheckEvent::Started);
        }
        let settings = self.config.settings.clone();
        let (mut rx, cancel) = runtime::stream(move |tx| checks::run_section(section, name, kind, settings, port, tx));
        self.jobs.insert((key.clone(), section), cancel);
        cx.spawn(async move |this, cx| {
            while let Some(event) = rx.recv().await {
                let key = key.clone();
                if this
                    .update(cx, |app, cx| {
                        if let Some(tab) = app.ws.diagnosis_mut_for(&key) {
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
        let Some(settled) = self
            .ws
            .tabs
            .iter()
            .filter_map(Slot::diagnosis)
            .find(|t| t.target.value == key)
            .and_then(|t| t.settled(section))
        else {
            return;
        };
        let now = Instant::now();
        if let Some(stopped) = self.watches.finished(key, section, settled.as_deref(), now) {
            let message = stopped.message();
            if let Some((summary, body)) = notice::watch_notice(&self.config.settings, &message) {
                notice::send(summary, body);
            }
            self.toast = Some((message, now));
        }
    }

    fn tick(&mut self, cx: &mut Context<Self>) {
        let now = Instant::now();
        let alive: Vec<String> =
            self.ws.tabs.iter().filter_map(Slot::diagnosis).map(|t| t.target.value.clone()).collect();
        self.watches.keep_targets(|t| alive.iter().any(|a| a == t));
        self.jobs.retain(|(target, _), job| {
            let keep = alive.iter().any(|a| a == target);
            if !keep {
                job.abort();
            }
            keep
        });
        self.tab_open.keep_targets(|t| alive.iter().any(|a| a == t));
        for (target, section) in self.watches.due(now) {
            self.start_section_for(&target, section, cx);
        }
        if let Some((_, at)) = self.toast {
            if now.duration_since(at) > TOAST_FOR && self.toast_leave.is_none_or(|l| l < at) {
                self.toast_leave = Some(now);
            }
            if self
                .toast_leave
                .is_some_and(|l| l >= at && !self.motion.running(now.duration_since(l), motion::TOAST_OUT))
            {
                self.toast = None;
                self.toast_leave = None;
            }
        }
        if !self.watches.is_empty() || self.toast.is_some() {
            cx.notify();
        }
    }

    fn toggle_watch(&mut self) {
        let Some(tab) = self.ws.current() else { return };
        let (target, section) = (tab.target.value.clone(), tab.section);
        if !checks::watchable(section) {
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
        for section in checks::automatic(kind) {
            self.start_section(section, cx);
        }
    }

    /// Stop what is running in the section on screen, and abort the tasks behind it.
    fn cancel_running(&mut self) {
        let Some(tab) = self.ws.current_mut() else { return };
        let (key, section) = (tab.target.value.clone(), tab.section);
        let stopped = tab.cancel(section);
        for &s in &stopped {
            if let Some(job) = self.jobs.remove(&(key.clone(), s)) {
                job.abort();
            }
        }
        let message = match stopped.as_slice() {
            [] => return,
            [one] => format!("Cancelled the {} Check.", one.label()),
            many => format!("Cancelled {} Checks.", many.len()),
        };
        self.toast = Some((message, Instant::now()));
    }

    /// `j`, `k` and the arrows: focus the next or previous finding, then row, of this section.
    fn walk(&mut self, delta: isize, window: &mut Window, cx: &mut Context<Self>) {
        use zombo_ui::focus_nav::{Stop, step};
        let Some(tab) = self.ws.current() else { return };
        let section = tab.section;
        let rows = match section {
            Section::Dns => tab.propagation.view(tab.record).len(),
            Section::Summary => 0,
            s => tab.runs.get(&s).map_or(0, |r| r.outcome.facts.len()),
        };
        let findings = tab.findings(section).len();
        self.nav = step(findings, rows, self.nav, delta);
        let last = FINDING_HANDLES - 1;
        let handle = match self.nav {
            Some(Stop::Finding(i)) => self.finding_focus.get(i.min(last)),
            Some(Stop::Row(i)) => self.nav_rows.get(i.min(last)),
            None => None,
        };
        if let Some(h) = handle {
            window.focus(h, cx);
        }
    }

    fn perform(&mut self, action: Action, window: &mut Window, cx: &mut Context<Self>) {
        if !matches!(action, Action::FocusNext | Action::FocusPrev) {
            self.nav = None;
        }
        match action {
            Action::Cancel => self.cancel_running(),
            Action::FocusNext => self.walk(1, window, cx),
            Action::FocusPrev => self.walk(-1, window, cx),
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
                            self.remember_recent();
                            self.sync_omnibox(window, cx);
                            self.start_automatic(cx);
                            window.focus(&self.root_focus, cx);
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
            }
            Action::Palette => self.palette = if self.palette.is_some() { None } else { Some(0) },
            Action::Rerun => match self.ws.current().map(|t| t.section) {
                Some(Section::Summary) => self.start_automatic(cx),
                Some(section) => self.start_section(section, cx),
                None => {}
            },
            Action::Run(section) => match self.ws.current().map(|t| t.target.kind) {
                None => self.toast = Some(("Enter a target first, then run this Check.".into(), Instant::now())),
                Some(kind) if !ondemand::runnable(kind, section) => {
                    self.toast =
                        Some((format!("The {} Check does not apply to this target.", section.label()), Instant::now()))
                }
                Some(_) => {
                    self.ws.jump(section.index());
                    self.focus_on_demand(window, cx);
                    self.start_section(section, cx);
                }
            },
            Action::ToggleWatch => self.toggle_watch(),
            Action::NextRecord | Action::PrevRecord => {
                let delta = if action == Action::NextRecord { 1 } else { -1 };
                match self.ws.current().map(|t| t.section) {
                    Some(Section::Dns) => self.ws.step_record(delta),
                    Some(Section::Smtp) => self.ws.current_mut().into_iter().for_each(|t| t.step_port(delta)),
                    Some(Section::TlsPort) => {
                        self.ws.current_mut().into_iter().for_each(|t| t.step_tls_port(delta));
                        self.sync_port_input(window, cx);
                    }
                    _ => {}
                }
            }
            Action::Jump(n) => {
                self.ws.jump(n);
                self.focus_on_demand(window, cx);
            }
            Action::PrevSection | Action::NextSection => {
                self.ws.step_section(if action == Action::NextSection { 1 } else { -1 });
                self.focus_on_demand(window, cx);
            }
            Action::NewTab => {
                self.ws.new_tab();
                self.error = None;
                self.set_omnibox("", window, cx);
                self.focus_omnibox(window, cx);
            }
            Action::CloseTab => {
                self.ws.close_active();
                self.drop_closed_pastes();
                self.sync_omnibox(window, cx);
                if self.ws.is_empty_state() {
                    self.focus_omnibox(window, cx);
                }
            }
            Action::NextTab | Action::PrevTab => {
                self.ws.step_tab(if action == Action::NextTab { 1 } else { -1 });
                self.sync_omnibox(window, cx);
            }
            Action::OpenEvidence(kind) => self.open_evidence(kind, window, cx),
            Action::Analyse => self.analyse_pasted(window, cx),
            Action::CopySection => self.copy_current(Format::Section, cx),
            Action::CopyAll => self.copy_current(Format::Whole, cx),
            Action::CopyJson => self.copy_current(Format::Json, cx),
            Action::Cheatsheet => self.sheet = !self.sheet,
            Action::Settings => self.toggle_settings(window, cx),
            Action::Dismiss => {
                if self.settings.is_some() {
                    self.close_settings(window, cx);
                } else if self.palette.is_some() || self.sheet {
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

    fn remember_recent(&mut self) {
        let entries = config::from_recent(&self.ws.recent, config::unix_now(), Instant::now());
        if let Err(e) = self.config.save_recent(entries) {
            self.toast = Some((e, Instant::now()));
        }
    }

    fn toggle_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.settings.is_some() {
            return self.close_settings(window, cx);
        }
        self.palette = None;
        self.sheet = false;
        let (current, problem, path) =
            (self.config.settings.clone(), self.config.settings_problem.clone(), self.config.settings_path());
        let updates = self.update.read(cx).availability();
        let pane = cx.new(|cx| SettingsPane::new(&current, updates, problem, path, window, cx));
        cx.subscribe_in(&pane, window, |this, pane, event: &PaneEvent, window, cx| match event {
            PaneEvent::Close => this.close_settings(window, cx),
            PaneEvent::Save(settings) => match this.config.save_settings(settings.clone()) {
                Ok(()) => {
                    this.close_settings(window, cx);
                    this.toast =
                        Some(("Settings saved. They apply to the next run of each Check.".into(), Instant::now()));
                    cx.notify();
                }
                Err(e) => pane.update(cx, |p, cx| p.set_save_error(e, cx)),
            },
        })
        .detach();
        self.settings = Some(pane);
    }

    fn close_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.settings = None;
        window.focus(&self.root_focus, cx);
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
                // Both SVGs share one viewBox, so the slash lands on the text without measuring.
                div()
                    .id("wordmark")
                    .w(px(220.))
                    .flex()
                    .items_center()
                    .role(Role::Heading)
                    .aria_label("Zombo's Razor")
                    .child(
                        div()
                            .relative()
                            .w(px(WORDMARK_W))
                            .h(px(WORDMARK_H))
                            .child(icon("wordmark.svg", WORDMARK_H, t::GRAY_900).w(px(WORDMARK_W)).h(px(WORDMARK_H)))
                            .child(
                                icon("wordmark-slash.svg", WORDMARK_H, t::ACCENT)
                                    .absolute()
                                    .top_0()
                                    .left_0()
                                    .w(px(WORDMARK_W))
                                    .h(px(WORDMARK_H)),
                            ),
                    ),
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
                                .child(
                                    Input::new(&self.input)
                                        .appearance(false)
                                        .bordered(false)
                                        .focus_bordered(false)
                                        .aria_label("Target: domain, host, IP or email"),
                                ),
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
                    .child(
                        control("min", "icons/minimize.svg", "Minimize")
                            .on_click(|_, window, _| window.minimize_window()),
                    )
                    .child(
                        control("max", "icons/maximize.svg", "Maximize").on_click(|_, window, _| window.zoom_window()),
                    )
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
                .aria_label(format!("Tab {} of {}: {}", i + 1, self.ws.tabs.len(), tab.label()))
                .aria_selected(active)
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.ws.select_tab(i);
                    this.sync_omnibox(window, cx);
                    cx.notify();
                }))
                .child(tab.label().to_string())
                .child(
                    div()
                        .id(("tab-close", i))
                        .size(px(16.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .role(Role::Button)
                        .aria_label(format!("Close tab {}", tab.label()))
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
                .child(
                    div().text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_900)).child(relative(r.at.elapsed())),
                )
        });
        let hints = [
            ("Ctrl L", "focus the omnibox"),
            ("Enter", "run the Diagnosis"),
            ("Ctrl K", "command palette"),
            ("?", "shortcut cheat sheet"),
        ];
        div().flex_1().flex().justify_center().pt(px(72.)).child(
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
            div()
                .px(px(8.))
                .pt(px(12.))
                .pb(px(4.))
                .text_size(px(t::TEXT_CAPTION))
                .text_color(color(t::GRAY_800))
                .child(text)
        };
        let items = Section::ALL.iter().enumerate().map(|(i, &section)| {
            let state = tab.state(section);
            let selected = tab.section == section;
            let findings = tab.findings(section);
            let g = zombo_ui::rail::mark_glyph(&state, &findings, tab.verdict_glyph(section));
            let count_line = zombo_ui::rail::count_line(section, &state, &findings);
            let group = match i {
                1 => Some("CHECKS"),
                Section::FIRST_ON_DEMAND => Some("ON DEMAND"),
                _ => None,
            };
            let item = div()
                .id(("rail", i))
                .when_some(self.rail_focus.get(i), |d, h| d.track_focus(h))
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
                .map(|s| {
                    if selected {
                        s.bg(color(t::GRAY_300))
                    } else {
                        self.fx(s, ("rail", i), t::BG_200, t::GRAY_200, t::GRAY_300, cx)
                    }
                })
                .focus_visible(focus_ring)
                .cursor_pointer()
                .role(Role::Tab)
                .aria_selected(selected)
                .aria_label(format!("{}: {}", section.label(), state.label()))
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.ws.jump(i);
                    this.focus_on_demand(window, cx);
                    cx.notify();
                }))
                .on_key_down(cx.listener(move |this, ev: &KeyDownEvent, window, cx| {
                    if matches!(ev.keystroke.key.as_str(), "enter" | "space") {
                        this.ws.jump(i);
                        this.focus_on_demand(window, cx);
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
                        .child(count_line),
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
        let watchable = checks::watchable(section) && state != zombo_ui::status::CheckState::NotRun;
        let watching = self.watches.is_watching(&tab.target.value, section);
        let finding_views =
            findings.iter().enumerate().map(|(i, f)| self.finding_card(i, f, Some(section), cx)).collect::<Vec<_>>();
        let brief = ondemand::brief(section);
        let run_label = ondemand::run_label(section);
        let brief_open = self.open.contains("brief");
        let has_result = matches!(
            state,
            zombo_ui::status::CheckState::Done { .. }
                | zombo_ui::status::CheckState::Failed { .. }
                | zombo_ui::status::CheckState::TimedOut
        );
        let brief_collapsed = ondemand::collapsed(&state, brief_open);
        let can_run = brief.is_some() && !state.can_retry() && state != zombo_ui::status::CheckState::Running;
        div()
            .id("pane")
            .opacity(self.pane_opacity)
            .track_focus(&self.pane_focus)
            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, window, cx| window.focus(&this.pane_focus, cx)))
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, window, cx| {
                let plain_enter = ev.keystroke.key == "enter" && !ev.keystroke.modifiers.modified();
                if let Some(section) = this.ws.current().map(|t| t.section).filter(|s| plain_enter && s.is_on_demand())
                {
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
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .items_center()
                            .gap(px(8.))
                            .when(watchable, |s| s.child(self.watch_button(watching, cx)))
                            .when(show_chips, |s| {
                                s.child(div().flex().flex_none().gap(px(8.)).children(counts.map(|(sev, n)| {
                                    div()
                                        .id(("chip", sev.rank() as usize))
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
                            }),
                    ),
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
                        .child(self.brief_line(b.what, has_result, brief_open, cx))
                        .when(!brief_collapsed, |s| {
                            s.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap(px(2.))
                                    .child(
                                        div()
                                            .text_size(px(t::TEXT_CAPTION))
                                            .text_color(color(t::GRAY_800))
                                            .child("SERVERS IT CONTACTS"),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(t::TEXT_LABEL))
                                            .line_height(px(18.))
                                            .text_color(color(t::GRAY_900))
                                            .child(b.contacts),
                                    ),
                            )
                            .when_some(b.note, |s, n| {
                                s.child(
                                    div()
                                        .text_size(px(t::TEXT_LABEL))
                                        .line_height(px(18.))
                                        .text_color(color(t::GRAY_800))
                                        .child(n),
                                )
                            })
                        })
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
                                    .map(|s| self.fx(s, ("run", 0), t::GRAY_100, t::GRAY_200, t::GRAY_300, cx))
                                    .focus_visible(focus_ring)
                                    .role(Role::Button)
                                    .aria_label(run_label.unwrap_or("Run this Check"))
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.perform(Action::Run(section), window, cx)
                                    }))
                                    .child(if state == zombo_ui::status::CheckState::NotRun {
                                        run_label.unwrap_or("Run")
                                    } else {
                                        "Run again"
                                    })
                                    .child(kbd("Enter")),
                            )
                        }),
                )
            })
            .when(section == Section::Smtp, |s| s.child(self.port_field(tab, cx)))
            .when(section == Section::TlsPort, |s| s.child(self.tls_port_field(tab, cx)))
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
                        .map(|s| self.fx(s, ("retry", 0), t::GRAY_100, t::GRAY_200, t::GRAY_300, cx))
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
            .when(section == Section::Dns, |s| s.child(self.resolver_table(tab, cx)).child(self.dns_rows(tab, cx)))
            .when(section != Section::Dns && section != Section::Summary, |s| s.child(self.facts(tab, section, cx)))
            .when_some(tab.history(section).and_then(|h| h.changes.clone()), |s, d| s.child(self.changes_view(d, cx)))
            .when(!zombo_ui::blind_spots::lines(section).is_empty(), |s| s.child(self.blind_spots_view(section, cx)))
    }

    fn blind_spots_view(&self, section: Section, cx: &mut Context<Self>) -> Div {
        let lines: Vec<_> = zombo_ui::blind_spots::lines(section)
            .iter()
            .map(|l| ("Cannot see".to_string(), l.to_string(), t::GRAY_900))
            .collect();
        let n = lines.len();
        self.disclosure("blind", zombo_ui::blind_spots::TITLE.into(), format!("{n} limits of this Check"), lines, cx)
    }

    fn finding_card(
        &self,
        i: usize,
        f: &zombo_core::Finding,
        current: Option<Section>,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let c = severity_color(f.severity);
        let go = current.and_then(|c| zombo_ui::finding_owner::jump_target(f.code, c));
        let label = dg::finding_label(f);
        div()
            .id(("finding", i))
            .w_full()
            .min_w_0()
            .when_some(self.finding_focus.get(i.min(FINDING_HANDLES - 1)), |d, h| d.track_focus(h))
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
                    .child(
                        div()
                            .text_size(px(t::TEXT_BODY))
                            .line_height(px(20.))
                            .font_weight(FontWeight::MEDIUM)
                            .child(f.title.to_string()),
                    )
                    .when(!f.message.is_empty(), |s| {
                        s.child(
                            div()
                                .text_size(px(t::TEXT_LABEL))
                                .line_height(px(18.))
                                .text_color(color(t::GRAY_900))
                                .child(f.message.clone()),
                        )
                    })
                    .when_some(f.recommendation.clone(), |s, r| {
                        s.child(
                            div()
                                .text_size(px(t::TEXT_LABEL))
                                .line_height(px(18.))
                                .text_color(color(t::GRAY_800))
                                .child(r.to_string()),
                        )
                    }),
            )
            .when_some(go, |s, target| s.child(self.go_button(i, target, cx)))
    }

    fn go_button(&self, i: usize, target: Section, cx: &mut Context<Self>) -> impl IntoElement {
        let jump = move |this: &mut Self, cx: &mut Context<Self>| {
            this.ws.jump(target.index());
            cx.notify();
        };
        div()
            .id(("go", i))
            .when_some(self.action_focus.get(i.min(FINDING_HANDLES - 1)), |d, h| d.track_focus(h))
            .flex_none()
            .h(px(28.))
            .px(px(12.))
            .flex()
            .items_center()
            .gap(px(6.))
            .border_1()
            .border_color(color(t::GRAY_500))
            .rounded(px(t::RADIUS_SMALL))
            .text_size(px(t::TEXT_CAPTION))
            .cursor_pointer()
            .map(|s| self.fx(s, ("go", i), t::GRAY_100, t::GRAY_200, t::GRAY_300, cx))
            .focus_visible(focus_ring)
            .role(Role::Button)
            .aria_label(format!("Go to the {} section", target.label()))
            .on_click(cx.listener(move |this, _, _, cx| jump(this, cx)))
            .on_key_down(cx.listener(move |this, ev: &KeyDownEvent, _, cx| {
                if matches!(ev.keystroke.key.as_str(), "enter" | "space") {
                    cx.stop_propagation();
                    jump(this, cx);
                }
            }))
            .child(format!("{} \u{2192}", target.label()))
            .when_some(zombo_ui::finding_owner::jump_digit(target), |s, d| s.child(kbd(&format!("Ctrl {d}"))))
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
            .text_size(px(t::TEXT_CAPTION))
            .cursor_pointer()
            .map(|s| {
                self.fx(s, ("watch", 0), if watching { t::GRAY_300 } else { t::GRAY_100 }, t::GRAY_200, t::GRAY_300, cx)
            })
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

    /// Hover and press feedback: the element's background blends between the three colors over
    /// 80 ms, and its mouse events feed `Feedback`.
    fn fx(
        &self,
        el: Stateful<Div>,
        key: (&'static str, usize),
        rest: u32,
        hover: u32,
        press: u32,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let set = move |level: Level| {
            move |this: &mut Self, cx: &mut Context<Self>| {
                this.fx.set(key, level, Instant::now());
                cx.notify();
            }
        };
        let hovered = set(Level::Hover);
        let rested = set(Level::Rest);
        let pressed = set(Level::Press);
        el.bg(color(self.fx.color(&key, Instant::now(), self.motion, rest, hover, press)))
            .on_hover(cx.listener(move |this, h: &bool, _, cx| if *h { hovered(this, cx) } else { rested(this, cx) }))
            .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| pressed(this, cx)))
            .on_mouse_up(MouseButton::Left, cx.listener(move |this, _, _, cx| hovered(this, cx)))
    }

    fn toggle_row(&mut self, id: &'static str, cx: &mut Context<Self>) {
        if let Some((target, section)) = self.ws.current().map(|t| (t.target.value.clone(), t.section)) {
            self.tab_open.toggle(&target, section, id);
        }
        cx.notify();
    }

    fn dns_rows(&self, tab: &dg::Tab, cx: &mut Context<Self>) -> Div {
        let rows = [
            zombo_ui::dns_data::nameserver_answers(&tab.propagation.rows),
            zombo_ui::dns_data::all_records(&tab.propagation.rows),
        ];
        div().w_full().min_w_0().flex().flex_col().gap(px(8.)).children(rows.into_iter().flatten().map(|c| {
            let lines = c.lines.into_iter().map(|(k, v)| (k, v, t::GRAY_1000)).collect();
            self.disclosure(c.id, c.title.to_string(), c.summary, lines, cx)
        }))
    }

    fn disclosure(
        &self,
        id: &'static str,
        title: String,
        summary: String,
        lines: Vec<(String, String, u32)>,
        cx: &mut Context<Self>,
    ) -> Div {
        let kw = layout::key_column(lines.iter().map(|l| l.0.as_str()));
        let open = self.ws.current().is_some_and(|t| self.tab_open.is_open(&t.target.value, t.section, id));
        let slot = DISCLOSURES.iter().position(|&d| d == id).unwrap_or(0);
        let body = lines
            .into_iter()
            .enumerate()
            .map(|(i, (k, v, c))| {
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
                    .cursor_pointer()
                    .hover(|s| s.bg(color(t::GRAY_200)))
                    .on_click({
                        let v = v.clone();
                        cx.listener(move |this, _, _, cx| this.copy_value(&v, cx))
                    })
                    .child(div().w(px(kw)).flex_none().text_color(color(t::GRAY_900)).child(k))
                    .child(div().flex_1().min_w_0().font_family(t::FONT_MONO).text_color(color(c)).child(v))
            })
            .collect::<Vec<_>>();
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
                    .when_some(self.row_focus.get(slot), |d, h| d.track_focus(h))
                    .h(px(32.))
                    .px(px(12.))
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .cursor_pointer()
                    .map(|s| self.fx(s, ("disc", slot), t::GRAY_100, t::GRAY_200, t::GRAY_300, cx))
                    .focus_visible(focus_ring)
                    .role(Role::Button)
                    .aria_expanded(open)
                    .aria_label(format!("{title}, {summary}"))
                    .on_click(cx.listener(move |this, _, _, cx| this.toggle_row(id, cx)))
                    .on_key_down(cx.listener(move |this, ev: &KeyDownEvent, _, cx| {
                        if matches!(ev.keystroke.key.as_str(), "enter" | "space") {
                            cx.stop_propagation();
                            this.toggle_row(id, cx);
                        }
                    }))
                    .child(icon("icons/chevron.svg", 12., t::GRAY_800).when(open, |s| {
                        s.with_transformation(Transformation::rotate(radians(std::f32::consts::FRAC_PI_2)))
                    }))
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
        let kw = layout::key_column(o.facts.iter().map(|f| f.key.as_str()));
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap(px(8.))
            .when(!open_rows.is_empty(), |s| {
                s.child(
                    div()
                        .text_size(px(t::TEXT_LABEL))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(format!("{} data", section.label())),
                )
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
                            let shown = if i > 0 && o.facts.get(i - 1).is_some_and(|f| f.key == k) {
                                String::new()
                            } else {
                                k.clone()
                            };
                            div()
                                .id(("fact", i))
                                .min_h(px(t::ROW_HEIGHT))
                                .px(px(12.))
                                .py(px(4.))
                                .flex()
                                .gap(px(12.))
                                .when(i > 0, |s| s.border_t_1().border_color(color(t::GRAY_400)))
                                .text_size(px(t::TEXT_LABEL))
                                .when_some(self.nav_rows.get(i.min(FINDING_HANDLES - 1)), |d, h| d.track_focus(h))
                                .focus_visible(focus_ring)
                                .role(Role::Row)
                                .aria_label(format!("{k}: {v}"))
                                .cursor_pointer()
                                .hover(|s| s.bg(color(t::GRAY_200)))
                                .on_click({
                                    let v = v.clone();
                                    cx.listener(move |this, _, _, cx| this.copy_value(&v, cx))
                                })
                                .child(div().w(px(kw)).flex_none().text_color(color(t::GRAY_900)).child(shown))
                                .child(div().flex_1().min_w_0().font_family(t::FONT_MONO).text_color(color(c)).child(v))
                        })),
                )
            })
            .when(!o.details.is_empty(), |s| {
                let n = o.details.len();
                s.child(self.disclosure(
                    "details",
                    o.details_title.to_string(),
                    format!("{n} {}", if n == 1 { "line" } else { "lines" }),
                    rows(&o.details),
                    cx,
                ))
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
        let body = rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let status_color = match r.status {
                    dg::RowStatus::Truth | dg::RowStatus::Match => t::OK,
                    dg::RowStatus::Stale | dg::RowStatus::Differs => t::WARNING,
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
                    .when_some(self.nav_rows.get(i.min(FINDING_HANDLES - 1)), |d, h| d.track_focus(h))
                    .focus_visible(focus_ring)
                    .role(Role::Row)
                    .aria_label(r.label())
                    .cursor_pointer()
                    .hover(|s| s.bg(color(t::GRAY_200)))
                    .on_click({
                        let answer = r.answer.clone();
                        cx.listener(move |this, _, _, cx| this.copy_value(&answer, cx))
                    })
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
            })
            .collect::<Vec<_>>();
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
                    .text_color(color(if on { t::GRAY_1000 } else { t::GRAY_900 }))
                    .font_family(t::FONT_MONO)
                    .text_size(px(t::TEXT_LABEL))
                    .cursor_pointer()
                    .map(|s| {
                        self.fx(
                            s,
                            ("rtype", i),
                            if on { t::GRAY_300 } else { t::GRAY_100 },
                            t::GRAY_200,
                            t::GRAY_300,
                            cx,
                        )
                    })
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
            .child(
                div()
                    .h(px(28.))
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .pl(px(8.))
                    .text_size(px(t::TEXT_CAPTION))
                    .text_color(color(t::GRAY_800))
                    .child(kbd("["))
                    .child(kbd("]"))
                    .child("switch"),
            );
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
        let hint =
            |k: &'static str, text: &'static str| div().flex().items_center().gap(px(6.)).child(kbd(k)).child(text);
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
                    s.cursor_pointer().hover(|s| s.bg(color(t::GRAY_200))).on_click(cx.listener(
                        move |this, _, window, cx| {
                            this.palette = None;
                            this.perform(action, window, cx);
                        },
                    ))
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
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.palette = None;
                    this.sheet = false;
                    cx.notify();
                }),
            )
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
                    .child(
                        div()
                            .px(px(12.))
                            .py(px(6.))
                            .text_size(px(t::TEXT_CAPTION))
                            .text_color(color(t::GRAY_900))
                            .child(title.to_uppercase()),
                    )
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
        let now = Instant::now();
        if let Some((key, word)) =
            self.ws.current().map(|t| (t.target.value.clone(), (t.section, t.state(t.section).word())))
        {
            self.pane_opacity = self.fade.opacity((key, word.0, word.1), now, self.motion);
        }
        if self.fx.animating(now, self.motion)
            || self.fade.animating(now, self.motion)
            || self.toast.as_ref().is_some_and(|&(_, at)| {
                self.motion.running(now.saturating_duration_since(at), motion::TOAST_IN)
                    || self.toast_leave.is_some_and(|l| {
                        l >= at && self.motion.running(now.saturating_duration_since(l), motion::TOAST_OUT)
                    })
            })
        {
            window.request_animation_frame();
        }
        let body = if self.ws.is_empty_state() {
            div().flex_1().flex().flex_col().child(self.empty_state(cx).into_any_element())
        } else if self.ws.current_evidence().is_some() {
            div().flex_1().min_h_0().flex().child(self.evidence_rail(cx)).child(self.evidence_pane(cx))
        } else {
            div().flex_1().min_h_0().flex().child(self.rail(cx)).child(self.pane(cx))
        };
        let root = div()
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
            .when_some(
                self.toast.clone().and_then(|(text, at)| {
                    let left = self.toast_leave.filter(|&l| l >= at).map(|l| now.saturating_duration_since(l));
                    motion::toast_frame(self.motion, now.saturating_duration_since(at), left).map(|(o, y)| (text, o, y))
                }),
                |s, (text, opacity, drop)| {
                    s.child(
                        div()
                            .id("toast")
                            .absolute()
                            .opacity(opacity)
                            .bottom(px(t::STATUS_BAR_HEIGHT + 12. - drop))
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
                                this.toast_leave = Some(Instant::now());
                                cx.notify();
                            }))
                            .child(glyph(Glyph::Info, 16.))
                            .child(div().flex_1().min_w_0().child(text)),
                    )
                },
            )
            .child(self.update.clone())
            .when(self.palette.is_some(), |s| s.child(self.overlay("Command palette", self.palette, cx)))
            .when(self.sheet, |s| s.child(self.overlay("Keyboard shortcuts", None, cx)))
            .when_some(self.settings.clone(), |s, pane| s.child(pane));
        frame::frame(window, root)
    }
}
