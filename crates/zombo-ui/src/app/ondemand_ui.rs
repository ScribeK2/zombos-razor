//! Pieces of the on-demand panes that only the shell draws.

use super::*;
use zombo_ui::smtp_plan::PORTS;

impl Shell {
    /// The port the SMTP Check dials: 25, 587 or 465. `[` and `]` step through them.
    pub(super) fn port_field(&self, tab: &dg::Tab, cx: &mut Context<Self>) -> Stateful<Div> {
        let label = |port: u16| match port {
            25 => "25 mail transfer",
            587 => "587 submission",
            _ => "465 implicit TLS",
        };
        div()
            .id("smtp-port")
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(4.))
            .role(Role::TabList)
            .aria_label("SMTP port")
            .child(div().pr(px(8.)).text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child("PORT"))
            .children(PORTS.iter().enumerate().map(|(i, &port)| {
                let on = port == tab.smtp_port;
                div()
                    .id(("smtp-port-pill", i))
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
                    .aria_label(format!("Check port {port}"))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(tab) = this.ws.current_mut() {
                            tab.smtp_port = port;
                        }
                        cx.notify();
                    }))
                    .child(label(port))
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
            )
    }

    /// An on-demand pane takes the keyboard when it is selected, so Enter runs its Check.
    pub(super) fn focus_on_demand(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.ws.current().is_some_and(|t| t.section.is_on_demand()) {
            window.focus(&self.pane_focus, cx);
        }
    }

    /// The card's first line. With a result it is a disclosure that opens the rest of the card.
    pub(super) fn brief_line(
        &self,
        what: String,
        has_result: bool,
        open: bool,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let line = div()
            .id("brief-line")
            .w_full()
            .min_w_0()
            .flex()
            .items_center()
            .gap(px(8.))
            .text_size(px(t::TEXT_BODY))
            .line_height(px(20.));
        if !has_result {
            return line.child(div().flex_1().min_w_0().child(what));
        }
        line.cursor_pointer()
            .hover(|s| s.bg(color(t::GRAY_200)))
            .focus_visible(focus_ring)
            .role(Role::Button)
            .aria_expanded(open)
            .aria_label(if open { "Hide what this Check does" } else { "Show what this Check does" })
            .on_click(cx.listener(|this, _, _, cx| {
                if !this.open.remove("brief") {
                    this.open.insert("brief");
                }
                cx.notify();
            }))
            .child(
                icon("icons/chevron.svg", 12., t::GRAY_800).when(open, |s| {
                    s.with_transformation(Transformation::rotate(radians(std::f32::consts::FRAC_PI_2)))
                }),
            )
            .child(div().flex_1().min_w_0().when(!open, |s| s.truncate()).text_color(color(t::GRAY_900)).child(what))
    }
}
