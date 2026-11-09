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
            .child(div().h(px(28.)).flex().items_center().gap(px(6.)).pl(px(8.)).text_size(px(t::TEXT_CAPTION)).text_color(color(t::GRAY_800)).child(kbd("[")).child(kbd("]")).child("switch"))
    }
}
