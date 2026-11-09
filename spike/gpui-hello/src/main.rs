use gpui_kit::component::button::*;
use gpui_kit::component::*;
use gpui_kit::*;

struct Hello(std::time::Instant, bool);
impl Render for Hello {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        if !self.1 { self.1 = true; eprintln!("first render {:?} after main()", self.0.elapsed()); }
        div()
            .v_flex()
            .gap_2()
            .size_full()
            .items_center()
            .justify_center()
            .child("Zombo's Razor spike: hello GPUI")
            .child(Button::new("ok").primary().label("Click").on_click(|_, _, _| println!("clicked")))
    }
}

fn main() {
    let t0 = std::time::Instant::now();
    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);
        gpui_kit::open_window(WindowOptions::default(), cx, |_, cx| cx.new(|_| Hello(t0, false)))
            .expect("open window");
    });
}
