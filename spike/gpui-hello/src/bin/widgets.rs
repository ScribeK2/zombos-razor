use std::{borrow::Cow, time::Instant};

use gpui_kit::component::input::*;
use gpui_kit::component::table::*;
use gpui_kit::component::*;
use gpui_kit::*;

const ROWS: usize = 100_000;

struct Records;
impl TableDelegate for Records {
    fn columns_count(&self, _: &App) -> usize { 3 }
    fn rows_count(&self, _: &App) -> usize { ROWS }
    fn column(&self, ix: usize, _: &App) -> Column {
        match ix {
            0 => Column::new("name", "Name"),
            1 => Column::new("type", "Type"),
            _ => Column::new("value", "Value"),
        }
    }
    fn cell_label(&self, row: usize, col: usize, _: &App) -> Option<SharedString> {
        Some(cell(row, col).into())
    }
    fn render_td(&mut self, row: usize, col: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        div().font_family("Geist Mono").child(cell(row, col))
    }
}
fn cell(row: usize, col: usize) -> String {
    match col {
        0 => format!("host{row}.example.com"),
        1 => ["A", "AAAA", "MX", "TXT", "CNAME"][row % 5].to_string(),
        _ => format!("203.0.113.{}", row % 256),
    }
}

struct Demo {
    input: Entity<InputState>,
    table: Entity<TableState<Records>>,
    first: Instant,
    logged: bool,
}
impl Render for Demo {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        if !self.logged {
            self.logged = true;
            eprintln!("first render {:?} after main()", self.first.elapsed());
        }
        div().v_flex().size_full().p_4().gap_3().font_family("Geist")
            .child("Zombo's Razor spike: Geist Sans heading, then a Geist Mono input and 100,000-row table")
            .child(div().font_family("Geist Mono").child(Input::new(&self.input)))
            .child(div().flex_1().child(DataTable::new(&self.table)))
    }
}

fn main() {
    let first = Instant::now();
    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);
        cx.text_system()
            .add_fonts(vec![
                Cow::Borrowed(include_bytes!("../../assets/Geist-Regular.ttf").as_slice()),
                Cow::Borrowed(include_bytes!("../../assets/GeistMono-Regular.ttf").as_slice()),
            ])
            .expect("fonts");
        gpui_kit::open_window(WindowOptions::default(), cx, move |window, cx| {
            let input = cx.new(|cx| InputState::new(window, cx).placeholder("example.com"));
            let table = cx.new(|cx| TableState::new(Records, window, cx));
            cx.new(|_| Demo { input, table, first, logged: false })
        })
        .expect("open window");
    });
}
