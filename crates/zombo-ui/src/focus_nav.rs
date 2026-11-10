//! `j` and `k` (and the arrow keys) walk the findings, then the rows, of the section on screen.

/// One stop on the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Finding(usize),
    Row(usize),
}

/// The stop `delta` places from `current` among `findings` findings followed by `rows` rows.
/// The walk does not wrap: at the last stop `j` stays, so a rep holding the key does not loop.
/// With no stop yet, forward goes to the first and backward to the last. `None` when the
/// section has nothing to walk.
pub fn step(findings: usize, rows: usize, current: Option<Stop>, delta: isize) -> Option<Stop> {
    let len = findings + rows;
    if len == 0 {
        return None;
    }
    let at = |s: Stop| match s {
        Stop::Finding(i) => i,
        Stop::Row(i) => findings + i,
    };
    let next = match current.map(at).filter(|&i| i < len) {
        Some(i) => i.saturating_add_signed(delta).min(len - 1),
        None if delta < 0 => len - 1,
        None => 0,
    };
    Some(if next < findings { Stop::Finding(next) } else { Stop::Row(next - findings) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use Stop::{Finding, Row};

    #[test]
    fn forward_walks_the_findings_then_the_rows_and_stops_at_the_end() {
        let mut at = None;
        let mut seen = vec![];
        for _ in 0..6 {
            at = step(2, 2, at, 1);
            seen.push(at);
        }
        assert_eq!(seen, [Some(Finding(0)), Some(Finding(1)), Some(Row(0)), Some(Row(1)), Some(Row(1)), Some(Row(1))]);
    }

    #[test]
    fn backward_starts_at_the_last_stop_and_stops_at_the_first() {
        assert_eq!(step(2, 2, None, -1), Some(Row(1)));
        assert_eq!(step(2, 2, Some(Row(0)), -1), Some(Finding(1)));
        assert_eq!(step(2, 2, Some(Finding(0)), -1), Some(Finding(0)));
    }

    #[test]
    fn a_section_with_nothing_to_walk_has_no_stop_and_a_stale_stop_is_ignored() {
        assert_eq!(step(0, 0, None, 1), None);
        assert_eq!(step(0, 0, Some(Row(3)), 1), None);
        assert_eq!(step(1, 1, Some(Row(9)), 1), Some(Finding(0)), "a stop past the end restarts");
        assert_eq!(step(0, 3, None, 1), Some(Row(0)));
    }
}
