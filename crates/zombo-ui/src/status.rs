#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckState {
    NotRun,
    Running,
    Done { problems: usize },
    Failed { reason: String },
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    Ring,
    Dashed,
    Check,
    Triangle,
    Octagon,
    Clock,
    Info,
}

impl Glyph {
    pub fn asset(self) -> &'static str {
        match self {
            Glyph::Ring => "icons/ring.svg",
            Glyph::Dashed => "icons/dashed.svg",
            Glyph::Check => "icons/check.svg",
            Glyph::Triangle => "icons/triangle.svg",
            Glyph::Octagon => "icons/octagon.svg",
            Glyph::Clock => "icons/clock.svg",
            Glyph::Info => "icons/info.svg",
        }
    }
}

impl CheckState {
    pub fn word(&self) -> &'static str {
        match self {
            CheckState::NotRun => "not run",
            CheckState::Running => "running",
            CheckState::Done { .. } => "done",
            CheckState::Failed { .. } => "failed",
            CheckState::TimedOut => "timed out",
        }
    }

    pub fn label(&self) -> String {
        match self {
            CheckState::Done { problems: 0 } => "done".into(),
            CheckState::Done { problems: 1 } => "done \u{b7} 1 problem".into(),
            CheckState::Done { problems } => format!("done \u{b7} {problems} problems"),
            CheckState::Failed { reason } => format!("failed: {reason}"),
            other => other.word().into(),
        }
    }

    pub fn glyph(&self) -> Glyph {
        match self {
            CheckState::NotRun => Glyph::Ring,
            CheckState::Running => Glyph::Dashed,
            CheckState::Done { problems: 0 } => Glyph::Check,
            CheckState::Done { .. } => Glyph::Triangle,
            CheckState::Failed { .. } => Glyph::Octagon,
            CheckState::TimedOut => Glyph::Clock,
        }
    }

    pub fn can_retry(&self) -> bool {
        matches!(self, CheckState::Failed { .. } | CheckState::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<CheckState> {
        vec![
            CheckState::NotRun,
            CheckState::Running,
            CheckState::Done { problems: 0 },
            CheckState::Done { problems: 2 },
            CheckState::Failed { reason: "no resolver answered".into() },
            CheckState::TimedOut,
        ]
    }

    #[test]
    fn every_state_reads_as_its_own_label() {
        let labels: Vec<_> = all().iter().map(CheckState::label).collect();
        assert_eq!(
            labels,
            ["not run", "running", "done", "done \u{b7} 2 problems", "failed: no resolver answered", "timed out"]
        );
    }

    #[test]
    fn one_problem_is_singular() {
        assert_eq!(CheckState::Done { problems: 1 }.label(), "done \u{b7} 1 problem");
    }

    #[test]
    fn the_five_states_have_five_distinct_shapes() {
        let shapes = [
            CheckState::NotRun.glyph(),
            CheckState::Running.glyph(),
            CheckState::Done { problems: 0 }.glyph(),
            CheckState::Failed { reason: String::new() }.glyph(),
            CheckState::TimedOut.glyph(),
        ];
        for (i, a) in shapes.iter().enumerate() {
            for b in &shapes[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_ne!(CheckState::Done { problems: 3 }.glyph(), CheckState::Done { problems: 0 }.glyph());
    }

    #[test]
    fn only_failed_and_timed_out_offer_retry() {
        let retry: Vec<_> = all().iter().map(CheckState::can_retry).collect();
        assert_eq!(retry, [false, false, false, false, true, true]);
    }
}
