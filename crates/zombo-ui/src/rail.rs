use zombo_core::{Finding, Severity};

use crate::{section::Section, status::CheckState};

/// The quiet text at the right of a rail item, as the sketch shows it: "done", "done · 1 note",
/// "done · 1 warning", and for the Summary "2 problems". Problems are warnings and criticals;
/// info findings are notes. A finished Check that has problems names them and drops the notes,
/// so the line fits the rail. Every state keeps its text label.
pub fn count_line(section: Section, state: &CheckState, findings: &[Finding]) -> String {
    let CheckState::Done { problems } = state else { return state.label() };
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    let (warnings, criticals, notes) = (count(Severity::Warning), count(Severity::Critical), count(Severity::Info));
    let tail = match *problems {
        0 if notes == 0 => None,
        0 => Some(plural(notes, "note")),
        p if section == Section::Summary => Some(plural(p, "problem")),
        p if p == warnings => Some(plural(p, "warning")),
        p if p == criticals => Some(format!("{p} critical")),
        p => Some(plural(p, "problem")),
    };
    match (section, tail) {
        (_, None) => "done".into(),
        (Section::Summary, Some(t)) if *problems > 0 => t,
        (_, Some(t)) => format!("done \u{b7} {t}"),
    }
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(severity: Severity) -> Finding {
        Finding { code: "t", severity, title: "t".into(), message: String::new(), recommendation: None }
    }

    fn line(section: Section, problems: usize, sev: &[Severity]) -> String {
        let findings: Vec<_> = sev.iter().map(|&s| f(s)).collect();
        count_line(section, &CheckState::Done { problems }, &findings)
    }

    #[test]
    fn a_clean_check_just_says_done() {
        assert_eq!(line(Section::Delegation, 0, &[Severity::Ok, Severity::Ok]), "done");
    }

    #[test]
    fn info_findings_count_as_notes() {
        assert_eq!(line(Section::Dns, 0, &[Severity::Info, Severity::Ok]), "done \u{b7} 1 note");
        assert_eq!(line(Section::Dns, 0, &[Severity::Info, Severity::Info]), "done \u{b7} 2 notes");
    }

    #[test]
    fn warnings_and_criticals_are_the_problems() {
        assert_eq!(line(Section::Email, 1, &[Severity::Warning, Severity::Ok]), "done \u{b7} 1 warning");
        assert_eq!(line(Section::Email, 2, &[Severity::Warning, Severity::Warning]), "done \u{b7} 2 warnings");
        assert_eq!(line(Section::Tls, 1, &[Severity::Critical]), "done \u{b7} 1 critical");
        assert_eq!(line(Section::Tls, 3, &[Severity::Critical, Severity::Warning, Severity::Warning]), "done \u{b7} 3 problems");
    }

    #[test]
    fn problems_win_over_notes() {
        assert_eq!(line(Section::Web, 1, &[Severity::Warning, Severity::Info, Severity::Info]), "done \u{b7} 1 warning");
    }

    #[test]
    fn the_summary_leads_with_the_problem_count() {
        assert_eq!(line(Section::Summary, 2, &[Severity::Warning, Severity::Warning, Severity::Info]), "2 problems");
        assert_eq!(line(Section::Summary, 1, &[]), "1 problem");
        assert_eq!(line(Section::Summary, 0, &[Severity::Info]), "done \u{b7} 1 note");
        assert_eq!(line(Section::Summary, 0, &[]), "done");
    }

    #[test]
    fn a_check_that_did_not_finish_keeps_its_own_label() {
        for state in [CheckState::NotRun, CheckState::Running, CheckState::TimedOut, CheckState::Failed { reason: "no answer".into() }] {
            assert_eq!(count_line(Section::Dns, &state, &[f(Severity::Warning)]), state.label());
        }
    }
}
