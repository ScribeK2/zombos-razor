use zombo_core::{
    Finding, Severity,
    propagation::{Agreement, PropagationResult, VantageAnswer, VantageKind},
    target::Target,
};

use crate::{
    section::Section,
    status::{CheckState, Glyph},
};

pub fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::Warning => 1,
        Severity::Info => 2,
        Severity::Ok => 3,
    }
}

pub fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::Warning => "Warning",
        Severity::Info => "Info",
        Severity::Ok => "Ok",
    }
}

pub fn severity_glyph(s: Severity) -> Glyph {
    match s {
        Severity::Critical => Glyph::Octagon,
        Severity::Warning => Glyph::Triangle,
        Severity::Info => Glyph::Info,
        Severity::Ok => Glyph::Check,
    }
}

pub fn ordered(findings: &[Finding]) -> Vec<Finding> {
    let mut out = findings.to_vec();
    out.sort_by_key(|f| severity_rank(f.severity));
    out
}

pub fn problems(findings: &[Finding]) -> usize {
    findings.iter().filter(|f| matches!(f.severity, Severity::Warning | Severity::Critical)).count()
}

pub fn counts(findings: &[Finding]) -> [(Severity, usize); 4] {
    [Severity::Critical, Severity::Warning, Severity::Info, Severity::Ok]
        .map(|s| (s, findings.iter().filter(|f| f.severity == s).count()))
}

pub fn finding_label(f: &Finding) -> String {
    let mut text = format!("{}: {}. {}", severity_word(f.severity), f.title, f.message);
    if let Some(r) = &f.recommendation {
        text.push_str(&format!(" Recommendation: {r}"));
    }
    text
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub word: String,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowStatus {
    Answered,
    Truth,
    Match,
    Stale,
    NoAnswer,
}

impl RowStatus {
    pub fn label(&self) -> &'static str {
        match self {
            RowStatus::Answered => "Answered",
            RowStatus::Truth => "Truth",
            RowStatus::Match => "Match",
            RowStatus::Stale => "Stale",
            RowStatus::NoAnswer => "No answer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub resolver: String,
    pub location: String,
    pub answer: String,
    pub ttl: Option<u32>,
    pub status: RowStatus,
    pub authoritative: bool,
}

impl Row {
    pub fn from_answer(a: &VantageAnswer) -> Row {
        let answer = match &a.error {
            Some(e) => e.clone(),
            None => {
                let parts: Vec<String> = a
                    .answers
                    .iter()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(t, v)| format!("{t} {}", v.join(", ")))
                    .collect();
                if parts.is_empty() { "empty answer".into() } else { parts.join(" \u{b7} ") }
            }
        };
        Row {
            resolver: a.vantage.name.clone(),
            location: a.vantage.location.clone(),
            answer,
            ttl: a.ttl.values().copied().min(),
            status: if a.error.is_some() { RowStatus::NoAnswer } else { RowStatus::Answered },
            authoritative: a.vantage.kind == VantageKind::Authoritative,
        }
    }

    pub fn label(&self) -> String {
        let ttl = self.ttl.map(|t| format!(", TTL {t}")).unwrap_or_default();
        format!("{}, {}, {}{ttl}, {}", self.resolver, self.location, self.answer, self.status.label())
    }
}

pub enum PropEvent {
    Started,
    Answer(Box<VantageAnswer>),
    Finished(Box<Result<PropagationResult, String>>),
    TimedOut,
}

#[derive(Debug, Clone)]
pub struct Propagation {
    pub state: CheckState,
    pub rows: Vec<Row>,
    pub agreement: Option<Agreement>,
    pub findings: Vec<Finding>,
}

impl Propagation {
    pub fn new() -> Self {
        Propagation { state: CheckState::NotRun, rows: vec![], agreement: None, findings: vec![] }
    }

    pub fn apply(&mut self, target: &str, event: PropEvent) {
        match event {
            PropEvent::Started => *self = Propagation { state: CheckState::Running, ..Propagation::new() },
            PropEvent::Answer(a) => {
                if self.state == CheckState::Running {
                    self.rows.push(Row::from_answer(&a));
                }
            }
            PropEvent::TimedOut => {
                if self.state == CheckState::Running {
                    self.state = CheckState::TimedOut;
                }
            }
            PropEvent::Finished(result) => {
                if self.state != CheckState::Running {
                    return;
                }
                match *result {
                    Ok(r) => {
                        self.rows = settled_rows(&r);
                        self.findings = ordered(&zombo_core::propagation::propagation_findings(target, &r));
                        self.agreement = Some(r.agreement);
                        self.state = CheckState::Done { problems: problems(&self.findings) };
                    }
                    Err(reason) => self.state = CheckState::Failed { reason },
                }
            }
        }
    }
}

impl Default for Propagation {
    fn default() -> Self {
        Self::new()
    }
}

fn settled_rows(r: &PropagationResult) -> Vec<Row> {
    let stale: Vec<&str> = r.stale.values().flatten().map(String::as_str).collect();
    r.nameservers
        .iter()
        .chain(&r.resolvers)
        .map(|a| {
            let mut row = Row::from_answer(a);
            if row.status != RowStatus::NoAnswer {
                row.status = if row.authoritative {
                    RowStatus::Truth
                } else if stale.contains(&row.resolver.as_str()) {
                    RowStatus::Stale
                } else {
                    RowStatus::Match
                };
            }
            row
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Tab {
    pub target: Target,
    pub section: Section,
    pub propagation: Propagation,
}

impl Tab {
    pub fn new(target: Target) -> Self {
        Tab { target, section: Section::Dns, propagation: Propagation::new() }
    }

    pub fn state(&self, section: Section) -> CheckState {
        match section {
            Section::Dns => self.propagation.state.clone(),
            Section::Summary => self.summary_state(),
            _ => CheckState::NotRun,
        }
    }

    fn summary_state(&self) -> CheckState {
        let states: Vec<CheckState> = Section::ALL.iter().filter(|&&s| s != Section::Summary).map(|&s| self.state(s)).collect();
        if states.contains(&CheckState::Running) {
            return CheckState::Running;
        }
        let run: Vec<&CheckState> = states.iter().filter(|s| **s != CheckState::NotRun).collect();
        if run.is_empty() {
            return CheckState::NotRun;
        }
        let failed = run.iter().filter(|s| s.can_retry()).count();
        let problems = run.iter().map(|s| if let CheckState::Done { problems } = s { *problems } else { 0 }).sum::<usize>();
        if problems == 0 && failed > 0 {
            return CheckState::Failed { reason: if failed == 1 { "1 Check did not finish".into() } else { format!("{failed} Checks did not finish") } };
        }
        CheckState::Done { problems: problems + failed }
    }

    pub fn findings(&self, section: Section) -> Vec<Finding> {
        match section {
            Section::Dns => self.propagation.findings.clone(),
            Section::Summary => ordered(&self.propagation.findings),
            _ => vec![],
        }
    }

    pub fn verdict(&self, section: Section) -> Verdict {
        let state = self.state(section);
        let v = |w: &str, y: &str| Verdict { word: w.into(), why: y.into() };
        match &state {
            CheckState::NotRun if section == Section::Dns && crate::checks::propagation_name(&self.target).is_none() => {
                v("NOT RUN", "Propagation needs a domain or host name, so it does not apply to an IP address.")
            }
            CheckState::NotRun => v("NOT RUN", &not_run_reason(section)),
            CheckState::Running => v("RUNNING", "Results appear here as each answer arrives."),
            CheckState::Failed { reason } => v("FAILED", reason),
            CheckState::TimedOut => v("TIMED OUT", "The Check did not finish in time. Retry it, or try again from another network."),
            CheckState::Done { problems } => match (section, self.propagation.agreement) {
                (Section::Dns, Some(a)) => v(a.label(), a.reason()),
                _ if *problems == 0 => v("NO PROBLEMS", "Every Check that ran found nothing wrong. Checks that have not run are listed as not run."),
                _ => v(&format!("{problems} PROBLEM{}", if *problems == 1 { "" } else { "S" }), "Read the findings below, worst first."),
            },
        }
    }

    pub fn verdict_glyph(&self, section: Section) -> Glyph {
        let state = self.state(section);
        match (&state, section) {
            (CheckState::Done { .. }, Section::Dns) => match self.propagation.agreement {
                Some(Agreement::Agree) => Glyph::Check,
                Some(Agreement::Cached) | Some(Agreement::Inconclusive) => Glyph::Info,
                _ => Glyph::Triangle,
            },
            _ => state.glyph(),
        }
    }
}

fn not_run_reason(section: Section) -> String {
    match section {
        Section::Dns => "The propagation Check has not started for this target.".into(),
        Section::Summary => "No Check has run for this target yet.".into(),
        s => format!("The {} Check is not part of this build yet, so nothing was checked.", s.label()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use zombo_core::{
        propagation::Vantage,
        target::{Kind, Target},
    };

    use super::*;

    fn finding(sev: Severity, title: &'static str) -> Finding {
        Finding { code: "t", severity: sev, title: title.into(), message: "m".into(), recommendation: None }
    }

    fn answer(name: &str, kind_ns: bool, value: &str) -> VantageAnswer {
        let vantage = if kind_ns {
            Vantage::nameserver(name, "127.0.0.1:53".parse().unwrap())
        } else {
            Vantage::resolver(name, "Global", "127.0.0.1:53".parse().unwrap())
        };
        VantageAnswer {
            vantage,
            rcode: None,
            authoritative: None,
            recursion_available: None,
            answers: BTreeMap::from([("TXT".to_string(), vec![value.to_string()])]),
            ttl: BTreeMap::from([("TXT".to_string(), 54)]),
            failed: vec![],
            soa: None,
            error: None,
        }
    }

    fn result(stale: &[&str]) -> PropagationResult {
        PropagationResult {
            agreement: Agreement::Cached,
            intercepted: false,
            types: vec!["TXT".into()],
            resolvers: vec![answer("Google", false, "new"), answer("Quad9", false, "old")],
            nameservers: vec![answer("ns1", true, "new")],
            disagree: vec!["TXT".into()],
            ns_disagree: vec![],
            stale: BTreeMap::from([("TXT".to_string(), stale.iter().map(|s| s.to_string()).collect())]),
        }
    }

    fn tab() -> Tab {
        Tab::new(Target { value: "example.com".into(), kind: Kind::Domain })
    }

    #[test]
    fn findings_sort_worst_first_and_keep_input_order_within_a_severity() {
        let sorted = ordered(&[
            finding(Severity::Ok, "ok"),
            finding(Severity::Warning, "w1"),
            finding(Severity::Critical, "c"),
            finding(Severity::Info, "i"),
            finding(Severity::Warning, "w2"),
        ]);
        let titles: Vec<_> = sorted.iter().map(|f| f.title.to_string()).collect();
        assert_eq!(titles, ["c", "w1", "w2", "i", "ok"]);
    }

    #[test]
    fn only_warnings_and_criticals_count_as_problems() {
        let f = [finding(Severity::Ok, "a"), finding(Severity::Info, "b"), finding(Severity::Warning, "c"), finding(Severity::Critical, "d")];
        assert_eq!(problems(&f), 2);
        assert_eq!(counts(&f).map(|(_, n)| n), [1, 1, 1, 1]);
    }

    #[test]
    fn a_finding_reads_to_a_screen_reader_with_its_severity_word() {
        let mut f = finding(Severity::Warning, "No DKIM key found");
        f.recommendation = Some("Add one.".into());
        assert_eq!(finding_label(&f), "Warning: No DKIM key found. m Recommendation: Add one.");
    }

    #[test]
    fn answers_stream_into_rows_before_the_result_exists() {
        let mut p = Propagation::new();
        p.apply("example.com", PropEvent::Started);
        p.apply("example.com", PropEvent::Answer(Box::new(answer("Google", false, "v"))));
        assert_eq!(p.state, CheckState::Running);
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0].status, RowStatus::Answered);
        assert_eq!(p.rows[0].answer, "TXT v");
        assert_eq!(p.rows[0].ttl, Some(54));
    }

    #[test]
    fn a_late_answer_after_a_timeout_is_ignored() {
        let mut p = Propagation::new();
        p.apply("e", PropEvent::Started);
        p.apply("e", PropEvent::TimedOut);
        p.apply("e", PropEvent::Answer(Box::new(answer("Google", false, "v"))));
        assert_eq!(p.state, CheckState::TimedOut);
        assert!(p.rows.is_empty());
    }

    #[test]
    fn finishing_settles_every_row_against_the_authoritative_answer() {
        let mut p = Propagation::new();
        p.apply("example.com", PropEvent::Started);
        p.apply("example.com", PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
        let status: Vec<_> = p.rows.iter().map(|r| (r.resolver.as_str(), r.status.clone())).collect();
        assert_eq!(status, [("ns1", RowStatus::Truth), ("Google", RowStatus::Match), ("Quad9", RowStatus::Stale)]);
        assert_eq!(p.agreement, Some(Agreement::Cached));
        assert!(matches!(p.state, CheckState::Done { .. }));
    }

    #[test]
    fn a_failure_keeps_its_reason() {
        let mut p = Propagation::new();
        p.apply("e", PropEvent::Started);
        p.apply("e", PropEvent::Finished(Box::new(Err("none of the resolvers answered".into()))));
        assert_eq!(p.state, CheckState::Failed { reason: "none of the resolvers answered".into() });
    }

    #[test]
    fn an_unanswered_vantage_never_shows_as_a_match() {
        let mut a = answer("Yandex", false, "");
        a.error = Some("timed out".into());
        let mut r = result(&[]);
        r.resolvers.push(a);
        let rows = settled_rows(&r);
        assert_eq!(rows.last().map(|r| r.status.clone()), Some(RowStatus::NoAnswer));
    }

    #[test]
    fn sections_without_a_check_say_not_run_honestly() {
        let t = tab();
        for s in [Section::Delegation, Section::Dnssec, Section::Email, Section::Web, Section::Tls, Section::Registration] {
            assert_eq!(t.state(s), CheckState::NotRun);
            let v = t.verdict(s);
            assert_eq!(v.word, "NOT RUN");
            assert!(v.why.contains("nothing was checked"));
        }
    }

    #[test]
    fn the_dns_verdict_is_the_agreement_after_the_check_finishes() {
        let mut t = tab();
        assert_eq!(t.verdict(Section::Dns).word, "NOT RUN");
        t.propagation.apply("example.com", PropEvent::Started);
        assert_eq!(t.verdict(Section::Dns).word, "RUNNING");
        t.propagation.apply("example.com", PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
        assert_eq!(t.verdict(Section::Dns).word, "CACHED");
    }

    #[test]
    fn summary_follows_the_checks_that_ran_and_never_claims_a_pass_for_none() {
        let mut t = tab();
        assert_eq!(t.state(Section::Summary), CheckState::NotRun);
        t.propagation.apply("e", PropEvent::Started);
        assert_eq!(t.state(Section::Summary), CheckState::Running);
        t.propagation.apply("e", PropEvent::TimedOut);
        assert!(matches!(t.state(Section::Summary), CheckState::Failed { .. }));
    }

    #[test]
    fn a_timed_out_failed_and_done_state_each_get_a_verdict_word() {
        let mut t = tab();
        t.propagation.state = CheckState::TimedOut;
        assert_eq!(t.verdict(Section::Dns).word, "TIMED OUT");
        t.propagation.state = CheckState::Failed { reason: "r".into() };
        assert_eq!(t.verdict(Section::Dns), Verdict { word: "FAILED".into(), why: "r".into() });
    }
}
