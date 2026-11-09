use std::collections::{BTreeMap, BTreeSet, HashMap};

use zombo_core::{
    Finding, Severity,
    propagation::{Agreement, PropagationResult, VantageAnswer, VantageKind},
    target::{Kind, Target},
};

use crate::{
    outcome::{History, Run},
    record::RecordKind,
    section::Section,
    smtp_plan,
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

/// Findings about the rep's own network, not about the target: every Check that sees one
/// reports the same fact in different words, so the Summary shows it once.
fn is_network_wide(code: &str) -> bool {
    code == "dns_network_intercepts"
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

/// One Vantage's raw answers, for every record type it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub resolver: String,
    pub location: String,
    pub answers: BTreeMap<String, Vec<String>>,
    pub ttls: BTreeMap<String, u32>,
    pub error: Option<String>,
    pub authoritative: bool,
    pub serial: Option<u32>,
}

/// What the table shows for one Vantage and one record type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowView {
    pub resolver: String,
    pub location: String,
    pub answer: String,
    pub ttl: Option<u32>,
    pub status: RowStatus,
    pub authoritative: bool,
}

impl Row {
    pub fn from_answer(a: &VantageAnswer) -> Row {
        Row {
            resolver: a.vantage.name.clone(),
            location: a.vantage.location.clone(),
            answers: a.answers.clone(),
            ttls: a.ttl.clone(),
            error: a.error.clone(),
            authoritative: a.vantage.kind == VantageKind::Authoritative,
            serial: a.soa.as_ref().map(|s| s.serial),
        }
    }

    fn view(&self, ty: RecordKind, settled: bool, stale: &[String]) -> RowView {
        let code = ty.code();
        let values = self.answers.get(code).filter(|v| !v.is_empty());
        let (answer, status) = match &self.error {
            Some(e) => (e.clone(), RowStatus::NoAnswer),
            None => {
                let text = values.map(|v| v.join(", ")).unwrap_or_else(|| "no record".into());
                let status = if !settled {
                    RowStatus::Answered
                } else if self.authoritative {
                    RowStatus::Truth
                } else if stale.contains(&self.resolver) {
                    RowStatus::Stale
                } else {
                    RowStatus::Match
                };
                (text, status)
            }
        };
        RowView {
            resolver: self.resolver.clone(),
            location: self.location.clone(),
            answer,
            ttl: self.ttls.get(code).copied(),
            status,
            authoritative: self.authoritative,
        }
    }
}

impl RowView {
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
    pub settled: bool,
    pub stale: BTreeMap<String, Vec<String>>,
    pub agreement: Option<Agreement>,
    pub findings: Vec<Finding>,
    pub history: History,
}

/// Every record any Vantage returned, as "TYPE: value" lines, for comparing runs.
pub fn propagation_records(r: &PropagationResult) -> Vec<String> {
    let lines: BTreeSet<String> = r
        .nameservers
        .iter()
        .chain(&r.resolvers)
        .flat_map(|a| a.answers.iter().flat_map(|(t, vs)| vs.iter().map(move |v| format!("{t}: {v}"))))
        .collect();
    lines.into_iter().collect()
}

impl Propagation {
    pub fn new() -> Self {
        Propagation {
            state: CheckState::NotRun,
            rows: vec![],
            settled: false,
            stale: BTreeMap::new(),
            agreement: None,
            findings: vec![],
            history: History::default(),
        }
    }

    pub fn apply(&mut self, target: &str, event: PropEvent) {
        match event {
            PropEvent::Started => {
                let history = std::mem::take(&mut self.history);
                *self = Propagation { state: CheckState::Running, history, ..Propagation::new() };
            }
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
                        self.rows = r.nameservers.iter().chain(&r.resolvers).map(Row::from_answer).collect();
                        self.stale = r.stale.clone();
                        self.settled = true;
                        self.history.settle(propagation_records(&r));
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

impl Propagation {
    pub fn view(&self, ty: RecordKind) -> Vec<RowView> {
        let stale = self.stale.get(ty.code()).map(Vec::as_slice).unwrap_or(&[]);
        self.rows.iter().map(|r| r.view(ty, self.settled, stale)).collect()
    }
}

#[derive(Debug, Clone)]
pub struct Tab {
    pub target: Target,
    pub section: Section,
    pub propagation: Propagation,
    pub record: RecordKind,
    pub runs: HashMap<Section, Run>,
    pub smtp_port: u16,
}

impl Tab {
    pub fn new(target: Target) -> Self {
        Tab {
            target,
            section: Section::Dns,
            propagation: Propagation::new(),
            record: RecordKind::default(),
            runs: HashMap::new(),
            smtp_port: smtp_plan::PORTS[0],
        }
    }

    pub fn step_port(&mut self, delta: isize) {
        let i = smtp_plan::PORTS.iter().position(|&p| p == self.smtp_port).unwrap_or(0) as isize;
        self.smtp_port = smtp_plan::PORTS[(i + delta).rem_euclid(smtp_plan::PORTS.len() as isize) as usize];
    }

    pub fn smtp_request(&self) -> smtp_plan::Request {
        smtp_plan::Request::new(self.target.kind, self.smtp_port)
    }

    pub fn run_mut(&mut self, section: Section) -> &mut Run {
        self.runs.entry(section).or_default()
    }

    pub fn state(&self, section: Section) -> CheckState {
        match section {
            Section::Dns => self.propagation.state.clone(),
            Section::Summary => self.summary_state(),
            s => self.runs.get(&s).map(|r| r.state.clone()).unwrap_or(CheckState::NotRun),
        }
    }

    /// `None` until the Check has finished. `Some(None)` when it finished without an
    /// answer (failed or timed out), `Some(Some(records))` when it answered.
    pub fn settled(&self, section: Section) -> Option<Option<Vec<String>>> {
        match self.state(section) {
            CheckState::Done { .. } => Some(self.records(section)),
            CheckState::Failed { .. } | CheckState::TimedOut => Some(None),
            CheckState::NotRun | CheckState::Running => None,
        }
    }

    /// The records of the last run that finished with an answer.
    pub fn records(&self, section: Section) -> Option<Vec<String>> {
        self.history(section).and_then(|h| h.records()).map(<[String]>::to_vec)
    }

    pub fn history(&self, section: Section) -> Option<&History> {
        match section {
            Section::Dns => Some(&self.propagation.history),
            Section::Summary => None,
            s => self.runs.get(&s).map(|r| &r.history),
        }
    }

    fn summary_state(&self) -> CheckState {
        let states: Vec<CheckState> =
            Section::ALL.iter().filter(|&&s| s != Section::Summary).map(|&s| self.state(s)).collect();
        if states.contains(&CheckState::Running) {
            return CheckState::Running;
        }
        let run: Vec<&CheckState> = states.iter().filter(|s| **s != CheckState::NotRun).collect();
        if run.is_empty() {
            return CheckState::NotRun;
        }
        let failed = run.iter().filter(|s| s.can_retry()).count();
        let problems = problems(&self.findings(Section::Summary));
        if problems == 0 && failed > 0 {
            return CheckState::Failed {
                reason: if failed == 1 {
                    "1 Check did not finish".into()
                } else {
                    format!("{failed} Checks did not finish")
                },
            };
        }
        CheckState::Done { problems: problems + failed }
    }

    pub fn findings(&self, section: Section) -> Vec<Finding> {
        match section {
            Section::Dns => self.propagation.findings.clone(),
            Section::Summary => {
                let mut seen = BTreeSet::new();
                let all: Vec<Finding> = Section::ALL
                    .iter()
                    .filter(|&&s| s != Section::Summary)
                    .flat_map(|&s| self.findings(s))
                    .filter(|f| {
                        seen.insert((f.code, if is_network_wide(f.code) { String::new() } else { f.message.clone() }))
                    })
                    .collect();
                ordered(&all)
            }
            s => self.runs.get(&s).map(|r| r.outcome.findings.clone()).unwrap_or_default(),
        }
    }

    pub fn verdict(&self, section: Section) -> Verdict {
        let state = self.state(section);
        let v = |w: &str, y: &str| Verdict { word: w.into(), why: y.into() };
        match &state {
            CheckState::NotRun => v("NOT RUN", &self.not_run_reason(section)),
            CheckState::Running => v("RUNNING", "Results appear here as each answer arrives."),
            CheckState::Failed { reason } => v("FAILED", reason),
            CheckState::TimedOut => {
                v("TIMED OUT", "The Check did not finish in time. Retry it, or try again from another network.")
            }
            CheckState::Done { problems } => match (section, self.propagation.agreement) {
                (Section::Dns, Some(a)) => v(a.label(), a.reason()),
                _ if *problems == 0 && section == Section::Summary => v(
                    "NO PROBLEMS",
                    "Every Check that ran found nothing wrong. Checks that have not run are listed as not run.",
                ),
                _ if *problems == 0 => {
                    v("NO PROBLEMS", "This Check found nothing wrong. Read the findings below for what it looked at.")
                }
                _ => v(
                    &format!("{problems} PROBLEM{}", if *problems == 1 { "" } else { "S" }),
                    "Read the findings below, worst first.",
                ),
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

impl Tab {
    fn not_run_reason(&self, section: Section) -> String {
        let kind = self.target.kind;
        match section {
            Section::Summary => "No Check has run for this target yet.".into(),
            s if s.is_on_demand() => format!(
                "The {} Check runs only when you ask for it, because it connects to the target's servers or sends many queries. Nothing was checked yet. Press Run, or Ctrl+R in this section.",
                s.label()
            ),
            s if kind == Kind::Ip => {
                format!("The {} Check needs a domain or host name, so it does not apply to an IP address.", s.label())
            }
            s if !crate::checks::automatic(kind).contains(&s) => {
                format!("The {} Check does not start on its own for a host name. Press Ctrl+R to run it.", s.label())
            }
            s => format!("The {} Check has not started for this target.", s.label()),
        }
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
        let f = [
            finding(Severity::Ok, "a"),
            finding(Severity::Info, "b"),
            finding(Severity::Warning, "c"),
            finding(Severity::Critical, "d"),
        ];
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
        let rows = p.view(RecordKind::Txt);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, RowStatus::Answered);
        assert_eq!(rows[0].answer, "v");
        assert_eq!(rows[0].ttl, Some(54));
    }

    #[test]
    fn the_table_shows_one_record_type_at_a_time() {
        let mut p = Propagation::new();
        p.apply("example.com", PropEvent::Started);
        p.apply("example.com", PropEvent::Answer(Box::new(answer("Google", false, "v"))));
        let a = p.view(RecordKind::A);
        assert_eq!(a[0].answer, "no record");
        assert_eq!(a[0].ttl, None);
        assert_eq!(p.view(RecordKind::Txt)[0].answer, "v");
    }

    #[test]
    fn staleness_is_judged_per_record_type() {
        let mut p = Propagation::new();
        p.apply("example.com", PropEvent::Started);
        p.apply("example.com", PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
        let status = |ty| p.view(ty).iter().map(|r| r.status.clone()).collect::<Vec<_>>();
        assert_eq!(status(RecordKind::Txt), [RowStatus::Truth, RowStatus::Match, RowStatus::Stale]);
        assert_eq!(status(RecordKind::A), [RowStatus::Truth, RowStatus::Match, RowStatus::Match]);
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
        let view = p.view(RecordKind::Txt);
        let status: Vec<_> = view.iter().map(|r| (r.resolver.as_str(), r.status.clone())).collect();
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
        let mut p = Propagation::new();
        p.apply("e", PropEvent::Started);
        p.apply("e", PropEvent::Finished(Box::new(Ok(r))));
        assert_eq!(p.view(RecordKind::Txt).last().map(|r| r.status.clone()), Some(RowStatus::NoAnswer));
    }

    #[test]
    fn sections_that_have_not_run_say_not_run_honestly() {
        let t = tab();
        for s in
            [Section::Delegation, Section::Dnssec, Section::Email, Section::Web, Section::Tls, Section::Registration]
        {
            assert_eq!(t.state(s), CheckState::NotRun);
            let v = t.verdict(s);
            assert_eq!(v.word, "NOT RUN");
            assert!(v.why.contains("has not started"), "{}", v.why);
        }
        for s in [Section::Ports, Section::Smtp, Section::Blacklist] {
            assert_eq!(t.state(s), CheckState::NotRun);
            assert!(t.verdict(s).why.contains("only when you ask"));
        }
    }

    #[test]
    fn an_ip_address_and_a_host_name_explain_why_a_check_does_not_start() {
        let ip = Tab::new(Target { value: "192.0.2.1".into(), kind: Kind::Ip });
        assert!(ip.verdict(Section::Dns).why.contains("does not apply to an IP address"));
        let host = Tab::new(Target { value: "www.example.com".into(), kind: Kind::Hostname });
        assert!(host.verdict(Section::Dnssec).why.contains("Ctrl+R"));
        assert!(host.verdict(Section::Web).why.contains("has not started"));
    }

    #[test]
    fn a_wired_check_streams_into_its_own_section_and_the_summary() {
        use crate::outcome::{CheckEvent, Outcome};
        let mut t = tab();
        let f = finding(Severity::Warning, "w");
        t.run_mut(Section::Registration).apply(CheckEvent::Started);
        assert_eq!(t.state(Section::Summary), CheckState::Running);
        t.run_mut(Section::Registration)
            .apply(CheckEvent::Finished(Box::new(Ok(Outcome { findings: vec![f], ..Outcome::default() }))));
        assert_eq!(t.state(Section::Registration), CheckState::Done { problems: 1 });
        assert_eq!(t.state(Section::Dns), CheckState::NotRun);
        assert_eq!(t.findings(Section::Summary).len(), 1);
        assert_eq!(t.verdict(Section::Registration).word, "1 PROBLEM");
    }

    #[test]
    fn the_summary_lists_a_finding_that_several_checks_share_once() {
        use crate::outcome::{CheckEvent, Outcome};
        let mut t = tab();
        for s in [Section::Delegation, Section::Dnssec] {
            t.run_mut(s).apply(CheckEvent::Started);
            t.run_mut(s).apply(CheckEvent::Finished(Box::new(Ok(Outcome {
                findings: vec![finding(Severity::Warning, "dns_network_intercepts")],
                ..Outcome::default()
            }))));
        }
        assert_eq!(t.findings(Section::Delegation).len(), 1);
        assert_eq!(t.findings(Section::Summary).len(), 1);
    }

    #[test]
    fn a_network_wide_finding_with_different_wording_is_listed_once_and_counted_once() {
        use crate::outcome::{CheckEvent, Outcome};
        let mut t = tab();
        for (s, text) in [(Section::Delegation, "ns2 and ns1 answered"), (Section::Dnssec, "ns1 and ns2 answered")] {
            let mut f = finding(Severity::Warning, "This network appears to intercept DNS");
            f.code = "dns_network_intercepts";
            f.message = text.to_string();
            t.run_mut(s).apply(CheckEvent::Started);
            t.run_mut(s).apply(CheckEvent::Finished(Box::new(Ok(Outcome { findings: vec![f], ..Outcome::default() }))));
        }
        assert_eq!(t.findings(Section::Summary).len(), 1);
        assert_eq!(t.state(Section::Summary), CheckState::Done { problems: 1 });
    }

    #[test]
    fn a_tab_reports_a_settled_check_for_the_watch_and_nothing_while_it_runs() {
        use crate::outcome::{CheckEvent, Fact, Outcome};
        let mut t = tab();
        assert_eq!(t.settled(Section::Web), None);
        t.run_mut(Section::Web).apply(CheckEvent::Started);
        assert_eq!(t.settled(Section::Web), None);
        let o = Outcome { facts: vec![Fact::new("Status", "200")], ..Outcome::default() };
        t.run_mut(Section::Web).apply(CheckEvent::Finished(Box::new(Ok(o))));
        assert_eq!(t.settled(Section::Web), Some(Some(vec!["Status: 200".to_string()])));
        t.run_mut(Section::Web).apply(CheckEvent::Started);
        t.run_mut(Section::Web).apply(CheckEvent::TimedOut);
        assert_eq!(t.settled(Section::Web), Some(None));
    }

    #[test]
    fn a_propagation_rerun_reports_records_added_and_removed() {
        let mut p = Propagation::new();
        p.apply("e", PropEvent::Started);
        p.apply("e", PropEvent::Finished(Box::new(Ok(result(&[])))));
        assert_eq!(p.history.changes, None);
        let mut second = result(&[]);
        second.resolvers = vec![answer("Google", false, "newer")];
        second.nameservers = vec![answer("ns1", true, "newer")];
        p.apply("e", PropEvent::Started);
        p.apply("e", PropEvent::Finished(Box::new(Ok(second))));
        let d = p.history.changes.clone().unwrap();
        assert_eq!(d.added, ["TXT: newer"]);
        assert_eq!(d.removed, ["TXT: new", "TXT: old"]);
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
    fn the_dns_rail_mark_follows_the_agreement_not_the_problem_count() {
        let mut t = tab();
        t.propagation.apply("example.com", PropEvent::Started);
        t.propagation.apply("example.com", PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
        assert_eq!(t.verdict_glyph(Section::Dns), Glyph::Info);
        assert_eq!(t.verdict_glyph(Section::Web), Glyph::Ring);
    }

    #[test]
    fn the_smtp_port_steps_through_the_three_ports_and_a_domain_asks_for_mx() {
        let mut t = tab();
        assert_eq!(t.smtp_request(), smtp_plan::Request { port: 25, via_mx: true });
        t.step_port(1);
        t.step_port(1);
        assert_eq!(t.smtp_port, 465);
        t.step_port(1);
        assert_eq!(t.smtp_port, 25);
        t.step_port(-1);
        assert_eq!(t.smtp_port, 465);
        let host = Tab::new(Target { value: "mail.example.com".into(), kind: Kind::Hostname });
        assert!(!host.smtp_request().via_mx);
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
