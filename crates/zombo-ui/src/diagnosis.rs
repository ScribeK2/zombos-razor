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
    /// This machine's resolver answered otherwise than the truth. Only that row can show it.
    Differs,
    NoAnswer,
}

impl RowStatus {
    pub fn label(&self) -> &'static str {
        match self {
            RowStatus::Answered => "Answered",
            RowStatus::Truth => "Truth",
            RowStatus::Match => "Match",
            RowStatus::Stale => "Stale",
            RowStatus::Differs => "Differs",
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
    /// This machine's own resolver. Shown with the others, never part of the verdict.
    Local(Box<VantageAnswer>),
    Cancelled,
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
    local: Option<VantageAnswer>,
    local_differs: Vec<String>,
    truth_known: bool,
    pub cancelled: bool,
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
            local: None,
            local_differs: vec![],
            truth_known: false,
            cancelled: false,
        }
    }

    pub fn apply(&mut self, target: &Target, event: PropEvent) {
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
            PropEvent::Local(a) => {
                if self.state == CheckState::Running {
                    self.local = Some(*a);
                }
            }
            PropEvent::TimedOut => {
                if self.state == CheckState::Running {
                    self.state = CheckState::TimedOut;
                }
            }
            PropEvent::Cancelled => {
                if self.state == CheckState::Running {
                    let history = std::mem::take(&mut self.history);
                    *self = Propagation { history, cancelled: true, ..Propagation::new() };
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
                        let name = crate::checks::check_name(target).unwrap_or_else(|| target.value.clone());
                        let mut findings = zombo_core::propagation::propagation_findings(&name, &r);
                        findings.extend(crate::record_findings::record_findings(target, &name, &r, &findings));
                        let truth = crate::record_findings::source(&r);
                        self.truth_known = truth.is_some();
                        self.local_differs = match (truth, &self.local) {
                            (Some(t), Some(l)) => crate::this_machine::differs(t, l, &r.types),
                            _ => vec![],
                        };
                        findings.extend(crate::this_machine::finding(&self.local_differs));
                        self.findings = ordered(&findings);
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
        let mut views: Vec<RowView> = self.rows.iter().map(|r| r.view(ty, self.settled, stale)).collect();
        views.extend(self.local.as_ref().map(|l| self.local_view(l, ty)));
        views
    }

    fn local_view(&self, local: &VantageAnswer, ty: RecordKind) -> RowView {
        let mut view = Row::from_answer(local).view(ty, self.settled, &[]);
        if self.settled && view.status != RowStatus::NoAnswer {
            let differs = self.local_differs.iter().any(|t| t == ty.code() || t == "existence");
            view.status = match (self.truth_known, differs) {
                (false, _) => RowStatus::Answered,
                (true, true) => RowStatus::Differs,
                (true, false) => RowStatus::Match,
            };
        }
        view
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
    pub tls_port: crate::tls_port::PortChoice,
}

impl Tab {
    pub fn new(target: Target) -> Self {
        let section = if target.kind == Kind::Ip { Section::Rdns } else { Section::Dns };
        Tab {
            target,
            section,
            propagation: Propagation::new(),
            record: RecordKind::default(),
            runs: HashMap::new(),
            smtp_port: smtp_plan::PORTS[0],
            tls_port: Default::default(),
        }
    }

    pub fn step_port(&mut self, delta: isize) {
        self.smtp_port = crate::cycle::step(&smtp_plan::PORTS, self.smtp_port, delta);
    }

    /// `[` and `]` step through the five chips. A typed port that is not a chip starts at the first.
    pub fn step_tls_port(&mut self, delta: isize) {
        let next = crate::cycle::step(&crate::tls_port::PRESETS, self.tls_port.port(), delta);
        self.tls_port.choose(next);
    }

    pub fn smtp_request(&self) -> smtp_plan::Request {
        smtp_plan::Request::new(self.target.kind, self.smtp_port)
    }

    /// The choices the on-demand Checks run with. A typed TLS port that is not a port is an
    /// error here, so the Check never runs on a port the rep did not ask for.
    pub fn options(&self) -> Result<crate::checks::Options, &'static str> {
        Ok(crate::checks::Options { smtp: self.smtp_request(), tls_port: self.tls_port.to_run()? })
    }

    pub fn cancelled(&self, section: Section) -> bool {
        match section {
            Section::Dns => self.propagation.cancelled,
            Section::Summary => false,
            s => self.runs.get(&s).is_some_and(|r| r.cancelled),
        }
    }

    /// Stop what is running in `section`; on the Summary, everything that is running. Returns the
    /// sections stopped, so the caller can abort their tasks.
    pub fn cancel(&mut self, section: Section) -> Vec<Section> {
        let targets: Vec<Section> = match section {
            Section::Summary => Section::ALL.iter().copied().filter(|&s| s != Section::Summary).collect(),
            s => vec![s],
        };
        let running: Vec<Section> = targets.into_iter().filter(|&s| self.state(s) == CheckState::Running).collect();
        for &s in &running {
            match s {
                Section::Dns => {
                    let target = self.target.clone();
                    self.propagation.apply(&target, PropEvent::Cancelled);
                }
                s => self.run_mut(s).apply(crate::outcome::CheckEvent::Cancelled),
            }
        }
        running
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
            s if self.cancelled(s) => format!(
                "Cancelled. You stopped the {} Check before it finished, so nothing was checked. Press Ctrl+R to run it again.",
                s.label()
            ),
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
    use crate::outcome::CheckEvent;
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

    fn tgt(value: &str) -> Target {
        Target { value: value.into(), kind: Kind::Domain }
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
        p.apply(&tgt("example.com"), PropEvent::Started);
        p.apply(&tgt("example.com"), PropEvent::Answer(Box::new(answer("Google", false, "v"))));
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
        p.apply(&tgt("example.com"), PropEvent::Started);
        p.apply(&tgt("example.com"), PropEvent::Answer(Box::new(answer("Google", false, "v"))));
        let a = p.view(RecordKind::A);
        assert_eq!(a[0].answer, "no record");
        assert_eq!(a[0].ttl, None);
        assert_eq!(p.view(RecordKind::Txt)[0].answer, "v");
    }

    #[test]
    fn staleness_is_judged_per_record_type() {
        let mut p = Propagation::new();
        p.apply(&tgt("example.com"), PropEvent::Started);
        p.apply(&tgt("example.com"), PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
        let status = |ty| p.view(ty).iter().map(|r| r.status.clone()).collect::<Vec<_>>();
        assert_eq!(status(RecordKind::Txt), [RowStatus::Truth, RowStatus::Match, RowStatus::Stale]);
        assert_eq!(status(RecordKind::A), [RowStatus::Truth, RowStatus::Match, RowStatus::Match]);
    }

    #[test]
    fn a_late_answer_after_a_timeout_is_ignored() {
        let mut p = Propagation::new();
        p.apply(&tgt("e"), PropEvent::Started);
        p.apply(&tgt("e"), PropEvent::TimedOut);
        p.apply(&tgt("e"), PropEvent::Answer(Box::new(answer("Google", false, "v"))));
        assert_eq!(p.state, CheckState::TimedOut);
        assert!(p.rows.is_empty());
    }

    #[test]
    fn finishing_settles_every_row_against_the_authoritative_answer() {
        let mut p = Propagation::new();
        p.apply(&tgt("example.com"), PropEvent::Started);
        p.apply(&tgt("example.com"), PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
        let view = p.view(RecordKind::Txt);
        let status: Vec<_> = view.iter().map(|r| (r.resolver.as_str(), r.status.clone())).collect();
        assert_eq!(status, [("ns1", RowStatus::Truth), ("Google", RowStatus::Match), ("Quad9", RowStatus::Stale)]);
        assert_eq!(p.agreement, Some(Agreement::Cached));
        assert!(matches!(p.state, CheckState::Done { .. }));
    }

    #[test]
    fn a_failure_keeps_its_reason() {
        let mut p = Propagation::new();
        p.apply(&tgt("e"), PropEvent::Started);
        p.apply(&tgt("e"), PropEvent::Finished(Box::new(Err("none of the resolvers answered".into()))));
        assert_eq!(p.state, CheckState::Failed { reason: "none of the resolvers answered".into() });
    }

    fn finished_with_local(local: VantageAnswer) -> Propagation {
        let mut r = result(&[]);
        r.types = zombo_core::propagation::Scope::All.types().iter().map(ToString::to_string).collect();
        let mut ns = answer("ns1", true, "x");
        ns.rcode = Some(zombo_core::lookup::Rcode::NoError);
        ns.authoritative = Some(true);
        ns.answers = BTreeMap::from([("TXT".to_string(), vec!["v".to_string()])]);
        r.nameservers = vec![ns];
        r.agreement = Agreement::Agree;
        r.stale = BTreeMap::new();
        r.disagree = vec![];
        let mut p = Propagation::new();
        p.apply(&tgt("example.com"), PropEvent::Started);
        p.apply(&tgt("example.com"), PropEvent::Local(Box::new(local)));
        p.apply(&tgt("example.com"), PropEvent::Finished(Box::new(Ok(r))));
        p
    }

    fn local_answer(txt: &str) -> VantageAnswer {
        let mut l = answer(crate::this_machine::NAME, false, txt);
        l.vantage =
            Vantage::resolver(crate::this_machine::NAME, "Resolver 192.168.1.1", "192.168.1.1:53".parse().unwrap());
        l.rcode = Some(zombo_core::lookup::Rcode::NoError);
        l
    }

    #[test]
    fn this_machine_is_the_last_row_and_matches_when_it_agrees_with_the_truth() {
        let p = finished_with_local(local_answer("v"));
        let last = p.view(RecordKind::Txt).pop().unwrap();
        assert_eq!((last.resolver.as_str(), last.status), (crate::this_machine::NAME, RowStatus::Match));
        assert!(p.findings.iter().all(|f| f.code != crate::this_machine::CODE));
    }

    #[test]
    fn a_rewriting_router_shows_as_a_differing_row_and_a_finding_but_never_changes_the_verdict() {
        let p = finished_with_local(local_answer("rewritten"));
        let last = p.view(RecordKind::Txt).pop().unwrap();
        assert_eq!(last.status, RowStatus::Differs);
        assert!(p.findings.iter().any(|f| f.code == crate::this_machine::CODE));
        assert_eq!(p.agreement, Some(Agreement::Agree), "this machine is not a vote");
        assert!(p.stale.is_empty());
        let on_a = p.view(RecordKind::A).pop().unwrap();
        assert_ne!(on_a.status, RowStatus::Differs, "only the type that differs is flagged");
    }

    #[test]
    fn a_machine_with_no_resolver_says_why_in_its_row() {
        let p = finished_with_local(crate::this_machine::unavailable());
        let last = p.view(RecordKind::A).pop().unwrap();
        assert_eq!(last.status, RowStatus::NoAnswer);
        assert!(last.answer.contains("resolv.conf"), "{}", last.answer);
        assert!(p.findings.iter().all(|f| f.code != crate::this_machine::CODE));
    }

    #[test]
    fn cancelling_a_running_check_returns_it_to_not_run_with_the_note_and_leaves_the_others() {
        let mut t = tab();
        t.run_mut(Section::Web).apply(CheckEvent::Started);
        t.run_mut(Section::Tls).apply(CheckEvent::Started);
        t.propagation.apply(&tgt("example.com"), PropEvent::Started);
        assert_eq!(t.cancel(Section::Web), [Section::Web]);
        assert_eq!(t.state(Section::Web), CheckState::NotRun);
        assert!(t.verdict(Section::Web).why.starts_with("Cancelled."), "{}", t.verdict(Section::Web).why);
        assert_eq!(t.verdict(Section::Web).word, "NOT RUN");
        assert_eq!(t.state(Section::Tls), CheckState::Running);
        assert_eq!(t.cancel(Section::Web), Vec::<Section>::new(), "nothing left to stop in Web");
        assert_eq!(t.cancel(Section::Dns), [Section::Dns]);
        assert!(t.propagation.cancelled && t.propagation.rows.is_empty());
        assert!(t.cancelled(Section::Dns));
    }

    #[test]
    fn cancelling_on_the_summary_stops_every_running_check() {
        let mut t = tab();
        for s in [Section::Web, Section::Registration] {
            t.run_mut(s).apply(CheckEvent::Started);
        }
        t.run_mut(Section::Tls).apply(CheckEvent::Started);
        t.run_mut(Section::Tls).apply(CheckEvent::Finished(Box::new(Err("no".into()))));
        let mut stopped = t.cancel(Section::Summary);
        stopped.sort_by_key(|s| s.index());
        assert_eq!(stopped, [Section::Web, Section::Registration]);
        assert!(matches!(t.state(Section::Tls), CheckState::Failed { .. }), "a finished Check is left alone");
    }

    #[test]
    fn a_dns_answer_that_arrives_after_the_cancel_is_dropped() {
        let mut t = tab();
        let target = tgt("example.com");
        t.propagation.apply(&target, PropEvent::Started);
        t.cancel(Section::Dns);
        t.propagation.apply(&target, PropEvent::Answer(Box::new(answer("Google", false, "v"))));
        assert!(t.propagation.rows.is_empty());
        assert_eq!(t.state(Section::Dns), CheckState::NotRun);
    }

    #[test]
    fn an_unanswered_vantage_never_shows_as_a_match() {
        let mut a = answer("Yandex", false, "");
        a.error = Some("timed out".into());
        let mut r = result(&[]);
        r.resolvers.push(a);
        let mut p = Propagation::new();
        p.apply(&tgt("e"), PropEvent::Started);
        p.apply(&tgt("e"), PropEvent::Finished(Box::new(Ok(r))));
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
        for s in [Section::Ports, Section::Smtp, Section::TlsPort, Section::Blacklist] {
            assert_eq!(t.state(s), CheckState::NotRun);
            assert!(t.verdict(s).why.contains("only when you ask"));
        }
    }

    #[test]
    fn the_tls_port_runs_what_was_chosen_and_never_a_bad_typed_port() {
        let mut t = tab();
        assert_eq!(t.options().map(|o| o.tls_port), Ok(443));
        t.step_tls_port(1);
        assert_eq!(t.options().map(|o| o.tls_port), Ok(465));
        t.step_tls_port(-1);
        t.step_tls_port(-1);
        assert_eq!(t.options().map(|o| o.tls_port), Ok(8443));
        t.tls_port.typed("0");
        assert_eq!(t.options().map(|o| o.tls_port), Err(crate::tls_port::INVALID));
        t.tls_port.typed("2525");
        assert_eq!(t.options().map(|o| o.tls_port), Ok(2525));
    }

    #[test]
    fn an_ip_tab_opens_on_reverse_dns_and_every_other_kind_on_dns() {
        assert_eq!(Tab::new(Target { value: "192.0.2.1".into(), kind: Kind::Ip }).section, Section::Rdns);
        assert_eq!(tab().section, Section::Dns);
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
        p.apply(&tgt("e"), PropEvent::Started);
        p.apply(&tgt("e"), PropEvent::Finished(Box::new(Ok(result(&[])))));
        assert_eq!(p.history.changes, None);
        let mut second = result(&[]);
        second.resolvers = vec![answer("Google", false, "newer")];
        second.nameservers = vec![answer("ns1", true, "newer")];
        p.apply(&tgt("e"), PropEvent::Started);
        p.apply(&tgt("e"), PropEvent::Finished(Box::new(Ok(second))));
        let d = p.history.changes.clone().unwrap();
        assert_eq!(d.added, ["TXT: newer"]);
        assert_eq!(d.removed, ["TXT: new", "TXT: old"]);
    }

    #[test]
    fn the_dns_verdict_is_the_agreement_after_the_check_finishes() {
        let mut t = tab();
        assert_eq!(t.verdict(Section::Dns).word, "NOT RUN");
        t.propagation.apply(&tgt("example.com"), PropEvent::Started);
        assert_eq!(t.verdict(Section::Dns).word, "RUNNING");
        t.propagation.apply(&tgt("example.com"), PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
        assert_eq!(t.verdict(Section::Dns).word, "CACHED");
    }

    #[test]
    fn the_dns_rail_mark_follows_the_agreement_not_the_problem_count() {
        let mut t = tab();
        t.propagation.apply(&tgt("example.com"), PropEvent::Started);
        t.propagation.apply(&tgt("example.com"), PropEvent::Finished(Box::new(Ok(result(&["Quad9"])))));
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
        t.propagation.apply(&tgt("e"), PropEvent::Started);
        assert_eq!(t.state(Section::Summary), CheckState::Running);
        t.propagation.apply(&tgt("e"), PropEvent::TimedOut);
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
