//! The Evidence tab: pasted headers or a pasted mail log, analysed by
//! `zombo_core::evidence`. This module holds no UI and no I/O. The pasted text
//! itself lives only in the paste pane's text area and in the analysis task
//! that owns a copy, so it never reaches a file.

use zombo_core::{
    Finding,
    evidence::{
        headers::{self, HeaderAnalysis},
        maillog::{self, MailLogAnalysis},
    },
};

use crate::{
    diagnosis::{ordered, problems, severity_word},
    outcome::Fact,
    status::{CheckState, Glyph},
};

/// The most pasted text accepted. Core accepts 4 MiB; the window stays quick at this size.
pub const MAX_PASTE: usize = 1 << 20;

/// How much of the text the sniffer reads. A header block or a log shows its kind at the top.
const SNIFF_BYTES: usize = 64 * 1024;
const SNIFF_LINES: usize = 200;

/// Hops, messages and recipient lines shown open before the rest is collapsed.
const OPEN_ROWS: usize = 8;
const RECIPIENTS_PER_MESSAGE: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Headers,
    MailLog,
}

impl Kind {
    pub const ALL: [Kind; 2] = [Kind::Headers, Kind::MailLog];

    pub fn label(self) -> &'static str {
        match self {
            Kind::Headers => "Headers",
            Kind::MailLog => "Mail log",
        }
    }

    pub fn noun(self) -> &'static str {
        match self {
            Kind::Headers => "email headers",
            Kind::MailLog => "a mail log",
        }
    }
}

const HEADER_NAMES: &[&str] = &[
    "received",
    "from",
    "to",
    "subject",
    "date",
    "message-id",
    "return-path",
    "reply-to",
    "authentication-results",
    "received-spf",
    "dkim-signature",
    "delivered-to",
    "mime-version",
    "x-originating-ip",
];

fn is_header_line(line: &str) -> bool {
    line.split_once(':').is_some_and(|(name, _)| HEADER_NAMES.iter().any(|h| name.eq_ignore_ascii_case(h)))
}

/// A Postfix log line carries `postfix/<daemon>[pid]:` after the host name.
fn is_log_line(line: &str) -> bool {
    let Some(at) = line.find(" postfix/").or_else(|| line.find("/postfix/")) else { return false };
    let rest = &line[at + 1..];
    rest.find('[').is_some_and(|b| {
        rest[b + 1..].find("]:").is_some_and(|e| rest[b + 1..b + 1 + e].bytes().all(|c| c.is_ascii_digit()))
    })
}

/// Guess what the text is. `None` when it looks like neither, so the rep chooses.
pub fn sniff(text: &str) -> Option<Kind> {
    let mut end = text.len().min(SNIFF_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let (mut headers, mut logs) = (0, 0);
    for line in text[..end].lines().take(SNIFF_LINES) {
        if is_log_line(line) {
            logs += 1;
        } else if is_header_line(line) {
            headers += 1;
        }
    }
    match (headers, logs) {
        (0, 0) => None,
        (h, l) if h > l => Some(Kind::Headers),
        (h, l) if l > h => Some(Kind::MailLog),
        _ => None,
    }
}

/// `Err` carries the message the rep reads when the paste is too large.
pub fn check_size(bytes: usize) -> Result<(), String> {
    if bytes > MAX_PASTE {
        Err(format!(
            "That text is {} KiB. The limit is 1 MiB, so nothing was pasted. Paste only the part you need.",
            bytes.div_ceil(1024)
        ))
    } else {
        Ok(())
    }
}

/// Control characters other than a newline become a replacement mark, so a hostile paste cannot
/// move the cursor or hide text. A tab is a space.
pub fn display_text(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' => c,
            '\r' => '\u{fffd}',
            '\t' => ' ',
            c if c.is_control() => '\u{fffd}',
            c => c,
        })
        .collect::<String>()
        .replace("\u{fffd}\n", "\n")
}

/// `Headers 14:03 UTC`. The wall clock here is UTC: a local offset is not safely readable in a
/// threaded process.
pub fn tab_label(kind: Kind, unix_secs: u64) -> String {
    let day = unix_secs % 86_400;
    format!("{} {:02}:{:02} UTC", kind.label(), day / 3600, day % 3600 / 60)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Path,
    Authentication,
    Timeline,
    Findings,
}

impl Section {
    pub fn label(self) -> &'static str {
        match self {
            Section::Path => "Message path",
            Section::Authentication => "Authentication",
            Section::Timeline => "Timeline",
            Section::Findings => "Findings",
        }
    }
}

pub fn sections(kind: Kind) -> &'static [Section] {
    match kind {
        Kind::Headers => &[Section::Path, Section::Authentication, Section::Findings],
        Kind::MailLog => &[Section::Timeline, Section::Findings],
    }
}

#[derive(Debug, Clone)]
pub enum Analysis {
    Headers(Box<HeaderAnalysis>),
    MailLog(Box<MailLogAnalysis>),
}

#[derive(Debug, Clone)]
pub struct Report {
    pub analysis: Analysis,
    pub findings: Vec<Finding>,
}

/// Pure and CPU-bound: the app runs it on a blocking thread.
pub fn analyse(kind: Kind, text: &str) -> Result<Report, String> {
    check_size(text.len())?;
    match kind {
        Kind::Headers => {
            let a = headers::analyse_headers(text).map_err(|e| e.to_string())?;
            let findings = ordered(&headers::header_findings(&a));
            Ok(Report { analysis: Analysis::Headers(Box::new(a)), findings })
        }
        Kind::MailLog => {
            let a = maillog::analyse_maillog(text).map_err(|e| e.to_string())?;
            let findings = ordered(&maillog::maillog_findings(&a));
            Ok(Report { analysis: Analysis::MailLog(Box::new(a)), findings })
        }
    }
}

#[derive(Debug, Clone)]
pub enum Stage {
    Paste,
    Analysing,
    Done(Box<Report>),
}

#[derive(Debug, Clone)]
pub struct EvidenceTab {
    pub id: u64,
    pub label: String,
    /// What the rep chose, starting from what the command asked for.
    pub kind: Kind,
    pub suggested: Option<Kind>,
    /// Set once the rep picks a kind; the sniffed suggestion then stops changing `kind`.
    pub overridden: bool,
    pub stage: Stage,
    pub section: Section,
    /// The last thing to tell the rep in the paste pane: too large, not this kind, and so on.
    pub notice: Option<String>,
}

impl EvidenceTab {
    pub fn new(id: u64, kind: Kind, unix_secs: u64) -> Self {
        EvidenceTab {
            id,
            label: tab_label(kind, unix_secs),
            kind,
            suggested: None,
            overridden: false,
            stage: Stage::Paste,
            section: sections(kind)[0],
            notice: None,
        }
    }

    pub fn report(&self) -> Option<&Report> {
        match &self.stage {
            Stage::Done(r) => Some(r),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: Kind) {
        self.kind = kind;
        self.section = sections(kind)[0];
    }

    pub fn state(&self, section: Section) -> CheckState {
        match &self.stage {
            Stage::Paste => CheckState::NotRun,
            Stage::Analysing => CheckState::Running,
            Stage::Done(r) => CheckState::Done { problems: section_problems(r, section) },
        }
    }

    /// What the rail shows for a section: the state's glyph and label, except that a section
    /// with no problems carries its own verdict, so "Not reported" never looks like a pass.
    pub fn mark(&self, section: Section) -> Mark {
        let state = self.state(section);
        let Some(report) = self.report().filter(|_| section != Section::Findings) else {
            return Mark { glyph: state.glyph(), label: state.label() };
        };
        if matches!(state, CheckState::Done { problems: 0 }) {
            let v = view(report, section);
            let glyph = if v.glyph == Glyph::Info { Glyph::Info } else { Glyph::Check };
            return Mark { glyph, label: v.word.to_lowercase() };
        }
        Mark { glyph: state.glyph(), label: state.label() }
    }

    pub fn choose(&mut self, kind: Kind) {
        self.overridden = true;
        self.set_kind(kind);
    }

    /// Sniffs the text. The suggestion steers `kind` only until the rep has chosen one.
    pub fn suggest(&mut self, text: &str) {
        self.suggested = sniff(text);
        if let Some(k) = self.suggested.filter(|&k| !self.overridden && k != self.kind) {
            self.set_kind(k);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub glyph: Glyph,
    pub label: String,
}

/// Header findings that are about the route and the clock, not about who the sender is.
const PATH_CODES: &[&str] = &[
    "email_headers_delayed",
    "email_headers_clock_skew",
    "email_headers_too_many_hops",
    "email_headers_truncated",
    "email_headers_multiple_from",
];

/// The warnings and criticals that belong to one rail section. Findings counts them all.
pub fn section_problems(report: &Report, section: Section) -> usize {
    let own = |f: &Finding| match (&report.analysis, section) {
        (_, Section::Findings) | (Analysis::MailLog(_), _) => true,
        (Analysis::Headers(_), Section::Path) => PATH_CODES.contains(&f.code),
        (Analysis::Headers(_), _) => !PATH_CODES.contains(&f.code),
    };
    let mine: Vec<Finding> = report.findings.iter().filter(|f| own(f)).cloned().collect();
    problems(&mine)
}

#[derive(Debug, Clone)]
pub struct Disclosure {
    pub id: &'static str,
    pub title: String,
    pub rows: Vec<Fact>,
}

/// Everything one rail section shows.
#[derive(Debug, Clone)]
pub struct View {
    pub word: String,
    pub why: String,
    pub glyph: Glyph,
    pub findings: Vec<Finding>,
    pub rows: Vec<Fact>,
    pub disclosures: Vec<Disclosure>,
}

fn secs(n: i64) -> String {
    let (sign, n) = if n < 0 { ("-", n.unsigned_abs()) } else { ("", n.unsigned_abs()) };
    match n {
        0..=59 => format!("{sign}{n} s"),
        60..=3599 => format!("{sign}{} min {} s", n / 60, n % 60),
        _ => format!("{sign}{} h {} min", n / 3600, n % 3600 / 60),
    }
}

fn ip(ip: Option<std::net::IpAddr>) -> String {
    ip.map(|i| format!(" [{i}]")).unwrap_or_default()
}

fn push_if(rows: &mut Vec<Fact>, key: &str, value: &str) {
    if !value.trim().is_empty() {
        rows.push(Fact::new(key, value));
    }
}

fn path_view(a: &HeaderAnalysis) -> View {
    let mut rows = Vec::new();
    let h = &a.headers;
    for (k, v) in [
        ("From", &h.from),
        ("To", &h.to),
        ("Subject", &h.subject),
        ("Date", &h.date),
        ("Message-ID", &h.message_id),
        ("Return-Path", &h.return_path),
        ("Reply-To", &h.reply_to),
    ] {
        push_if(&mut rows, k, v);
    }
    let hops: Vec<Fact> = a
        .hops
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            let mut v = format!("{}{} to {}", orunknown(&hop.from_host), ip(hop.from_ip), orunknown(&hop.by_host));
            if !hop.with.is_empty() {
                v.push_str(&format!(" with {}", hop.with));
            }
            if let Some(at) = hop.at {
                let off = at.offset();
                v.push_str(&format!(
                    " at {} {:02}:{:02}:{:02} {:+03}:{:02}",
                    at.date(),
                    at.hour(),
                    at.minute(),
                    at.second(),
                    off.whole_hours(),
                    off.minutes_past_hour().abs()
                ));
            }
            if let Some(d) = hop.delay_s {
                v.push_str(&format!(", {} after the previous hop", secs(d)));
            }
            Fact::new(format!("Hop {}", i + 1), v)
        })
        .collect();
    let (word, why, glyph) = match (a.hops.len(), a.total_transit_s) {
        (0, _) => {
            ("No Received headers".to_string(), "The pasted headers hold no hop to follow.".to_string(), Glyph::Info)
        }
        (n, Some(t)) => (
            format!("{n} hops"),
            format!("The message took {} from the first server to the last.", secs(t)),
            Glyph::Info,
        ),
        (n, None) => (
            if n == 1 { "1 hop".into() } else { format!("{n} hops") },
            "The hops carry too few dates to time the journey.".into(),
            Glyph::Info,
        ),
    };
    let mut disclosures = Vec::new();
    if hops.len() > OPEN_ROWS {
        disclosures.push(Disclosure { id: "ev-hops", title: "All hops, oldest first".into(), rows: hops });
    } else {
        rows.extend(hops);
    }
    let mut seen: Vec<Fact> = a.extracted.ips.iter().map(|i| Fact::new("Address", i.to_string())).collect();
    seen.extend(a.extracted.hosts.iter().map(|h| Fact::new("Host", h)));
    if !seen.is_empty() {
        disclosures.push(Disclosure { id: "ev-seen", title: "Addresses and hosts in the headers".into(), rows: seen });
    }
    View { word, why, glyph, findings: Vec::new(), rows, disclosures }
}

fn orunknown(s: &str) -> &str {
    if s.is_empty() { "an unknown server" } else { s }
}

fn verdict_text(v: &Option<headers::Verdict>) -> String {
    v.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "not reported".into())
}

fn yes_no(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "aligned",
        Some(false) => "not aligned",
        None => "not known",
    }
}

fn auth_view(a: &HeaderAnalysis) -> View {
    use headers::Verdict::{Fail, Pass};
    let au = &a.auth;
    let all = [&au.spf, &au.dkim, &au.dmarc];
    let (word, glyph) = if all.iter().all(|v| v.is_none()) {
        ("Not reported", Glyph::Info)
    } else if all.iter().any(|v| matches!(v, Some(Fail))) {
        ("Failed", Glyph::Octagon)
    } else if all.iter().all(|v| **v == Some(Pass)) {
        ("Passed", Glyph::Check)
    } else {
        ("Partly passed", Glyph::Triangle)
    };
    let why =
        format!("SPF {}, DKIM {}, DMARC {}.", verdict_text(&au.spf), verdict_text(&au.dkim), verdict_text(&au.dmarc));
    let mut rows = vec![
        Fact::new("SPF", verdict_text(&au.spf)),
        Fact::new("DKIM", verdict_text(&au.dkim)),
        Fact::new("DMARC", verdict_text(&au.dmarc)),
    ];
    if au.compauth.is_some() {
        rows.push(Fact::new("Composite authentication", verdict_text(&au.compauth)));
    }
    let al = &a.alignment;
    rows.push(Fact::new("From domain", &al.from_domain));
    rows.push(Fact::new("Return-Path", yes_no(al.from_return_path_aligned)));
    rows.push(Fact::new("DKIM signing domain", yes_no(al.dkim_aligned)));
    rows.push(Fact::new("Message-ID", yes_no(al.message_id_aligned)));
    let mut disclosures = Vec::new();
    if !au.dkim_signatures.is_empty() {
        let rows = au
            .dkim_signatures
            .iter()
            .map(|s| Fact::new("DKIM-Signature", format!("d={} s={}", s.domain, s.selector)))
            .collect();
        disclosures.push(Disclosure { id: "ev-dkim", title: "DKIM signatures as written (not verified)".into(), rows });
    }
    let sp = &a.spam;
    let mut spam = Vec::new();
    if let Some(s) = sp.score {
        spam.push(Fact::new(
            "Spam score",
            format!("{s}{}", sp.required.map(|r| format!(" of {r}")).unwrap_or_default()),
        ));
    }
    if let Some(n) = sp.scl {
        spam.push(Fact::new("Spam confidence level", n.to_string()));
    }
    if !spam.is_empty() {
        disclosures.push(Disclosure { id: "ev-spam", title: "Spam signals".into(), rows: spam });
    }
    View { word: word.into(), why, glyph, findings: Vec::new(), rows, disclosures }
}

fn timeline_view(a: &MailLogAnalysis) -> View {
    use maillog::{Status, Verdict};
    let count = |v: Verdict| a.messages.iter().filter(|m| m.verdict == v).count();
    let (word, glyph) = if a.messages.is_empty() && a.rejections.is_empty() {
        ("Nothing to follow", Glyph::Info)
    } else if count(Verdict::Bounced) > 0 {
        ("Bounced", Glyph::Octagon)
    } else if count(Verdict::Deferred) > 0 {
        ("Deferred", Glyph::Triangle)
    } else if count(Verdict::Incomplete) > 0 || a.messages.is_empty() {
        ("Incomplete", Glyph::Info)
    } else {
        ("Delivered", Glyph::Check)
    };
    let why = format!(
        "{} messages: {} delivered, {} deferred, {} bounced. {} refused at the door.",
        a.messages.len(),
        count(Verdict::Delivered),
        count(Verdict::Deferred),
        count(Verdict::Bounced),
        a.rejections.len()
    );
    let mut lines: Vec<Fact> = Vec::new();
    for m in &a.messages {
        let verdict = match m.verdict {
            Verdict::Delivered => "delivered",
            Verdict::Deferred => "deferred",
            Verdict::Bounced => "bounced",
            Verdict::Incomplete => "incomplete",
        };
        lines.push(Fact::new(
            format!("{} {}", m.time, m.queue_id),
            format!(
                "{verdict}: from {} via {}{}, {} bytes",
                orunknown(&m.from),
                orunknown(&m.client_host),
                ip(m.client_ip),
                m.size
            ),
        ));
        for r in m.recipients.iter().take(RECIPIENTS_PER_MESSAGE) {
            let status = match &r.status {
                Some(Status::Sent) => "sent".to_string(),
                Some(Status::Deferred) => "deferred".into(),
                Some(Status::Bounced) => "bounced".into(),
                Some(Status::Other(w)) => w.clone(),
                None => "no status".into(),
            };
            let mut v = format!("{status} via {}{}", orunknown(&r.relay_host), ip(r.relay_ip));
            if let Some(d) = r.delay_s {
                v.push_str(&format!(", delay {d} s"));
            }
            if r.attempts > 1 {
                v.push_str(&format!(", {} attempts", r.attempts));
            }
            if let Some(reason) = r.reason {
                v.push_str(&format!(". {}", reason.text()));
            } else if !r.reply.is_empty() {
                v.push_str(&format!(". {}", r.reply));
            }
            lines.push(Fact::new(format!("    to {}", r.to), v));
        }
        if m.recipients.len() > RECIPIENTS_PER_MESSAGE {
            lines.push(Fact::new(
                "    more",
                format!("{} more recipients", m.recipients.len() - RECIPIENTS_PER_MESSAGE),
            ));
        }
    }
    let mut rows = Vec::new();
    let mut disclosures = Vec::new();
    if a.messages.len() > OPEN_ROWS {
        disclosures.push(Disclosure {
            id: "ev-messages",
            title: format!("All {} messages", a.messages.len()),
            rows: lines,
        });
    } else {
        rows = lines;
    }
    if !a.rejections.is_empty() {
        let rej = a
            .rejections
            .iter()
            .map(|r| {
                let code = r.smtp_code.map(|c| format!("{c} ")).unwrap_or_default();
                let why = r.reason.map(|x| x.text().to_string()).unwrap_or_else(|| r.reply.clone());
                Fact::new(
                    format!("{} refused", r.time),
                    format!(
                        "{}{} from {} to {}: {code}{why}",
                        orunknown(&r.client_host),
                        ip(r.client_ip),
                        orunknown(&r.from),
                        orunknown(&r.to)
                    ),
                )
            })
            .collect();
        disclosures.push(Disclosure {
            id: "ev-refused",
            title: format!("{} refused at the door", a.rejections.len()),
            rows: rej,
        });
    }
    if a.truncated || a.unparsed > 0 {
        rows.push(Fact::new(
            "Skipped",
            format!(
                "{} lines were not Postfix lines{}",
                a.unparsed,
                if a.truncated { "; some data went over the limits and was left out" } else { "" }
            ),
        ));
    }
    View { word: word.into(), why, glyph, findings: Vec::new(), rows, disclosures }
}

/// What a rail section shows for a finished analysis.
pub fn view(report: &Report, section: Section) -> View {
    let mut v = match (&report.analysis, section) {
        (Analysis::Headers(a), Section::Path) => path_view(a),
        (Analysis::Headers(a), Section::Authentication) => auth_view(a),
        (Analysis::MailLog(a), Section::Timeline) => timeline_view(a),
        _ => {
            let n = report.findings.len();
            let word = match report.findings.first() {
                None => "No findings".to_string(),
                Some(f) => severity_word(f.severity).to_string(),
            };
            let glyph =
                report.findings.first().map(|f| crate::diagnosis::severity_glyph(f.severity)).unwrap_or(Glyph::Info);
            return View {
                word,
                why: format!("{n} findings, most serious first."),
                glyph,
                findings: report.findings.clone(),
                rows: Vec::new(),
                disclosures: Vec::new(),
            };
        }
    };
    if section == Section::Findings {
        v.findings = report.findings.clone();
    }
    v
}

/// A value as a Markdown code span: no control characters, and no backtick to end the span early.
pub(crate) fn code(s: &str) -> String {
    let flat: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    format!("`{}`", flat.replace('`', "'"))
}

pub(crate) fn fact_lines(out: &mut String, rows: &[Fact]) {
    for f in rows {
        out.push_str(&format!("- {}: {}\n", f.key.trim(), code(&f.value)));
    }
}

pub(crate) fn finding_lines(out: &mut String, findings: &[Finding]) {
    for f in findings {
        out.push_str(&format!("- **{}** {}: {}", severity_word(f.severity), f.title, f.message));
        if let Some(r) = &f.recommendation {
            out.push_str(&format!(" {r}"));
        }
        out.push('\n');
    }
}

/// One section as Markdown: readable as plain text, values in code spans.
pub fn section_markdown(report: &Report, section: Section) -> String {
    let v = view(report, section);
    let mut out = format!("## {}\n\n**{}.** {}\n\n", section.label(), v.word, v.why);
    finding_lines(&mut out, &v.findings);
    if !v.findings.is_empty() && !v.rows.is_empty() {
        out.push('\n');
    }
    fact_lines(&mut out, &v.rows);
    for d in &v.disclosures {
        out.push_str(&format!("\n### {}\n\n", d.title));
        fact_lines(&mut out, &d.rows);
    }
    out
}

/// The whole Evidence tab as Markdown, every section in rail order.
pub fn evidence_markdown(tab: &EvidenceTab) -> Option<String> {
    let report = tab.report()?;
    let mut out = format!("# Evidence: {}\n\n", tab.label);
    for &s in sections(tab.kind) {
        out.push_str(&section_markdown(report, s));
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/evidence/", $name))
        };
    }

    #[test]
    fn the_sniffer_tells_the_four_fixtures_apart() {
        assert_eq!(sniff(fixture!("gmail.txt")), Some(Kind::Headers));
        assert_eq!(sniff(fixture!("minimal.txt")), Some(Kind::Headers));
        assert_eq!(sniff(fixture!("spoofed.txt")), Some(Kind::Headers));
        assert_eq!(sniff(fixture!("sent.log")), Some(Kind::MailLog));
    }

    #[test]
    fn the_sniffer_does_not_guess_at_other_text() {
        assert_eq!(sniff(""), None);
        assert_eq!(sniff("hello world\nthis is not mail"), None);
        assert_eq!(sniff("Dear Sam: the invoice is attached"), None);
        assert_eq!(sniff("Jun 12 02:26 mail postfix/smtpd[abc]: not a pid"), None);
    }

    #[test]
    fn a_tie_between_kinds_is_no_suggestion_and_the_majority_wins() {
        let log = "Jun 12 02:26:20 mail01 postfix/qmgr[2790]: A1: removed";
        assert_eq!(sniff(&format!("Subject: x\n{log}")), None);
        assert_eq!(sniff(&format!("Subject: x\nFrom: a@b.c\n{log}")), Some(Kind::Headers));
        assert_eq!(sniff(&format!("Subject: x\n{log}\n{log}")), Some(Kind::MailLog));
    }

    #[test]
    fn a_syslog_line_is_a_mail_log() {
        assert_eq!(sniff("Jun 12 02:26:20 mail01 postfix/qmgr[2790]: A1: removed"), Some(Kind::MailLog));
    }

    #[test]
    fn the_sniffer_reads_only_the_top_of_a_huge_paste() {
        let text = format!("{}{}", "x".repeat(SNIFF_BYTES + 10), fixture!("sent.log"));
        assert_eq!(sniff(&text), None);
        assert_eq!(sniff(&"é".repeat(SNIFF_BYTES)), None);
    }

    #[test]
    fn the_size_cap_is_one_mebibyte_inclusive() {
        assert!(check_size(MAX_PASTE).is_ok());
        let msg = check_size(MAX_PASTE + 1).unwrap_err();
        assert!(msg.contains("1 MiB") && msg.contains("nothing was pasted"), "{msg}");
        assert!(analyse(Kind::Headers, &"a".repeat(MAX_PASTE + 1)).is_err());
    }

    #[test]
    fn control_characters_are_replaced_and_newlines_kept() {
        assert_eq!(display_text("a\u{1b}[31m\tb\r\nc\u{7}"), "a\u{fffd}[31m b\nc\u{fffd}");
    }

    #[test]
    fn tab_labels_carry_the_kind_and_the_time() {
        assert_eq!(tab_label(Kind::Headers, 14 * 3600 + 3 * 60 + 59), "Headers 14:03 UTC");
        assert_eq!(tab_label(Kind::MailLog, 86_400 + 5), "Mail log 00:00 UTC");
    }

    #[test]
    fn a_header_analysis_fills_every_header_section() {
        let r = analyse(Kind::Headers, fixture!("gmail.txt")).unwrap();
        let path = view(&r, Section::Path);
        assert_eq!(path.word, "2 hops");
        let hops: Vec<_> = path.rows.iter().filter(|f| f.key.starts_with("Hop")).collect();
        assert_eq!(hops.len(), 2);
        assert!(hops[0].value.contains("sender.example.com [203.0.113.5]"), "{:?}", hops[0]);
        assert!(hops[1].value.contains("after the previous hop"));
        let auth = view(&r, Section::Authentication);
        assert_eq!(auth.word, "Passed");
        assert_eq!(auth.rows[0].value, "pass");
        assert!(!view(&r, Section::Findings).findings.is_empty());
    }

    #[test]
    fn a_failing_header_set_reads_failed_and_most_serious_findings_come_first() {
        let r = analyse(Kind::Headers, fixture!("spoofed.txt")).unwrap();
        assert_eq!(view(&r, Section::Authentication).word, "Failed");
        let f = view(&r, Section::Findings).findings;
        assert!(
            f.windows(2)
                .all(|w| crate::diagnosis::severity_rank(w[0].severity)
                    <= crate::diagnosis::severity_rank(w[1].severity))
        );
    }

    #[test]
    fn a_mail_log_analysis_builds_a_timeline() {
        let r = analyse(Kind::MailLog, fixture!("sent.log")).unwrap();
        let t = view(&r, Section::Timeline);
        assert_eq!(t.word, "Delivered");
        assert!(t.rows[0].key.contains("A1B2C3D4"));
        assert!(
            t.rows
                .iter()
                .any(|f| f.key.contains("rcpt@example.net")
                    && f.value.starts_with("sent via mx.example.net [198.51.100.5]")),
            "{:?}",
            t.rows
        );
    }

    #[test]
    fn the_wrong_kind_is_an_error_the_rep_can_read() {
        let e = analyse(Kind::MailLog, fixture!("gmail.txt")).unwrap_err();
        assert!(e.contains("doesn't look like"), "{e}");
    }

    #[test]
    fn a_failed_authentication_shows_a_problem_mark_with_its_count() {
        let mut tab = EvidenceTab::new(1, Kind::Headers, 0);
        tab.stage = Stage::Done(Box::new(analyse(Kind::Headers, fixture!("spoofed.txt")).unwrap()));
        let n = match tab.state(Section::Authentication) {
            CheckState::Done { problems } => problems,
            other => panic!("{other:?}"),
        };
        assert!(n >= 1);
        let mark = tab.mark(Section::Authentication);
        assert_eq!(mark.glyph, Glyph::Triangle);
        assert!(mark.label.starts_with("done \u{b7} ") && mark.label.contains("problem"), "{}", mark.label);
        assert_ne!(tab.state(Section::Findings), CheckState::Done { problems: 0 });
    }

    #[test]
    fn a_clean_section_carries_its_verdict_and_never_a_bare_pass() {
        let mut tab = EvidenceTab::new(1, Kind::Headers, 0);
        tab.stage = Stage::Done(Box::new(analyse(Kind::Headers, fixture!("gmail.txt")).unwrap()));
        let auth = tab.mark(Section::Authentication);
        assert_eq!((auth.glyph, auth.label.as_str()), (Glyph::Check, "passed"));
        let path = tab.mark(Section::Path);
        assert_eq!((path.glyph, path.label.as_str()), (Glyph::Info, "2 hops"));
    }

    #[test]
    fn a_section_counts_only_its_own_findings() {
        let report = analyse(Kind::Headers, fixture!("spoofed.txt")).unwrap();
        let all = section_problems(&report, Section::Findings);
        assert_eq!(section_problems(&report, Section::Path) + section_problems(&report, Section::Authentication), all);
        assert!(section_problems(&report, Section::Authentication) > 0);
    }

    #[test]
    fn a_mail_log_timeline_carries_its_verdict() {
        let mut tab = EvidenceTab::new(1, Kind::MailLog, 0);
        tab.stage = Stage::Done(Box::new(analyse(Kind::MailLog, fixture!("sent.log")).unwrap()));
        assert_eq!(tab.mark(Section::Timeline).label, "delivered");
    }

    #[test]
    fn long_hop_lists_collapse() {
        let mut text = String::new();
        for i in 0..20 {
            text.push_str(&format!("Received: from h{i}.example.com (h{i}.example.com [203.0.113.{i}]) by m{i}.example.com with ESMTP; Wed, 14 Jun 2026 10:00:{i:02} +0000\n"));
        }
        text.push_str("From: a@example.com\n");
        let r = analyse(Kind::Headers, &text).unwrap();
        let v = view(&r, Section::Path);
        assert!(v.rows.iter().all(|f| !f.key.starts_with("Hop")));
        assert_eq!(v.disclosures[0].rows.len(), 20);
    }

    #[test]
    fn sections_as_markdown_name_the_section_and_quote_values() {
        let r = analyse(Kind::Headers, fixture!("gmail.txt")).unwrap();
        let md = section_markdown(&r, Section::Authentication);
        assert!(md.starts_with("## Authentication\n\n**Passed.**"), "{md}");
        assert!(md.contains("- SPF: `pass`\n"), "{md}");
    }

    #[test]
    fn the_whole_evidence_lists_sections_in_rail_order() {
        let mut tab = EvidenceTab::new(1, Kind::Headers, 0);
        assert!(evidence_markdown(&tab).is_none());
        tab.stage = Stage::Done(Box::new(analyse(Kind::Headers, fixture!("gmail.txt")).unwrap()));
        let md = evidence_markdown(&tab).unwrap();
        let at = |s: &str| md.find(s).unwrap_or_else(|| panic!("missing {s}"));
        assert!(md.starts_with("# Evidence: Headers 00:00 UTC"));
        assert!(at("## Message path") < at("## Authentication") && at("## Authentication") < at("## Findings"));
    }

    #[test]
    fn the_suggestion_steers_the_kind_until_the_rep_overrides_it() {
        let mut tab = EvidenceTab::new(1, Kind::Headers, 0);
        tab.suggest(fixture!("sent.log"));
        assert_eq!((tab.suggested, tab.kind), (Some(Kind::MailLog), Kind::MailLog));
        tab.choose(Kind::Headers);
        tab.suggest(fixture!("sent.log"));
        assert_eq!((tab.suggested, tab.kind), (Some(Kind::MailLog), Kind::Headers));
        tab.suggest("nothing useful");
        assert_eq!((tab.suggested, tab.kind), (None, Kind::Headers));
    }

    #[test]
    fn every_section_state_follows_the_stage() {
        let mut tab = EvidenceTab::new(1, Kind::MailLog, 0);
        assert_eq!(tab.state(Section::Timeline), CheckState::NotRun);
        tab.stage = Stage::Analysing;
        assert_eq!(tab.state(Section::Findings), CheckState::Running);
    }

    #[test]
    fn the_tab_holds_pasted_text_in_memory_only_by_construction() {
        let source = include_str!("evidence_model.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for api in ["std::fs", "File::", "OpenOptions", "std::io", "tempfile", "::write(", "create_dir"] {
            assert!(!production.contains(api), "evidence_model.rs uses {api}");
        }
        let view = include_str!("app/evidence.rs");
        let view = view.split("#[cfg(test)]").next().unwrap();
        for api in ["std::fs", "File::", "OpenOptions", "std::io", "tempfile"] {
            assert!(!view.contains(api), "app/evidence.rs uses {api}");
        }
    }

    #[test]
    fn a_hostile_paste_is_refused_or_analysed_without_a_panic() {
        let nasty = "Received: \u{0}\u{1b}[2J from ((((((\n".repeat(40_000);
        assert!(nasty.len() < MAX_PASTE * 2);
        let _ = analyse(Kind::Headers, &nasty[..MAX_PASTE.min(nasty.len())]);
        let _ = analyse(Kind::MailLog, &"postfix/smtpd[1]: ".repeat(50_000));
    }
}
