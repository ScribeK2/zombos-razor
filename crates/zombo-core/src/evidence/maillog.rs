//! Pasted mail logs: Postfix and Dovecot-LMTP delivery logs as reps copy them
//! out of a log viewer, regrouped by queue id into messages with a delivery
//! verdict and the receiving server's reply in plain English. Ported from the
//! Go `maillog.go`.

use std::{collections::HashMap, net::IpAddr, sync::LazyLock};

use regex::Regex;
use serde::Serialize;

use super::{EvidenceError, Extracted, MAX_INPUT, MAX_LINE, bracket_ip, capture, clean_lines, re};
use crate::{Finding, Severity};

const LABEL: &str = "a mail log (Postfix / Dovecot)";
/// Per message and per log; a hostile paste can make a million of them.
const MAX_RECIPIENTS: usize = 1000;
const MAX_MESSAGES: usize = 50_000;
const MAX_REJECTIONS: usize = 50_000;
/// Findings of one code shown; the rest are counted in one summary Finding.
const FINDING_CAP: usize = 10;

static POSTFIX_TAG: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"postfix(?:/[\w.-]+)*/(smtpd|cleanup|qmgr|smtp|lmtp|local|virtual|pipe|error|discard|bounce|pickup)\[\d+\]:\s*(.*)$",
    )
});
static DOVECOT_TAG: LazyLock<Regex> = LazyLock::new(|| re(r"\bdovecot(?:\[\d+\])?:\s*(.*)$"));
/// A record starts with a timestamp or carries a Postfix/Dovecot tag; a
/// hard-wrapped fragment has neither.
static RECORD_START: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^\s*(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|\b(?:postfix|dovecot)(?:/[\w.-]+)*(?:\[\d+\])?:",
    )
});
/// `warning:`, `error:`, `statistics:` and `NOQUEUE:` are not queue ids.
static NOT_QUEUE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^(?:[a-z]+|NOQUEUE)$"));
static QUEUE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^([0-9A-Za-z]{6,}):\s*(.*)$"));
static ISO_STAMP: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"));
static SYSLOG_STAMP: LazyLock<Regex> = LazyLock::new(|| re(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"));
static CLIENT: LazyLock<Regex> = LazyLock::new(|| re(r"client=([^\s\[]+)\[(?:IPv6:)?([0-9a-fA-F.:]+)\]"));
static MESSAGE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"message-id=(<[^>]*>|\S+)"));
static FROM: LazyLock<Regex> = LazyLock::new(|| re(r"from=<([^>]*)>"));
static TO: LazyLock<Regex> = LazyLock::new(|| re(r"to=<([^>]*)>"));
static SIZE: LazyLock<Regex> = LazyLock::new(|| re(r"size=(\d+)"));
static NRCPT: LazyLock<Regex> = LazyLock::new(|| re(r"nrcpt=(\d+)"));
static RELAY: LazyLock<Regex> = LazyLock::new(|| re(r"relay=([^,]+)"));
static RELAY_HOST: LazyLock<Regex> = LazyLock::new(|| re(r"^([^\[\s]+)"));
static BRACKET_IP: LazyLock<Regex> = LazyLock::new(|| re(r"\[(?:IPv6:)?([0-9a-fA-F.:]+)\]"));
static DELAY: LazyLock<Regex> = LazyLock::new(|| re(r"\bdelay=([\d.]+)"));
static DSN: LazyLock<Regex> = LazyLock::new(|| re(r"\bdsn=([\d.]+)"));
static STATUS: LazyLock<Regex> = LazyLock::new(|| re(r"\bstatus=(\w+)"));
static REPLY: LazyLock<Regex> = LazyLock::new(|| re(r"status=\w+\s+\((.*)\)\s*$"));
static REJECT_FROM: LazyLock<Regex> = LazyLock::new(|| re(r"from\s+([^\s\[]+)\[(?:IPv6:)?([0-9a-fA-F.:]+)\]:\s*(.*)$"));
static REJECT_SPLIT: LazyLock<Regex> = LazyLock::new(|| re(r";\s*from="));
static SMTP_CODE: LazyLock<Regex> = LazyLock::new(|| re(r"\b([245]\d\d)\b"));
static ENHANCED_DSN: LazyLock<Regex> = LazyLock::new(|| re(r"\b([45]\.\d+\.\d+)\b"));

/// The Postfix program that wrote a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Daemon {
    Smtpd,
    Cleanup,
    Qmgr,
    Smtp,
    Lmtp,
    Local,
    Virtual,
    Pipe,
    Error,
    Discard,
    Bounce,
    Pickup,
}

impl Daemon {
    fn from_word(w: &str) -> Option<Self> {
        Some(match w {
            "smtpd" => Self::Smtpd,
            "cleanup" => Self::Cleanup,
            "qmgr" => Self::Qmgr,
            "smtp" => Self::Smtp,
            "lmtp" => Self::Lmtp,
            "local" => Self::Local,
            "virtual" => Self::Virtual,
            "pipe" => Self::Pipe,
            "error" => Self::Error,
            "discard" => Self::Discard,
            "bounce" => Self::Bounce,
            "pickup" => Self::Pickup,
            _ => return None,
        })
    }

    /// Daemons that write a delivery attempt.
    fn delivers(self) -> bool {
        matches!(self, Self::Smtp | Self::Lmtp | Self::Local | Self::Virtual | Self::Pipe | Self::Error | Self::Discard)
    }

    /// Daemons that hand the message to a mailbox on this host.
    fn is_local(self) -> bool {
        matches!(self, Self::Lmtp | Self::Local | Self::Virtual | Self::Pipe)
    }
}

/// How one delivery attempt ended, as Postfix wrote `status=`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Sent,
    Deferred,
    Bounced,
    #[serde(untagged)]
    Other(String),
}

impl Status {
    fn from_word(w: &str) -> Self {
        match w {
            "sent" => Self::Sent,
            "deferred" => Self::Deferred,
            "bounced" => Self::Bounced,
            other => Self::Other(other.to_string()),
        }
    }
}

/// The state of one message at the end of the pasted log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Delivered,
    Deferred,
    Bounced,
    /// No delivery line: a truncated paste never reads as delivered.
    Incomplete,
}

/// A refusal or delay, in plain English.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    MailboxMissing,
    DomainMissing,
    MailboxFull,
    SenderPolicy,
    Greylisted,
    Policy,
    ConnectFailed,
    RemoteSystemError,
    Accepted,
    Permanent,
    Temporary,
}

impl Reason {
    pub fn text(self) -> &'static str {
        match self {
            Self::MailboxMissing => "Recipient mailbox doesn't exist at the receiving server",
            Self::DomainMissing => "Recipient domain doesn't exist or has no working MX",
            Self::MailboxFull => "Recipient mailbox is full (over quota)",
            Self::SenderPolicy => {
                "Rejected by the receiving server's policy on the sender's reverse DNS, DMARC or authentication"
            }
            Self::Greylisted => "Greylisted or rate-limited; temporary, Postfix will retry",
            Self::Policy => "Rejected by the receiving server's policy (spam, blocklist or policy)",
            Self::ConnectFailed => "Could not connect to the recipient's server; temporary, Postfix will retry",
            Self::RemoteSystemError => "The receiving mail system had an error (a problem on their side)",
            Self::Accepted => "Accepted by the receiving server",
            Self::Permanent => "Permanent failure: the recipient's server refused it (see its reply)",
            Self::Temporary => "Temporary failure; Postfix will retry (see the reply)",
        }
    }
}

/// What a bounce pattern needs from the reply's permanence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Needs {
    Any,
    Temporary,
    Permanent,
}

/// One way a rule recognises a reply.
enum Test {
    /// The enhanced status code starts with one of these.
    DsnPrefix(&'static [&'static str]),
    /// The enhanced status code is one of these.
    DsnIs(&'static [&'static str]),
    /// The SMTP reply code starts with this.
    CodePrefix(&'static str),
    Reply(Regex),
    /// A status code prefix and a reply pattern together.
    DsnPrefixAndReply(&'static [&'static str], Regex),
    Always,
}

struct Rule {
    reason: Reason,
    needs: Needs,
    any: Vec<Test>,
}

struct Reply<'a> {
    dsn: &'a str,
    text: &'a str,
    code: Option<&'a str>,
    permanent: bool,
}

impl Test {
    fn matches(&self, r: &Reply) -> bool {
        match self {
            Self::DsnPrefix(p) => p.iter().any(|p| r.dsn.starts_with(p)),
            Self::DsnIs(d) => d.contains(&r.dsn),
            Self::CodePrefix(p) => r.code.is_some_and(|c| c.starts_with(p)),
            Self::Reply(re) => re.is_match(r.text),
            Self::DsnPrefixAndReply(p, re) => p.iter().any(|p| r.dsn.starts_with(p)) && re.is_match(r.text),
            Self::Always => true,
        }
    }
}

/// The known bounce patterns, first match wins. The order is the Go order. A
/// permanent (5.x) reply is never described as something that will retry.
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let rule = |reason, needs, any| Rule { reason, needs, any };
    let ci = |p: &str| re(&format!("(?i){p}"));
    vec![
        // Not "Recipient address rejected": Postfix prefixes many refusals with it
        // (greylisting, access denied), so it says nothing about the mailbox.
        rule(
            Reason::MailboxMissing,
            Needs::Any,
            vec![
                Test::DsnPrefix(&["5.1.1", "5.1.0"]),
                Test::Reply(ci("user unknown|unknown user|no such user|does not exist")),
            ],
        ),
        rule(Reason::DomainMissing, Needs::Any, vec![Test::DsnPrefix(&["5.1.2"])]),
        rule(
            Reason::MailboxFull,
            Needs::Any,
            vec![Test::DsnIs(&["5.2.2", "4.2.2"]), Test::Reply(ci(r"mailbox full|over\s?quota"))],
        ),
        rule(Reason::SenderPolicy, Needs::Any, vec![Test::DsnPrefix(&["5.7.25", "5.7.26"])]),
        rule(
            Reason::Greylisted,
            Needs::Temporary,
            vec![
                Test::DsnPrefixAndReply(&["5.7", "4.7"], ci("greylist|try again|rate")),
                Test::CodePrefix("421"),
                Test::Reply(ci("greylist|try again later|rate limit")),
            ],
        ),
        rule(
            Reason::Policy,
            Needs::Any,
            vec![
                Test::DsnPrefix(&["5.7"]),
                Test::Reply(ci("blocked|spam|blacklist|blocklist|policy|denied|reputation")),
            ],
        ),
        rule(
            Reason::ConnectFailed,
            Needs::Temporary,
            vec![
                Test::DsnPrefix(&["4.4"]),
                Test::Reply(ci(
                    "timed out|timeout|connection refused|no route|unable to connect|conversation timed out",
                )),
            ],
        ),
        rule(Reason::RemoteSystemError, Needs::Any, vec![Test::DsnPrefix(&["4.3", "5.3"])]),
        rule(Reason::Accepted, Needs::Any, vec![Test::DsnIs(&["2.0.0"]), Test::CodePrefix("250")]),
        rule(Reason::Permanent, Needs::Permanent, vec![Test::Always]),
        rule(Reason::Temporary, Needs::Any, vec![Test::CodePrefix("4"), Test::DsnPrefix(&["4"])]),
    ]
});

/// Turn an enhanced status code (X.Y.Z) or SMTP reply into plain English. The
/// raw reply is always shown beside it, so a miss hides nothing.
pub fn decode_reason(dsn: &str, reply: &str) -> Option<Reason> {
    let code = capture(&SMTP_CODE, reply);
    let permanent = dsn.starts_with('5') || (dsn.is_empty() && code.is_some_and(|c| c.starts_with('5')));
    let r = Reply { dsn, text: reply, code, permanent };
    RULES
        .iter()
        .filter(|rule| match rule.needs {
            Needs::Any => true,
            Needs::Temporary => !r.permanent,
            Needs::Permanent => r.permanent,
        })
        .find(|rule| rule.any.iter().any(|t| t.matches(&r)))
        .map(|rule| rule.reason)
}

/// One recipient's delivery attempt.
#[derive(Debug, Clone, Serialize)]
pub struct Recipient {
    pub to: String,
    pub relay_host: String,
    pub relay_ip: Option<IpAddr>,
    /// Delivered to a mailbox on this host (LMTP).
    pub local: bool,
    pub delay_s: Option<f64>,
    pub dsn: String,
    pub status: Option<Status>,
    /// The receiving server's own words.
    pub reply: String,
    /// The first SMTP reply code in the reply (2xx, 4xx or 5xx).
    pub smtp_code: Option<u16>,
    pub reason: Option<Reason>,
    /// Delivery attempts seen; the other fields are the latest.
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub queue_id: String,
    pub time: String,
    pub client_host: String,
    pub client_ip: Option<IpAddr>,
    pub from: String,
    pub message_id: String,
    pub size: u64,
    pub nrcpt: u32,
    pub recipients: Vec<Recipient>,
    pub removed: bool,
    pub verdict: Verdict,
}

/// Mail our server refused before queueing it (NOQUEUE).
#[derive(Debug, Clone, Serialize)]
pub struct Rejection {
    pub client_host: String,
    pub client_ip: Option<IpAddr>,
    pub smtp_code: Option<u16>,
    pub dsn: String,
    pub from: String,
    pub to: String,
    pub reply: String,
    pub reason: Option<Reason>,
    pub time: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MailLogAnalysis {
    /// In first-seen order.
    pub messages: Vec<Message>,
    pub rejections: Vec<Rejection>,
    /// Lines that were neither Postfix nor Dovecot.
    pub unparsed: usize,
    /// Dovecot lines; they add nothing Postfix's lmtp line does not.
    pub dovecot_lines: usize,
    /// Lines, recipients or messages went over the limits and were left out.
    pub truncated: bool,
    /// Every IP and host name the log names.
    pub extracted: Extracted,
}

/// One Postfix log line, by what it says.
enum Event {
    Client { host: String, ip: Option<IpAddr> },
    MessageId(String),
    Queued { from: String, size: u64, nrcpt: u32 },
    Removed,
    Delivery(Recipient),
}

enum Line {
    Queue {
        id: String,
        event: Option<Event>,
    },
    Rejection(Rejection),
    /// A Postfix line about something other than a queued message (a warning, a connect).
    Other,
}

fn stamp(line: &str) -> String {
    capture(&ISO_STAMP, line).or_else(|| capture(&SYSLOG_STAMP, line)).unwrap_or_default().to_string()
}

fn text(re: &Regex, s: &str) -> String {
    capture(re, s).unwrap_or_default().to_string()
}

fn smtp_code(reply: &str) -> Option<u16> {
    capture(&SMTP_CODE, reply)?.parse().ok()
}

/// The reply of a refusal at our server: what follows `from host[ip]:`, up to `; from=`.
fn parse_rejection(payload: &str, time: String) -> Option<Rejection> {
    let m = REJECT_FROM.captures(payload)?;
    let body = &m[3];
    let reply = REJECT_SPLIT.split(body).next().unwrap_or(body).trim().to_string();
    let dsn = text(&ENHANCED_DSN, &reply);
    // Postfix's word for "no reverse DNS".
    let host = if &m[1] == "unknown" { String::new() } else { m[1].to_string() };
    Some(Rejection {
        client_host: host,
        client_ip: m[2].parse().ok(),
        smtp_code: smtp_code(&reply),
        reason: decode_reason(&dsn, &reply),
        from: text(&FROM, body),
        to: text(&TO, body),
        dsn,
        reply,
        time,
    })
}

fn parse_delivery(rest: &str, local: bool) -> Recipient {
    let relay = text(&RELAY, rest);
    let relay = relay.trim();
    let dsn = text(&DSN, rest);
    let reply = text(&REPLY, rest);
    Recipient {
        to: text(&TO, rest),
        relay_host: text(&RELAY_HOST, relay),
        relay_ip: bracket_ip(&BRACKET_IP, relay),
        local: local || relay.contains("dovecot"),
        delay_s: capture(&DELAY, rest).and_then(|d| d.parse().ok()),
        status: capture(&STATUS, rest).map(Status::from_word),
        smtp_code: smtp_code(&reply),
        reason: decode_reason(&dsn, &reply),
        dsn,
        reply,
        attempts: 1,
    }
}

fn parse_postfix(daemon: Daemon, payload: &str, time: &str) -> Line {
    if payload.starts_with("NOQUEUE: reject") || payload.starts_with("NOQUEUE: milter-reject") {
        return parse_rejection(payload, time.to_string()).map_or(Line::Other, Line::Rejection);
    }
    let Some(q) = QUEUE_ID.captures(payload).filter(|q| !NOT_QUEUE_ID.is_match(&q[1])) else { return Line::Other };
    let rest = &q[2];
    let event = match daemon {
        Daemon::Smtpd => CLIENT.captures(rest).map(|c| Event::Client { host: c[1].to_string(), ip: c[2].parse().ok() }),
        Daemon::Cleanup => capture(&MESSAGE_ID, rest).map(|id| Event::MessageId(id.to_string())),
        Daemon::Qmgr if rest.trim() == "removed" => Some(Event::Removed),
        Daemon::Qmgr => FROM.captures(rest).map(|f| Event::Queued {
            from: f[1].to_string(),
            size: capture(&SIZE, rest).and_then(|n| n.parse().ok()).unwrap_or(0),
            nrcpt: capture(&NRCPT, rest).and_then(|n| n.parse().ok()).unwrap_or(0),
        }),
        d if d.delivers() => Some(Event::Delivery(parse_delivery(rest, d.is_local()))),
        _ => None,
    };
    Line::Queue { id: q[1].to_string(), event }
}

/// Undo hard wrapping: a real record starts with a timestamp or carries a
/// program tag, a wrapped fragment does neither, so only such a fragment is
/// joined onto the previous record. Other log lines stay whole.
fn logical_lines(raw: &str, truncated: &mut bool) -> Vec<String> {
    let mut lines: Vec<String> = vec![];
    for (line, cut) in clean_lines(raw) {
        *truncated |= cut;
        if line.trim().is_empty() {
            continue;
        }
        match lines.last_mut() {
            Some(last) if !RECORD_START.is_match(&line) => {
                if last.len() < MAX_LINE {
                    last.push(' ');
                    last.push_str(line.trim());
                } else {
                    *truncated = true;
                }
            }
            _ => lines.push(line.into_owned()),
        }
    }
    lines
}

/// Bounced beats deferred beats delivered; no delivery line is incomplete.
fn verdict_for(m: &Message) -> Verdict {
    let has = |s: &Status| m.recipients.iter().any(|r| r.status.as_ref() == Some(s));
    let all_sent = m.recipients.iter().filter_map(|r| r.status.as_ref()).all(|s| *s == Status::Sent);
    let any_status = m.recipients.iter().any(|r| r.status.is_some());
    if !any_status {
        Verdict::Incomplete
    } else if has(&Status::Bounced) {
        Verdict::Bounced
    } else if has(&Status::Deferred) {
        Verdict::Deferred
    } else if all_sent {
        Verdict::Delivered
    } else {
        Verdict::Incomplete
    }
}

/// Analyse a pasted mail log. Pure: it reads the text and nothing else.
pub fn analyse_maillog(raw: &str) -> Result<MailLogAnalysis, EvidenceError> {
    if raw.len() > MAX_INPUT {
        return Err(EvidenceError::TooLarge);
    }
    let mut a = MailLogAnalysis::default();
    // Queue id and recipient address to their positions, so a retry is found
    // without scanning every recipient.
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut recipient_at: HashMap<(usize, String), usize> = HashMap::new();
    for line in logical_lines(raw, &mut a.truncated) {
        let Some(tag) = POSTFIX_TAG.captures(&line) else {
            if DOVECOT_TAG.is_match(&line) {
                a.dovecot_lines += 1;
            } else {
                a.unparsed += 1;
            }
            continue;
        };
        let Some(daemon) = Daemon::from_word(&tag[1]) else { continue };
        let time = stamp(&line);
        match parse_postfix(daemon, &tag[2], &time) {
            Line::Other => {}
            Line::Rejection(r) if a.rejections.len() < MAX_REJECTIONS => {
                a.extracted.host(&r.client_host);
                a.extracted.ip(r.client_ip);
                a.rejections.push(r);
            }
            Line::Rejection(_) => a.truncated = true,
            Line::Queue { id, event } => {
                let i = match index.get(&id) {
                    Some(&i) => i,
                    None if a.messages.len() >= MAX_MESSAGES => {
                        a.truncated = true;
                        continue;
                    }
                    None => {
                        index.insert(id.clone(), a.messages.len());
                        a.messages.push(Message {
                            queue_id: id,
                            time,
                            client_host: String::new(),
                            client_ip: None,
                            from: String::new(),
                            message_id: String::new(),
                            size: 0,
                            nrcpt: 0,
                            recipients: vec![],
                            removed: false,
                            verdict: Verdict::Incomplete,
                        });
                        a.messages.len() - 1
                    }
                };
                let m = &mut a.messages[i];
                match event {
                    Some(Event::Client { host, ip }) => {
                        a.extracted.host(&host);
                        a.extracted.ip(ip);
                        (m.client_host, m.client_ip) = (host, ip);
                    }
                    Some(Event::MessageId(id)) => m.message_id = id,
                    Some(Event::Removed) => m.removed = true,
                    Some(Event::Queued { from, size, nrcpt }) => (m.from, m.size, m.nrcpt) = (from, size, nrcpt),
                    Some(Event::Delivery(mut r)) => {
                        a.extracted.host(&r.relay_host);
                        a.extracted.ip(r.relay_ip);
                        // A later attempt for the same recipient (a retry after a
                        // deferral) is its outcome now; count the attempts.
                        let key = (i, r.to.clone());
                        if let Some(&j) = recipient_at.get(&key) {
                            r.attempts = m.recipients[j].attempts.saturating_add(1);
                            m.recipients[j] = r;
                        } else if m.recipients.len() < MAX_RECIPIENTS {
                            recipient_at.insert(key, m.recipients.len());
                            m.recipients.push(r);
                        } else {
                            a.truncated = true;
                        }
                    }
                    None => {}
                }
            }
        }
    }
    if a.messages.is_empty() && a.rejections.is_empty() {
        return Err(EvidenceError::NotThisKind(LABEL));
    }
    for m in &mut a.messages {
        m.verdict = verdict_for(m);
    }
    Ok(a)
}

fn or_default<'a>(s: &'a str, default: &'a str) -> &'a str {
    if s.is_empty() { default } else { s }
}

fn reason_text(r: Option<Reason>) -> &'static str {
    r.map_or("see the reply", Reason::text)
}

fn ip_text(ip: Option<IpAddr>) -> String {
    ip.map(|i| i.to_string()).unwrap_or_default()
}

/// The Findings for one mail log analysis, wording as in the Go version. A big
/// log shows at most ten of each code and counts the rest.
pub fn maillog_findings(a: &MailLogAnalysis) -> Vec<Finding> {
    let mut out: Vec<Finding> = vec![];
    let mut shown: HashMap<&'static str, usize> = HashMap::new();
    let mut hidden = 0usize;
    let mut add = |f: Finding| {
        let n = shown.entry(f.code).or_default();
        if *n >= FINDING_CAP {
            hidden += 1;
        } else {
            *n += 1;
            out.push(f);
        }
    };
    let mut delivered = 0usize;
    for m in &a.messages {
        let from = or_default(&m.from, "an unknown sender");
        match m.verdict {
            Verdict::Delivered => delivered += 1,
            Verdict::Bounced => {
                let bad: Vec<&Recipient> = m.recipients.iter().filter(|r| r.status == Some(Status::Bounced)).collect();
                let Some(r) = bad.first() else { continue };
                // Some recipients got it.
                let severity = if bad.len() == m.recipients.len() { Severity::Critical } else { Severity::Warning };
                add(Finding {
                    code: "mail_log_bounced",
                    severity,
                    title: format!("Bounced: {}", r.to).into(),
                    message: format!(
                        "Message {} from {} was refused by {}: {}. Their reply: {}",
                        m.queue_id,
                        from,
                        or_default(&r.relay_host, "an unknown server"),
                        reason_text(r.reason),
                        r.reply
                    ),
                    recommendation: Some("Tell the sender the reason; fix the address or the cause, then send again.".into()),
                });
            }
            Verdict::Deferred => {
                let Some(r) = m.recipients.iter().find(|r| r.status == Some(Status::Deferred)).or(m.recipients.first()) else { continue };
                add(Finding {
                    code: "mail_log_deferred",
                    severity: Severity::Info,
                    title: format!("Deferred: {}", r.to).into(),
                    message: format!("Message {} from {} is waiting to be retried: {}. Their reply: {}", m.queue_id, from, reason_text(r.reason), r.reply),
                    recommendation: None,
                });
            }
            Verdict::Incomplete => add(Finding {
                code: "mail_log_incomplete",
                severity: Severity::Info,
                title: format!("No final status for {}", m.queue_id).into(),
                message: "The pasted lines stop before this message was delivered, deferred or bounced. Paste more of the log to see how it ended.".into(),
                recommendation: None,
            }),
        }
    }
    for r in &a.rejections {
        let who = if r.client_host.is_empty() { ip_text(r.client_ip) } else { r.client_host.clone() };
        add(Finding {
            code: "mail_log_rejected",
            severity: Severity::Warning,
            title: format!("Refused at our server: {who}").into(),
            message: format!(
                "Mail from {} to {} was refused before it was queued: {}. Our reply: {}",
                or_default(&r.from, "an unknown sender"),
                or_default(&r.to, "an unknown recipient"),
                reason_text(r.reason),
                r.reply
            ),
            recommendation: Some(
                "If this sender is legitimate, check the listing or policy named in the reply.".into(),
            ),
        });
    }
    if hidden > 0 {
        out.push(Finding {
            code: "mail_log_more",
            severity: Severity::Info,
            title: "More in the log".into(),
            message: format!(
                "{hidden} more problems aren't listed here; every message is in the pasted log's analysis."
            ),
            recommendation: None,
        });
    }
    if delivered > 0 {
        out.push(Finding {
            code: "mail_log_delivered",
            severity: Severity::Ok,
            title: "Delivered".into(),
            message: format!(
                "{delivered} of {} messages in the log were delivered to every recipient.",
                a.messages.len()
            ),
            recommendation: None,
        });
    }
    if a.truncated {
        out.push(Finding {
            code: "mail_log_truncated",
            severity: Severity::Info,
            title: "Part of the paste was skipped".into(),
            message: "A line, a message or a recipient list went over the analysis limits; the rest was left out."
                .into(),
            recommendation: None,
        });
    }
    out
}
