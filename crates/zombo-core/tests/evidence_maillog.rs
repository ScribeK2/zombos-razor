//! Mail log analysis: the Go scenarios, plus hostile input.

#[path = "common/evidence.rs"]
mod evidence;

use std::time::{Duration, Instant};

use evidence::fixture;
use zombo_core::{
    Severity,
    evidence::{
        EvidenceError, MAX_INPUT,
        maillog::{MailLogAnalysis, Reason, Status, Verdict, analyse_maillog, decode_reason, maillog_findings},
    },
};

fn analyse(raw: &str) -> MailLogAnalysis {
    analyse_maillog(raw).unwrap_or_else(|e| panic!("{e}"))
}

fn ip(s: &str) -> Option<std::net::IpAddr> {
    s.parse().ok()
}

fn sent_log() -> String {
    fixture("sent.log")
}

#[test]
fn text_that_is_not_a_mail_log_is_refused() {
    assert_eq!(analyse_maillog("not a log at all\n\n").err(), Some(EvidenceError::NotThisKind("a mail log (Postfix / Dovecot)")));
    assert_eq!(analyse_maillog("").err(), Some(EvidenceError::NotThisKind("a mail log (Postfix / Dovecot)")));
}

#[test]
fn a_delivered_message_is_reconstructed_by_queue_id() {
    let a = analyse(&sent_log());
    assert_eq!(a.messages.len(), 1);
    let m = &a.messages[0];
    assert_eq!((m.queue_id.as_str(), m.from.as_str(), m.client_host.as_str()), ("A1B2C3D4", "sender@client.com", "mail.client.com"));
    assert_eq!((m.client_ip, m.message_id.as_str(), m.size, m.nrcpt, m.removed, m.verdict), (ip("203.0.113.10"), "<abc123@client.com>", 4523, 1, true, Verdict::Delivered));
    assert_eq!(m.time, "2026-06-12T02:26:20.123Z");
    let r = &m.recipients[0];
    assert_eq!((r.to.as_str(), r.relay_host.as_str(), r.relay_ip, r.dsn.as_str()), ("rcpt@example.net", "mx.example.net", ip("198.51.100.5"), "2.0.0"));
    assert_eq!((r.status.clone(), r.local, r.reply.as_str(), r.reason, r.smtp_code, r.delay_s), (Some(Status::Sent), false, "250 2.0.0 OK 1A2B3C", Some(Reason::Accepted), Some(250), Some(1.3)));
    // The names and addresses the log mentions are exposed for later lookups.
    assert_eq!(a.extracted.ips, vec![ip("203.0.113.10").unwrap(), ip("198.51.100.5").unwrap()]);
    assert_eq!(a.extracted.hosts, vec!["mail.client.com", "mx.example.net"]);
}

#[test]
fn verdicts() {
    let cases = [
        ("bounced", "Jun 12 02:30:00 mail01 postfix/smtp[2820]: B2C3D4E5: to=<nobody@example.net>, relay=mx.example.net[198.51.100.5]:25, delay=0.9, dsn=5.1.1, status=bounced (host mx.example.net[198.51.100.5] said: 550 5.1.1 <nobody@example.net>: Recipient address rejected: User unknown (in reply to RCPT TO command))", Verdict::Bounced),
        ("deferred", "2026-06-12T02:40:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, delay=2.1, dsn=4.7.1, status=deferred (host mx.example.org[192.0.2.7] said: 451 4.7.1 Greylisting in effect, please try again later)", Verdict::Deferred),
        ("local lmtp", "2026-06-12T02:50:00Z mail01 postfix/lmtp[3001]: D4E5F6A1: to=<local@ourdomain.com>, relay=ourdomain.com[private/dovecot-lmtp], delay=0.1, dsn=2.0.0, status=sent (250 2.0.0 <local@ourdomain.com> Saved)", Verdict::Delivered),
        ("mixed recipients", "postfix/qmgr[2790]: AA11BB22: from=<s@client.com>, size=10, nrcpt=2 (queue active)\npostfix/smtp[2820]: AA11BB22: to=<ok@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)\npostfix/smtp[2820]: AA11BB22: to=<bad@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)", Verdict::Bounced),
        ("truncated", "postfix/qmgr[2790]: TRUNC123: from=<a@client.com>, size=10, nrcpt=1 (queue active)", Verdict::Incomplete),
        ("an unusual status", "postfix/smtp[2820]: EXP00001: to=<a@example.net>, relay=none, dsn=4.0.0, status=expired (delivery temporarily suspended)", Verdict::Incomplete),
    ];
    for (name, log, want) in cases {
        assert_eq!(analyse(log).messages[0].verdict, want, "{name}");
    }
    let local = analyse(cases[2].1);
    let r = &local.messages[0].recipients[0];
    assert!(r.local);
    assert_eq!(r.relay_ip, None, "[private/dovecot-lmtp] is not an address");
}

#[test]
fn interleaved_queue_ids_regroup() {
    let a = analyse(
        "postfix/qmgr[2790]: QID0001A: from=<a@client.com>, size=10, nrcpt=1 (queue active)\npostfix/qmgr[2790]: QID0002B: from=<b@client.com>, size=20, nrcpt=1 (queue active)\npostfix/smtp[2820]: QID0001A: to=<x@example.net>, relay=mx[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)\npostfix/smtp[2820]: QID0002B: to=<y@example.net>, relay=mx[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 User unknown)",
    );
    let v: Vec<_> = a.messages.iter().map(|m| (m.queue_id.as_str(), m.verdict)).collect();
    assert_eq!(v, [("QID0001A", Verdict::Delivered), ("QID0002B", Verdict::Bounced)]);
}

#[test]
fn rejections_at_our_server() {
    let a = analyse("Jun 12 03:00:00 mail01 postfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[185.220.101.1]: 554 5.7.1 Service unavailable; Client host [185.220.101.1] blocked using zen.spamhaus.org; from=<spammer@bad.com> to=<victim@ourdomain.com> proto=ESMTP helo=<bad.com>");
    assert_eq!(a.rejections.len(), 1);
    let r = &a.rejections[0];
    assert_eq!((r.client_ip, r.to.as_str(), r.from.as_str(), r.smtp_code, r.client_host.as_str()), (ip("185.220.101.1"), "victim@ourdomain.com", "spammer@bad.com", Some(554), ""));
    assert!(r.reply.contains("zen.spamhaus.org"));
    assert_eq!(r.reason, Some(Reason::Policy));
    assert_eq!(r.time, "Jun 12 03:00:00");
    assert_eq!(a.extracted.ips, vec![ip("185.220.101.1").unwrap()]);
}

#[test]
fn noise_before_a_record_is_counted_and_the_record_still_parses() {
    let a = analyse("this is noise\npostfix/qmgr[1]: 9F2A1B3C4D: from=<a@b.com>, size=1, nrcpt=1 (queue active)");
    assert_eq!(a.messages.len(), 1);
    assert!(a.unparsed >= 1);
}

#[test]
fn hard_wrapped_graylog_lines_are_joined() {
    let a = analyse("2026-06-12T02:26:21Z mail01 postfix/smtp[2820]: 7Fk9R2p1Zc7Yb3Na12: to=<ghost@example.net>,\nrelay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1\n<ghost@example.net>: Recipient address rejected: User unknown)");
    assert_eq!((a.unparsed, a.messages.len()), (0, 1));
    let r = &a.messages[0].recipients[0];
    assert_eq!((r.to.as_str(), r.relay_host.as_str(), r.relay_ip, r.status.clone(), r.dsn.as_str()), ("ghost@example.net", "mx.example.net", ip("198.51.100.5"), Some(Status::Bounced), "5.1.1"));
}

#[test]
fn a_wrapped_rejection_keeps_from_and_to() {
    let a = analyse("Jun 12 02:32:00 mail01 postfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[185.220.101.1]: 554 5.7.1 blocked using\nzen.spamhaus.org; from=<spammer@bad.com> to=<victim@ourdomain.com> proto=ESMTP");
    let r = &a.rejections[0];
    assert_eq!((r.client_ip, r.from.as_str(), r.to.as_str()), (ip("185.220.101.1"), "spammer@bad.com", "victim@ourdomain.com"));
}

#[test]
fn long_queue_ids() {
    let a = analyse("postfix/qmgr[2790]: 4Xk8R2p1Zc7Yb3Na12: from=<a@client.com>, size=10, nrcpt=1 (queue active)\npostfix/smtp[2820]: 4Xk8R2p1Zc7Yb3Na12: to=<x@example.net>, relay=mx[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)");
    assert_eq!((a.messages.len(), a.messages[0].queue_id.as_str(), a.messages[0].verdict), (1, "4Xk8R2p1Zc7Yb3Na12", Verdict::Delivered));
}

#[test]
fn ipv6_relay_and_client() {
    let a = analyse("postfix/smtp[2820]: AB12CD34: to=<u@example.net>, relay=mx.example.net[IPv6:2001:db8::25]:25, dsn=2.0.0, status=sent (250 OK)\npostfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[IPv6:2001:db8::bad]: 554 5.7.1 blocked; from=<s@bad.com> to=<v@ourdomain.com> proto=ESMTP");
    let r = &a.messages[0].recipients[0];
    assert_eq!((r.relay_host.as_str(), r.relay_ip), ("mx.example.net", ip("2001:db8::25")));
    assert_eq!((a.rejections[0].client_ip, a.rejections[0].to.as_str()), (ip("2001:db8::bad"), "v@ourdomain.com"));
}

#[test]
fn replies_are_decoded_into_plain_english() {
    // (dsn, reply, expected reason)
    let cases = [
        ("5.1.1", "550 5.1.1 User unknown", Reason::MailboxMissing),
        ("5.1.2", "550 5.1.2 Host not found", Reason::DomainMissing),
        ("5.2.2", "552 5.2.2 Over quota", Reason::MailboxFull),
        ("5.7.1", "554 5.7.1 Message rejected as spam", Reason::Policy),
        ("5.7.25", "550 5.7.25 PTR record required", Reason::SenderPolicy),
        ("4.7.1", "451 4.7.1 Greylisting, try again later", Reason::Greylisted),
        ("4.4.1", "conversation timed out", Reason::ConnectFailed),
        ("5.3.0", "550 5.3.0 Mail system full", Reason::RemoteSystemError),
        ("2.0.0", "250 2.0.0 OK", Reason::Accepted),
        ("5.9.9", "599 weird", Reason::Permanent),
        ("4.9.9", "499 weird", Reason::Temporary),
        // A permanent 5.x is never presented as something that will retry.
        ("5.4.4", "550 5.4.4 No route to host", Reason::Permanent),
        ("5.7.0", "550 5.7.0 Too many errors, try again later", Reason::Policy),
    ];
    for (dsn, reply, want) in cases {
        let status = if dsn.starts_with('2') { "sent" } else if dsn.starts_with('4') { "deferred" } else { "bounced" };
        let a = analyse(&format!("postfix/smtp[1]: DEC0DE01: to=<u@example.net>, relay=mx[198.51.100.5]:25, dsn={dsn}, status={status} ({reply})"));
        let got = a.messages[0].recipients[0].reason;
        assert_eq!(got, Some(want), "{dsn} {reply:?}");
        if dsn.starts_with('5') {
            assert!(!matches!(got, Some(Reason::Greylisted | Reason::ConnectFailed | Reason::Temporary)), "{dsn}");
        }
    }
}

#[test]
fn a_reply_with_no_code_at_all_decodes_to_nothing() {
    assert_eq!(decode_reason("", "something odd"), None);
    assert_eq!(decode_reason("", "554 refused"), Some(Reason::Permanent));
    assert_eq!(decode_reason("", "421 busy"), Some(Reason::Greylisted));
}

#[test]
fn findings_for_every_kind_of_outcome() {
    let log = format!(
        "{}\nJun 12 02:30:00 mail01 postfix/smtp[2820]: B2C3D4E5: to=<nobody@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)\n2026-06-12T02:40:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, dsn=4.7.1, status=deferred (451 4.7.1 Greylisting, try again later)\nJun 12 03:00:00 mail01 postfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[185.220.101.1]: 554 5.7.1 blocked using zen.spamhaus.org; from=<spammer@bad.com> to=<victim@ourdomain.com> proto=ESMTP",
        sent_log()
    );
    let a = analyse(&log);
    let f = maillog_findings(&a);
    let get = |code: &str| f.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("no {code} in {f:?}"));
    let (b, d, r, ok) = (get("mail_log_bounced"), get("mail_log_deferred"), get("mail_log_rejected"), get("mail_log_delivered"));
    assert_eq!((b.severity, b.title.as_ref()), (Severity::Critical, "Bounced: nobody@example.net"));
    assert_eq!(b.message, "Message B2C3D4E5 from an unknown sender was refused by mx.example.net: Recipient mailbox doesn't exist at the receiving server. Their reply: 550 5.1.1 User unknown");
    assert_eq!((d.severity, d.title.as_ref()), (Severity::Info, "Deferred: user@example.org"));
    assert_eq!((r.severity, r.title.as_ref()), (Severity::Warning, "Refused at our server: 185.220.101.1"));
    assert_eq!((ok.severity, ok.message.as_str()), (Severity::Ok, "1 of 3 messages in the log were delivered to every recipient."));
    // The servers that refused or held up mail are in the result.
    let refused: Vec<_> = a.messages.iter().flat_map(|m| &m.recipients).filter(|r| r.status != Some(Status::Sent)).map(|r| r.relay_host.as_str()).collect();
    assert_eq!(refused, ["mx.example.net", "mx.example.org"]);
}

#[test]
fn a_partly_bounced_message_is_only_a_warning() {
    let a = analyse("postfix/qmgr[2790]: AA11BB22: from=<s@client.com>, size=10, nrcpt=2 (queue active)\npostfix/smtp[2820]: AA11BB22: to=<ok@example.net>, relay=mx[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)\npostfix/smtp[2820]: AA11BB22: to=<bad@example.net>, relay=mx[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)");
    let f = maillog_findings(&a);
    assert_eq!(f[0].severity, Severity::Warning);
    assert_eq!(f[0].title, "Bounced: bad@example.net");
}

#[test]
fn an_incomplete_message_has_its_own_finding() {
    let f = maillog_findings(&analyse("postfix/qmgr[2790]: TRUNC123: from=<a@client.com>, size=10, nrcpt=1 (queue active)"));
    assert_eq!((f[0].code, f[0].title.as_ref()), ("mail_log_incomplete", "No final status for TRUNC123"));
}

#[test]
fn a_large_log_does_not_flood_the_findings() {
    let mut log = String::new();
    for i in 0..250 {
        log.push_str(&format!("postfix/smtp[1]: Q{i:07}: to=<u{i}@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)\n"));
    }
    let a = analyse(&log);
    assert_eq!(a.messages.len(), 250);
    let f = maillog_findings(&a);
    assert_eq!(f.iter().filter(|f| f.code == "mail_log_bounced").count(), 10);
    let more = f.iter().find(|f| f.code == "mail_log_more").expect("summary");
    assert!(more.message.contains("240"), "{}", more.message);
}

#[test]
fn other_log_lines_are_never_glued_onto_a_record() {
    let a = analyse("2026-06-12T02:26:21Z mail01 postfix/smtp[2820]: AAA11111: to=<x@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)\n2026-06-12T02:26:22Z mail01 dovecot[99]: lmtp(u): msgid=<1@x>: saved mail to INBOX\n2026-06-12T02:26:23Z mail01 postfix/local[3100]: BBB22222: to=<nobody@ourdomain.com>, relay=local, dsn=5.1.1, status=bounced (unknown user: \"nobody\")\n2026-06-12T02:26:24Z mail01 kernel: something unrelated");
    assert_eq!(a.messages[0].recipients[0].reply, "250 OK");
    assert_eq!(a.messages.len(), 2);
    assert_eq!(a.messages[1].verdict, Verdict::Bounced);
    assert!(a.messages[1].recipients[0].local);
    assert_eq!((a.unparsed, a.dovecot_lines), (1, 1));
}

#[test]
fn warnings_are_not_messages() {
    let a = analyse(&format!(
        "{}\n2026-06-12T02:27:00Z mail01 postfix/smtpd[2811]: warning: hostname bad.example does not resolve to address 203.0.113.99\n2026-06-12T02:27:01Z mail01 postfix/cleanup[2815]: NOQUEUE: milter-reject: END-OF-MESSAGE from unknown[203.0.113.99]: 5.7.1 Rejected by spam filter; from=<s@bad.test> to=<v@ourdomain.com> proto=ESMTP",
        sent_log()
    ));
    assert!(a.messages.iter().all(|m| m.queue_id == "A1B2C3D4"), "{:?}", a.messages.iter().map(|m| &m.queue_id).collect::<Vec<_>>());
    assert_eq!(a.rejections.len(), 1);
    assert_eq!(a.rejections[0].client_ip, ip("203.0.113.99"));
    assert_eq!(a.rejections[0].dsn, "5.7.1");
}

#[test]
fn a_retry_that_succeeds_is_delivered() {
    let a = analyse("2026-06-12T02:40:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, dsn=4.7.1, status=deferred (451 4.7.1 Greylisting in effect, please try again later)\n2026-06-12T02:55:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, dsn=2.0.0, status=sent (250 2.0.0 OK)");
    let m = &a.messages[0];
    assert_eq!((m.verdict, m.recipients.len(), m.recipients[0].status.clone(), m.recipients[0].attempts), (Verdict::Delivered, 1, Some(Status::Sent), 2));
}

#[test]
fn recipient_address_rejected_is_not_always_a_missing_mailbox() {
    for (dsn, reply, status) in [
        ("4.2.0", "450 4.2.0 <u@x.test>: Recipient address rejected: Greylisted, see http://postgrey", "deferred"),
        ("5.7.1", "554 5.7.1 <u@x.test>: Recipient address rejected: Access denied", "bounced"),
    ] {
        let a = analyse(&format!("postfix/smtp[1]: DEC0DE01: to=<u@x.test>, relay=mx[198.51.100.5]:25, dsn={dsn}, status={status} ({reply})"));
        assert_ne!(a.messages[0].recipients[0].reason, Some(Reason::MailboxMissing), "{reply}");
    }
}

#[test]
fn crlf_logs_read_the_same() {
    let lf = sent_log();
    let (a, b) = (analyse(&lf), analyse(&lf.replace('\n', "\r\n")));
    assert_eq!(serde_json::to_string(&a).ok(), serde_json::to_string(&b).ok());
}

#[test]
fn control_characters_never_reach_a_finding() {
    let a = analyse("postfix/smtp[1]: DEC0DE01: to=<u@x.test>, relay=mx\u{1b}[31m[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 \u{7}\u{1b}]0;pwned\u{7} User unknown)");
    for f in maillog_findings(&a) {
        let text = format!("{} {} {}", f.title, f.message, f.recommendation.unwrap_or_default());
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }
}

#[test]
fn a_megabyte_single_line_is_bounded() {
    let raw = format!("postfix/smtp[1]: DEC0DE01: to=<u@x.test>, relay=mx[198.51.100.5]:25, dsn=5.1.1, status=bounced ({})\n{}", "x".repeat(1 << 20), "y".repeat(1 << 20));
    let start = Instant::now();
    let a = analyse(&raw);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
    assert!(a.truncated);
    assert_eq!(a.unparsed, 0, "the second long line is glued on and cut");
    assert!(maillog_findings(&a).iter().any(|f| f.code == "mail_log_truncated"));
}

#[test]
fn many_lines_for_one_queue_id_are_bounded() {
    let mut raw = String::new();
    for i in 0..60_000 {
        raw.push_str(&format!("postfix/smtp[1]: SAMEQID1: to=<u{i}@x>, status=sent (250)\n"));
    }
    let start = Instant::now();
    let a = analyse(&raw);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
    assert_eq!(a.messages[0].recipients.len(), 1000);
    assert!(a.truncated);
}

#[test]
fn a_hundred_thousand_messages_are_bounded() {
    let mut raw = String::new();
    for i in 0..100_000 {
        raw.push_str(&format!("postfix/qmgr[1]: Q{i:07}: removed\n"));
    }
    let start = Instant::now();
    let a = analyse(&raw);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
    assert_eq!(a.messages.len(), 50_000);
    assert!(maillog_findings(&a).len() < 20);
}

#[test]
fn binary_junk_does_not_panic() {
    let mut x: u32 = 0x9e37_79b9;
    for round in 0..50 {
        let bytes: Vec<u8> = (0..20_000)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let b = (x >> 24) as u8;
                if round % 2 == 0 && b.is_multiple_of(9) { b'[' } else { b }
            })
            .collect();
        let text = String::from_utf8_lossy(&bytes);
        if let Ok(a) = analyse_maillog(&text) {
            let _ = maillog_findings(&a);
        }
    }
    let a = analyse(&format!("postfix/smtp[1]: DEC0DE01: to=<\u{ff}>, relay=[[[[, status=sent (\u{0}\u{1}\u{2})\n{}", "(".repeat(10_000)));
    assert_eq!(a.messages.len(), 1);
}

#[test]
fn input_over_four_mebibytes_is_refused() {
    let big = "postfix/qmgr[1]: Q0000001: removed\n".repeat(MAX_INPUT / 30);
    assert_eq!(analyse_maillog(&big).err(), Some(EvidenceError::TooLarge));
}
