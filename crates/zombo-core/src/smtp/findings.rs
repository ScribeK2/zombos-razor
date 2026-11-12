//! Findings from an SMTP Check result. Pure: no network, and the clock is a parameter.

use time::OffsetDateTime;

use super::{Extensions, Mode, Reach, SmtpResult, Stage, Starttls};
use crate::{
    check::{Fact, Outcome},
    email_auth::clip,
    finding::{Finding, Severity},
    tls::tls_findings_at,
};

/// Ports that many networks and hosting providers refuse to let customers dial out to.
const OUTBOUND_MAIL: [u16; 4] = [25, 465, 587, 2525];

pub fn smtp_findings(r: &SmtpResult, expect_names: &[String]) -> Vec<Finding> {
    smtp_findings_at(r, expect_names, OffsetDateTime::now_utc())
}

/// `expect_names` are the names the greeting is compared with: the host's own
/// name and the PTR names of the address that answered. Empty means no comparison.
pub fn smtp_findings_at(r: &SmtpResult, expect_names: &[String], now: OffsetDateTime) -> Vec<Finding> {
    let place = format!("{}:{}", r.host, r.port);
    let detail = r.failure.as_ref().map(|f| clip(&f.message)).unwrap_or_default();
    match r.reach {
        Reach::Answered => {}
        Reach::NoAnswer => {
            let why = if OUTBOUND_MAIL.contains(&r.port) {
                "Many networks and hosting providers block outbound mail connections, so this may be the network doing the Check and not the server."
            } else {
                "A firewall may be dropping the connection, or nothing may be there."
            };
            return vec![
                Finding::new(
                    "smtp_no_answer",
                    Severity::Info,
                    "No answer from the mail server",
                    format!("{place} did not answer in time. {why}"),
                )
                .recommend("Re-run from a network that allows outbound mail, or check the server's own mail logs."),
            ];
        }
        Reach::Refused => {
            return vec![
                Finding::new(
                    "smtp_refused",
                    Severity::Warning,
                    "Mail port refused the connection",
                    format!("{place} refused the connection: the host is up and nothing listens on that port."),
                )
                .recommend("Check that the mail server is running and listening on this port."),
            ];
        }
        Reach::NoRoute => {
            return vec![
                Finding::new(
                    "smtp_no_route",
                    Severity::Info,
                    "No route to the mail server",
                    format!("This network has no route to {place} ({detail})."),
                )
                .recommend("Your own connection may lack a route (for example no IPv6); re-run from another network."),
            ];
        }
        Reach::Failed => {
            return vec![Finding::new(
                "smtp_connect_failed",
                Severity::Warning,
                "Could not connect to the mail server",
                format!("The connection to {place} failed: {detail}."),
            )];
        }
    }

    let mut out = vec![];
    if let Some(f) = &r.failure {
        out.push(match f.stage {
            Stage::Greeting => Finding::new(
                "smtp_no_greeting",
                Severity::Warning,
                "No usable greeting from the mail server",
                format!("{place} accepted the connection but sent no usable SMTP greeting: {detail}. Some networks accept connections on mail ports and then stall them, so this may not be the server."),
            )
                .recommend("Re-run from another network. If it persists, check the mail server and any firewall or proxy in front of it."),
            Stage::Tls => Finding::new(
                "smtp_tls_failed",
                Severity::Critical,
                "TLS handshake failed",
                format!("{place} expects TLS from the first byte, and the handshake failed: {detail}."),
            )
                .recommend("Check the mail server's TLS configuration and certificate."),
            _ => Finding::new(
                "smtp_protocol_error",
                Severity::Warning,
                "The mail server broke the SMTP dialogue",
                format!("The dialogue with {place} failed: {detail}."),
            ),
        });
    }

    if let Some(b) = &r.banner {
        if b.code != 220 {
            out.push(Finding::new(
                "smtp_banner_rejected",
                Severity::Warning,
                "The server did not greet with 220",
                format!("{place} answered with {} {} instead of a 220 greeting, so it is not accepting mail from this address right now.", b.code, clip(&b.text)),
            )
                .recommend("A 4xx code is temporary and a 5xx code is a refusal; read the text for the reason (a blocklist, a rate limit, no service on this port)."));
        } else if let Some(name) = &b.hostname
            && !expect_names.is_empty()
            && !expect_names.iter().any(|n| n.trim_end_matches('.').eq_ignore_ascii_case(name))
        {
            let shown = expect_names.iter().map(|n| n.trim_end_matches('.')).collect::<Vec<_>>().join(", ");
            out.push(Finding::new(
                "smtp_banner_name_mismatch",
                Severity::Info,
                format!("The greeting names {}", clip(name)),
                format!("{place} greets as {}, which is none of {shown}. Receiving servers that compare the greeting with reverse DNS may score this mail as suspicious.", clip(name)),
            )
                .recommend("Set the mail server's host name (Postfix myhostname) to the name in its PTR record."));
        }
    }

    if r.mode == Mode::Starttls {
        match &r.starttls {
            Starttls::NotOffered => out.push(Finding::new(
                "smtp_no_starttls",
                Severity::Warning,
                "STARTTLS not offered",
                format!("{place} did not offer STARTTLS, so mail to and from it crosses the network unencrypted."),
            )
                .recommend("Enable TLS on the mail server (Postfix smtpd_tls_cert_file and smtpd_tls_security_level=may) with a certificate for its name.")),
            Starttls::Refused { code, text } => out.push(Finding::new(
                "smtp_starttls_failed",
                Severity::Warning,
                "STARTTLS refused",
                format!("{place} offered STARTTLS and then answered the command with {code} {}.", clip(text)),
            )
                .recommend("Check the mail server's TLS configuration and its logs.")),
            Starttls::HandshakeFailed(why) => out.push(Finding::new(
                "smtp_starttls_failed",
                Severity::Warning,
                "STARTTLS handshake failed",
                format!("{place} accepted STARTTLS and the TLS handshake then failed: {}.", clip(why)),
            )
                .recommend("Check the mail server's certificate, protocol versions and ciphers.")),
            Starttls::Upgraded | Starttls::NotApplicable | Starttls::NotAttempted => {}
        }
        if let Some(e) = &r.extensions
            && !e.auth.is_empty()
        {
            out.push(Finding::new(
                "smtp_auth_before_tls",
                Severity::Warning,
                "Login offered before TLS",
                format!(
                    "{place} offers AUTH ({}) before TLS starts. A client that skips STARTTLS would send its password in clear text.",
                    e.auth.join(", ")
                ),
            )
                .recommend("Offer AUTH only after STARTTLS (Postfix smtpd_tls_auth_only=yes)."));
        }
    }

    if let Some(tls) = &r.tls {
        out.extend(tls_findings_at(&r.host, r.port, tls, now));
        let how = if r.mode == Mode::Implicit { "Implicit TLS accepted" } else { "STARTTLS accepted" };
        out.push(Finding::new(
            "smtp_tls_ok",
            Severity::Ok,
            how,
            format!("{place} spoke {} ({}).", tls.version, tls.cipher),
        ));
    }
    out
}

fn extensions_text(e: &Extensions) -> String {
    let mut parts = vec![];
    for (on, name) in [(e.starttls, "STARTTLS"), (e.pipelining, "PIPELINING"), (e.eight_bit_mime, "8BITMIME")] {
        if on {
            parts.push(name.to_string());
        }
    }
    if let Some(n) = e.size {
        parts.push(format!("SIZE {n}"));
    }
    if !e.auth.is_empty() {
        parts.push(format!("AUTH {}", e.auth.join(" ")));
    }
    parts.extend(e.other.iter().cloned());
    if parts.is_empty() { "nothing".into() } else { parts.join(", ") }
}

pub(super) fn outcome(r: &SmtpResult, expect_names: &[String]) -> Outcome {
    let peer = r.peer.map(|p| format!(" ({p})")).unwrap_or_default();
    let mut facts = vec![
        Fact::new("Server", format!("{}:{}{peer}", r.host, r.port)),
        Fact::new(
            "Reached",
            match r.reach {
                Reach::Answered => "answered",
                Reach::NoAnswer => "no answer",
                Reach::Refused => "refused",
                Reach::NoRoute => "no route from this network",
                Reach::Failed => "failed",
            },
        ),
    ];
    if let Some(b) = &r.banner {
        facts.push(Fact::new("Banner", format!("{} {}", b.code, b.text)));
    }
    if let Some(e) = &r.extensions {
        facts.push(Fact::new("Offers", extensions_text(e)));
    }
    facts.push(Fact::new(
        "STARTTLS",
        match &r.starttls {
            Starttls::NotApplicable => "not used, the port starts TLS at once".to_string(),
            Starttls::NotAttempted => "not tried".to_string(),
            Starttls::NotOffered => "not offered".to_string(),
            Starttls::Refused { code, text } => format!("refused: {code} {text}"),
            Starttls::HandshakeFailed(why) => format!("handshake failed: {why}"),
            Starttls::Upgraded => "upgraded to TLS".to_string(),
        },
    ));
    if let Some(t) = &r.tls {
        facts.push(Fact::new("Protocol", &t.version));
        facts.push(Fact::new("Cipher", &t.cipher));
        facts.push(Fact::new("Trust", format!("{:?}", t.trust)));
        if let Some(leaf) = t.chain.first() {
            facts.push(Fact::new("Certificate", format!("{}, expires {}", leaf.subject, leaf.not_after)));
        }
    }
    if let Some(f) = &r.failure {
        facts.push(Fact::new("Stopped", format!("{:?}: {}", f.stage, f.message)));
    }
    let details = r
        .extensions_after_tls
        .as_ref()
        .map(|e| vec![Fact::new("Offers after STARTTLS", extensions_text(e))])
        .unwrap_or_default();
    Outcome { findings: smtp_findings(r, expect_names), facts, details_title: "After STARTTLS", details }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_smtp_server_that_never_answered_is_reported_as_no_answer_with_the_cores_finding() {
        let r = SmtpResult {
            host: "mail.example.com".into(),
            port: 25,
            mode: Mode::Starttls,
            reach: Reach::NoAnswer,
            peer: None,
            banner: None,
            extensions: None,
            starttls: Starttls::NotAttempted,
            tls: None,
            extensions_after_tls: None,
            failure: None,
        };
        let o = outcome(&r, &[]);
        let lines = o.records();
        assert!(lines.contains(&"Reached: no answer".to_string()));
        assert!(lines.contains(&"STARTTLS: not tried".to_string()));
        assert!(!o.findings.is_empty());
    }
}
