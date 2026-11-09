//! Findings from an SMTP Check result. Pure: no network, and the clock is a parameter.

use std::borrow::Cow;

use time::OffsetDateTime;

use super::{Mode, Reach, SmtpResult, Stage, Starttls};
use crate::{
    email_auth::clip,
    finding::{Finding, Severity},
    tls::tls_findings_at,
};

/// Ports that many networks and hosting providers refuse to let customers dial out to.
const OUTBOUND_MAIL: [u16; 4] = [25, 465, 587, 2525];

fn finding(code: &'static str, severity: Severity, title: impl Into<Cow<'static, str>>, message: String, recommendation: Option<&'static str>) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation: recommendation.map(Cow::Borrowed) }
}

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
            return vec![finding(
                "smtp_no_answer",
                Severity::Info,
                "No answer from the mail server",
                format!("{place} did not answer in time. {why}"),
                Some("Re-run from a network that allows outbound mail, or check the server's own mail logs."),
            )];
        }
        Reach::Refused => {
            return vec![finding(
                "smtp_refused",
                Severity::Warning,
                "Mail port refused the connection",
                format!("{place} refused the connection: the host is up and nothing listens on that port."),
                Some("Check that the mail server is running and listening on this port."),
            )];
        }
        Reach::NoRoute => {
            return vec![finding(
                "smtp_no_route",
                Severity::Info,
                "No route to the mail server",
                format!("This network has no route to {place} ({detail})."),
                Some("Your own connection may lack a route (for example no IPv6); re-run from another network."),
            )];
        }
        Reach::Failed => {
            return vec![finding(
                "smtp_connect_failed",
                Severity::Warning,
                "Could not connect to the mail server",
                format!("The connection to {place} failed: {detail}."),
                None,
            )];
        }
    }

    let mut out = vec![];
    if let Some(f) = &r.failure {
        out.push(match f.stage {
            Stage::Greeting => finding(
                "smtp_no_greeting",
                Severity::Warning,
                "No usable greeting from the mail server",
                format!("{place} accepted the connection but sent no usable SMTP greeting: {detail}. Some networks accept connections on mail ports and then stall them, so this may not be the server."),
                Some("Re-run from another network. If it persists, check the mail server and any firewall or proxy in front of it."),
            ),
            Stage::Tls => finding(
                "smtp_tls_failed",
                Severity::Critical,
                "TLS handshake failed",
                format!("{place} expects TLS from the first byte, and the handshake failed: {detail}."),
                Some("Check the mail server's TLS configuration and certificate."),
            ),
            _ => finding(
                "smtp_protocol_error",
                Severity::Warning,
                "The mail server broke the SMTP dialogue",
                format!("The dialogue with {place} failed: {detail}."),
                None,
            ),
        });
    }

    if let Some(b) = &r.banner {
        if b.code != 220 {
            out.push(finding(
                "smtp_banner_rejected",
                Severity::Warning,
                "The server did not greet with 220",
                format!("{place} answered with {} {} instead of a 220 greeting, so it is not accepting mail from this address right now.", b.code, clip(&b.text)),
                Some("A 4xx code is temporary and a 5xx code is a refusal; read the text for the reason (a blocklist, a rate limit, no service on this port)."),
            ));
        } else if let Some(name) = &b.hostname
            && !expect_names.is_empty()
            && !expect_names.iter().any(|n| n.trim_end_matches('.').eq_ignore_ascii_case(name))
        {
            let shown = expect_names.iter().map(|n| n.trim_end_matches('.')).collect::<Vec<_>>().join(", ");
            out.push(finding(
                "smtp_banner_name_mismatch",
                Severity::Info,
                format!("The greeting names {}", clip(name)),
                format!("{place} greets as {}, which is none of {shown}. Receiving servers that compare the greeting with reverse DNS may score this mail as suspicious.", clip(name)),
                Some("Set the mail server's host name (Postfix myhostname) to the name in its PTR record."),
            ));
        }
    }

    if r.mode == Mode::Starttls {
        match &r.starttls {
            Starttls::NotOffered => out.push(finding(
                "smtp_no_starttls",
                Severity::Warning,
                "STARTTLS not offered",
                format!("{place} did not offer STARTTLS, so mail to and from it crosses the network unencrypted."),
                Some("Enable TLS on the mail server (Postfix smtpd_tls_cert_file and smtpd_tls_security_level=may) with a certificate for its name."),
            )),
            Starttls::Refused { code, text } => out.push(finding(
                "smtp_starttls_failed",
                Severity::Warning,
                "STARTTLS refused",
                format!("{place} offered STARTTLS and then answered the command with {code} {}.", clip(text)),
                Some("Check the mail server's TLS configuration and its logs."),
            )),
            Starttls::HandshakeFailed(why) => out.push(finding(
                "smtp_starttls_failed",
                Severity::Warning,
                "STARTTLS handshake failed",
                format!("{place} accepted STARTTLS and the TLS handshake then failed: {}.", clip(why)),
                Some("Check the mail server's certificate, protocol versions and ciphers."),
            )),
            Starttls::Upgraded | Starttls::NotApplicable | Starttls::NotAttempted => {}
        }
        if let Some(e) = &r.extensions
            && !e.auth.is_empty()
        {
            out.push(finding(
                "smtp_auth_before_tls",
                Severity::Warning,
                "Login offered before TLS",
                format!(
                    "{place} offers AUTH ({}) before TLS starts. A client that skips STARTTLS would send its password in clear text.",
                    e.auth.join(", ")
                ),
                Some("Offer AUTH only after STARTTLS (Postfix smtpd_tls_auth_only=yes)."),
            ));
        }
    }

    if let Some(tls) = &r.tls {
        out.extend(tls_findings_at(&r.host, r.port, tls, now));
        let how = if r.mode == Mode::Implicit { "Implicit TLS accepted" } else { "STARTTLS accepted" };
        out.push(finding("smtp_tls_ok", Severity::Ok, how, format!("{place} spoke {} ({}).", tls.version, tls.cipher), None));
    }
    out
}
