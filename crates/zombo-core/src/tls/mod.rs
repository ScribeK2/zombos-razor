//! TLS certificate and chain, level 1: what the server presents, whether a
//! client would trust it, and when it expires. Ported from the Go
//! `ssl_inspection` Check. A cipher-suite scan is out of scope.
//!
//! The handshake accepts any certificate so that broken ones can be shown in
//! full. Trust is then judged here, with an injected clock, so every failure
//! is its own finding.

use std::time::Duration;

use crate::{
    check::{Check, Fact, OnDemand, Outcome, Request, RunFlag},
    target::Kind,
};

mod caa;
mod handshake;
mod ocsp;

pub use caa::{CaaRecord, CaaResult, ca_identifiers, caa_findings, check_caa};
pub use handshake::{
    Assessment, KeyInfo, MAX_CERT_BYTES, MAX_CHAIN, TlsCert, TlsError, TlsResult, Trust, assess, check_tls,
    check_tls_via, inspect_stream, inspect_stream_keep, public_roots, tls_findings, tls_findings_at,
};
pub use ocsp::ocsp_findings;

/// Everything one TLS run saw: the handshake, and the CAA records when the run asked for them.
struct Observed {
    handshake: TlsResult,
    caa: Option<CaaResult>,
}

const LIMITS: (Duration, Duration) = (Duration::from_secs(10), Duration::from_secs(8));

/// The automatic TLS row: the handshake and the CAA records, on `Request::port`.
pub static CHECK: Check = Check {
    label: "TLS",
    id: "tls",
    accepts: &[Kind::Domain, Kind::Hostname, Kind::Email],
    automatic_for: &[Kind::Domain, Kind::Hostname, Kind::Email],
    budget: LIMITS,
    owns: &["ssl_", "tls_", "caa_"],
    blind_spots: &[
        "Other ports: the TLS on a port Check asks for those.",
        "Protocol versions below TLS 1.2: this tool speaks only 1.2 and 1.3.",
        "Cipher suites the server accepts but did not choose.",
        "Revocation at the CA: only an OCSP response stapled by the server is seen.",
    ],
    honours: &[RunFlag::Timeout, RunFlag::Resolver],
    ..Check::base(|request| Box::pin(observe(request, true)))
};

/// The on-demand TLS row: the handshake alone, on the port the rep picked. It emits `ssl_` and
/// `tls_` findings too, but [`CHECK`] owns those prefixes.
pub static ON_PORT: Check = Check {
    label: "TLS on a port",
    id: "tls-port",
    accepts: &[Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip],
    on_demand: Some(OnDemand {
        run_label: "Run TLS check",
        what: "Opens a TLS connection to one port of the target and reads the certificate and protocol it presents. It sends no mail and no web request.",
        contacts: "The target's own server, on the port you pick below: its first address, found by this machine's resolver. The target sees one TLS handshake.",
        note: Some(
            "Port 443 is the website. Mail servers present their own certificate on 465, 993 and 995. A server that starts TLS with STARTTLS on 25 or 587 is checked in the SMTP banner check.",
        ),
    }),
    budget: LIMITS,
    blind_spots: &[
        "Services that start TLS after a plain greeting (STARTTLS): the SMTP banner check covers those.",
        "A server that requires a client certificate.",
        "Protocol versions below TLS 1.2, and revocation at the CA.",
    ],
    takes_chosen_port: true,
    ..Check::base(|request| Box::pin(observe(request, false)))
};

async fn observe(request: &Request<'_>, with_caa: bool) -> Result<Outcome, String> {
    let (name, port, query) = (request.name, request.port, request.query);
    let (handshake, caa) = if with_caa {
        let (h, c) = tokio::join!(check_tls(name, port, query), check_caa(request.bootstrap, name, query));
        (h, Some(c))
    } else {
        (check_tls(name, port, query).await, None)
    };
    handshake.map(|handshake| outcome(name, port, &Observed { handshake, caa })).map_err(|e| e.to_string())
}

fn outcome(host: &str, port: u16, seen: &Observed) -> Outcome {
    let o = tls_outcome_on(host, port, &seen.handshake);
    match &seen.caa {
        Some(caa) => with_caa(o, caa, Some(&seen.handshake)),
        None => o,
    }
}

/// The TLS section's rows and findings for a handshake on any port. Off 443 the port is the
/// first row, so a copied section says which service it describes.
fn tls_outcome_on(host: &str, port: u16, r: &TlsResult) -> Outcome {
    let mut facts = vec![];
    if port != 443 {
        facts.push(Fact::new("Port", port.to_string()));
    }
    facts.extend([
        Fact::new("Protocol", &r.version),
        Fact::new("Cipher", &r.cipher),
        Fact::new("Trust", format!("{:?}", r.trust)),
        Fact::new("Name matches", if r.hostname_match { "yes" } else { "no" }),
    ]);
    if let Some(leaf) = r.chain.first() {
        facts.push(Fact::new("Subject", &leaf.subject));
        facts.push(Fact::new("Issuer", &leaf.issuer));
        facts.push(Fact::new("Expires", leaf.not_after.to_string()));
    }
    let details = r
        .chain
        .iter()
        .enumerate()
        .map(|(i, c)| {
            Fact::new(format!("Certificate {}", i + 1), format!("{} issued by {}, {}", c.subject, c.issuer, c.key))
        })
        .collect();
    let mut findings = tls_findings(host, port, r);
    findings.extend(ocsp_findings(host, port, r));
    Outcome { findings, facts, details_title: "Certificate chain", details }
}

/// The CAA records that apply to the name, as rows and findings in the TLS section.
fn with_caa(mut o: Outcome, caa: &CaaResult, tls: Option<&TlsResult>) -> Outcome {
    match (&caa.error, caa.found_at.as_deref()) {
        (Some(e), _) => o.facts.push(Fact::new("CAA", format!("lookup failed: {e}"))),
        (None, None) => o.facts.push(Fact::new("CAA", "none: any certificate authority may issue")),
        (None, Some(at)) => {
            for r in &caa.records {
                o.facts.push(Fact::new(
                    format!("CAA at {at}"),
                    format!("{} {} \"{}\"", if r.critical { 128 } else { 0 }, r.tag, r.value),
                ));
            }
        }
    }
    o.findings.extend(caa_findings(caa, tls));
    // Worst first; the sort is stable, so equal ones keep their order.
    o.findings.sort_by_key(|f| f.severity.rank());
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_descriptors_say_how_each_row_is_named_when_it_runs_and_what_it_tells_the_rep() {
        assert_eq!((CHECK.label, ON_PORT.label), ("TLS", "TLS on a port"));
        assert_eq!(CHECK.automatic_for, [Kind::Domain, Kind::Hostname, Kind::Email]);
        assert!(!CHECK.is_on_demand() && CHECK.on_demand.is_none());
        assert!(ON_PORT.is_on_demand());
        let brief = ON_PORT.on_demand.unwrap();
        assert_eq!(brief.run_label, "Run TLS check");
        assert!(brief.what.starts_with("Opens a TLS connection") && brief.contacts.contains("on the port you pick"));
    }

    fn tls_outcome(host: &str, r: &TlsResult) -> Outcome {
        tls_outcome_on(host, 443, r)
    }

    fn tls_result() -> TlsResult {
        let now = time::OffsetDateTime::now_utc();
        TlsResult {
            version: "TLS 1.3".into(),
            cipher: "TLS_AES_128_GCM_SHA256".into(),
            chain: vec![TlsCert {
                subject: "other.example".into(),
                issuer: "Test CA".into(),
                sans: vec!["other.example".into()],
                not_before: now - time::Duration::days(30),
                not_after: now + time::Duration::days(300),
                self_signed: false,
                is_ca: false,
                key: KeyInfo::Rsa(2048),
                signature: "SHA256-RSA".into(),
            }],
            hostname_match: false,
            verified: false,
            trust: Trust::Ok,
            verify_error: None,
            ocsp_stapled: false,
        }
    }

    #[test]
    fn a_tls_check_on_another_port_names_the_port_in_its_rows_and_findings() {
        let on_993 = tls_outcome_on("mail.example.com", 993, &tls_result());
        assert_eq!(on_993.facts[0], Fact::new("Port", "993"));
        assert!(on_993.findings.iter().any(|f| f.message.contains("mail.example.com:993")), "{:?}", on_993.findings);
        assert!(on_993.findings.iter().all(|f| !f.message.contains(":443")), "{:?}", on_993.findings);
        let on_443 = tls_outcome("mail.example.com", &tls_result());
        assert_eq!(on_443.facts[0].key, "Protocol");
        assert!(on_443.findings.iter().any(|f| f.message.contains("mail.example.com:443")));
    }

    fn caa(found_at: Option<&str>, records: &[(bool, &str, &str)], error: Option<&str>) -> CaaResult {
        CaaResult {
            name: "www.example.com".into(),
            found_at: found_at.map(Into::into),
            records: records
                .iter()
                .map(|(c, t, v)| CaaRecord { critical: *c, tag: t.to_string(), value: v.to_string() })
                .collect(),
            error: error.map(Into::into),
        }
    }

    #[test]
    fn caa_records_join_the_tls_rows_and_its_findings_join_the_tls_findings() {
        let o =
            with_caa(Outcome::default(), &caa(Some("example.com"), &[(false, "issue", "letsencrypt.org")], None), None);
        assert_eq!(o.records(), ["CAA at example.com: 0 issue \"letsencrypt.org\""]);
        assert!(
            o.findings.iter().any(|f| f.code == "caa_ok"),
            "{:?}",
            o.findings.iter().map(|f| f.code).collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_caa_record_is_stated_and_flagged_not_left_blank() {
        let o = with_caa(Outcome::default(), &caa(None, &[], None), None);
        assert_eq!(o.records(), ["CAA: none: any certificate authority may issue"]);
        assert!(o.findings.iter().any(|f| f.code == "caa_none"));
    }

    #[test]
    fn a_caa_lookup_that_failed_says_so_and_is_a_warning() {
        let o = with_caa(Outcome::default(), &caa(None, &[], Some("timed out")), None);
        assert_eq!(o.records(), ["CAA: lookup failed: timed out"]);
        assert!(o.findings.iter().any(|f| f.code == "caa_lookup_failed"));
    }

    #[test]
    fn a_critical_flag_is_shown_as_128() {
        let o = with_caa(Outcome::default(), &caa(Some("example.com"), &[(true, "issue", ";")], None), None);
        assert!(o.records()[0].contains(": 128 issue"));
    }
}
