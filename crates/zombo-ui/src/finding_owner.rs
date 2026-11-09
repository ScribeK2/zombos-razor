use crate::section::Section;

/// Which rail section owns a finding, by the prefix of its code. The first matching row wins,
/// so a specific prefix goes above a general one. `None` is a deliberate "no section owns this":
/// Evidence findings live in their own tab, and reverse DNS has no section of its own yet.
const OWNERS: &[(&str, Option<Section>)] = &[
    ("email_headers_", None),
    ("mail_log_", None),
    ("rdns_", None),
    ("dns_delegation_", Some(Section::Delegation)),
    ("dns_glue_", Some(Section::Delegation)),
    ("dns_ns_", Some(Section::Delegation)),
    ("dns_", Some(Section::Dns)),
    ("dnssec_", Some(Section::Dnssec)),
    ("spf_", Some(Section::Email)),
    ("dkim_", Some(Section::Email)),
    ("dmarc_", Some(Section::Email)),
    ("email_", Some(Section::Email)),
    ("website_", Some(Section::Web)),
    ("web_", Some(Section::Web)),
    ("ssl_", Some(Section::Tls)),
    ("tls_", Some(Section::Tls)),
    ("caa_", Some(Section::Tls)),
    ("registration_", Some(Section::Registration)),
    ("hosting_reachability_", Some(Section::Ports)),
    ("smtp_", Some(Section::Smtp)),
    ("blacklist_", Some(Section::Blacklist)),
];

pub fn row(code: &str) -> Option<&'static (&'static str, Option<Section>)> {
    OWNERS.iter().find(|(prefix, _)| code.starts_with(prefix))
}

/// The section a finding belongs to, or `None` when no section owns it.
pub fn owner(code: &str) -> Option<Section> {
    row(code).and_then(|(_, s)| *s)
}

/// The section a "go there" button should open from `current`: the owner, unless the rep is
/// already looking at it.
pub fn jump_target(code: &str, current: Section) -> Option<Section> {
    owner(code).filter(|&s| s != current && !(current == Section::TlsPort && s == Section::Tls))
}

/// The digit of the Ctrl+digit shortcut that opens `section`, when it has one. Ctrl+9 opens the
/// first on-demand Check; the other two on-demand Checks have no digit.
pub fn jump_digit(section: Section) -> Option<usize> {
    let i = section.index();
    (i <= Section::FIRST_ON_DEMAND).then_some(i + 1)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::*;

    fn rust_files(dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(fs::read_to_string(path).unwrap());
            }
        }
    }

    /// Every `"word_word"` literal in zombo-core's sources. Finding codes are all of that shape.
    fn core_codes() -> Vec<String> {
        let mut sources = vec![];
        rust_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../zombo-core/src"), &mut sources);
        let mut codes = vec![];
        for src in sources {
            for lit in src.split('"').skip(1).step_by(2) {
                let snake = lit.contains('_')
                    && lit.starts_with(|c: char| c.is_ascii_lowercase())
                    && lit.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    && !lit.ends_with('_')
                    && lit != "snake_case";
                if snake {
                    codes.push(lit.to_string());
                }
            }
        }
        codes.sort();
        codes.dedup();
        codes
    }

    #[test]
    fn every_code_zombo_core_emits_has_a_row_in_the_table() {
        let codes = core_codes();
        assert!(codes.len() > 150, "found only {} codes; the scan is broken", codes.len());
        let missing: Vec<_> = codes.iter().filter(|c| row(c).is_none()).collect();
        assert!(missing.is_empty(), "no owner row for: {missing:?}");
    }

    #[test]
    fn each_family_goes_to_its_section() {
        let cases = [
            ("spf_missing_provider", Some(Section::Email)),
            ("dkim_missing", Some(Section::Email)),
            ("dmarc_policy_none", Some(Section::Email)),
            ("email_bimi_ok", Some(Section::Email)),
            ("email_headers_spf_fail", None),
            ("mail_log_bounced", None),
            ("rdns_no_ptr", None),
            ("dns_delegation_lame", Some(Section::Delegation)),
            ("dns_glue_missing", Some(Section::Delegation)),
            ("dns_ns_is_cname", Some(Section::Delegation)),
            ("dns_propagation_stale_cache", Some(Section::Dns)),
            ("dns_authoritative_behind", Some(Section::Dns)),
            ("dns_network_intercepts", Some(Section::Dns)),
            ("dnssec_bogus", Some(Section::Dnssec)),
            ("website_inspection_slow", Some(Section::Web)),
            ("web_redirect_downgrade", Some(Section::Web)),
            ("ssl_inspection_expired", Some(Section::Tls)),
            ("tls_no_ocsp_staple", Some(Section::Tls)),
            ("caa_no_issue", Some(Section::Tls)),
            ("registration_expiring", Some(Section::Registration)),
            ("hosting_reachability_unreachable", Some(Section::Ports)),
            ("smtp_no_starttls", Some(Section::Smtp)),
            ("blacklist_listed", Some(Section::Blacklist)),
        ];
        for (code, want) in cases {
            assert_eq!(owner(code), want, "{code}");
        }
    }

    #[test]
    fn a_certificate_finding_in_the_tls_port_pane_does_not_send_the_rep_to_the_other_tls_section() {
        assert_eq!(jump_target("tls_expired", Section::TlsPort), None);
        assert_eq!(jump_target("tls_expired", Section::Summary), Some(Section::Tls));
        assert_eq!(jump_target("caa_no_issue", Section::TlsPort), None);
    }

    #[test]
    fn the_digit_matches_the_ctrl_number_bindings() {
        assert_eq!(jump_digit(Section::Email), Some(5));
        assert_eq!(jump_digit(Section::Registration), Some(8));
        assert_eq!(jump_digit(Section::Ports), Some(9));
        assert_eq!(jump_digit(Section::Smtp), None);
        assert_eq!(jump_digit(Section::Blacklist), None);
    }

    #[test]
    fn a_finding_has_no_button_in_the_section_that_owns_it() {
        assert_eq!(jump_target("dkim_missing", Section::Summary), Some(Section::Email));
        assert_eq!(jump_target("dkim_missing", Section::Email), None);
        assert_eq!(jump_target("rdns_no_ptr", Section::Summary), None);
    }
}
