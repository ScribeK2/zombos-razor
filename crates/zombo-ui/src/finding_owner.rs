use std::{cmp::Reverse, sync::LazyLock};

use crate::section::Section;

/// Which rail section owns a finding, by the prefix of its code. The longest matching prefix
/// wins, so row order does not matter. A migrated Check lists its own prefixes in its descriptor
/// and is not repeated here. `None` is a deliberate "no section owns this":
/// Evidence findings live in their own tab.
const OWNERS: &[(&str, Option<Section>)] = &[
    ("email_headers_", None),
    ("mail_log_", None),
    ("dns_delegation_", Some(Section::Delegation)),
    ("dns_glue_", Some(Section::Delegation)),
    ("dns_ns_", Some(Section::Delegation)),
    ("dns_", Some(Section::Dns)),
    ("spf_", Some(Section::Email)),
    ("dkim_", Some(Section::Email)),
    ("dmarc_", Some(Section::Email)),
    ("email_", Some(Section::Email)),
    ("website_", Some(Section::Web)),
    ("web_", Some(Section::Web)),
    ("registration_", Some(Section::Registration)),
    ("rdns_", Some(Section::Rdns)),
    ("hosting_reachability_", Some(Section::Ports)),
    ("smtp_", Some(Section::Smtp)),
    ("blacklist_", Some(Section::Blacklist)),
];

type Row = (&'static str, Option<Section>);

/// The table above plus every prefix a migrated Check's descriptor lists.
static TABLE: LazyLock<Vec<Row>> = LazyLock::new(|| {
    let migrated = Section::ALL.into_iter().filter_map(|s| Some((s, s.check()?)));
    let owned = migrated.flat_map(|(s, c)| c.owns.iter().map(move |&p| (p, Some(s))));
    OWNERS.iter().copied().chain(owned).collect()
});

/// The longest prefix that `code` starts with wins, wherever its row sits. Two rows with the same
/// prefix tie and the earlier row wins, so the lookup stays deterministic; no registered prefix
/// relies on that, as `no_two_registered_rows_declare_the_same_prefix` checks.
fn longest<'a>(table: &'a [Row], code: &str) -> Option<&'a Row> {
    table.iter().filter(|(prefix, _)| code.starts_with(prefix)).min_by_key(|(prefix, _)| Reverse(prefix.len()))
}

pub fn row(code: &str) -> Option<&'static Row> {
    longest(&TABLE, code)
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

/// The digit of the Ctrl+digit shortcut that opens `section`, when it has one. Ctrl+1 to 8 open
/// the first eight sections and Ctrl+9 the first on-demand Check; Reverse DNS and the other
/// on-demand Checks have no digit.
pub fn jump_digit(section: Section) -> Option<usize> {
    match section.index() {
        i if i < 8 => Some(i + 1),
        i if i == Section::FIRST_ON_DEMAND => Some(9),
        _ => None,
    }
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

    /// The table as it stood before any Check had a descriptor: the first matching row wins, so a
    /// specific prefix sits above a general one.
    const OLD_FIRST_MATCH: &[(&str, Option<Section>)] = &[
        ("email_headers_", None),
        ("mail_log_", None),
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
        ("rdns_", Some(Section::Rdns)),
        ("hosting_reachability_", Some(Section::Ports)),
        ("smtp_", Some(Section::Smtp)),
        ("blacklist_", Some(Section::Blacklist)),
    ];

    #[test]
    fn the_longest_prefix_owner_equals_the_old_first_match_owner_for_every_code_zombo_core_emits() {
        let codes = core_codes();
        assert!(codes.len() > 150, "found only {} codes; the scan is broken", codes.len());
        for code in &codes {
            let old = OLD_FIRST_MATCH.iter().find(|(p, _)| code.starts_with(p)).and_then(|(_, s)| *s);
            assert_eq!(owner(code), old, "{code}");
        }
    }

    #[test]
    fn a_specific_prefix_wins_over_a_general_one_whichever_row_comes_first() {
        let general_first = [("dns_", Some(Section::Dns)), ("dns_glue_", Some(Section::Delegation))];
        assert_eq!(longest(&general_first, "dns_glue_x").unwrap().1, Some(Section::Delegation));
        assert_eq!(longest(&general_first, "dns_other").unwrap().1, Some(Section::Dns));
        assert_eq!(longest(&general_first, "web_x"), None);
    }

    #[test]
    fn two_rows_with_the_same_prefix_tie_and_the_earlier_row_wins() {
        let table = [("tls_", Some(Section::Tls)), ("tls_", Some(Section::TlsPort))];
        assert_eq!(longest(&table, "tls_x").unwrap().1, Some(Section::Tls));
        let table = [("tls_", Some(Section::TlsPort)), ("tls_", Some(Section::Tls))];
        assert_eq!(longest(&table, "tls_x").unwrap().1, Some(Section::TlsPort));
    }

    #[test]
    fn no_two_registered_rows_declare_the_same_prefix() {
        let mut prefixes: Vec<_> = TABLE.iter().map(|(p, _)| *p).collect();
        prefixes.sort_unstable();
        let dupes: Vec<_> = prefixes.windows(2).filter(|w| w[0] == w[1]).map(|w| w[0]).collect();
        assert!(dupes.is_empty(), "declared twice: {dupes:?}");
    }

    #[test]
    fn the_tls_prefixes_belong_to_the_automatic_section_not_the_on_demand_one() {
        for code in ["ssl_inspection_expired", "tls_no_ocsp_staple", "caa_none"] {
            assert_eq!(owner(code), Some(Section::Tls), "{code}");
        }
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
            ("rdns_no_ptr", Some(Section::Rdns)),
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
        assert_eq!(jump_digit(Section::Rdns), None);
        assert_eq!(jump_digit(Section::Smtp), None);
        assert_eq!(jump_digit(Section::Blacklist), None);
    }

    #[test]
    fn a_finding_has_no_button_in_the_section_that_owns_it() {
        assert_eq!(jump_target("dkim_missing", Section::Summary), Some(Section::Email));
        assert_eq!(jump_target("dkim_missing", Section::Email), None);
        assert_eq!(jump_target("rdns_no_ptr", Section::Summary), Some(Section::Rdns));
        assert_eq!(jump_target("rdns_no_ptr", Section::Rdns), None);
    }
}
