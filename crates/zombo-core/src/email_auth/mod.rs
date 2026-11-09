//! Email authentication: SPF, DKIM and DMARC audits and their Findings, plus the
//! DNS-only checks for TLS-RPT, BIMI and the MTA-STS TXT record. All input is
//! untrusted DNS text: nothing here panics on it, and every walk is bounded.

mod dkim;
mod dmarc;
mod records;
mod spf;

pub use dkim::{DKIM_COMMON_SELECTORS, DkimFlags, DkimKey, DkimKeyError, KeyType, parse_dkim_key};
pub use dmarc::{Alignment, DmarcRecord, Policy, parse_dmarc};
pub use records::{Bimi, MtaSts, TlsRpt, parse_bimi, parse_mta_sts, parse_tls_rpt};
pub use spf::{
    EffectiveAll, HostSpec, MAX_LOOKUPS, Mechanism, NodeError, ParsedSpf, Qualifier, RefKind, SpfError, SpfNode, SpfTerm, effective_all, parse_spf,
    spf_records,
};

use std::collections::BTreeMap;

/// DKIM and DMARC records are `tag=value; tag=value` lists. Tag names are
/// case-insensitive, whitespace inside a value is dropped, and a repeated tag
/// keeps its last value.
pub(crate) fn tags(record: &str) -> BTreeMap<String, String> {
    record
        .split(';')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.split_whitespace().collect()))
        })
        .collect()
}

/// Whether the record's first tag is `v=<version>` (the version is case-insensitive).
pub(crate) fn has_version(record: &str, version: &str) -> bool {
    let first = record.split(';').next().unwrap_or_default();
    first.split_whitespace().collect::<String>().eq_ignore_ascii_case(&format!("v={version}"))
}

/// A record or name read from DNS may hold terminal control characters; the
/// results get printed, so they are replaced where the text enters.
pub(crate) fn printable(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '\u{fffd}' } else { c }).collect()
}

/// A hostile token can be 64 KB long; keep the part of it that ends up in a message.
pub(crate) fn clip(s: &str) -> String {
    const MAX: usize = 80;
    match s.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_case_insensitive_whitespace_free_and_last_wins() {
        let t = tags("v=DKIM1 ; K = rsa;p=AB CD\n EF;junk;p=XY;;=x");
        assert_eq!(t["k"], "rsa");
        assert_eq!(t["p"], "XY");
        assert_eq!(t["v"], "DKIM1");
        assert_eq!(t[""], "x");
    }

    #[test]
    fn the_version_is_the_first_tag_only() {
        assert!(has_version("v=DMARC1; p=none", "DMARC1"));
        assert!(has_version(" V = dmarc1 ;p=none", "DMARC1"));
        assert!(!has_version("p=none; v=DMARC1", "DMARC1"));
        assert!(!has_version("", "DMARC1"));
    }

    #[test]
    fn clip_cuts_on_a_char_boundary() {
        assert_eq!(clip("short"), "short");
        let long = "é".repeat(200);
        assert_eq!(clip(&long).chars().count(), 83);
    }
}
