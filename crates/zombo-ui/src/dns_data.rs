use std::collections::{BTreeMap, BTreeSet};

use crate::diagnosis::Row;

/// A collapsed row of the DNS section: a title, a one-line summary and the lines under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collapsed {
    pub id: &'static str,
    pub title: &'static str,
    pub summary: String,
    pub lines: Vec<(String, String)>,
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// What each authoritative nameserver answered, with the SOA serial in the summary.
pub fn nameserver_answers(rows: &[Row]) -> Option<Collapsed> {
    let servers: Vec<&Row> = rows.iter().filter(|r| r.authoritative).collect();
    if servers.is_empty() {
        return None;
    }
    let serials: BTreeSet<u32> = servers.iter().filter_map(|r| r.serial).collect();
    let mut summary = plural(servers.len(), "nameserver");
    match (serials.len(), serials.first()) {
        (1, Some(serial)) => {
            let on = if servers.len() == 1 { "" } else if servers.len() == 2 { " on both" } else { " on all" };
            summary.push_str(&format!(" \u{b7} SOA serial {serial}{on}"));
        }
        (n, _) if n > 1 => summary.push_str(" \u{b7} SOA serials differ"),
        _ => {}
    }
    let lines = servers
        .iter()
        .flat_map(|r| match &r.error {
            Some(e) => vec![(r.resolver.clone(), e.clone())],
            None => r.answers.iter().map(|(ty, vs)| (format!("{} {ty}", r.resolver), vs.join(", "))).collect(),
        })
        .collect();
    Some(Collapsed { id: "nameservers", title: "Nameserver answers", summary, lines })
}

/// Every record the zone returned, for every type asked. The authoritative nameservers are the
/// truth when they answered; otherwise the resolvers' answers are merged.
pub fn all_records(rows: &[Row]) -> Option<Collapsed> {
    let answered = |r: &&Row| r.error.is_none();
    let mut source: Vec<&Row> = rows.iter().filter(answered).filter(|r| r.authoritative).collect();
    if source.is_empty() {
        source = rows.iter().filter(answered).collect();
    }
    let mut by_type: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in source {
        for (ty, values) in &r.answers {
            by_type.entry(ty).or_default().extend(values.iter().map(String::as_str));
        }
    }
    by_type.retain(|_, v| !v.is_empty());
    if by_type.is_empty() {
        return None;
    }
    let summary = by_type.keys().copied().collect::<Vec<_>>().join(", ");
    let lines = by_type.iter().flat_map(|(ty, vs)| vs.iter().map(move |v| (ty.to_string(), v.to_string()))).collect();
    Some(Collapsed { id: "records", title: "All records", summary, lines })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, authoritative: bool, serial: Option<u32>, answers: &[(&str, &[&str])]) -> Row {
        Row {
            resolver: name.into(),
            location: String::new(),
            answers: answers.iter().map(|(t, vs)| (t.to_string(), vs.iter().map(|v| v.to_string()).collect())).collect(),
            ttls: BTreeMap::new(),
            error: None,
            authoritative,
            serial,
        }
    }

    #[test]
    fn two_nameservers_with_one_serial_read_like_the_sketch() {
        let rows = [
            row("ns1", true, Some(2026110902), &[("TXT", &["\"a\""])]),
            row("ns2", true, Some(2026110902), &[("TXT", &["\"a\""])]),
            row("Google", false, None, &[("TXT", &["\"b\""])]),
        ];
        let c = nameserver_answers(&rows).unwrap();
        assert_eq!(c.title, "Nameserver answers");
        assert_eq!(c.summary, "2 nameservers \u{b7} SOA serial 2026110902 on both");
        assert_eq!(c.lines, vec![("ns1 TXT".to_string(), "\"a\"".to_string()), ("ns2 TXT".to_string(), "\"a\"".to_string())]);
    }

    #[test]
    fn differing_serials_are_called_out() {
        let rows = [row("ns1", true, Some(1), &[]), row("ns2", true, Some(2), &[])];
        assert_eq!(nameserver_answers(&rows).unwrap().summary, "2 nameservers \u{b7} SOA serials differ");
    }

    #[test]
    fn a_failed_nameserver_shows_its_error() {
        let mut bad = row("ns1", true, None, &[]);
        bad.error = Some("timed out".into());
        let c = nameserver_answers(&[bad]).unwrap();
        assert_eq!(c.summary, "1 nameserver");
        assert_eq!(c.lines, vec![("ns1".to_string(), "timed out".to_string())]);
    }

    #[test]
    fn no_nameserver_means_no_row() {
        assert_eq!(nameserver_answers(&[row("Google", false, None, &[])]), None);
    }

    #[test]
    fn all_records_lists_types_from_the_authoritative_truth() {
        let rows = [
            row("ns1", true, None, &[("A", &["1.2.3.4"]), ("TXT", &["\"x\"", "\"y\""])]),
            row("Google", false, None, &[("MX", &["10 stale.example."])]),
        ];
        let c = all_records(&rows).unwrap();
        assert_eq!(c.summary, "A, TXT");
        assert_eq!(c.lines.len(), 3);
        assert_eq!(c.lines[0], ("A".to_string(), "1.2.3.4".to_string()));
    }

    #[test]
    fn all_records_falls_back_to_resolvers_and_skips_empty_types() {
        let rows = [row("Google", false, None, &[("MX", &["10 mx."]), ("AAAA", &[])])];
        assert_eq!(all_records(&rows).unwrap().summary, "MX");
        assert_eq!(all_records(&[row("Google", false, None, &[("A", &[])])]), None);
    }
}
