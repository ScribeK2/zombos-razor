//! Diagnosis copy: one value, one section, the whole Diagnosis. Markdown is the default,
//! JSON is offered per section. Pure text builders; the shell only puts the text on the clipboard.

use serde_json::{Value, json};
use zombo_core::text::single_line;

use crate::{
    diagnosis::Tab,
    evidence_model::{code, fact_lines, finding_lines},
    outcome::Fact,
    record::RecordKind,
    section::Section,
    status::CheckState,
};

/// One section's words and data, the single shape both formats are built from.
struct Doc {
    word: String,
    why: String,
    findings: Vec<zombo_core::Finding>,
    rows: Vec<Fact>,
    details_title: String,
    details: Vec<Fact>,
}

fn doc(tab: &Tab, section: Section) -> Doc {
    let v = tab.verdict(section);
    let mut d = Doc {
        word: v.word,
        why: v.why,
        findings: tab.findings(section),
        rows: vec![],
        details_title: String::new(),
        details: vec![],
    };
    if section == Section::Dns {
        for kind in RecordKind::ALL {
            for r in tab.propagation.view(kind).into_iter().filter(|r| r.answer != "no record") {
                let ttl = r.ttl.map(|t| format!(", TTL {t}")).unwrap_or_default();
                d.rows.push(Fact::new(
                    format!("{} at {}", kind.code(), r.resolver),
                    format!("{}{ttl}, {}", r.answer, r.status.label()),
                ));
            }
        }
    } else if let Some(run) = tab.runs.get(&section) {
        d.rows = run.outcome.facts.clone();
        d.details_title = run.outcome.details_title.to_string();
        d.details = run.outcome.details.clone();
    }
    d
}

fn section_md(tab: &Tab, section: Section, level: &str) -> String {
    let d = doc(tab, section);
    let mut out = format!("{level} {}\n\n**{}.** {}\n\n", section.label(), single_line(&d.word), single_line(&d.why));
    let findings: Vec<_> = d
        .findings
        .iter()
        .map(|f| zombo_core::Finding {
            title: single_line(&f.title).into(),
            message: single_line(&f.message),
            recommendation: f.recommendation.as_deref().map(|r| single_line(r).into()),
            ..f.clone()
        })
        .collect();
    finding_lines(&mut out, &findings);
    if !findings.is_empty() && !d.rows.is_empty() {
        out.push('\n');
    }
    fact_lines(&mut out, &d.rows);
    if !d.details.is_empty() {
        out.push_str(&format!("\n{level}# {}\n\n", single_line(&d.details_title)));
        fact_lines(&mut out, &d.details);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Section,
    Whole,
    Json,
}

/// The text to copy and the sentence that confirms it.
pub fn build(tab: &Tab, format: Format) -> (String, String) {
    let s = tab.section;
    match format {
        Format::Section => (section_markdown(tab, s), format!("Copied the {} section as Markdown.", s.label())),
        Format::Whole => (diagnosis_markdown(tab), "Copied the whole Diagnosis as Markdown.".into()),
        Format::Json => (section_json(tab, s), format!("Copied the {} section as JSON.", s.label())),
    }
}

pub fn section_markdown(tab: &Tab, section: Section) -> String {
    section_md(tab, section, "##")
}

/// The whole Diagnosis: every section that ran, in rail order, then the ones that did not.
pub fn diagnosis_markdown(tab: &Tab) -> String {
    let mut out = format!("# Diagnosis: {}\n\n", code(&tab.target.value));
    let mut not_run = vec![];
    for s in Section::ALL {
        if tab.state(s) == CheckState::NotRun && s != Section::Summary {
            not_run.push(s.label());
        } else if s != Section::Summary || tab.state(s) != CheckState::NotRun {
            out.push_str(&section_md(tab, s, "##"));
            out.push('\n');
        }
    }
    if !not_run.is_empty() {
        out.push_str(&format!(
            "## Not run\n\n{}\n",
            not_run.iter().map(|l| format!("- {l}")).collect::<Vec<_>>().join("\n")
        ));
    }
    out
}

fn facts_json(rows: &[Fact]) -> Vec<Value> {
    rows.iter().map(|f| json!({ "key": f.key.trim(), "value": f.value })).collect()
}

pub fn section_json(tab: &Tab, section: Section) -> String {
    let d = doc(tab, section);
    let v = json!({
        "target": tab.target.value,
        "section": section.label(),
        "state": tab.state(section).label(),
        "verdict": { "word": d.word, "why": d.why },
        "findings": d.findings,
        "facts": facts_json(&d.rows),
        "details": { "title": d.details_title, "rows": facts_json(&d.details) },
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use zombo_core::{
        Finding, Severity,
        target::{Kind, Target},
        text::strip,
    };

    use super::*;
    use crate::outcome::{CheckEvent, Outcome};

    fn tab_with_web() -> Tab {
        let mut t = Tab::new(Target { value: "example.com".into(), kind: Kind::Domain });
        let f = Finding {
            code: "web_x",
            severity: Severity::Warning,
            title: "No HSTS".into(),
            message: "Add the header.\u{1b}[31m".into(),
            recommendation: Some("Set it.".into()),
        };
        let o = Outcome {
            findings: vec![f],
            facts: vec![Fact::new("Status", "200"), Fact::new("Server", "a`b")],
            details_title: "Redirect chain",
            details: vec![Fact::new("Hop 1", "301 http://example.com")],
        };
        t.run_mut(Section::Web).apply(CheckEvent::Started);
        t.run_mut(Section::Web).apply(CheckEvent::Finished(Box::new(Ok(o))));
        t
    }

    #[test]
    fn a_section_is_markdown_with_values_in_code_spans() {
        let md = section_markdown(&tab_with_web(), Section::Web);
        assert!(md.starts_with("## Web\n\n**1 PROBLEM.** "), "{md}");
        assert!(md.contains("- **Warning** No HSTS: Add the header. [31m Set it.\n"), "{md}");
        assert!(md.contains("- Status: `200`\n"), "{md}");
        assert!(md.contains("- Server: `a'b`\n"), "{md}");
        assert!(md.contains("\n### Redirect chain\n\n- Hop 1: `301 http://example.com`\n"), "{md}");
    }

    #[test]
    fn no_copied_text_holds_a_control_character() {
        let t = tab_with_web();
        for text in [section_markdown(&t, Section::Web), diagnosis_markdown(&t), strip("a\u{1b}[2Jb\nc")] {
            assert!(!text.chars().any(|c| zombo_core::text::is_unsafe_char(c) && c != '\n'), "{text:?}");
        }
        assert_eq!(strip("a\u{7}b\r\nc"), "abc");
    }

    #[test]
    fn the_whole_diagnosis_lists_sections_that_ran_in_rail_order_and_names_the_rest() {
        let md = diagnosis_markdown(&tab_with_web());
        assert!(md.starts_with("# Diagnosis: `example.com`\n"), "{md}");
        let at = |s: &str| md.find(s).unwrap_or_else(|| panic!("missing {s}\n{md}"));
        assert!(at("## Summary") < at("## Web"));
        assert!(!md.contains("## DNS") && !md.contains("## Registration"));
        assert!(at("## Not run") > at("## Web"));
        assert!(md.contains("- DNS\n") && md.contains("- Blacklist"), "{md}");
    }

    #[test]
    fn a_target_nothing_ran_for_copies_only_the_not_run_list() {
        let md = diagnosis_markdown(&Tab::new(Target { value: "example.com".into(), kind: Kind::Domain }));
        assert!(!md.contains("## Summary") && md.contains("## Not run"), "{md}");
    }

    #[test]
    fn a_section_as_json_carries_the_verdict_findings_and_facts() {
        let v: Value = serde_json::from_str(&section_json(&tab_with_web(), Section::Web)).unwrap();
        assert_eq!(v["target"], "example.com");
        assert_eq!(v["section"], "Web");
        assert_eq!(v["verdict"]["word"], "1 PROBLEM");
        assert_eq!(v["findings"][0]["code"], "web_x");
        assert_eq!(v["findings"][0]["title"], "No HSTS");
        assert_eq!(v["facts"][0], json!({ "key": "Status", "value": "200" }));
        assert_eq!(v["details"]["rows"][0]["key"], "Hop 1");
    }

    #[test]
    fn each_format_names_what_it_copied() {
        let mut t = tab_with_web();
        t.section = Section::Web;
        assert_eq!(build(&t, Format::Section).1, "Copied the Web section as Markdown.");
        assert_eq!(build(&t, Format::Json).1, "Copied the Web section as JSON.");
        assert_eq!(build(&t, Format::Whole).1, "Copied the whole Diagnosis as Markdown.");
        assert!(build(&t, Format::Json).0.starts_with('{'));
    }

    #[test]
    fn a_section_that_did_not_run_says_so_in_json() {
        let t = Tab::new(Target { value: "example.com".into(), kind: Kind::Domain });
        let v: Value = serde_json::from_str(&section_json(&t, Section::Tls)).unwrap();
        assert_eq!((v["state"].as_str(), v["verdict"]["word"].as_str()), (Some("not run"), Some("NOT RUN")));
        assert_eq!(v["facts"], json!([]));
    }
}
