//! What each Check cannot see from this machine. Fixed lines, kept as data so a rep reads the
//! limit of a result next to the result, and the copied Markdown carries it too.

use crate::section::Section;

pub const TITLE: &str = "Not visible from here";

pub fn lines(section: Section) -> &'static [&'static str] {
    match section {
        Section::Summary => &[],
        Section::Dns => &[
            "The registrar account: who controls the domain, and a change saved there but not yet published.",
            "The host's own resolver, and its cache or hosts file. Only the This machine row shows this machine's.",
            "Answers given only to some networks (split-horizon DNS) or regions beyond the resolvers asked.",
            "The DNS provider's panel: records saved there but not yet served.",
        ],
        Section::Delegation => &[
            "The registrar account where the nameservers are set.",
            "Nameservers that answer only some networks: a server that is silent here may answer elsewhere.",
            "Why a nameserver is lame: its configuration and logs are on its own host.",
        ],
        Section::Dnssec => zombo_core::dnssec::CHECK.blind_spots,
        Section::Email => &[
            "Recipient-side filtering: spam filters, quarantine and allow lists decide delivery after DNS passes.",
            "Mail that was really sent: DMARC reports and mail logs hold that, DNS does not.",
            "DKIM keys under a selector this Check did not try.",
            "The settings inside the sending service's own console.",
        ],
        Section::Web => &[
            "Application logs and errors behind the page.",
            "The CDN's origin server: the Check sees what the CDN returns, not what is behind it.",
            "Pages behind a login, and content that JavaScript builds.",
            "How the site answers other regions or networks than this one.",
        ],
        Section::Tls => zombo_core::tls::CHECK.blind_spots,
        Section::Registration => &[
            "The registrar account: ownership contact, locks, billing and auto-renew.",
            "Contact details hidden by a privacy service.",
            "Changes the registry has not yet published to RDAP or WHOIS.",
        ],
        Section::Rdns => &[
            "The hosting provider's panel, where the PTR record is set.",
            "Reverse names published only to some networks.",
            "Whether a mail server's greeting name matches its PTR: only the DNS side is read.",
        ],
        Section::Ports => &[
            "UDP services: only TCP ports are tried.",
            "Ports outside the quick list.",
            "Whether a firewall that allows only some source addresses is hiding a service from this machine.",
            "Whether this network or the target blocks a port that gives no answer.",
        ],
        Section::Smtp => &[
            "Whether the server accepts mail from you: no mail is sent.",
            "Recipient-side filtering of mail it does accept.",
            "MX hosts after the first three tried.",
            "Whether this network blocks the port, when there is no answer.",
        ],
        Section::TlsPort => zombo_core::tls::ON_PORT.blind_spots,
        Section::Blacklist => &[
            "Lists that are not in the table this Check asks.",
            "Private block lists inside the receiving company.",
            "Whether a listing changes delivery: the receiving server decides.",
            "The sending reputation of the domain's mail history.",
        ],
    }
}

/// The Markdown block under a section's copy, or nothing for a section with no lines.
pub fn markdown(section: Section, level: &str) -> String {
    let lines = lines(section);
    if lines.is_empty() {
        return String::new();
    }
    let bullets: String = lines.iter().map(|l| format!("- {l}\n")).collect();
    format!("\n{level}# {TITLE}\n\n{bullets}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_section_but_the_summary_has_three_or_four_lines() {
        for s in Section::ALL {
            let n = lines(s).len();
            if s == Section::Summary {
                assert_eq!(n, 0);
            } else {
                assert!((3..=4).contains(&n), "{s:?} has {n}");
            }
        }
    }

    #[test]
    fn the_lines_are_one_sentence_each_and_say_what_the_brief_promised() {
        for s in Section::ALL {
            for l in lines(s) {
                assert!(l.ends_with('.') && !l.contains('\n') && l.len() < 130, "{l}");
            }
        }
        let has = |s, needle: &str| lines(s).iter().any(|l| l.contains(needle));
        assert!(has(Section::Dns, "registrar account") && has(Section::Dns, "host's own resolver"));
        assert!(has(Section::Web, "Application logs") && has(Section::Web, "origin server"));
        assert!(has(Section::Email, "Recipient-side filtering"));
        assert!(has(Section::Registration, "registrar account"));
    }

    #[test]
    fn markdown_is_a_titled_bullet_list_one_level_down() {
        let md = markdown(Section::Registration, "##");
        assert!(md.starts_with("\n### Not visible from here\n\n- "), "{md}");
        assert_eq!(md.matches("\n- ").count(), lines(Section::Registration).len());
        assert_eq!(markdown(Section::Summary, "##"), "");
    }
}
