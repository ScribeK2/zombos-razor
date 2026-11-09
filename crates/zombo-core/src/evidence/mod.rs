//! Evidence analysis: text the rep pasted in (email headers, mail logs). Pure
//! functions over the text, no network and no DNS. The text is hostile: input
//! is capped, every line and header is capped, and nothing here panics on it.

pub mod headers;
pub mod maillog;

use std::{borrow::Cow, io::Read, net::IpAddr};

use regex::Regex;
use serde::Serialize;

/// Largest pasted text accepted; more is an error, not a silent cut.
pub const MAX_INPUT: usize = 4 << 20;
/// Longest line or header value looked at. Real log lines and headers are far shorter.
pub(crate) const MAX_LINE: usize = 16 * 1024;
/// Most distinct IPs and host names kept in a result.
pub(crate) const MAX_EXTRACTED: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("the pasted text is larger than 4 MiB")]
    TooLarge,
    #[error("this doesn't look like {0}: no recognisable content")]
    NotThisKind(&'static str),
    #[error("could not read the text: {0}")]
    Read(String),
}

/// Read pasted text from a file or stdin. Reads at most `MAX_INPUT + 1` bytes,
/// so a huge file is refused without being loaded. Bytes that are not UTF-8
/// are replaced, so binary junk reaches the parsers as text.
pub fn read_limited(r: impl Read) -> Result<String, EvidenceError> {
    let mut bytes = Vec::new();
    r.take(MAX_INPUT as u64 + 1).read_to_end(&mut bytes).map_err(|e| EvidenceError::Read(e.to_string()))?;
    if bytes.len() > MAX_INPUT {
        return Err(EvidenceError::TooLarge);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Lines of pasted text: CRLF or LF, each cut to `MAX_LINE` (the flag says it
/// was cut), controls replaced (a tab is a space, any other control character
/// becomes U+FFFD).
pub(crate) fn clean_lines(raw: &str) -> impl Iterator<Item = (Cow<'_, str>, bool)> {
    raw.split('\n').map(|l| {
        let l = l.strip_suffix('\r').unwrap_or(l);
        let short = cut(l, MAX_LINE);
        (clean(short), short.len() < l.len())
    })
}

/// The part of `s` that is at most `max` bytes, ending on a character boundary.
pub(crate) fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

pub(crate) fn clean(s: &str) -> Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| {
                if c == '\t' {
                    ' '
                } else if c.is_control() {
                    '\u{fffd}'
                } else {
                    c
                }
            })
            .collect(),
    )
}

pub(crate) fn re(pattern: &str) -> Regex {
    // Every pattern is a constant in this module; the tests compile them all.
    Regex::new(pattern).unwrap_or_else(|e| unreachable!("{pattern}: {e}"))
}

pub(crate) fn capture<'a>(re: &Regex, s: &'a str) -> Option<&'a str> {
    re.captures(s)?.get(1).map(|m| m.as_str())
}

/// The address inside `[...]` or `[IPv6:...]`, if there is one.
pub(crate) fn bracket_ip(re: &Regex, s: &str) -> Option<IpAddr> {
    capture(re, s)?.parse().ok()
}

/// Distinct IPs and host names found in the text, in first-seen order.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Extracted {
    pub ips: Vec<IpAddr>,
    pub hosts: Vec<String>,
}

impl Extracted {
    pub(crate) fn ip(&mut self, ip: Option<IpAddr>) {
        if let Some(ip) = ip.filter(|ip| self.ips.len() < MAX_EXTRACTED && !self.ips.contains(ip)) {
            self.ips.push(ip);
        }
    }

    pub(crate) fn host(&mut self, host: &str) {
        let host = host.trim_matches(|c: char| c == '.' || c.is_whitespace()).to_ascii_lowercase();
        if !host.is_empty() && self.hosts.len() < MAX_EXTRACTED && !self.hosts.contains(&host) {
            self.hosts.push(host);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_respects_char_boundaries() {
        assert_eq!(cut("aéb", 2), "a");
        assert_eq!(cut("abc", 10), "abc");
    }

    #[test]
    fn controls_are_replaced() {
        assert_eq!(clean("a\u{1b}[31m\tb"), "a\u{fffd}[31m b");
    }

    #[test]
    fn input_over_the_cap_is_refused() {
        assert_eq!(read_limited(vec![b'a'; MAX_INPUT + 1].as_slice()), Err(EvidenceError::TooLarge));
        assert_eq!(read_limited(vec![b'a'; MAX_INPUT].as_slice()).map(|s| s.len()), Ok(MAX_INPUT));
    }
}
