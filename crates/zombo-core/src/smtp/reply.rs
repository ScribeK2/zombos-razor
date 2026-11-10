//! Reading SMTP replies from an untrusted server: every line, reply and wait is bounded.

use std::time::Duration;

use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::{email_auth::clip, text::printable};

/// RFC 5321 allows 512 bytes per reply line, CRLF included.
pub const MAX_LINE: usize = 512;
pub const MAX_REPLY_LINES: usize = 64;
const MAX_KEYWORDS: usize = 16;
const MAX_WORD: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reply {
    pub code: u16,
    /// The text of each line with the code removed and control characters replaced.
    pub lines: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplyError {
    #[error("no reply within {0} s")]
    TimedOut(u64),
    #[error("the server closed the connection")]
    Closed,
    #[error("a reply line is longer than {MAX_LINE} bytes")]
    LineTooLong,
    #[error("the reply has more than {MAX_REPLY_LINES} lines")]
    TooManyLines,
    #[error("not an SMTP reply: {0:?}")]
    Malformed(String),
    #[error("{0}")]
    Io(String),
}

/// A connection plus the bytes read past the end of the last reply.
pub struct Conn<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(stream: S) -> Self {
        Conn { stream, buf: vec![] }
    }

    /// The raw stream for a TLS handshake. Bytes the server sent after its
    /// STARTTLS reply and before the handshake are a plaintext injection
    /// attempt: they are refused and their count is returned.
    pub fn into_stream(self) -> Result<S, usize> {
        if self.buf.is_empty() { Ok(self.stream) } else { Err(self.buf.len()) }
    }

    async fn line(&mut self) -> Result<Vec<u8>, ReplyError> {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                if i + 1 > MAX_LINE {
                    return Err(ReplyError::LineTooLong);
                }
                let mut l: Vec<u8> = self.buf.drain(..=i).collect();
                l.pop();
                if l.last() == Some(&b'\r') {
                    l.pop();
                }
                return Ok(l);
            }
            if self.buf.len() >= MAX_LINE {
                return Err(ReplyError::LineTooLong);
            }
            let mut chunk = [0u8; MAX_LINE];
            let n = self.stream.read(&mut chunk).await.map_err(|e| ReplyError::Io(printable(&e.to_string())))?;
            if n == 0 {
                return Err(ReplyError::Closed);
            }
            self.buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        }
    }

    /// One whole reply, however many lines, within `step`.
    pub async fn reply(&mut self, step: Duration) -> Result<Reply, ReplyError> {
        timeout(step, self.reply_unbounded()).await.map_err(|_| ReplyError::TimedOut(step.as_secs().max(1)))?
    }

    async fn reply_unbounded(&mut self) -> Result<Reply, ReplyError> {
        let mut code = None;
        let mut lines = vec![];
        loop {
            let raw = self.line().await?;
            let (c, more, text) = parse_line(&raw)?;
            if *code.get_or_insert(c) != c {
                return Err(ReplyError::Malformed(printable(&clip(&String::from_utf8_lossy(&raw)))));
            }
            lines.push(text);
            if !more {
                return Ok(Reply { code: c, lines });
            }
            if lines.len() >= MAX_REPLY_LINES {
                return Err(ReplyError::TooManyLines);
            }
        }
    }

    /// Send one command line. `cmd` must not hold a line break.
    pub async fn send(&mut self, cmd: &str, step: Duration) -> Result<(), ReplyError> {
        let io = async {
            self.stream.write_all(cmd.as_bytes()).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream.flush().await
        };
        timeout(step, io)
            .await
            .map_err(|_| ReplyError::TimedOut(step.as_secs().max(1)))?
            .map_err(|e| ReplyError::Io(printable(&e.to_string())))
    }
}

fn parse_line(raw: &[u8]) -> Result<(u16, bool, String), ReplyError> {
    let bad = || ReplyError::Malformed(printable(&clip(&String::from_utf8_lossy(raw))));
    let digits = raw.get(..3).filter(|d| d.iter().all(u8::is_ascii_digit)).ok_or_else(bad)?;
    let code = digits.iter().fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
    if !(200..600).contains(&code) {
        return Err(bad());
    }
    let more = match raw.get(3) {
        None | Some(b' ') => false,
        Some(b'-') => true,
        Some(_) => return Err(bad()),
    };
    let text = raw.get(4..).unwrap_or_default();
    Ok((code, more, printable(&String::from_utf8_lossy(text))))
}

/// What a server's EHLO reply says it can do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Extensions {
    pub starttls: bool,
    pub size: Option<u64>,
    /// The mechanisms of the AUTH extension, upper case; empty when AUTH is not offered.
    pub auth: Vec<String>,
    pub pipelining: bool,
    pub eight_bit_mime: bool,
    /// Other keywords the server listed (bounded).
    pub other: Vec<String>,
}

impl Extensions {
    /// `lines` is the EHLO reply text: the first line is the server's greeting, the rest are extensions.
    pub fn parse(lines: &[String]) -> Extensions {
        let mut e = Extensions::default();
        for line in lines.iter().skip(1) {
            let mut words = line.split_whitespace();
            let Some(keyword) = words.next() else { continue };
            let keyword = keyword.to_ascii_uppercase();
            match keyword.as_str() {
                "STARTTLS" => e.starttls = true,
                "PIPELINING" => e.pipelining = true,
                "8BITMIME" => e.eight_bit_mime = true,
                "SIZE" => e.size = words.next().and_then(|n| n.parse().ok()),
                "AUTH" => e.add_mechanisms(words),
                k if k.starts_with("AUTH=") => e.add_mechanisms(k.split_at(5).1.split_whitespace().chain(words)),
                k if e.other.len() < MAX_KEYWORDS => e.other.push(k.chars().take(MAX_WORD).collect()),
                _ => {}
            }
        }
        e
    }

    fn add_mechanisms<'a>(&mut self, words: impl Iterator<Item = &'a str>) {
        for w in words {
            let w: String = w.to_ascii_uppercase().chars().take(MAX_WORD).collect();
            if self.auth.len() < MAX_KEYWORDS && !self.auth.contains(&w) {
                self.auth.push(w);
            }
        }
    }
}

/// The host name a 220 greeting opens with ("mail.example.com ESMTP ready"), lower case; none when it opens with anything else.
pub fn banner_host(first_line: &str) -> Option<String> {
    let word = first_line.split_whitespace().next()?.trim_end_matches('.').to_ascii_lowercase();
    let looks_like_name = word.contains('.')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        && word.parse::<std::net::IpAddr>().is_err();
    looks_like_name.then_some(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(l: &[&str]) -> Vec<String> {
        l.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn extensions_are_read_case_insensitively_and_bounded() {
        let e = Extensions::parse(&lines(&[
            "mx.test Hello",
            "starttls",
            "SIZE 52428800",
            "AUTH PLAIN login PLAIN",
            "PIPELINING",
            "8BITMIME",
            "ENHANCEDSTATUSCODES",
        ]));
        assert!(e.starttls && e.pipelining && e.eight_bit_mime);
        assert_eq!(e.size, Some(52_428_800));
        assert_eq!(e.auth, ["PLAIN", "LOGIN"]);
        assert_eq!(e.other, ["ENHANCEDSTATUSCODES"]);
        let many: Vec<String> = std::iter::once("h".to_string()).chain((0..100).map(|i| format!("X{i}"))).collect();
        assert_eq!(Extensions::parse(&many).other.len(), MAX_KEYWORDS);
        assert_eq!(Extensions::parse(&lines(&["h", "SIZE banana", "AUTH=CRAM-MD5"])).auth, ["CRAM-MD5"]);
    }

    #[test]
    fn the_banner_host_is_the_first_word_when_it_is_a_name() {
        assert_eq!(banner_host("MX1.Example.COM. ESMTP Postfix").as_deref(), Some("mx1.example.com"));
        assert_eq!(banner_host("ESMTP ready"), None);
        assert_eq!(banner_host("192.0.2.1 hello"), None);
        assert_eq!(banner_host(""), None);
    }

    #[test]
    fn lines_without_a_code_are_refused() {
        assert!(parse_line(b"hello").is_err());
        assert!(parse_line(b"2200 x").is_err());
        assert!(parse_line(b"199 x").is_err());
        assert_eq!(parse_line(b"250").unwrap(), (250, false, String::new()));
        assert_eq!(parse_line(b"250-a\x01b").unwrap(), (250, true, "a\u{fffd}b".to_string()));
    }
}
