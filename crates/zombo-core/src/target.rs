use std::net::{IpAddr, SocketAddr};

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use psl::Type;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A registrable name: example.com, example.co.uk.
    Domain,
    /// A name below one: www.example.com.
    Hostname,
    Ip,
    Email,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub value: String,
    pub kind: Kind,
}

/// Normalise what the rep typed and classify it: scheme, port, path and
/// trailing dot are dropped, case is folded, and international names become
/// punycode.
pub fn parse_target(raw: &str) -> Result<Target, String> {
    let mut s = raw.trim().to_string();
    if s.is_empty() {
        return Err("enter a domain, host, IP or email address".into());
    }
    // URLs first: they may contain @ (user info, /@handle paths).
    if s.contains("://") || s.contains('/') {
        if !s.contains("://") {
            s = format!("http://{s}");
        }
        s = match url::Url::parse(&s).ok().and_then(|u| u.host_str().map(str::to_string)) {
            Some(h) if !h.is_empty() => h,
            _ => return Err(format!("\"{raw}\" is not a valid URL")),
        };
    }
    if let Some((local, domain)) = s.split_once('@') {
        let bad = || format!("\"{s}\" is not a valid email address");
        let host = parse_host(domain).map_err(|_| bad())?;
        if local.is_empty() || local.contains(['@', ' ', '\t']) {
            return Err(bad());
        }
        return Ok(Target { value: format!("{}@{host}", local.to_lowercase()), kind: Kind::Email });
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(ip(sa.ip()));
    }
    if let Ok(a) = s.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(ip(a));
    }
    let host = parse_host(&s)?;
    // A private suffix (github.io) is itself a resolvable site, so it counts as a domain.
    let is_domain = psl::domain_str(&host) == Some(host.as_str()) || psl::suffix_str(&host) == Some(host.as_str());
    Ok(Target { value: host, kind: if is_domain { Kind::Domain } else { Kind::Hostname } })
}

fn ip(a: IpAddr) -> Target {
    let a = match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(a),
        v4 => v4,
    };
    Target { value: a.to_string(), kind: Kind::Ip }
}

fn parse_host(s: &str) -> Result<String, String> {
    let invalid = || format!("\"{s}\" is not a valid domain or host name");
    let s = s.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(s, |(h, _)| h);
    let lower = s.trim_end_matches('.').to_lowercase();
    // The empty deny list allows underscores: reps look up names such as
    // selector._domainkey.example.com and _dmarc.example.com.
    let host = Uts46::new()
        .to_ascii(lower.as_bytes(), AsciiDenyList::EMPTY, Hyphens::Allow, DnsLength::Verify)
        .map_err(|_| invalid())?
        .into_owned();
    if !host.contains('.') || host.len() > 253 {
        return Err(invalid());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err(invalid());
        }
    }
    // "com" or "co.uk" alone is not a target; privately run suffixes such as
    // github.io or cloudfront.net are real hosts and are allowed.
    if let Some(suf) = psl::suffix(host.as_bytes())
        && suf.as_bytes() == host.as_bytes()
        && suf.typ() == Some(Type::Icann)
    {
        return Err(invalid());
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> (String, Kind) {
        let t = parse_target(s).unwrap_or_else(|e| panic!("{s}: {e}"));
        (t.value, t.kind)
    }

    #[test]
    fn classifies_and_normalises() {
        use Kind::*;
        assert_eq!(p("Example.COM."), ("example.com".into(), Domain));
        assert_eq!(p("www.example.com"), ("www.example.com".into(), Hostname));
        assert_eq!(p("example.co.uk"), ("example.co.uk".into(), Domain));
        assert_eq!(p("https://user@www.Example.com:8080/a/b?x=1"), ("www.example.com".into(), Hostname));
        assert_eq!(p("example.com/path"), ("example.com".into(), Domain));
        assert_eq!(p("Bob@Example.com"), ("bob@example.com".into(), Email));
        assert_eq!(p("93.184.216.34:443"), ("93.184.216.34".into(), Ip));
        assert_eq!(p("[2606:2800::1]"), ("2606:2800::1".into(), Ip));
        assert_eq!(p("::ffff:1.2.3.4"), ("1.2.3.4".into(), Ip));
        assert_eq!(p("bücher.example"), ("xn--bcher-kva.example".into(), Domain));
        assert_eq!(p("github.io"), ("github.io".into(), Domain));
        assert_eq!(p("foo.github.io"), ("foo.github.io".into(), Domain));
    }

    #[test]
    fn allows_underscore_labels() {
        assert_eq!(p("_dmarc.example.com").1, Kind::Hostname);
        assert_eq!(p("sel._domainkey.example.com").1, Kind::Hostname);
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "   ", "com", "co.uk", "-a.example.com", "a..example.com", "exa mple.com", "@example.com", "http://"] {
            assert!(parse_target(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
