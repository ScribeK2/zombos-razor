//! Entry points that feed untrusted bytes to parsers that are otherwise private
//! to a Check. The fuzz targets and the hostile-input tests drive these; each
//! must return for any input, in bounded time, without panicking.

use std::time::Duration;

use hickory_proto::{op::Message, rr::RecordType};

use crate::{
    delegation, dns,
    finding::Finding,
    lookup, ports, rdns, registration,
    web::{self, Hop, fetch},
};

/// A DNS message and every consumer that reads answers out of one.
pub fn dns_message(wire: &[u8]) -> Option<Message> {
    let m = dns::parse_message(wire).ok()?;
    for r in m.answers.iter().chain(&m.authorities).chain(&m.additionals) {
        let _ = lookup::presentation(&r.data);
    }
    let _ = rdns::addresses_of(&m, RecordType::A);
    let _ = rdns::addresses_of(&m, RecordType::AAAA);
    let _ = delegation::addrs(&m, None);
    let _ = delegation::ns_set(&m, "example.com");
    for t in web::providers::txt_strings(&m) {
        let _ = web::providers::parse_cymru_origin(&t);
        let _ = web::providers::parse_cymru_name(&t);
    }
    Some(m)
}

/// An RDAP domain answer, then the findings read from it.
pub fn rdap(body: &[u8]) -> Vec<Finding> {
    let r = registration::Registration::empty("example.com", registration::Source::Rdap, "https://rdap.example");
    registration::read_rdap(r, body).map(|r| registration::registration_findings("example.com", &r)).unwrap_or_default()
}

/// A WHOIS reply, then the findings read from it.
pub fn whois(text: &str) -> Vec<Finding> {
    let r = registration::parse_whois("example.com", "whois.example:43", text);
    registration::registration_findings("example.com", &r)
}

/// A banner read from a port.
pub fn banner(raw: &[u8]) -> Option<String> {
    ports::clean_banner(raw)
}

/// What a web server could say: lines of `Name: value` become response headers,
/// a `Location` line becomes a redirect, and the result is checked the way a
/// Check checks a fetched page. `body` is the page.
pub fn web_page(head: &str, body: &[u8]) -> web::WebResult {
    let page = || {
        let mut f = fetch::Fetch::default();
        let mut url = "https://example.com/".to_string();
        for line in head.lines().take(200) {
            let Some((name, value)) = line.split_once(':') else { continue };
            let (name, value) = (name.trim().to_ascii_lowercase(), fetch::clean(value.trim().as_bytes()));
            if name == "location" {
                f.chain.push(Hop { url: url.clone(), status: 301, location: Some(value.clone()) });
                match fetch::next_url(&url, &value) {
                    Ok(next) => url = next,
                    Err(e) => f.error = Some(e),
                }
            }
            f.headers.push((name, value));
        }
        f.chain.push(Hop { url, status: 200, location: None });
        f.body = body.to_vec();
        f.elapsed = Duration::from_millis(5);
        f
    };
    web::inspect_with("https://example.com/", "http://example.com/", &|_| page())
}

/// Every reply a server could read out of `wire`. The server side closes after the bytes.
pub async fn smtp_replies(wire: Vec<u8>) -> usize {
    use tokio::io::AsyncWriteExt;
    let (mut server, client) = tokio::io::duplex(1 << 16);
    let feed = tokio::spawn(async move {
        let _ = server.write_all(&wire).await;
        let _ = server.shutdown().await;
    });
    let mut conn = crate::smtp::reply::Conn::new(client);
    let mut lines = 0;
    while let Ok(r) = conn.reply(Duration::from_secs(2)).await {
        lines += r.lines.len();
        if lines > 4096 {
            break;
        }
    }
    let _ = conn.into_stream();
    let _ = feed.await;
    lines
}

/// A certificate chain made of `data`: each certificate is a two-byte length then that
/// many bytes. The chain is assessed against the bundled roots, then findings are read from it.
pub fn tls_chain(data: &[u8]) -> Vec<Finding> {
    use std::sync::OnceLock;

    use tokio_rustls::rustls::{RootCertStore, pki_types::CertificateDer};
    static ROOTS: OnceLock<RootCertStore> = OnceLock::new();
    let mut chain = vec![];
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first_chunk::<2>() {
        let (der, tail) = tail.split_at(usize::from(u16::from_be_bytes(len)).min(tail.len()));
        chain.push(CertificateDer::from(der.to_vec()));
        rest = tail;
    }
    let roots = ROOTS.get_or_init(crate::tls::public_roots);
    let Ok(a) = crate::tls::assess(&chain, "example.com", roots, time::OffsetDateTime::UNIX_EPOCH) else {
        return vec![];
    };
    let r = crate::tls::TlsResult {
        version: "TLSv1.3".into(),
        cipher: "TLS_AES_128_GCM_SHA256".into(),
        chain: a.chain,
        hostname_match: a.hostname_match,
        verified: a.verified,
        trust: a.trust,
        verify_error: a.verify_error,
        ocsp_stapled: false,
    };
    let mut f = crate::tls::tls_findings("example.com", 443, &r);
    f.extend(crate::tls::ocsp_findings("example.com", 443, &r));
    f
}
