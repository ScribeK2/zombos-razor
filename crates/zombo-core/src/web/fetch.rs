//! One bounded HTTP GET that follows redirects by hand, so every hop is recorded.

use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use std::sync::Arc;

use rustls::CertificateError;

use serde::Serialize;
use ureq::{
    Agent,
    config::Config,
    http::Uri,
    tls::{Certificate, RootCerts, TlsConfig},
    unversioned::{
        resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver},
        transport::{DefaultConnector, NextTimeout},
    },
};

use crate::email_auth::printable;

pub const MAX_REDIRECTS: usize = 10;
/// Nothing is read from a body beyond this: it only feeds the WordPress markers.
const MAX_BODY: u64 = 64 * 1024;
const MAX_HEADER_BLOCK: usize = 32 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_HEADER_VALUE: usize = 8 * 1024;
const USER_AGENT: &str = concat!("zombo/", env!("CARGO_PKG_VERSION"));

/// One response in the chain: the URL asked, what came back, and where it pointed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hop {
    pub url: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Whether a fetch checks the server certificate. `SkipVerification` is only ever
/// built by the caller who asked for it (`--insecure-origin`), never by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum CertCheck {
    #[default]
    Verify,
    SkipVerification,
}

/// How a fetch treats TLS. `roots` are DER certificates trusted in place of the bundled
/// ones (a test seam).
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsMode {
    pub check: CertCheck,
    pub roots: Vec<Vec<u8>>,
}

/// Makes one host name resolve to a chosen address, whatever DNS says. The URL keeps
/// the real name, so the Host header and the TLS server name are the real ones.
#[derive(Debug, Clone)]
pub struct Pin {
    pub host: String,
    pub ip: IpAddr,
}

#[derive(Debug)]
struct PinResolver(Option<Pin>);

impl Resolver for PinResolver {
    fn resolve(&self, uri: &Uri, config: &Config, timeout: NextTimeout) -> Result<ResolvedSocketAddrs, ureq::Error> {
        if let Some(pin) = &self.0
            && uri.host().is_some_and(|h| h.eq_ignore_ascii_case(&pin.host))
        {
            let port = uri
                .port_u16()
                .or(match uri.scheme_str() {
                    Some("https") => Some(443),
                    Some("http") => Some(80),
                    _ => None,
                })
                .ok_or(ureq::Error::HostNotFound)?;
            let mut out = self.empty();
            out.push(SocketAddr::new(pin.ip, port));
            return Ok(out);
        }
        DefaultResolver::default().resolve(uri, config, timeout)
    }
}

/// What one fetch saw. `error` set with an empty `chain` means nothing answered;
/// with a chain it means a redirect led somewhere that failed.
#[derive(Debug, Default)]
pub(crate) struct Fetch {
    pub chain: Vec<Hop>,
    pub redirect_loop: bool,
    pub too_many: bool,
    /// Headers of the last response, names lowercase, values cleaned and capped.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Until the last response's headers arrived, across every redirect.
    pub elapsed: Duration,
    pub error: Option<String>,
    /// Set with `error` when the server answered TLS but its certificate was refused.
    pub cert_rejected: Option<String>,
}

impl Fetch {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn tls_config(tls: &TlsMode) -> TlsConfig {
    let mut b = TlsConfig::builder().disable_verification(tls.check == CertCheck::SkipVerification);
    if !tls.roots.is_empty() {
        let certs = tls.roots.iter().map(|d| Certificate::from_der(d).to_owned()).collect();
        b = b.root_certs(RootCerts::Specific(Arc::new(certs)));
    }
    b.build()
}

fn agent(pin: Option<&Pin>, tls: &TlsMode) -> Agent {
    let config = Agent::config_builder()
        .tls_config(tls_config(tls))
        .max_redirects(0)
        .http_status_as_error(false)
        .https_only(false)
        .proxy(None) // a diagnostic must show what the site does, not what a proxy does
        .max_response_header_size(MAX_HEADER_BLOCK)
        .build();
    Agent::with_parts(config, DefaultConnector::default(), PinResolver(pin.cloned()))
}

fn clean(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let s = match s.char_indices().nth(MAX_HEADER_VALUE) {
        Some((i, _)) => &s[..i],
        None => &s,
    };
    printable(s)
}

/// The reason, when the failure is a certificate the client refused.
fn cert_rejection(e: &ureq::Error) -> Option<String> {
    let rustls = match e {
        ureq::Error::Rustls(r) => r,
        ureq::Error::Io(io) => io.get_ref()?.downcast_ref::<rustls::Error>()?,
        _ => return None,
    };
    match rustls {
        rustls::Error::InvalidCertificate(reason) => Some(match reason {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => "it has expired".to_string(),
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "it is not valid yet".to_string()
            }
            CertificateError::UnknownIssuer => "it is not signed by a trusted authority".to_string(),
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "it is not valid for the site name".to_string()
            }
            other => printable(&format!("{other:?}")),
        }),
        _ => None,
    }
}

fn describe(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Timeout(_) => "timed out".into(),
        other => other.to_string(),
    }
}

/// GET `start`, following 301/302/303/307/308 itself: stops at a URL already
/// visited (a loop) and after `MAX_REDIRECTS` requests. A redirect to a scheme
/// other than http or https is never followed. `limit` covers the whole chain.
pub(crate) fn fetch_chain(start: &str, pin: Option<&Pin>, limit: Duration, tls: &TlsMode) -> Fetch {
    let started = Instant::now();
    let deadline = started + limit;
    let agent = agent(pin, tls);
    let mut f = Fetch::default();
    let mut url = match url::Url::parse(start) {
        Ok(u) => u.to_string(),
        Err(e) => {
            f.error = Some(e.to_string());
            return f;
        }
    };
    let mut visited = vec![url.clone()];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            f.error = Some("timed out".into());
            return f;
        }
        let request = agent.get(&url).config().timeout_global(Some(left)).build().header("User-Agent", USER_AGENT);
        let mut resp = match request.call() {
            Ok(r) => r,
            Err(e) => {
                f.cert_rejected = cert_rejection(&e);
                f.error = Some(describe(&e));
                return f;
            }
        };
        f.elapsed = started.elapsed();
        let status = resp.status().as_u16();
        f.headers = resp
            .headers()
            .iter()
            .take(MAX_HEADERS)
            .map(|(n, v)| (n.as_str().to_ascii_lowercase(), clean(v.as_bytes())))
            .collect();
        let location = f.header("location").filter(|l| !l.is_empty()).map(str::to_string);
        f.chain.push(Hop { url: url.clone(), status, location: location.clone() });

        let follow = matches!(status, 301 | 302 | 303 | 307 | 308).then_some(location).flatten();
        let next = match follow.map(|loc| next_url(&url, &loc)).transpose() {
            Ok(n) => n,
            Err(e) => {
                f.error = Some(e);
                return f;
            }
        };
        match next {
            Some(n) if visited.contains(&n) => f.redirect_loop = true,
            Some(_) if visited.len() >= MAX_REDIRECTS => f.too_many = true,
            Some(n) => {
                visited.push(n.clone());
                url = n;
                continue;
            }
            None => {}
        }
        // A body that stalls or breaks keeps what arrived: the status and headers are already known.
        let _ = resp.body_mut().as_reader().take(MAX_BODY).read_to_end(&mut f.body);
        return f;
    }
}

fn next_url(current: &str, location: &str) -> Result<String, String> {
    let base = url::Url::parse(current).map_err(|e| e.to_string())?;
    let mut next = base.join(location).map_err(|_| format!("redirect to an invalid Location {location:?}"))?;
    if !matches!(next.scheme(), "http" | "https") {
        return Err(format!("redirect to unsupported scheme {}:", next.scheme()));
    }
    next.set_fragment(None);
    Ok(next.to_string())
}
