//! The handshake half of the TLS Check: connect, read what the server
//! presents and judge the chain.
//!
//! The handshake accepts any certificate so that broken ones can be shown in
//! full. Trust is then judged here, with an injected clock, so every failure
//! is its own finding.

use std::{
    borrow::Cow,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rustls::{
    AlertDescription, CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor, verify_server_name,
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use serde::{Serialize, Serializer};

use crate::text::printable;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, public_key::PublicKey, signature_algorithm::RsaSsaPssParams,
    x509::AlgorithmIdentifier,
};

use crate::finding::{Finding, Severity};

/// A server that sends more certificates than this is not building a chain.
pub const MAX_CHAIN: usize = 10;
/// Real certificates are 1 to 4 KiB; a 16 KiB one is hostile or broken.
pub const MAX_CERT_BYTES: usize = 16 * 1024;
const MAX_NAMES_LISTED: usize = 10;

/// Go's five trust states: whether the chain leads to a trusted root, ignoring
/// hostname and expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    Ok,
    SelfSigned,
    MissingIntermediate,
    UnknownAuthority,
    Invalid,
}

/// A certificate's public key, named the way Go names it ("RSA 2048", "ECDSA P-256").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyInfo {
    Rsa(u32),
    Ecdsa(Cow<'static, str>),
    Ed25519,
    Unknown,
}

impl fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyInfo::Rsa(bits) => write!(f, "RSA {bits}"),
            KeyInfo::Ecdsa(curve) => write!(f, "ECDSA {curve}"),
            KeyInfo::Ed25519 => f.write_str("Ed25519"),
            KeyInfo::Unknown => f.write_str("unknown"),
        }
    }
}

impl Serialize for KeyInfo {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

fn rfc3339<S: Serializer>(t: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&t.format(&Rfc3339).map_err(serde::ser::Error::custom)?)
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCert {
    pub subject: String,
    pub issuer: String,
    /// DNS names; filled for the leaf only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    #[serde(serialize_with = "rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(serialize_with = "rfc3339")]
    pub not_after: OffsetDateTime,
    pub self_signed: bool,
    pub is_ca: bool,
    pub key: KeyInfo,
    /// Go's name for the signature algorithm, such as "SHA256-RSA" or "ECDSA-SHA256".
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsResult {
    pub version: String,
    pub cipher: String,
    /// As the server sent it, leaf first.
    pub chain: Vec<TlsCert>,
    pub hostname_match: bool,
    /// What a browser or mail client would accept: trusted, in date and for this name.
    pub verified: bool,
    pub trust: Trust,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_error: Option<String>,
    /// The server sent an OCSP response in the handshake. Its content is not checked.
    pub ocsp_stapled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("{0:?} is not a valid server name")]
    BadName(String),
    #[error("could not connect: {0}")]
    Connect(String),
    #[error("TLS handshake: {0}")]
    Handshake(String),
    #[error("timed out")]
    TimedOut,
    #[error("the server sent no certificate")]
    NoCertificate,
    #[error("the server sent a certificate chain this tool refuses to process: {0}")]
    Chain(String),
}

/// The Mozilla root store bundled with the program.
pub fn public_roots() -> RootCertStore {
    RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Accepts every certificate and every handshake signature.
///
/// Safe here because the connection is only used to read what the server
/// presents: nothing the rep or the program secret is ever sent over it, and
/// the handshake is dropped right after. Trust is judged separately in
/// [`assess`]. The handshake signature is not checked either, because ring
/// refuses RSA keys under 2048 bits and such a server must still be reported
/// (as a weak key) rather than fail to connect. So `verified` does not prove
/// that the server holds the certificate's private key.
#[derive(Debug)]
struct AcceptAnything(WebPkiSupportedAlgorithms, Arc<AtomicBool>);

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        ocsp: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.1.store(!ocsp.is_empty(), Ordering::Relaxed);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

fn client_config() -> Result<(ClientConfig, Arc<AtomicBool>), RustlsError> {
    let p = provider();
    let stapled = Arc::new(AtomicBool::new(false));
    let verifier = AcceptAnything(p.signature_verification_algorithms, stapled.clone());
    let config = ClientConfig::builder_with_provider(p)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok((config, stapled))
}

/// Handshake over a stream that is already connected and, for STARTTLS, already
/// upgraded to the point where the server expects a ClientHello, and report
/// what the server presents. `now` is the clock for every validity decision.
/// The handshake must finish within `timeout`.
pub async fn inspect_stream<S>(
    stream: S,
    server_name: &str,
    roots: &RootCertStore,
    now: OffsetDateTime,
    timeout: Duration,
) -> Result<TlsResult, TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    inspect_stream_keep(stream, server_name, roots, now, timeout).await.map(|(_, r)| r)
}

/// `inspect_stream`, but the encrypted stream is handed back so the caller can
/// keep talking over it (an SMTP greeting after implicit TLS, EHLO after STARTTLS).
pub async fn inspect_stream_keep<S>(
    stream: S,
    server_name: &str,
    roots: &RootCertStore,
    now: OffsetDateTime,
    timeout: Duration,
) -> Result<(tokio_rustls::client::TlsStream<S>, TlsResult), TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(server_name.to_owned()).map_err(|_| TlsError::BadName(server_name.to_owned()))?;
    let (config, stapled) = client_config().map_err(|e| TlsError::Handshake(e.to_string()))?;
    let connector = TlsConnector::from(Arc::new(config));
    let tls = tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| TlsError::TimedOut)?
        .map_err(handshake_error)?;
    let conn = tls.get_ref().1;
    let ocsp_stapled = stapled.load(Ordering::Relaxed);
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".to_string(),
        other => format!("{other:?}"),
    };
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()).replacen("TLS13_", "TLS_", 1))
        .unwrap_or_default();
    let chain = conn.peer_certificates().ok_or(TlsError::NoCertificate)?;
    let a = assess(chain, server_name, roots, now)?;
    let result = TlsResult {
        version,
        cipher,
        chain: a.chain,
        hostname_match: a.hostname_match,
        verified: a.verified,
        trust: a.trust,
        verify_error: a.verify_error,
        ocsp_stapled,
    };
    Ok((tls, result))
}

/// Connect to `addr` (a name is resolved with the system resolver) and inspect
/// the TLS the server there presents for `server_name`. One `timeout` covers
/// the connection and the handshake together.
pub async fn check_tls_via(
    addr: impl tokio::net::ToSocketAddrs,
    server_name: &str,
    roots: &RootCertStore,
    now: OffsetDateTime,
    timeout: Duration,
) -> Result<TlsResult, TlsError> {
    ServerName::try_from(server_name.to_owned()).map_err(|_| TlsError::BadName(server_name.to_owned()))?;
    tokio::time::timeout(timeout, async {
        let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| TlsError::Connect(e.to_string()))?;
        inspect_stream(tcp, server_name, roots, now, timeout).await
    })
    .await
    .map_err(|_| TlsError::TimedOut)?
}

/// Inspect `host:port` against the bundled public roots, as of now.
pub async fn check_tls(host: &str, port: u16, timeout: Duration) -> Result<TlsResult, TlsError> {
    check_tls_via((host, port), host, &public_roots(), OffsetDateTime::now_utc(), timeout).await
}

fn handshake_error(e: io::Error) -> TlsError {
    let inner = e.get_ref().and_then(|i| i.downcast_ref::<RustlsError>());
    match inner {
        // rustls speaks TLS 1.2 and 1.3 only, so a server stuck on 1.0 or 1.1 answers with one of these.
        Some(
            RustlsError::AlertReceived(AlertDescription::ProtocolVersion | AlertDescription::HandshakeFailure)
            | RustlsError::PeerIncompatible(_),
        ) => TlsError::Handshake(format!(
            "the server refused the handshake; it may offer only TLS 1.0 or 1.1 (deprecated, and not spoken by this tool) or no cipher suite in common ({e})"
        )),
        _ => TlsError::Handshake(printable(&e.to_string())),
    }
}

/// What can be said about a presented chain without the network.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub chain: Vec<TlsCert>,
    pub hostname_match: bool,
    pub verified: bool,
    pub trust: Trust,
    pub verify_error: Option<String>,
}

fn unix(t: OffsetDateTime) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(t.unix_timestamp().max(0) as u64))
}

/// Describe each certificate and judge the chain against `roots` at `now`.
/// Trust ignores hostname and expiry (as Go does): when the leaf is outside
/// its validity the check runs at the middle of that validity, so an expired
/// certificate is not also reported as untrusted.
pub fn assess(
    chain: &[CertificateDer<'_>],
    server_name: &str,
    roots: &RootCertStore,
    now: OffsetDateTime,
) -> Result<Assessment, TlsError> {
    let Some((first, intermediates)) = chain.split_first() else {
        return Err(TlsError::NoCertificate);
    };
    if chain.len() > MAX_CHAIN {
        return Err(TlsError::Chain(format!("{} certificates, more than {MAX_CHAIN}", chain.len())));
    }
    if let Some(big) = chain.iter().find(|c| c.len() > MAX_CERT_BYTES) {
        return Err(TlsError::Chain(format!("a certificate of {} bytes, more than {MAX_CERT_BYTES}", big.len())));
    }
    let certs = chain.iter().enumerate().map(|(i, der)| describe(der, i == 0)).collect::<Result<Vec<_>, _>>()?;
    let (Some(leaf), Some(last)) = (certs.first(), certs.last()) else { return Err(TlsError::NoCertificate) };

    let name = ServerName::try_from(server_name.to_owned()).map_err(|_| TlsError::BadName(server_name.to_owned()))?;
    let algs = provider().signature_verification_algorithms.all;
    let parsed = match ParsedCertificate::try_from(first) {
        Ok(p) => p,
        Err(e) => {
            let (trust, verify_error) = (Trust::Invalid, Some(printable(&e.to_string())));
            return Ok(Assessment { chain: certs, hostname_match: false, verified: false, trust, verify_error });
        }
    };
    let verify =
        |at: OffsetDateTime| verify_server_cert_signed_by_trust_anchor(&parsed, roots, intermediates, unix(at), algs);
    let name_error = verify_server_name(&parsed, &name).err();
    let at_now = verify(now);
    let in_date = leaf.not_before <= now && now <= leaf.not_after;
    let trust_check =
        if in_date { at_now.clone() } else { verify(leaf.not_before + (leaf.not_after - leaf.not_before) / 2) };

    let trust = match &trust_check {
        Ok(()) => Trust::Ok,
        Err(RustlsError::InvalidCertificate(CertificateError::UnknownIssuer)) => {
            if leaf.self_signed {
                Trust::SelfSigned
            } else if !last.is_ca {
                // Only end-entity certificates were sent: the intermediate is missing.
                // (A sent intermediate under an unknown root reads as a private CA.)
                Trust::MissingIntermediate
            } else {
                Trust::UnknownAuthority
            }
        }
        Err(_) => Trust::Invalid,
    };
    let verify_error =
        at_now.as_ref().err().or(name_error.as_ref()).or(trust_check.as_ref().err()).map(|e| printable(&e.to_string()));
    let verified = at_now.is_ok() && name_error.is_none();
    Ok(Assessment { chain: certs, hostname_match: name_error.is_none(), verified, trust, verify_error })
}

fn describe(der: &CertificateDer<'_>, leaf: bool) -> Result<TlsCert, TlsError> {
    let (_, c) = x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|e| TlsError::Chain(format!("unreadable certificate: {e}")))?;
    let name = |n: &x509_parser::x509::X509Name<'_>| {
        // A "*" is not a PrintableString character, so a strict decode refuses wildcard names.
        let cn = n.iter_common_name().next().map(|a| {
            a.as_str().map_or_else(|_| String::from_utf8_lossy(a.attr_value().data).into_owned(), str::to_string)
        });
        printable(&cn.unwrap_or_else(|| n.to_string()))
    };
    let sans = match (leaf, c.subject_alternative_name()) {
        (true, Ok(Some(ext))) => ext
            .value
            .general_names
            .iter()
            .filter_map(|g| match g {
                GeneralName::DNSName(d) => Some(printable(d)),
                _ => None,
            })
            .collect(),
        _ => vec![],
    };
    let not_before = c.validity().not_before.to_datetime();
    let not_after = c.validity().not_after.to_datetime();
    Ok(TlsCert {
        subject: name(c.subject()),
        issuer: name(c.issuer()),
        sans,
        not_before,
        not_after,
        self_signed: self_signed(&c),
        is_ca: c.is_ca(),
        key: key_info(&c),
        signature: signature_name(&c.signature_algorithm),
    })
}

/// Checks the signature directly: a self-signed leaf is usually not marked as a CA.
fn self_signed(c: &X509Certificate<'_>) -> bool {
    c.subject().as_raw() == c.issuer().as_raw() && c.verify_signature(None).is_ok()
}

fn key_info(c: &X509Certificate<'_>) -> KeyInfo {
    let spki = c.public_key();
    match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let m = rsa.modulus;
            let first = m.iter().position(|&b| b != 0);
            // The modulus has a leading zero byte in DER when its top bit is set.
            KeyInfo::Rsa(first.and_then(|i| Some(8 * (m.len() - i) as u32 - m.get(i)?.leading_zeros())).unwrap_or(0))
        }
        Ok(PublicKey::EC(_)) => {
            let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).map(|o| o.to_id_string());
            match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => KeyInfo::Ecdsa("P-256".into()),
                Some("1.3.132.0.34") => KeyInfo::Ecdsa("P-384".into()),
                Some("1.3.132.0.35") => KeyInfo::Ecdsa("P-521".into()),
                _ => KeyInfo::Unknown,
            }
        }
        _ if spki.algorithm.algorithm.to_id_string() == "1.3.101.112" => KeyInfo::Ed25519,
        _ => KeyInfo::Unknown,
    }
}

fn signature_name(a: &AlgorithmIdentifier<'_>) -> String {
    let oid = a.algorithm.to_id_string();
    let name = match oid.as_str() {
        "1.2.840.113549.1.1.2" => "MD2-RSA",
        "1.2.840.113549.1.1.4" => "MD5-RSA",
        "1.2.840.113549.1.1.5" => "SHA1-RSA",
        "1.2.840.113549.1.1.11" => "SHA256-RSA",
        "1.2.840.113549.1.1.12" => "SHA384-RSA",
        "1.2.840.113549.1.1.13" => "SHA512-RSA",
        "1.2.840.113549.1.1.10" => match a
            .parameters
            .as_ref()
            .and_then(|p| RsaSsaPssParams::try_from(p).ok())
            .map(|p| p.hash_algorithm_oid().to_id_string())
            .as_deref()
        {
            Some("2.16.840.1.101.3.4.2.1") => "SHA256-RSAPSS",
            Some("2.16.840.1.101.3.4.2.2") => "SHA384-RSAPSS",
            Some("2.16.840.1.101.3.4.2.3") => "SHA512-RSAPSS",
            _ => "RSASSA-PSS",
        },
        "1.2.840.10040.4.3" => "DSA-SHA1",
        "1.2.840.10045.4.1" => "ECDSA-SHA1",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
        "1.3.101.112" => "Ed25519",
        _ => return oid,
    };
    name.to_string()
}

fn is_weak_signature(name: &str) -> bool {
    matches!(name, "MD2-RSA" | "MD5-RSA" | "SHA1-RSA" | "ECDSA-SHA1" | "DSA-SHA1")
}

fn plural(n: i64, one: &str, many: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {many}") }
}

fn date(t: OffsetDateTime) -> String {
    use time::macros::format_description;
    t.format(format_description!("[day padding:none] [month repr:short] [year]")).unwrap_or_default()
}

fn finding(
    code: &'static str,
    severity: Severity,
    title: impl Into<Cow<'static, str>>,
    message: String,
    recommendation: Option<Cow<'static, str>>,
) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation }
}

/// The Go `ssl_inspection` findings, plus three the Go code lacks:
/// `ssl_inspection_not_yet_valid`, `ssl_inspection_weak_key` and
/// `ssl_inspection_weak_signature`. Days left are worked out from `now`, not
/// stored, so re-runs do not differ by date alone.
pub fn tls_findings(host: &str, port: u16, r: &TlsResult) -> Vec<Finding> {
    tls_findings_at(host, port, r, OffsetDateTime::now_utc())
}

pub fn tls_findings_at(host: &str, port: u16, r: &TlsResult, now: OffsetDateTime) -> Vec<Finding> {
    let Some(leaf) = r.chain.first() else { return vec![] };
    let place = format!("{host}:{port}");
    let mut out = vec![];

    let soonest = r.chain.iter().skip(1).fold(leaf, |s, c| if c.not_after < s.not_after { c } else { s });
    let which = if soonest.subject != leaf.subject || soonest.issuer != leaf.issuer {
        format!("The chain certificate {}", soonest.subject)
    } else {
        "The certificate".to_string()
    };
    let expiry = date(soonest.not_after);
    let renew = "Renew the certificate and install it, with its intermediates, on the server.";
    let days = (soonest.not_after - now).whole_seconds().div_euclid(86_400);
    if days < 0 {
        out.push(finding(
            "ssl_inspection_expired",
            Severity::Critical,
            "Certificate expired",
            format!(
                "{which} on {place} expired on {expiry} ({} ago); browsers and mail clients reject it.",
                plural(-days, "day", "days")
            ),
            Some(renew.into()),
        ));
    } else if days <= 14 {
        out.push(finding(
            "ssl_inspection_expiring",
            Severity::Warning,
            "Certificate expires within two weeks",
            format!("{which} on {place} expires on {expiry} (in {}).", plural(days, "day", "days")),
            Some(format!("{renew} If renewal is automated, check why it hasn't happened yet.").into()),
        ));
    } else if days <= 30 {
        out.push(finding(
            "ssl_inspection_expiring_soon",
            Severity::Info,
            "Certificate expires within a month",
            format!("{which} on {place} expires on {expiry} (in {}).", plural(days, "day", "days")),
            None,
        ));
    }

    if leaf.not_before > now {
        out.push(finding(
            "ssl_inspection_not_yet_valid",
            Severity::Critical,
            "Certificate not yet valid",
            format!(
                "The certificate on {place} is not valid until {}; browsers and mail clients reject it until then.",
                date(leaf.not_before)
            ),
            Some("Check the clock on the server, or wait until the certificate's start date.".into()),
        ));
    }

    if !r.hostname_match {
        let names: Vec<&str> =
            if leaf.sans.is_empty() { vec![&leaf.subject] } else { leaf.sans.iter().map(String::as_str).collect() };
        let shown = names.iter().take(MAX_NAMES_LISTED).copied().collect::<Vec<_>>().join(", ");
        let more = names.len().saturating_sub(MAX_NAMES_LISTED);
        let more = if more > 0 { format!(" and {more} more") } else { String::new() };
        out.push(finding(
            "ssl_inspection_hostname_mismatch",
            Severity::Critical,
            format!("Certificate doesn't cover {host}"),
            format!("The certificate on {place} is for {shown}{more}, not {host}."),
            Some(
                format!("Issue a certificate that includes {host}, or point {host} at the server that has one.").into(),
            ),
        ));
    }

    let Some(last) = r.chain.last() else { return out };
    match r.trust {
        Trust::SelfSigned => out.push(finding(
            "ssl_inspection_self_signed",
            Severity::Critical,
            "Self-signed certificate",
            format!("The certificate on {place} is signed by itself, not by a certificate authority, so no browser or mail client trusts it."),
            Some("Replace it with a certificate from a public CA (e.g. Let's Encrypt).".into()),
        )),
        Trust::MissingIntermediate => out.push(finding(
            "ssl_inspection_incomplete_chain",
            Severity::Critical,
            "Incomplete certificate chain",
            format!(
                "The chain on {place} stops at {}, issued by {}: the server isn't sending its intermediate certificate. Some browsers paper over this; most mail clients, apps and APIs fail.",
                last.subject, last.issuer
            ),
            Some("Install the full chain (the CA's fullchain or bundle file) on the server, not just the certificate.".into()),
        )),
        Trust::UnknownAuthority => out.push(finding(
            "ssl_inspection_untrusted",
            Severity::Critical,
            "Certificate not trusted",
            format!("The chain on {place} leads to {}, which isn't a trusted root (a private CA, or a CA clients don't recognise).", last.issuer),
            Some("Use a certificate from a publicly trusted CA, or install this private CA's root on every client that connects.".into()),
        )),
        Trust::Invalid => out.push(finding(
            "ssl_inspection_untrusted",
            Severity::Critical,
            "Certificate chain doesn't verify",
            format!("The chain on {place} fails verification: {}", r.verify_error.as_deref().unwrap_or("unknown error")),
            Some("Reinstall the certificate with its current, complete chain from the CA.".into()),
        )),
        Trust::Ok => {}
    }

    // A root the server sends along is the client's own business; its key and signature do not matter.
    for (i, c) in r.chain.iter().enumerate().filter(|(i, c)| *i == 0 || !c.self_signed) {
        let what = if i == 0 { "The certificate".to_string() } else { format!("The chain certificate {}", c.subject) };
        if let KeyInfo::Rsa(bits) = c.key
            && bits < 2048
        {
            out.push(finding(
                "ssl_inspection_weak_key",
                Severity::Warning,
                "Weak RSA key",
                format!("{what} on {place} has an RSA {bits}-bit key; keys under 2048 bits are considered breakable and current clients reject them."),
                Some("Reissue the certificate with a 2048-bit or larger RSA key, or an ECDSA key.".into()),
            ));
        }
        if is_weak_signature(&c.signature) {
            out.push(finding(
                "ssl_inspection_weak_signature",
                Severity::Warning,
                "Weak certificate signature",
                format!(
                    "{what} on {place} is signed with {}, which is broken; current clients reject it.",
                    c.signature
                ),
                Some("Reissue the certificate: CAs no longer sign with SHA-1 or MD5.".into()),
            ));
        }
    }

    if r.version == "TLS 1.0" || r.version == "TLS 1.1" {
        out.push(finding(
            "ssl_inspection_old_protocol",
            Severity::Warning,
            format!("{} negotiated", r.version),
            format!("{place} negotiated {}, which is deprecated; current browsers refuse it.", r.version),
            Some("Enable TLS 1.2 and 1.3 on the server and disable TLS 1.0/1.1.".into()),
        ));
    }

    if r.verified {
        out.push(finding(
            "ssl_inspection_valid",
            Severity::Ok,
            "Certificate valid",
            format!(
                "The certificate on {place} is valid for {host}, issued by {}, expiring {}.",
                leaf.issuer,
                date(leaf.not_after)
            ),
            None,
        ));
    }
    out
}
