//! Signed self-update for the AppImage. GPUI-free and offline-testable: every endpoint, limit and
//! trusted root is injected through `Endpoints`.
//!
//! Trust chain: the release carries `SHA256SUMS` and `SHA256SUMS.minisig`. The signature is checked
//! against the embedded public key, its trusted comment must name the release version (so an old
//! signed release cannot be replayed as a new one), and only then is the AppImage hashed against the
//! signed sums. Nothing is renamed over the old file until all of that has passed.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ureq::tls::{Certificate, RootCerts, TlsConfig};

/// The GitHub repository releases are read from. Placeholder: set the real `owner/repo` before the
/// first release.
pub const RELEASE_REPO: &str = "ScribeK2/zombos-razor";
const API_BASE: &str = "https://api.github.com";

/// The minisign public key every release must be signed with: the two lines of `update_key.pub`.
///
/// The file holds a TEST key now. To replace it, run `minisign -G -p update_key.pub -s <secret key
/// file>`, keep the secret key out of the repository, and commit the new `update_key.pub`. The
/// release build refuses every update, with `UpdateError::TestKeyEmbedded`, while the test key is here.
pub const PUBLIC_KEY: &str = include_str!("../update_key.pub");

/// The public half of the key the tests sign with (its seed is public on purpose). A release
/// build that still embeds it refuses to check or install anything. See `Endpoints::guard`.
pub const TEST_KEY_BASE64: &str = "RWRaUlRFU1RLWRCysoPTt6Udjpf4qaLvZZMjZ+nIRYFlX+1Pqps4kifA";

/// Whether the second line of a minisign public key file is the test key.
pub fn is_test_key(key: &str) -> bool {
    key.lines().nth(1).is_some_and(|l| l.trim() == TEST_KEY_BASE64)
}

/// Whether this build may update at all: not a release build holding the test key.
pub fn available() -> bool {
    available_in(!cfg!(debug_assertions))
}

pub fn available_in(release: bool) -> bool {
    !(release && is_test_key(PUBLIC_KEY))
}

pub const MAX_METADATA: u64 = 256 * 1024;
pub const MAX_SUMS: u64 = 64 * 1024;
pub const MAX_APPIMAGE: u64 = 120 * 1024 * 1024;
const MAX_REDIRECTS: u32 = 5;
const NOTES_CHARS: usize = 600;
const SIGNED_PREFIX: &str = "zombo-razor ";

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("cannot reach the release server: {0}")]
    Network(String),
    #[error("the release server did not answer in time")]
    TimedOut,
    #[error("the release server answered {0}")]
    Status(u16),
    #[error("a download address is not https: {0}")]
    Insecure(String),
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("{what} is larger than {limit} bytes")]
    TooLarge { what: &'static str, limit: u64 },
    #[error("the release information is not usable: {0}")]
    BadRelease(String),
    #[error("the signature on SHA256SUMS is not valid: {0}")]
    BadSignature(String),
    #[error("the signed checksums are for {signed:?}, not for version {wanted}")]
    WrongVersion { signed: String, wanted: String },
    #[error("SHA256SUMS does not list {0}")]
    NotListed(String),
    #[error("this build holds a test signing key, so updates are not available")]
    TestKeyEmbedded,
    #[error("the downloaded file does not match the signed checksum")]
    ChecksumMismatch,
    #[error("the download ended before the whole file arrived")]
    Truncated,
    #[error("cannot write the new version next to the AppImage: {0}")]
    Write(String),
}

/// A semantic version. Build metadata is dropped. A pre-release sorts before its release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Ident>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    Num(u64),
    Text(String),
}

impl Version {
    /// `1.4.0`, `v1.4.0` or `1.4.0-rc.1`. Anything else is `None`.
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.strip_prefix('v').unwrap_or(text);
        if text.len() > 64 {
            return None;
        }
        let text = text.split('+').next()?;
        let (core, pre) = match text.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (text, None),
        };
        let number =
            |s: &str| (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u64>().ok())?;
        let mut parts = core.split('.');
        let (major, minor, patch) = (number(parts.next()?)?, number(parts.next()?)?, number(parts.next()?)?);
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => vec![],
            Some(p) => p
                .split('.')
                .map(|id| match id {
                    "" => None,
                    _ if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') => None,
                    _ if id.bytes().all(|b| b.is_ascii_digit()) => id.parse().ok().map(Ident::Num),
                    _ => Some(Ident::Text(id.to_string())),
                })
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Version { major, minor, patch, pre })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)).then_with(|| {
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => std::cmp::Ordering::Equal,
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, id) in self.pre.iter().enumerate() {
            let sep = if i == 0 { '-' } else { '.' };
            match id {
                Ident::Num(n) => write!(f, "{sep}{n}")?,
                Ident::Text(t) => write!(f, "{sep}{t}")?,
            }
        }
        Ok(())
    }
}

/// Where to ask, what to trust and how much to accept. `Endpoints::real` is GitHub and the
/// embedded key; tests point it at a fake server and their own key.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub api_base: String,
    pub repo: String,
    /// The two lines of a minisign public key file.
    pub key: String,
    /// DER certificates trusted instead of the bundled web roots.
    pub roots: Option<Vec<Vec<u8>>>,
    pub user_agent: String,
    pub metadata_deadline: Duration,
    pub download_deadline: Duration,
    pub max_metadata: u64,
    pub max_sums: u64,
    pub max_appimage: u64,
}

impl Endpoints {
    pub fn real(running: &Version) -> Endpoints {
        let mut ep = Endpoints {
            api_base: API_BASE.into(),
            repo: RELEASE_REPO.into(),
            key: PUBLIC_KEY.into(),
            roots: None,
            user_agent: format!("zombo/{running}"),
            metadata_deadline: Duration::from_secs(20),
            download_deadline: Duration::from_secs(600),
            max_metadata: MAX_METADATA,
            max_sums: MAX_SUMS,
            max_appimage: MAX_APPIMAGE,
        };
        ep.apply_debug_hook();
        ep
    }

    /// Debug builds only: `ZOMBO_UPDATE_BASE` replaces the API address and `ZOMBO_UPDATE_CA` names
    /// a DER file to trust, so a local https server can stand in for GitHub. Release builds do not
    /// contain either name.
    #[cfg(debug_assertions)]
    fn apply_debug_hook(&mut self) {
        if let Ok(base) = std::env::var("ZOMBO_UPDATE_BASE") {
            self.api_base = base;
        }
        if let Some(ca) = std::env::var_os("ZOMBO_UPDATE_CA").and_then(|p| fs::read(p).ok()) {
            self.roots = Some(vec![ca]);
        }
    }

    #[cfg(not(debug_assertions))]
    fn apply_debug_hook(&mut self) {}

    /// Fail closed: a release build never trusts the test key, whatever else is configured.
    fn guard(&self, release: bool) -> Result<(), UpdateError> {
        if release && is_test_key(&self.key) { Err(UpdateError::TestKeyEmbedded) } else { Ok(()) }
    }

    fn agent(&self, deadline: Duration) -> Result<ureq::Agent, UpdateError> {
        let mut tls = TlsConfig::builder();
        if let Some(roots) = &self.roots {
            let certs: Vec<Certificate<'static>> = roots.iter().map(|d| Certificate::from_der(d).to_owned()).collect();
            tls = tls.root_certs(RootCerts::new_with_certs(&certs));
        }
        Ok(ureq::Agent::config_builder()
            .tls_config(tls.build())
            .timeout_global(Some(deadline))
            .max_redirects(MAX_REDIRECTS)
            .https_only(true)
            .http_status_as_error(false)
            .user_agent(self.user_agent.clone())
            .build()
            .into())
    }

    fn open(&self, url: &str, deadline: Duration, accept: &str) -> Result<ureq::Body, UpdateError> {
        let resp = self.agent(deadline)?.get(url).header("Accept", accept).call().map_err(net)?;
        match resp.status().as_u16() {
            200 => Ok(resp.into_body()),
            s => Err(UpdateError::Status(s)),
        }
    }

    fn fetch(&self, url: &str, deadline: Duration, limit: u64, what: &'static str) -> Result<Vec<u8>, UpdateError> {
        let mut body = self.open(url, deadline, "application/octet-stream, application/json")?;
        if body.content_length().is_some_and(|n| n > limit) {
            return Err(UpdateError::TooLarge { what, limit });
        }
        body.with_config().limit(limit).read_to_vec().map_err(|e| match e {
            ureq::Error::BodyExceedsLimit(_) => UpdateError::TooLarge { what, limit },
            e => net(e),
        })
    }
}

fn net(e: ureq::Error) -> UpdateError {
    match e {
        ureq::Error::Timeout(_) => UpdateError::TimedOut,
        ureq::Error::TooManyRedirects => UpdateError::TooManyRedirects,
        ureq::Error::RequireHttpsOnly(url) => UpdateError::Insecure(url),
        e => UpdateError::Network(e.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Asset {
    name: String,
    url: String,
    size: u64,
}

/// A newer release, with everything needed to fetch and verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Available {
    pub version: Version,
    /// The first 600 characters of the release notes, with no control characters.
    pub notes: String,
    /// The release page, for a rep who cannot be updated in place.
    pub page_url: String,
    appimage: Asset,
    sums: Asset,
    sig: Asset,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    body: Option<String>,
    html_url: String,
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// Release notes as shown to the rep: bounded, one line, no control or bidirectional characters.
pub fn notes_preview(notes: &str) -> String {
    let mut out: String = notes
        .chars()
        .take(NOTES_CHARS)
        .map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c })
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect();
    if notes.chars().nth(NOTES_CHARS).is_some() {
        out.push_str("...");
    }
    out.trim().to_string()
}

fn https(url: &str) -> Result<(), UpdateError> {
    match url::Url::parse(url) {
        Ok(u) if u.scheme() == "https" && u.host().is_some() => Ok(()),
        _ => Err(UpdateError::Insecure(notes_preview(url).chars().take(120).collect())),
    }
}

fn asset(release: &ApiRelease, pick: impl Fn(&str) -> bool, what: &str, cap: u64) -> Result<Asset, UpdateError> {
    let a = release
        .assets
        .iter()
        .find(|a| pick(&a.name))
        .ok_or_else(|| UpdateError::BadRelease(format!("release {} has no {what}", release.tag_name)))?;
    https(&a.browser_download_url)?;
    if a.size > cap {
        return Err(UpdateError::TooLarge { what: "an asset", limit: cap });
    }
    Ok(Asset { name: a.name.clone(), url: a.browser_download_url.clone(), size: a.size })
}

/// The newest release that is newer than `current`. Drafts never count. A pre-release counts only
/// when the running version is one too.
pub fn select(releases: &[u8], current: &Version, ep: &Endpoints) -> Result<Option<Available>, UpdateError> {
    let releases: Vec<ApiRelease> =
        serde_json::from_slice(releases).map_err(|e| UpdateError::BadRelease(e.to_string()))?;
    let best = releases
        .iter()
        .filter(|r| !r.draft && (!r.prerelease || current.is_prerelease()))
        .filter_map(|r| Version::parse(&r.tag_name).map(|v| (v, r)))
        .filter(|(v, _)| v > current && (!v.is_prerelease() || current.is_prerelease()))
        .max_by(|a, b| a.0.cmp(&b.0));
    let Some((version, r)) = best else { return Ok(None) };
    let appimage = asset(r, |n| n.ends_with(".AppImage"), "AppImage", ep.max_appimage)?;
    let sums = asset(r, |n| n == "SHA256SUMS", "SHA256SUMS", ep.max_sums)?;
    let sig = asset(r, |n| n == "SHA256SUMS.minisig", "SHA256SUMS.minisig", ep.max_sums)?;
    let page_url = if https(&r.html_url).is_ok() {
        r.html_url.clone()
    } else {
        format!("https://github.com/{}/releases", ep.repo)
    };
    Ok(Some(Available {
        version,
        notes: notes_preview(r.body.as_deref().unwrap_or("")),
        page_url,
        appimage,
        sums,
        sig,
    }))
}

/// Ask the release server whether a newer version exists. Blocking; run it off the UI thread.
pub fn check(ep: &Endpoints, current: &Version) -> Result<Option<Available>, UpdateError> {
    check_in(ep, current, !cfg!(debug_assertions))
}

/// `check` for an explicit build kind, so a release build can be simulated under test.
pub fn check_in(ep: &Endpoints, current: &Version, release: bool) -> Result<Option<Available>, UpdateError> {
    ep.guard(release)?;
    let url = format!("{}/repos/{}/releases?per_page=20", ep.api_base.trim_end_matches('/'), ep.repo);
    https(&url)?;
    let mut body = ep.open(&url, ep.metadata_deadline, "application/vnd.github+json")?;
    if body.content_length().is_some_and(|n| n > ep.max_metadata) {
        return Err(UpdateError::TooLarge { what: "the release list", limit: ep.max_metadata });
    }
    let bytes = body.with_config().limit(ep.max_metadata).read_to_vec().map_err(|e| match e {
        ureq::Error::BodyExceedsLimit(_) => UpdateError::TooLarge { what: "the release list", limit: ep.max_metadata },
        e => net(e),
    })?;
    select(&bytes, current, ep)
}

/// The signed checksum of `name`, once the signature over `sums` is proven good and bound to `version`.
fn signed_hash(key: &str, sums: &[u8], sig: &[u8], version: &Version, name: &str) -> Result<String, UpdateError> {
    let bad = |m: String| UpdateError::BadSignature(m);
    let key = PublicKey::decode(key).map_err(|e| bad(format!("the embedded public key is unusable: {e}")))?;
    let sig = std::str::from_utf8(sig).map_err(|_| bad("the signature file is not text".into()))?;
    let sig = Signature::decode(sig).map_err(|e| bad(e.to_string()))?;
    key.verify(sums, &sig, false).map_err(|e| bad(e.to_string()))?;
    let signed = sig.trusted_comment();
    if signed.strip_prefix(SIGNED_PREFIX).and_then(Version::parse).as_ref() != Some(version) {
        return Err(UpdateError::WrongVersion {
            signed: notes_preview(signed).chars().take(60).collect(),
            wanted: version.to_string(),
        });
    }
    let sums = std::str::from_utf8(sums).map_err(|_| bad("SHA256SUMS is not text".into()))?;
    sums.lines()
        .filter_map(|l| l.split_once(' '))
        .find(|(_, file)| file.trim_start_matches([' ', '*']) == name)
        .map(|(hash, _)| hash.to_ascii_lowercase())
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| UpdateError::NotListed(name.to_string()))
}

/// The running AppImage: where it lives and whether a file can be created beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub path: PathBuf,
    pub writable: bool,
}

impl Target {
    /// `None` unless `appimage` (the `APPIMAGE` variable) names a regular file.
    pub fn detect(appimage: Option<&std::ffi::OsStr>) -> Option<Target> {
        let path = fs::canonicalize(appimage.filter(|v| !v.is_empty())?).ok()?;
        fs::metadata(&path).ok()?.is_file().then_some(())?;
        let dir = path.parent()?;
        let probe = dir.join(format!(".zombo-update-probe-{}", std::process::id()));
        let writable = OpenOptions::new().write(true).create_new(true).open(&probe).is_ok();
        let _ = fs::remove_file(&probe);
        Some(Target { path, writable })
    }
}

/// Removes the half-written file on any early return.
struct Temp {
    path: PathBuf,
    keep: bool,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Fetch the signed checksums, verify them, download the AppImage, hash it, and rename it over
/// `target`. On any error `target` is untouched and no other file is left behind. Blocking.
pub fn install(ep: &Endpoints, rel: &Available, target: &Path) -> Result<(), UpdateError> {
    install_in(ep, rel, target, !cfg!(debug_assertions))
}

pub fn install_in(ep: &Endpoints, rel: &Available, target: &Path, release: bool) -> Result<(), UpdateError> {
    ep.guard(release)?;
    let write = |e: std::io::Error| UpdateError::Write(e.to_string());
    let sums = ep.fetch(&rel.sums.url, ep.metadata_deadline, ep.max_sums, "SHA256SUMS")?;
    let sig = ep.fetch(&rel.sig.url, ep.metadata_deadline, ep.max_sums, "the signature")?;
    let want = signed_hash(&ep.key, &sums, &sig, &rel.version, &rel.appimage.name)?;

    let dir = target.parent().ok_or_else(|| UpdateError::Write("the AppImage has no directory".into()))?;
    let name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| UpdateError::Write("bad file name".into()))?;
    let mode = fs::metadata(target).map_err(write)?.permissions().mode() & 0o7777;
    let tmp_path = dir.join(format!(".{name}.update-{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp_path);
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp_path).map_err(write)?;
    let mut tmp = Temp { path: tmp_path, keep: false };

    let mut body = ep.open(&rel.appimage.url, ep.download_deadline, "application/octet-stream")?;
    if body.content_length().is_some_and(|n| n > ep.max_appimage) {
        return Err(UpdateError::TooLarge { what: "the AppImage", limit: ep.max_appimage });
    }
    let mut reader = body.with_config().limit(ep.max_appimage).reader();
    let (mut hash, mut total, mut buf) = (Sha256::new(), 0u64, vec![0u8; 64 * 1024]);
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hash.update(&buf[..n]);
                file.write_all(&buf[..n]).map_err(write)?;
                total += n as u64;
            }
            Err(e) => {
                let inner = e.get_ref().and_then(|i| i.downcast_ref::<ureq::Error>());
                return Err(match inner {
                    Some(ureq::Error::BodyExceedsLimit(_)) => {
                        UpdateError::TooLarge { what: "the AppImage", limit: ep.max_appimage }
                    }
                    _ if total < rel.appimage.size => UpdateError::Truncated,
                    _ => UpdateError::Network(e.to_string()),
                });
            }
        }
    }
    if total < rel.appimage.size {
        return Err(UpdateError::Truncated);
    }
    let got: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != want {
        return Err(UpdateError::ChecksumMismatch);
    }
    file.set_permissions(fs::Permissions::from_mode(mode)).map_err(write)?;
    file.sync_all().map_err(write)?;
    drop(file);
    fs::rename(&tmp.path, target).map_err(write)?;
    tmp.keep = true;
    let _ = File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

/// Replace this process with `path`. Returns only if that failed.
pub fn restart(path: &Path) -> std::io::Error {
    std::os::unix::process::CommandExt::exec(&mut std::process::Command::new(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn ep() -> Endpoints {
        Endpoints::real(&v("1.0.0"))
    }

    fn release(tag: &str, draft: bool, pre: bool) -> String {
        let a = |n: &str| format!(r#"{{"name":"{n}","browser_download_url":"https://h/{n}","size":10}}"#);
        format!(
            r#"{{"tag_name":"{tag}","draft":{draft},"prerelease":{pre},"body":"notes","html_url":"https://h/r","assets":[{},{},{}]}}"#,
            a("zombo-x86_64.AppImage"),
            a("SHA256SUMS"),
            a("SHA256SUMS.minisig")
        )
    }

    fn pick(list: &[String], current: &str) -> Option<String> {
        let json = format!("[{}]", list.join(","));
        select(json.as_bytes(), &v(current), &ep()).unwrap().map(|a| a.version.to_string())
    }

    #[test]
    fn versions_compare_like_semver() {
        for (lo, hi) in [
            ("1.2.3", "1.10.0"),
            ("1.0.0-rc.1", "1.0.0"),
            ("1.0.0-rc.2", "1.0.0-rc.10"),
            ("1.0.0-alpha", "1.0.0-alpha.1"),
            ("1.0.0-1", "1.0.0-a"),
        ] {
            assert!(v(lo) < v(hi), "{lo} < {hi}");
        }
        assert_eq!(v("v1.4.0+build5"), v("1.4.0"));
        for bad in ["", "1.4", "1.4.0.1", "a.b.c", "1.4.0-", "1.4.0-a..b", "1.-4.0", "v"] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
        assert_eq!(v("1.4.0-rc.1").to_string(), "1.4.0-rc.1");
    }

    #[test]
    fn drafts_and_prereleases_are_ignored_and_the_newest_wins() {
        let list = [
            release("v1.1.0", false, false),
            release("v1.3.0", true, false),
            release("v1.2.0-rc.1", false, true),
            release("v1.2.0", false, false),
        ];
        assert_eq!(pick(&list, "1.0.0").as_deref(), Some("1.2.0"));
        assert_eq!(pick(&list, "1.2.0"), None);
        assert_eq!(pick(&list, "1.5.0"), None);
    }

    #[test]
    fn a_prerelease_build_sees_prereleases() {
        let list = [release("v1.2.0-rc.2", false, true)];
        assert_eq!(pick(&list, "1.2.0-rc.1").as_deref(), Some("1.2.0-rc.2"));
        assert_eq!(pick(&list, "1.1.0"), None);
    }

    #[test]
    fn a_release_missing_its_signature_is_unusable() {
        let json = release("v2.0.0", false, false).replace("SHA256SUMS.minisig", "other");
        let r = select(format!("[{json}]").as_bytes(), &v("1.0.0"), &ep());
        assert!(matches!(r, Err(UpdateError::BadRelease(_))), "{r:?}");
    }

    #[test]
    fn an_http_asset_address_is_refused() {
        let json = release("v2.0.0", false, false).replace("https://h/SHA256SUMS\"", "http://h/SHA256SUMS\"");
        let r = select(format!("[{json}]").as_bytes(), &v("1.0.0"), &ep());
        assert!(matches!(r, Err(UpdateError::Insecure(_))), "{r:?}");
    }

    #[test]
    fn notes_are_bounded_and_have_no_control_characters() {
        let long = format!("a\u{1b}[31m\nb\u{202e}{}", "x".repeat(700));
        let p = notes_preview(&long);
        assert!(!p.chars().any(|c| c.is_control() || c == '\u{202e}'), "{p:?}");
        assert!(p.starts_with("a[31m b"), "{p:?}");
        assert!(p.chars().count() <= NOTES_CHARS + 3 && p.ends_with("..."));
        assert_eq!(notes_preview("short"), "short");
    }

    #[test]
    fn detect_wants_a_regular_file() {
        let dir = std::env::temp_dir().join(format!("zombo-detect-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.AppImage");
        fs::write(&file, b"x").unwrap();
        assert_eq!(Target::detect(None), None);
        assert_eq!(Target::detect(Some("".as_ref())), None);
        assert_eq!(Target::detect(Some(dir.as_os_str())), None);
        assert_eq!(Target::detect(Some(dir.join("missing").as_os_str())), None);
        let t = Target::detect(Some(file.as_os_str())).unwrap();
        assert!(t.writable);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "the probe is removed");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let root = OpenOptions::new().write(true).create_new(true).open(dir.join("p")).is_ok();
        if !root {
            assert!(!Target::detect(Some(file.as_os_str())).unwrap().writable);
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn a_release_build_ignores_the_debug_hook() {
        let e = ep();
        assert_eq!(e.api_base, API_BASE);
        assert!(e.roots.is_none());
    }
}
