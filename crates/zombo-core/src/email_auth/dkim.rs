//! DKIM: one key per selector, read from the TXT record at `<selector>._domainkey.<domain>`.

use std::fmt;

use serde::Serialize;

use super::{
    query::{Dns, concurrently},
    tags,
};

/// Selectors the common mail providers use.
pub const DKIM_COMMON_SELECTORS: [&str; 37] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "mail",
    "dkim",
    "email",
    "smtp",
    "mandrill",
    "mailchimp",
    "mxvault",
    "zoho",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "fm1",
    "fm2",
    "fm3",
    "everlytickey1",
    "everlytickey2",
    "mailjet",
    "sendgrid",
    "smtpapi",
    "amazonses",
    "mailgun",
    "mg",
    "pm",
    "zendesk1",
    "zendesk2",
    "hs1",
    "hs2",
    "mimecast",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Rsa,
    Ed25519,
    Other(String),
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyType::Rsa => "rsa",
            KeyType::Ed25519 => "ed25519",
            KeyType::Other(k) => k,
        })
    }
}

/// The `t=` tag: `y` means the domain is testing DKIM, `s` forbids signing from subdomains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DkimFlags {
    pub testing: bool,
    pub strict: bool,
}

/// Why a key cannot verify anything. `Display` gives the wording the Go engine used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DkimKeyError {
    NoPublicKey,
    NotBase64,
    NotRsa,
}

impl fmt::Display for DkimKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DkimKeyError::NoPublicKey => "no p= tag",
            DkimKeyError::NotBase64 => "public key is not valid base64",
            DkimKeyError::NotRsa => "public key does not parse as RSA",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DkimKey {
    pub selector: String,
    /// The last alias followed to reach the record.
    pub cname: Option<String>,
    pub record: String,
    pub key_type: KeyType,
    /// RSA modulus size, when the key parses.
    pub bits: Option<u32>,
    pub flags: DkimFlags,
    /// An empty `p=`: the key was withdrawn.
    pub revoked: bool,
    pub error: Option<DkimKeyError>,
}

/// What an audit of one domain's DKIM selectors found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DkimAudit {
    /// Every selector queried: the common ones, then the caller's.
    pub checked: Vec<String>,
    pub custom: Vec<String>,
    pub keys: Vec<DkimKey>,
    /// Selectors whose lookup got no answer.
    pub failed: Vec<String>,
}

/// The most custom selectors one audit queries.
pub const MAX_CUSTOM_SELECTORS: usize = 20;

/// Turn what a person typed (selectors split by commas, semicolons or
/// whitespace) into valid, lowercase, distinct selectors.
pub fn parse_selectors(raw: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = vec![];
    for s in raw.iter().flat_map(|r| r.split([',', ';', ' ', '\t', '\n'])).filter(|s| !s.is_empty()) {
        let s = s.to_ascii_lowercase();
        let label = |l: &str| {
            !l.is_empty()
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        if !s.split('.').all(label) {
            return Err(format!("{s:?} is not a valid DKIM selector"));
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    if out.len() > MAX_CUSTOM_SELECTORS {
        return Err(format!("at most {MAX_CUSTOM_SELECTORS} custom DKIM selectors"));
    }
    Ok(out)
}

/// Ask for `<selector>._domainkey.<domain>` for every common selector and the
/// caller's (at most `MAX_CUSTOM_SELECTORS`), all at the same time.
pub(crate) async fn dkim_audit(dns: Dns, domain: &str, custom: &[String]) -> DkimAudit {
    let mut audit =
        DkimAudit { checked: DKIM_COMMON_SELECTORS.iter().map(ToString::to_string).collect(), ..Default::default() };
    for s in custom.iter().map(|s| s.to_ascii_lowercase()) {
        if audit.custom.len() == MAX_CUSTOM_SELECTORS {
            break;
        }
        if audit.custom.contains(&s) {
            continue;
        }
        if !audit.checked.contains(&s) {
            audit.checked.push(s.clone());
        }
        audit.custom.push(s);
    }
    let asked = audit.checked.iter().map(|sel| {
        let name = format!("{sel}._domainkey.{domain}");
        async move { dns.txt(&name).await }
    });
    let answers = concurrently(asked.collect()).await;
    for (sel, answer) in audit.checked.iter().zip(answers) {
        match answer {
            Some(Ok(txt)) => {
                audit.keys.extend(txt.records.iter().filter_map(|r| parse_dkim_key(sel, txt.cname.as_deref(), r)))
            }
            _ => audit.failed.push(sel.clone()),
        }
    }
    audit
}

/// Read a TXT record at a selector as a DKIM key. Records that are not
/// DKIM (no `p=` and no `v=DKIM1`) give `None`.
pub fn parse_dkim_key(selector: &str, cname: Option<&str>, record: &str) -> Option<DkimKey> {
    let t = tags(record);
    if !t.contains_key("p") && !t.get("v").is_some_and(|v| v.eq_ignore_ascii_case("DKIM1")) {
        return None;
    }
    let key_type = match t.get("k").map(|k| k.to_ascii_lowercase()) {
        None => KeyType::Rsa,
        Some(k) if k.is_empty() || k == "rsa" => KeyType::Rsa,
        Some(k) if k == "ed25519" => KeyType::Ed25519,
        Some(k) => KeyType::Other(k),
    };
    let flags = t.get("t").map_or_else(DkimFlags::default, |f| {
        let has = |x: &str| f.split(':').any(|p| p.eq_ignore_ascii_case(x));
        DkimFlags { testing: has("y"), strict: has("s") }
    });
    let mut key = DkimKey {
        selector: selector.into(),
        cname: cname.map(Into::into),
        record: record.into(),
        key_type,
        bits: None,
        flags,
        revoked: false,
        error: None,
    };
    match t.get("p").map(String::as_str) {
        None => key.error = Some(DkimKeyError::NoPublicKey),
        Some("") => key.revoked = true,
        Some(p) if key.key_type == KeyType::Rsa => match base64(p) {
            None => key.error = Some(DkimKeyError::NotBase64),
            Some(der) => match rsa_bits(&der) {
                Some(bits) => key.bits = Some(bits),
                None => key.error = Some(DkimKeyError::NotRsa),
            },
        },
        Some(_) => {}
    }
    Some(key)
}

/// Standard base64 with padding, as DKIM keys are published.
fn base64(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if !b.len().is_multiple_of(4) || pad > 2 {
        return None;
    }
    let (mut out, mut acc, mut n) = (Vec::with_capacity(b.len() / 4 * 3), 0u32, 0u32);
    for &c in &b[..b.len() - pad] {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        (acc, n) = (acc << 6 | u32::from(v), n + 6);
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    Some(out)
}

/// One DER element: tag, content, and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, b) = b.split_first()?;
    let (len, b) = match first {
        0..=0x7f => (usize::from(first), b),
        0x81..=0x84 => {
            let n = usize::from(first & 0x7f);
            let (len, rest) = b.split_at_checked(n)?;
            (len.iter().fold(0usize, |a, &x| a << 8 | usize::from(x)), rest)
        }
        _ => return None,
    };
    let (body, rest) = b.split_at_checked(len)?;
    Some((tag, body, rest))
}

/// The modulus size of an RSA public key, as a PKIX SubjectPublicKeyInfo or a
/// bare PKCS#1 RSAPublicKey. Only the shape is checked; the key is not validated.
fn rsa_bits(der: &[u8]) -> Option<u32> {
    // 1.2.840.113549.1.1.1, rsaEncryption
    const RSA_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let (0x30, body, _) = tlv(der)? else { return None };
    let (tag, first, rest) = tlv(body)?;
    match tag {
        0x02 => pkcs1_bits(body),
        0x30 => {
            let (0x06, oid, _) = tlv(first)? else { return None };
            let (0x03, bits, _) = tlv(rest)? else { return None };
            let (0, inner) = bits.split_first()? else { return None };
            let (0x30, inner, _) = tlv(inner)? else { return None };
            (oid == RSA_OID).then(|| pkcs1_bits(inner)).flatten()
        }
        _ => None,
    }
}

/// `INTEGER modulus, INTEGER exponent`.
fn pkcs1_bits(body: &[u8]) -> Option<u32> {
    let (0x02, n, rest) = tlv(body)? else { return None };
    let (0x02, _, _) = tlv(rest)? else { return None };
    let n = &n[n.iter().position(|&b| b != 0)?..];
    u32::try_from(n.len() * 8).ok()?.checked_sub(n[0].leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SubjectPublicKeyInfo for an RSA key whose modulus is 2^(bits-1) (the
    /// same trick the Go tests use: only the size matters), as base64.
    fn spki(bits: usize) -> String {
        let top = bits - 1;
        let len = bits.div_ceil(8);
        let mut modulus = vec![0u8; len + 1]; // a leading zero keeps the integer positive
        modulus[len - top / 8] = 1 << (top % 8);
        let int = |c: &[u8]| [vec![0x02], der_len(c.len()), c.to_vec()].concat();
        let rsa = seq(&[int(&modulus), int(&[1, 0, 1])].concat());
        let alg = seq(&[vec![0x06, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1], vec![5, 0]].concat());
        let bit = [vec![0x03], der_len(rsa.len() + 1), vec![0], rsa].concat();
        b64(&seq(&[alg, bit].concat()))
    }
    fn der_len(n: usize) -> Vec<u8> {
        match n {
            0..=127 => vec![n as u8],
            128..=255 => vec![0x81, n as u8],
            _ => vec![0x82, (n >> 8) as u8, n as u8],
        }
    }
    fn seq(body: &[u8]) -> Vec<u8> {
        [vec![0x30], der_len(body.len()), body.to_vec()].concat()
    }
    fn b64(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in bytes.chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
            for i in 0..4 {
                s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
            }
        }
        s
    }
    fn key(rec: &str) -> DkimKey {
        parse_dkim_key("s", None, rec).expect("a DKIM record")
    }

    fn raw(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn selectors_are_split_lowercased_and_made_distinct() {
        assert_eq!(
            parse_selectors(&raw(&["Acme2024, other  google", "OTHER;a.b\tc_d-e\nx"])).unwrap(),
            ["acme2024", "other", "google", "a.b", "c_d-e", "x"]
        );
        assert!(parse_selectors(&[]).unwrap().is_empty());
        assert!(parse_selectors(&raw(&[" , ;"])).unwrap().is_empty());
    }

    #[test]
    fn a_selector_must_be_a_dns_label_or_dotted_labels() {
        for bad in ["bad..name", "-x", "x-", ".x", "x.", "a/b", "a b!", "é", "a@b", "a.-b"] {
            let e = parse_selectors(&raw(&[bad])).expect_err(bad);
            assert!(e.contains("is not a valid DKIM selector"), "{bad}: {e}");
        }
        assert_eq!(parse_selectors(&raw(&["bad..name"])).unwrap_err(), r#""bad..name" is not a valid DKIM selector"#);
    }

    #[test]
    fn more_than_twenty_selectors_is_an_error() {
        let ok: Vec<String> = (0..20).map(|i| format!("s{i}")).collect();
        assert_eq!(parse_selectors(&ok).unwrap().len(), 20);
        let many: Vec<String> = (0..21).map(|i| format!("s{i}")).collect();
        assert_eq!(parse_selectors(&many).unwrap_err(), "at most 20 custom DKIM selectors");
        // Repeats do not count twice.
        assert_eq!(parse_selectors(&raw(&["a a a a"; 30])).unwrap(), ["a"]);
    }

    #[test]
    fn rsa_key_sizes_are_read_from_the_modulus() {
        for bits in [512, 1024, 2048, 4096] {
            let k = key(&format!("v=DKIM1; k=rsa; p={}", spki(bits)));
            assert_eq!(
                (k.bits, k.error, k.revoked, k.key_type),
                (Some(bits as u32), None, false, KeyType::Rsa),
                "{bits}"
            );
        }
    }

    #[test]
    fn k_defaults_to_rsa_and_is_case_insensitive() {
        assert_eq!(key(&format!("p={}", spki(1024))).key_type, KeyType::Rsa);
        assert_eq!(
            key("v=DKIM1; k=ED25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=").key_type,
            KeyType::Ed25519
        );
        assert_eq!(key("v=DKIM1; k=ecdsa; p=AAAA").key_type, KeyType::Other("ecdsa".into()));
    }

    #[test]
    fn a_bare_pkcs1_key_parses() {
        let rsa = {
            let int = |c: &[u8]| [vec![0x02], der_len(c.len()), c.to_vec()].concat();
            let mut m = vec![0u8; 129];
            m[1] = 0x80;
            seq(&[int(&m), int(&[1, 0, 1])].concat())
        };
        assert_eq!(key(&format!("v=DKIM1; p={}", b64(&rsa))).bits, Some(1024));
    }

    #[test]
    fn an_empty_p_is_revoked() {
        let k = key("v=DKIM1; k=rsa; p=");
        assert!(k.revoked && k.error.is_none() && k.bits.is_none());
    }

    #[test]
    fn broken_keys_say_why() {
        assert_eq!(key("v=DKIM1; p=!!notbase64").error, Some(DkimKeyError::NotBase64));
        assert_eq!(key("v=DKIM1; p=QUJD").error, Some(DkimKeyError::NotRsa)); // valid base64, not DER
        assert_eq!(key("v=DKIM1; k=rsa").error, Some(DkimKeyError::NoPublicKey));
        assert_eq!(DkimKeyError::NoPublicKey.to_string(), "no p= tag");
    }

    #[test]
    fn a_dkim_record_needs_p_or_the_version() {
        assert!(parse_dkim_key("s", None, "not a dkim record").is_none());
        assert!(parse_dkim_key("s", None, "v=spf1 -all").is_none());
        assert!(parse_dkim_key("s", None, "v=DKIM1").is_some());
        assert!(parse_dkim_key("s", None, "p=QUJD").is_some());
    }

    #[test]
    fn flags_and_cname_are_kept() {
        let k = parse_dkim_key("sel", Some("k.provider.test"), "v=DKIM1; t=y:s; p=").unwrap();
        assert_eq!(
            (k.flags, k.cname.as_deref(), k.selector.as_str()),
            (DkimFlags { testing: true, strict: true }, Some("k.provider.test"), "sel")
        );
        assert_eq!(key("v=DKIM1; p=").flags, DkimFlags::default());
    }

    #[test]
    fn hostile_keys_do_not_panic() {
        let mut cases = vec![
            "v=DKIM1; p=A".to_string(),
            "v=DKIM1; p====".into(),
            format!("v=DKIM1; p={}", "A".repeat(70_000)),
            format!("v=DKIM1; p={}", "/".repeat(65_536)),
            "v=DKIM1; p=é".into(),
        ];
        // A real key cut short at every base64 quantum, and DER whose lengths lie.
        let s = spki(1024);
        for end in (0..s.len()).step_by(4) {
            cases.push(format!("v=DKIM1; p={}", &s[..end]));
        }
        for len in [
            &[0x30u8, 0x84, 0xff, 0xff, 0xff, 0xff][..],
            &[0x30, 0x80],
            &[0x30, 0x82, 0x01],
            &[0x02, 0x00],
            &[0x30, 0x03, 0x02, 0x01, 0x00],
        ] {
            cases.push(format!("v=DKIM1; p={}", b64(len)));
        }
        for c in cases {
            let _ = parse_dkim_key("s", None, &c);
        }
    }
}
