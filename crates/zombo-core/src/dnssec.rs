//! DNSSEC Check: is a domain's DNSSEC healthy, and when it is not, why?
//!
//! Two parts, and no signature cryptography. First, known-validating public
//! resolvers are asked for the same record with and without the CD (checking
//! disabled) flag: SERVFAIL that turns into an answer is DNSSEC breaking the
//! domain. Second, the DS records at the parent and the DNSKEY and signature
//! the zone's own nameservers serve are compared, which explains why.
//! DNSSEC records are read from raw RDATA: hickory decodes them only with its
//! crypto features, which Zombo does not use.

use std::fmt;

use hickory_proto::rr::Name;
use serde::{Serialize, Serializer};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

/// RFC 4034 Appendix B key tag: a checksum that names a DNSKEY, so a DS or an
/// RRSIG can say which key it refers to. Not unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct KeyTag(pub u16);

impl fmt::Display for KeyTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn key_tag(rdata: &[u8], algorithm: Algorithm) -> KeyTag {
    if algorithm == Algorithm::RsaMd5 {
        // The one exception in Appendix B: the top 16 of the last 24 bits of the key.
        return KeyTag(rdata.len().checked_sub(3).map_or(0, |i| u16::from_be_bytes([rdata[i], rdata[i + 1]])));
    }
    let mut sum: u32 = rdata.iter().enumerate().map(|(i, &b)| u32::from(b) << if i % 2 == 0 { 8 } else { 0 }).sum();
    sum += sum >> 16;
    KeyTag((sum & 0xffff) as u16)
}

/// DNSSEC algorithm numbers (IANA registry), with the ones Zombo knows named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaMd5,
    Dsa,
    RsaSha1,
    DsaNsec3Sha1,
    RsaSha1Nsec3Sha1,
    RsaSha256,
    RsaSha512,
    Gost,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    Ed448,
    Unknown(u8),
}

use Algorithm::*;

/// (algorithm, number, name, deprecated). Deprecated means weak or no longer
/// accepted by modern resolvers.
const ALGORITHMS: [(Algorithm, u8, &str, bool); 12] = [
    (RsaMd5, 1, "RSAMD5", true),
    (Dsa, 3, "DSA", true),
    (RsaSha1, 5, "RSASHA1", true),
    (DsaNsec3Sha1, 6, "DSA-NSEC3-SHA1", true),
    (RsaSha1Nsec3Sha1, 7, "RSASHA1-NSEC3-SHA1", true),
    (RsaSha256, 8, "RSASHA256", false),
    (RsaSha512, 10, "RSASHA512", false),
    (Gost, 12, "ECC-GOST", true),
    (EcdsaP256Sha256, 13, "ECDSAP256SHA256", false),
    (EcdsaP384Sha384, 14, "ECDSAP384SHA384", false),
    (Ed25519, 15, "ED25519", false),
    (Ed448, 16, "ED448", false),
];

impl Algorithm {
    pub fn from_number(n: u8) -> Self {
        ALGORITHMS.iter().find(|a| a.1 == n).map_or(Unknown(n), |a| a.0)
    }

    fn row(self) -> Option<&'static (Algorithm, u8, &'static str, bool)> {
        ALGORITHMS.iter().find(|a| a.0 == self)
    }

    pub fn number(self) -> u8 {
        match self {
            Unknown(n) => n,
            known => known.row().map_or(0, |a| a.1),
        }
    }

    pub fn deprecated(self) -> bool {
        self.row().is_some_and(|a| a.3)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.row() {
            Some(a) => write!(f, "{} ({})", a.2, a.1),
            None => write!(f, "algorithm {}", self.number()),
        }
    }
}

impl Serialize for Algorithm {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// DS digest types (IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    Sha1,
    Sha256,
    Sha384,
    Unknown(u8),
}

fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}
fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
fn sha384(data: &[u8]) -> Vec<u8> {
    Sha384::digest(data).to_vec()
}

const DIGESTS: [(DigestType, u8, &str, fn(&[u8]) -> Vec<u8>); 3] = [
    (DigestType::Sha1, 1, "SHA-1", sha1),
    (DigestType::Sha256, 2, "SHA-256", sha256),
    (DigestType::Sha384, 4, "SHA-384", sha384),
];

impl DigestType {
    pub fn from_number(n: u8) -> Self {
        DIGESTS.iter().find(|d| d.1 == n).map_or(DigestType::Unknown(n), |d| d.0)
    }

    pub fn number(self) -> u8 {
        match self {
            DigestType::Unknown(n) => n,
            known => DIGESTS.iter().find(|d| d.0 == known).map_or(0, |d| d.1),
        }
    }

    /// The digest of `data`, or `None` for a type Zombo cannot compute.
    pub fn digest(self, data: &[u8]) -> Option<Vec<u8>> {
        DIGESTS.iter().find(|d| d.0 == self).map(|d| d.3(data))
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match DIGESTS.iter().find(|d| d.0 == *self) {
            Some(d) => f.write_str(d.2),
            None => write!(f, "digest type {}", self.number()),
        }
    }
}

impl Serialize for DigestType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

fn hex<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// A DNSKEY record as a zone serves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dnskey {
    pub flags: u16,
    #[serde(skip)]
    protocol: u8,
    pub algorithm: Algorithm,
    pub key_tag: KeyTag,
    #[serde(skip)]
    pub public_key: Vec<u8>,
}

impl Dnskey {
    pub fn new(flags: u16, protocol: u8, algorithm: Algorithm, public_key: Vec<u8>) -> Self {
        let mut k = Dnskey { flags, protocol, algorithm, key_tag: KeyTag(0), public_key };
        k.key_tag = key_tag(&k.rdata(), algorithm);
        k
    }

    /// From the record's wire RDATA: flags, protocol, algorithm, key.
    pub fn from_rdata(rdata: &[u8]) -> Option<Self> {
        let (&[f0, f1, protocol, alg], key) = rdata.split_first_chunk()?;
        Some(Dnskey::new(u16::from_be_bytes([f0, f1]), protocol, Algorithm::from_number(alg), key.to_vec()))
    }

    fn rdata(&self) -> Vec<u8> {
        let mut out = self.flags.to_be_bytes().to_vec();
        out.extend([self.protocol, self.algorithm.number()]);
        out.extend(&self.public_key);
        out
    }

    /// The secure entry point flag: a key signing key, the one a DS points at.
    pub fn is_ksk(&self) -> bool {
        self.flags & 0x0001 != 0
    }
}

/// A DS record: the parent zone's statement of which child key to trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ds {
    pub key_tag: KeyTag,
    pub algorithm: Algorithm,
    pub digest_type: DigestType,
    #[serde(serialize_with = "hex")]
    pub digest: Vec<u8>,
}

impl Ds {
    /// From the record's wire RDATA: key tag, algorithm, digest type, digest.
    pub fn from_rdata(rdata: &[u8]) -> Option<Self> {
        let (&[t0, t1, alg, digest_type], digest) = rdata.split_first_chunk()?;
        Some(Ds {
            key_tag: KeyTag(u16::from_be_bytes([t0, t1])),
            algorithm: Algorithm::from_number(alg),
            digest_type: DigestType::from_number(digest_type),
            digest: digest.to_vec(),
        })
    }

    /// Whether this DS points at `key`, a DNSKEY of the zone named `owner`: same
    /// key tag and algorithm, and the digest of owner name plus key is the one
    /// the DS holds. A digest type Zombo cannot compute is given the benefit of
    /// the doubt once tag and algorithm agree, so it never produces a false mismatch.
    pub fn matches(&self, owner: &Name, key: &Dnskey) -> bool {
        if self.key_tag != key.key_tag || self.algorithm != key.algorithm {
            return false;
        }
        let mut input = canonical_wire(owner);
        input.extend(key.rdata());
        self.digest_type.digest(&input).is_none_or(|d| d == self.digest)
    }
}

/// A name as it is hashed: lowercase labels, each with its length, ending in the root.
fn canonical_wire(name: &Name) -> Vec<u8> {
    let mut out = vec![];
    for label in name.iter() {
        out.push(label.len() as u8);
        out.extend(label.to_ascii_lowercase());
    }
    out.push(0);
    out
}
