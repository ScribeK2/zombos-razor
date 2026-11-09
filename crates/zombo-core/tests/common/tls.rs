//! A throwaway PKI and a local TLS server for the TLS and STARTTLS tests.
//! Every certificate is generated at test time, nothing real is contacted.
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::{
    RootCertStore, ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use time::{Duration as Span, OffsetDateTime, macros::datetime};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The injected clock of every test.
pub const NOW: OffsetDateTime = datetime!(2030-06-15 12:00 UTC);

pub fn days(n: i64) -> OffsetDateTime {
    NOW + Span::days(n)
}

pub struct Ca {
    pub name: String,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = days(-3650);
    p.not_after = days(3650);
    p
}

impl Ca {
    pub fn root(name: &str) -> Ca {
        let issuer = CertifiedIssuer::self_signed(ca_params(name), KeyPair::generate().unwrap()).unwrap();
        Ca { name: name.into(), issuer }
    }

    pub fn intermediate(&self, name: &str) -> Ca {
        self.intermediate_valid(name, days(-3000), days(3000))
    }

    pub fn intermediate_valid(&self, name: &str, from: OffsetDateTime, to: OffsetDateTime) -> Ca {
        let mut p = ca_params(name);
        (p.not_before, p.not_after) = (from, to);
        let issuer = CertifiedIssuer::signed_by(p, KeyPair::generate().unwrap(), &self.issuer).unwrap();
        Ca { name: name.into(), issuer }
    }

    pub fn der(&self) -> CertificateDer<'static> {
        self.issuer.der().clone()
    }

    /// A store that trusts only this CA.
    pub fn roots(&self) -> RootCertStore {
        let mut r = RootCertStore::empty();
        r.add(self.der()).unwrap();
        r
    }

    /// A server certificate for `sans`, valid between `from` and `to`.
    pub fn leaf(&self, sans: &[&str], from: OffsetDateTime, to: OffsetDateTime) -> Leaf {
        let mut p = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, sans[0]);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        (p.not_before, p.not_after) = (from, to);
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Leaf { der: cert.der().clone(), key: PrivatePkcs8KeyDer::from(key.serialize_der()) }
    }

    pub fn valid_leaf(&self, sans: &[&str]) -> Leaf {
        self.leaf(sans, days(-90), days(90))
    }
}

pub struct Leaf {
    pub der: CertificateDer<'static>,
    pub key: PrivatePkcs8KeyDer<'static>,
}

/// A self-signed leaf, which is also its own root.
pub fn self_signed(sans: &[&str]) -> Leaf {
    let mut p = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, sans[0]);
    (p.not_before, p.not_after) = (days(-90), days(90));
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    Leaf { der: cert.der().clone(), key: PrivatePkcs8KeyDer::from(key.serialize_der()) }
}

/// Presents `chain` signed with `key`, whether or not the key belongs to the first certificate.
#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub fn server_config(chain: Vec<CertificateDer<'static>>, key: PrivatePkcs8KeyDer<'static>) -> Arc<ServerConfig> {
    let provider = Arc::new(ring::default_provider());
    let signing = provider.key_provider.load_private_key(PrivateKeyDer::Pkcs8(key)).unwrap();
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(Arc::new(CertifiedKey::new(chain, signing)))));
    Arc::new(cfg)
}

/// Serves `chain` on a local port until the test ends.
pub async fn serve(chain: Vec<CertificateDer<'static>>, key: PrivatePkcs8KeyDer<'static>) -> SocketAddr {
    let acceptor = TlsAcceptor::from(server_config(chain, key));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(tcp).await;
            });
        }
    });
    addr
}

/// Accepts connections and never answers.
pub async fn serve_silent() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = vec![];
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    addr
}
