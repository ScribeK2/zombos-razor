//! A local TLS server that staples a fixed OCSP response (any bytes: the client does not parse them).
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc};

use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Debug)]
struct Stapled(Arc<CertifiedKey>);

impl ResolvesServerCert for Stapled {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub async fn serve_stapled(chain: Vec<CertificateDer<'static>>, key: PrivatePkcs8KeyDer<'static>, ocsp: Option<Vec<u8>>) -> SocketAddr {
    let provider = Arc::new(ring::default_provider());
    let signing = provider.key_provider.load_private_key(PrivateKeyDer::Pkcs8(key)).unwrap();
    let mut certified = CertifiedKey::new(chain, signing);
    certified.ocsp = ocsp;
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Stapled(Arc::new(certified))));
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
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
