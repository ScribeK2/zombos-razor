#[path = "common/registry.rs"]
mod registry;

use std::time::Duration as Wait;

use registry::{FakeHttp, Reply};
use zombo_core::registration::{Endpoints, check_proxy, check_registration};

const T: Wait = Wait::from_secs(5);
const CLOSED: &str = "127.0.0.1:1";

/// An RDAP base on a closed port, so only a proxy can answer.
fn behind_a_proxy(proxy: Option<String>) -> Endpoints {
    Endpoints {
        rdap: [("com".to_string(), "http://127.0.0.1:1/".to_string())].into(),
        whois: [("com".to_string(), CLOSED.to_string())].into(),
        whois_iana: CLOSED.into(),
        proxy,
        ..Endpoints::default()
    }
}

#[tokio::test]
async fn registration_goes_through_the_proxy_the_settings_name() {
    let proxy = FakeHttp::start(|_| Reply::new(403, "")).await;

    let e = check_registration("example.com", &behind_a_proxy(Some(proxy.base.clone())), T).await.unwrap_err();

    assert_eq!(proxy.paths(), ["127.0.0.1:1"], "the proxy was asked to CONNECT to the RDAP server");
    assert!(e.to_string().contains("CONNECT proxy failed"), "{e}");
}

#[tokio::test]
async fn with_no_proxy_setting_the_same_lookup_does_not_reach_the_proxy() {
    let proxy = FakeHttp::domain(200, "{}").await;
    let r = check_registration("example.com", &behind_a_proxy(None), T).await;
    assert!(r.is_err());
    assert_eq!(proxy.hits(), 0);
}

#[test]
fn a_proxy_setting_must_be_an_http_or_https_url() {
    for ok in ["http://proxy.example:3128", "https://proxy.example", "http://u:p@10.0.0.1:8080"] {
        assert!(check_proxy(ok).is_ok(), "{ok}");
    }
    for bad in ["", "proxy.example:3128", "socks5://proxy:1080", "ftp://x", "http://", "http://a b"] {
        assert!(check_proxy(bad).is_err(), "{bad:?}");
    }
}
