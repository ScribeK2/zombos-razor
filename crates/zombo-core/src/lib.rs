//! Zombo's Razor core: every Check, with no UI.

pub mod blacklist;
pub mod delegation;
pub mod dns;
pub mod dnssec;
pub mod email_auth;
pub mod evidence;
pub mod finding;
pub mod lookup;
pub mod lookup_findings;
pub mod ports;
pub mod propagation;
pub mod rdns;
pub mod registration;
pub mod resolver;
pub mod smtp;
pub mod target;
pub mod text;
pub mod tls;
pub mod tls_extras;
pub mod untrusted;
pub mod update;
pub mod web;

pub use finding::{Finding, Severity};

/// The release version. `packaging/build-appimage.sh` stamps it through `ZOMBO_VERSION`
/// (the Go build did the same with `-ldflags -X main.version`); without it, the crate version.
pub const VERSION: &str = match option_env!("ZOMBO_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
