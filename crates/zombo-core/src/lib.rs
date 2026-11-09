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

/// The User-Agent of every HTTP client (web, registration). The updater builds its own from the
/// running version it is given, which the app takes from `VERSION`. Never from `CARGO_PKG_VERSION`
/// directly: a stamped release would still say `zombo/0.0.0`.
pub fn user_agent() -> String {
    user_agent_for(VERSION)
}

pub fn user_agent_for(version: &str) -> String {
    format!("zombo/{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_agent_carries_the_given_version() {
        assert_eq!(user_agent_for("9.9.9"), "zombo/9.9.9");
        assert_eq!(user_agent(), format!("zombo/{VERSION}"));
    }
}
