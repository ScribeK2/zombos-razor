//! Zombo's Razor core: every Check, with no UI.

pub mod blacklist;
pub mod delegation;
pub mod dns;
pub mod dnssec;
pub mod email_auth;
pub mod evidence;
pub mod finding;
pub mod lookup;
pub mod ports;
pub mod propagation;
pub mod rdns;
pub mod registration;
pub mod resolver;
pub mod smtp;
pub mod target;
pub mod tls;
pub mod tls_extras;
pub mod untrusted;
pub mod web;

pub use finding::{Finding, Severity};
