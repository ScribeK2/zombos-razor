//! Zombo's Razor core: every Check, with no UI.

pub mod blacklist;
pub mod dns;
pub mod email_auth;
pub mod delegation;
pub mod dnssec;
pub mod finding;
pub mod lookup;
pub mod propagation;
pub mod rdns;
pub mod registration;
pub mod resolver;
pub mod target;

pub use finding::{Finding, Severity};
