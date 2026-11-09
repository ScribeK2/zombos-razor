//! Zombo's Razor core: every Check, with no UI.

pub mod dns;
pub mod delegation;
pub mod finding;
pub mod lookup;
pub mod propagation;
pub mod registration;
pub mod target;

pub use finding::{Finding, Severity};
