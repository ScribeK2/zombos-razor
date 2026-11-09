//! Zombo's Razor core: every Check, with no UI.

pub mod dns;
pub mod finding;
pub mod lookup;
pub mod propagation;
pub mod target;

pub use finding::{Finding, Severity};
