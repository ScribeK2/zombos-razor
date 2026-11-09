use std::borrow::Cow;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Critical,
}

/// A conclusion with a severity, derived from one Lookup.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    /// Usually a fixed sentence; a runtime string where the title carries a value.
    pub title: Cow<'static, str>,
    pub message: String,
    pub recommendation: Option<Cow<'static, str>>,
}
