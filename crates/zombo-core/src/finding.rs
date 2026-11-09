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
    pub title: &'static str,
    pub message: String,
    pub recommendation: Option<&'static str>,
}
