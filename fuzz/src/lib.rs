//! Helpers shared by the fuzz targets.

use std::{future::Future, sync::OnceLock};

use zombo_core::Finding;

/// What reaches the screen must not carry control characters, the one rule every Finding follows.
pub fn check_findings(findings: &[Finding]) {
    for f in findings {
        let shown = [f.title.as_ref(), f.message.as_str(), f.recommendation.as_deref().unwrap_or_default()];
        for s in shown {
            assert!(!s.chars().any(|c| c.is_control() && c != '\n'), "control character in a finding: {s:?}");
        }
    }
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap_or_else(|e| panic!("runtime: {e}"))
    })
    .block_on(f)
}
