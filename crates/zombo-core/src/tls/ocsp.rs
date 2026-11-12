//! The OCSP half of the TLS Check: whether the server stapled an OCSP
//! response. The flag comes from the handshake; no OCSP client is involved.

use super::{TlsResult, caa::finding};
use crate::finding::{Finding, Severity};

/// Whether the server stapled an OCSP response. Informational only: the
/// response is not fetched or checked here.
pub fn ocsp_findings(host: &str, port: u16, r: &TlsResult) -> Vec<Finding> {
    if r.ocsp_stapled {
        vec![finding(
            "tls_ocsp_stapled",
            Severity::Ok,
            "OCSP response stapled",
            format!(
                "{host}:{port} sent an OCSP response with its certificate, so clients need not ask the CA about revocation."
            ),
            None,
        )]
    } else {
        vec![finding(
            "tls_no_ocsp_staple",
            Severity::Info,
            "No OCSP stapling",
            format!(
                "{host}:{port} did not staple an OCSP response. Stapling is optional, and a server whose CA no longer runs OCSP has nothing to staple."
            ),
            None,
        )]
    }
}
