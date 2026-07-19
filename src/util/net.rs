/// Network utilities for veriscan (online mode only).
///
/// All network helpers are gated by policy; callers must check
/// `policy.allow_network` before invoking any function here.
/// Network calls are never made when offline mode is active.
use crate::error::VeriError;
use std::time::Duration;

/// Build a reqwest Client with appropriate timeouts and no redirect following
/// beyond the single initial request.
pub fn build_client(timeout_secs: u64) -> Result<reqwest::Client, VeriError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(concat!("veriscan/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(VeriError::Network)
}

/// Validate a URL against the policy denylist.
pub fn check_url_allowed(url: &str, denylist: &[String]) -> Result<(), VeriError> {
    for pattern in denylist {
        if url.contains(pattern.as_str()) {
            return Err(VeriError::UrlDenied {
                url: url.to_string(),
            });
        }
    }
    Ok(())
}
