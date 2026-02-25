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

/// Download a URL to bytes; returns the body as a Vec<u8>.
///
/// Does not follow more than 3 redirects. Enforces a size cap to prevent
/// memory exhaustion from unexpectedly large responses.
pub async fn download_bytes(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, VeriError> {
    use tokio::io::AsyncReadExt;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(VeriError::Network)?;

    let status = response.status();
    if !status.is_success() {
        return Err(VeriError::VtApiError {
            status: status.as_u16(),
            body: format!("HTTP {} from {}", status, url),
        });
    }

    // Use content_length hint if available, capped at max_bytes.
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(max_bytes as u64) as usize,
    );

    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(VeriError::Network)?;
        if body.len() + chunk.len() > max_bytes {
            return Err(VeriError::Internal(format!(
                "Download from '{}' exceeded max size of {} bytes",
                url, max_bytes
            )));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
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
