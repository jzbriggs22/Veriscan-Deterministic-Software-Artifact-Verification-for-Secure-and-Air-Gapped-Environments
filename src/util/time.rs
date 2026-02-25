/// Time utilities.
///
/// Centralised so that all timestamps in a run use the same format and
/// timezone (always UTC, always ISO 8601 with millisecond precision).
use chrono::{DateTime, Utc};

/// Return the current UTC instant formatted as ISO 8601.
pub fn iso8601_now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Format an arbitrary DateTime<Utc> as ISO 8601.
pub fn iso8601(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Parse an ISO 8601 string back to DateTime<Utc>.
pub fn parse_iso8601(s: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Return the number of seconds elapsed since `start`.
pub fn elapsed_secs(start: DateTime<Utc>) -> f64 {
    let elapsed = Utc::now() - start;
    elapsed.num_milliseconds() as f64 / 1000.0
}
