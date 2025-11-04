//! Time and date utility functions

use crate::types::{Error, Result};
use chrono::{DateTime, Duration, Utc};

/// Get current UTC timestamp
#[must_use]
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Parse RFC 2822 date format (commonly used in HTTP headers)
pub fn parse_rfc2822(date_str: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(date_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::generic(format!("Failed to parse date: {e}")))
}

/// Parse RFC 3339 date format (ISO 8601)
pub fn parse_rfc3339(date_str: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(date_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::generic(format!("Failed to parse date: {e}")))
}

/// Format date as RFC 2822
#[must_use]
pub fn format_rfc2822(dt: &DateTime<Utc>) -> String {
    dt.to_rfc2822()
}

/// Format date as RFC 3339
#[must_use]
pub fn format_rfc3339(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

/// Check if a date is in the past
#[must_use]
pub fn is_past(dt: &DateTime<Utc>) -> bool {
    dt < &Utc::now()
}

/// Check if a date is in the future
#[must_use]
pub fn is_future(dt: &DateTime<Utc>) -> bool {
    dt > &Utc::now()
}

/// Calculate duration between two dates
#[must_use]
pub fn duration_between(start: &DateTime<Utc>, end: &DateTime<Utc>) -> Duration {
    end.signed_duration_since(*start)
}

/// Add duration to date
#[must_use]
pub fn add_duration(dt: &DateTime<Utc>, duration: Duration) -> DateTime<Utc> {
    *dt + duration
}

/// Subtract duration from date
#[must_use]
pub fn subtract_duration(dt: &DateTime<Utc>, duration: Duration) -> DateTime<Utc> {
    *dt - duration
}

/// Convert seconds to Duration
#[must_use]
pub fn seconds_to_duration(seconds: i64) -> Duration {
    Duration::seconds(seconds)
}

/// Convert Duration to seconds
#[must_use]
pub fn duration_to_seconds(duration: &Duration) -> i64 {
    duration.num_seconds()
}

/// Format duration as human-readable string
#[must_use]
pub fn format_duration_human(duration: &Duration) -> String {
    let total_seconds = duration.num_seconds();

    if total_seconds < 60 {
        format!("{total_seconds}s")
    } else if total_seconds < 3600 {
        let minutes = total_seconds / 60;
        let seconds = total_seconds % 60;
        format!("{minutes}m {seconds}s")
    } else if total_seconds < 86400 {
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        format!("{hours}h {minutes}m")
    } else {
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        format!("{days}d {hours}h")
    }
}

/// Parse cookie expiry date (supports multiple formats)
pub fn parse_cookie_date(date_str: &str) -> Result<DateTime<Utc>> {
    use chrono::NaiveDateTime;

    let formats = [
        "%a, %d %b %Y %H:%M:%S GMT", // RFC 822
        "%A, %d-%b-%y %H:%M:%S GMT", // RFC 850
        "%a %b %e %H:%M:%S %Y",      // asctime
        "%a, %d-%b-%Y %H:%M:%S GMT", // Common variant
    ];

    let trimmed = date_str.trim();

    // Remove "GMT" suffix if present for parsing, then treat as UTC
    let date_without_tz = trimmed.trim_end_matches(" GMT").trim_end_matches("GMT");

    for format in &formats {
        // Remove GMT from format for NaiveDateTime parsing
        let naive_format = format.trim_end_matches(" GMT").trim_end_matches("GMT");

        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(date_without_tz, naive_format) {
            // Convert NaiveDateTime to UTC DateTime (assuming GMT/UTC)
            return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc));
        }
    }

    Err(Error::generic(format!(
        "Cannot parse cookie date: {date_str}"
    )))
}

/// Format timestamp as human-readable string
#[must_use]
pub fn format_timestamp(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Check if cookie expiry date has passed
#[must_use]
pub fn is_expired(expiry: &DateTime<Utc>) -> bool {
    is_past(expiry)
}

/// Parse timestamp from string (alias for `parse_rfc3339` for backward compatibility)
pub fn parse_timestamp(timestamp_str: &str) -> Result<DateTime<Utc>> {
    parse_rfc3339(timestamp_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now() {
        let now = now();
        assert!(is_past(&(now - Duration::seconds(1))));
        assert!(is_future(&(now + Duration::seconds(1))));
    }

    #[test]
    fn test_format_duration() {
        let d = Duration::seconds(90);
        assert_eq!(format_duration_human(&d), "1m 30s");

        let d = Duration::seconds(3661);
        assert_eq!(format_duration_human(&d), "1h 1m");
    }

    #[test]
    fn test_parse_cookie_date() {
        let date = parse_cookie_date("Wed, 21 Oct 2015 07:28:00 GMT");
        assert!(date.is_ok());
    }

    #[test]
    fn test_duration_conversion() {
        let d = seconds_to_duration(3600);
        assert_eq!(duration_to_seconds(&d), 3600);
    }
}
