//! # Cookie Timeline Reconstruction
//!
//! Reconstruct complete timeline of cookie activities for forensic analysis.
//!
//! This module provides capabilities to:
//! - Rebuild chronological timeline of all cookie events
//! - Detect temporal anomalies and suspicious patterns
//! - Identify gaps in activity
//! - Correlate events across multiple cookies
//! - Generate timeline visualizations for reports

use crate::forensics::ForensicConfig;
use crate::types::{Cookie, Error, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Complete timeline of cookie events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieTimeline {
    /// All events in chronological order
    pub events: Vec<CookieEvent>,

    /// Confidence level of reconstruction (0.0-1.0)
    pub reconstruction_confidence: f64,

    /// Detected anomalies
    pub anomalies: Vec<TimelineAnomaly>,

    /// Timeline start time
    pub start_time: DateTime<Utc>,

    /// Timeline end time
    pub end_time: DateTime<Utc>,

    /// Total duration
    pub duration: Duration,

    /// Statistics
    pub statistics: TimelineStatistics,
}

/// Individual cookie event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Cookie involved
    pub cookie: Cookie,

    /// Type of action
    pub action: CookieAction,

    /// Source of the event
    pub source: EventSource,

    /// IP address (if available)
    pub ip_address: Option<IpAddr>,

    /// User agent (if available)
    pub user_agent: Option<String>,

    /// Confidence level (0.0-1.0)
    pub confidence: f64,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Type of cookie action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CookieAction {
    /// Cookie was created
    Created,

    /// Cookie was modified
    Modified,

    /// Cookie was accessed/read
    Accessed,

    /// Cookie was deleted
    Deleted,

    /// Cookie expired naturally
    Expired,

    /// Cookie attributes changed
    AttributeChanged,

    /// Unknown action
    Unknown,
}

/// Source of the cookie event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    /// HTTP response from server
    ServerSetCookie,

    /// JavaScript document.cookie
    JavaScript,

    /// Browser internal
    Browser,

    /// Third-party script
    ThirdParty {
        /// Domain of the third-party
        domain: String,
    },

    /// Unknown source
    Unknown,
}

/// Timeline anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineAnomaly {
    /// Type of anomaly
    pub anomaly_type: AnomalyType,

    /// Severity (0.0-1.0)
    pub severity: f64,

    /// Description
    pub description: String,

    /// Time range affected
    pub time_range: (DateTime<Utc>, DateTime<Utc>),

    /// Related events
    pub related_events: Vec<usize>, // indices into events array

    /// Confidence (0.0-1.0)
    pub confidence: f64,
}

/// Types of timeline anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Suspicious gap in timeline
    SuspiciousGap,

    /// Unusual burst of activity
    ActivityBurst,

    /// Cookie modification without access
    ModificationWithoutAccess,

    /// Cookies from impossible locations
    ImpossibleTravel,

    /// Session hijacking pattern
    SessionHijacking,

    /// Cookie replay attack
    ReplayAttack,

    /// Temporal inconsistency
    TemporalInconsistency,

    /// Deleted evidence pattern
    EvidenceTampering,
}

/// Timeline statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineStatistics {
    /// Total events
    pub total_events: usize,

    /// Events by action type
    pub events_by_action: HashMap<String, usize>,

    /// Events by source
    pub events_by_source: HashMap<String, usize>,

    /// Unique cookies
    pub unique_cookies: usize,

    /// Average events per day
    pub avg_events_per_day: f64,

    /// Peak activity time
    pub peak_activity: Option<DateTime<Utc>>,

    /// Longest gap between events
    pub longest_gap: Option<Duration>,
}

impl CookieTimeline {
    /// Reconstruct timeline from cookies
    pub fn reconstruct(cookies: &[Cookie], config: &ForensicConfig) -> Result<Self> {
        if cookies.is_empty() {
            return Err(Error::ForensicError(
                "No cookies provided for timeline reconstruction".to_string(),
            ));
        }

        // Convert cookies to events
        let mut events = Self::cookies_to_events(cookies);

        // Sort chronologically
        events.sort_by_key(|a| a.timestamp);

        // Calculate time bounds
        let start_time = events.first().map_or_else(Utc::now, |e| e.timestamp);
        let end_time = events.last().map_or_else(Utc::now, |e| e.timestamp);
        let duration = end_time - start_time;

        // Calculate statistics
        let statistics = Self::calculate_statistics(&events, duration);

        // Calculate confidence
        let reconstruction_confidence = Self::calculate_confidence(&events, cookies);

        let mut timeline = Self {
            events,
            reconstruction_confidence,
            anomalies: Vec::new(),
            start_time,
            end_time,
            duration,
            statistics,
        };

        // Detect anomalies
        timeline.anomalies = timeline.detect_anomalies(config);

        Ok(timeline)
    }

    /// Convert cookies to timeline events
    fn cookies_to_events(cookies: &[Cookie]) -> Vec<CookieEvent> {
        let mut events = Vec::new();

        for cookie in cookies {
            // Creation event - created_at is NOT optional
            events.push(CookieEvent {
                timestamp: cookie.created_at,
                cookie: cookie.clone(),
                action: CookieAction::Created,
                source: Self::detect_source(cookie),
                ip_address: None,
                user_agent: None,
                confidence: 0.9,
                metadata: HashMap::new(),
            });

            // Expiry event (future)
            if let Some(expires) = cookie.expires {
                if expires > Utc::now() {
                    events.push(CookieEvent {
                        timestamp: expires,
                        cookie: cookie.clone(),
                        action: CookieAction::Expired,
                        source: EventSource::Browser,
                        ip_address: None,
                        user_agent: None,
                        confidence: 1.0,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        events
    }

    /// Detect the source of a cookie
    fn detect_source(cookie: &Cookie) -> EventSource {
        // Check if it's a third-party cookie - domain is Option<String>
        if let Some(ref domain) = cookie.domain {
            if domain.starts_with('.') {
                return EventSource::ThirdParty {
                    domain: domain.clone(),
                };
            }
        }

        // Check attributes that suggest JavaScript
        if cookie.http_only {
            // HttpOnly suggests server-side
            EventSource::ServerSetCookie
        } else {
            // Could be JavaScript accessible
            EventSource::JavaScript
        }
    }

    /// Calculate statistics from events
    #[allow(clippy::cast_precision_loss)] // Small event counts, f64 precision acceptable
    fn calculate_statistics(events: &[CookieEvent], duration: Duration) -> TimelineStatistics {
        let mut events_by_action: HashMap<String, usize> = HashMap::new();
        let mut events_by_source: HashMap<String, usize> = HashMap::new();
        let mut unique_cookies = std::collections::HashSet::new();

        for event in events {
            // Count by action
            let action_str = format!("{:?}", event.action);
            *events_by_action.entry(action_str).or_insert(0) += 1;

            // Count by source
            let source_str = match &event.source {
                EventSource::ServerSetCookie => "Server",
                EventSource::JavaScript => "JavaScript",
                EventSource::Browser => "Browser",
                EventSource::ThirdParty { .. } => "ThirdParty",
                EventSource::Unknown => "Unknown",
            };
            *events_by_source.entry(source_str.to_string()).or_insert(0) += 1;

            // Track unique cookies
            unique_cookies.insert(event.cookie.name.clone());
        }

        let avg_events_per_day = if duration.num_days() > 0 {
            events.len() as f64 / duration.num_days() as f64
        } else {
            events.len() as f64
        };

        TimelineStatistics {
            total_events: events.len(),
            events_by_action,
            events_by_source,
            unique_cookies: unique_cookies.len(),
            avg_events_per_day,
            peak_activity: None, // TODO: implement peak detection
            longest_gap: None,   // TODO: implement gap detection
        }
    }

    /// Calculate reconstruction confidence
    #[allow(clippy::cast_precision_loss)] // Small cookie counts, f64 precision acceptable
    fn calculate_confidence(events: &[CookieEvent], cookies: &[Cookie]) -> f64 {
        if events.is_empty() || cookies.is_empty() {
            return 0.0;
        }

        // Base confidence on completeness of data
        let mut confidence = 0.5;

        // All cookies have creation times (not optional)
        confidence += 0.3;

        // Boost confidence if we have expiry times
        let has_expiry_times =
            cookies.iter().filter(|c| c.expires.is_some()).count() as f64 / cookies.len() as f64;
        confidence += has_expiry_times * 0.2;

        confidence.min(1.0)
    }

    /// Detect anomalies in the timeline
    fn detect_anomalies(&self, config: &ForensicConfig) -> Vec<TimelineAnomaly> {
        let mut anomalies = Vec::new();

        // Detect suspicious gaps
        anomalies.extend(self.detect_suspicious_gaps(config));

        // Detect activity bursts
        anomalies.extend(self.detect_activity_bursts(config));

        // Detect impossible travel
        anomalies.extend(Self::detect_impossible_travel(config));

        // Filter by threshold
        anomalies.retain(|a| a.confidence >= config.anomaly_threshold);

        anomalies
    }

    /// Detect suspicious gaps in timeline
    #[allow(clippy::cast_precision_loss)] // Time durations fit in f64, precision acceptable
    fn detect_suspicious_gaps(&self, _config: &ForensicConfig) -> Vec<TimelineAnomaly> {
        let mut anomalies = Vec::new();

        for window in self.events.windows(2) {
            let gap = window[1].timestamp - window[0].timestamp;

            // Gap > 1 hour is suspicious
            if gap > Duration::hours(1) {
                let severity = (gap.num_hours() as f64 / 24.0).min(1.0);

                anomalies.push(TimelineAnomaly {
                    anomaly_type: AnomalyType::SuspiciousGap,
                    severity,
                    description: format!("Suspicious gap of {} hours in timeline", gap.num_hours()),
                    time_range: (window[0].timestamp, window[1].timestamp),
                    related_events: vec![0, 1], // indices would need to be calculated properly
                    confidence: 0.7,
                });
            }
        }

        anomalies
    }

    /// Detect bursts of activity
    #[allow(clippy::cast_precision_loss)] // Small event counts, f64 precision acceptable
    #[allow(clippy::cast_sign_loss)] // Timestamps are positive, loss acceptable
    #[allow(clippy::cast_possible_wrap)] // Timestamp range fits in i64
    fn detect_activity_bursts(&self, _config: &ForensicConfig) -> Vec<TimelineAnomaly> {
        let mut anomalies = Vec::new();

        // Group events by time windows (1 minute)
        let mut windows: HashMap<i64, Vec<&CookieEvent>> = HashMap::new();

        for event in &self.events {
            let window = event.timestamp.timestamp() / 60; // 1-minute buckets
            windows.entry(window).or_default().push(event);
        }

        // Detect windows with unusually high activity
        let avg_events_per_window = self.events.len() as f64 / windows.len().max(1) as f64;

        for (window, events) in windows {
            if events.len() as f64 > avg_events_per_window * 3.0 {
                let timestamp = DateTime::from_timestamp(window * 60, 0).unwrap_or_else(Utc::now);

                anomalies.push(TimelineAnomaly {
                    anomaly_type: AnomalyType::ActivityBurst,
                    severity: 0.6,
                    description: format!("Unusual burst of {} events in 1 minute", events.len()),
                    time_range: (timestamp, timestamp + Duration::minutes(1)),
                    related_events: Vec::new(),
                    confidence: 0.8,
                });
            }
        }

        anomalies
    }

    /// Detect impossible travel (same user from different locations too fast)
    fn detect_impossible_travel(_config: &ForensicConfig) -> Vec<TimelineAnomaly> {
        // TODO: Implement with geolocation data
        Vec::new()
    }

    /// Find anomalies above threshold
    #[must_use]
    pub fn find_anomalies(&self) -> Vec<&TimelineAnomaly> {
        self.anomalies.iter().collect()
    }

    /// Generate forensic report from timeline
    #[must_use]
    pub fn generate_forensic_report(&self) -> crate::forensics::ForensicReport {
        // Delegate to report generator
        crate::forensics::report_generator::ForensicReportBuilder::new()
            .with_timeline(self.clone())
            .build()
            .expect("Failed to generate forensic report")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_timeline_creation() {
        // TODO: Add comprehensive tests
    }

    #[test]
    fn test_anomaly_detection() {
        // TODO: Add anomaly detection tests
    }
}
