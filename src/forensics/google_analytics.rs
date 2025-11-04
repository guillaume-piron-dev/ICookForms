//! # Google Analytics Cookie Forensics
//!
//! Forensic analysis of Google Analytics cookies to extract user journey,
//! search terms, campaign information, and page views.
//!
//! ## Cookies Analyzed
//!
//! - `_ga`: Main Google Analytics ID
//! - `_gid`: Session ID
//! - `_gat`: Throttling
//! - `_gac`: Campaign info
//! - `__utma`, `__utmb`, `__utmc`, `__utmz`: Legacy GA
//!
//! ## Use Cases
//!
//! - Reconstruct user journey through website
//! - Extract search terms that led to site
//! - Identify campaign sources
//! - Timeline analysis of page views

use crate::types::{Cookie, Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Decoded Google Analytics cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleAnalyticsCookie {
    /// Client ID (unique user identifier)
    pub client_id: String,

    /// Session ID
    pub session_id: Option<String>,

    /// Campaign information
    pub campaign_info: Option<CampaignInfo>,

    /// Referrer URL
    pub referrer: Option<String>,

    /// Search terms
    pub search_terms: Option<Vec<String>>,

    /// Page views recorded
    pub page_views: Vec<PageView>,

    /// First visit timestamp
    pub first_visit: Option<DateTime<Utc>>,

    /// Last visit timestamp
    pub last_visit: Option<DateTime<Utc>>,

    /// Number of sessions
    pub session_count: u32,
}

/// Campaign information from GA cookies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignInfo {
    /// Campaign source (e.g., "google", "newsletter")
    pub source: String,

    /// Campaign medium (e.g., "cpc", "email")
    pub medium: String,

    /// Campaign name
    pub name: Option<String>,

    /// Campaign term (keywords)
    pub term: Option<String>,

    /// Campaign content
    pub content: Option<String>,
}

/// Individual page view
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageView {
    /// Page URL
    pub url: String,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Time spent on page (seconds)
    pub time_on_page: Option<u32>,
}

/// User journey through website
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserJourney {
    /// Chronological page views
    pub pages: Vec<PageView>,

    /// Entry point
    pub entry_page: Option<String>,

    /// Exit page
    pub exit_page: Option<String>,

    /// Total session duration
    pub total_duration: u32,

    /// Bounce (single page visit)
    pub is_bounce: bool,
}

impl GoogleAnalyticsCookie {
    /// Decode Google Analytics cookie
    pub fn decode(cookie: &Cookie) -> Result<Self> {
        match cookie.name.as_str() {
            "_ga" => Self::decode_ga_cookie(cookie),
            "_gid" => Self::decode_gid_cookie(cookie),
            "__utma" => Self::decode_utma_cookie(cookie),
            "__utmz" => Self::decode_utmz_cookie(cookie),
            _ => Err(Error::ForensicError(format!(
                "Not a recognized GA cookie: {}",
                cookie.name
            ))),
        }
    }

    /// Decode _ga cookie (main GA identifier)
    ///
    /// Format: GA1.2.XXXXXXXXXX.YYYYYYYYYY
    /// - GA1 = version
    /// - 2 = domain depth
    /// - XXXXXXXXXX = random client ID part 1
    /// - YYYYYYYYYY = timestamp of first visit
    fn decode_ga_cookie(cookie: &Cookie) -> Result<Self> {
        let parts: Vec<&str> = cookie.value.split('.').collect();

        if parts.len() < 4 {
            return Err(Error::ForensicError(
                "Invalid _ga cookie format".to_string(),
            ));
        }

        let client_id = format!("{}.{}", parts[2], parts[3]);

        // Parse first visit timestamp
        let first_visit_ts = parts[3]
            .parse::<i64>()
            .ok()
            .and_then(|ts| DateTime::from_timestamp(ts, 0));

        Ok(Self {
            client_id,
            session_id: None,
            campaign_info: None,
            referrer: None,
            search_terms: None,
            page_views: Vec::new(),
            first_visit: first_visit_ts,
            last_visit: Some(cookie.created_at),
            session_count: 1,
        })
    }

    /// Decode _gid cookie (session identifier)
    ///
    /// Format: GA1.2.XXXXXXXXXX.YYYYYYYYYY
    /// Similar to _ga but for current session
    fn decode_gid_cookie(cookie: &Cookie) -> Result<Self> {
        let parts: Vec<&str> = cookie.value.split('.').collect();

        if parts.len() < 4 {
            return Err(Error::ForensicError(
                "Invalid _gid cookie format".to_string(),
            ));
        }

        let session_id = format!("{}.{}", parts[2], parts[3]);

        Ok(Self {
            client_id: String::new(),
            session_id: Some(session_id),
            campaign_info: None,
            referrer: None,
            search_terms: None,
            page_views: Vec::new(),
            first_visit: None,
            last_visit: Some(cookie.created_at),
            session_count: 1,
        })
    }

    /// Decode legacy __utma cookie
    ///
    /// Format: DOMAINID.USERID.FIRSTVISIT.PREVIOUSVISIT.CURRENTVISIT.SESSIONCOUNT
    fn decode_utma_cookie(cookie: &Cookie) -> Result<Self> {
        let parts: Vec<&str> = cookie.value.split('.').collect();

        if parts.len() < 6 {
            return Err(Error::ForensicError(
                "Invalid __utma cookie format".to_string(),
            ));
        }

        let client_id = parts[1].to_string();
        let session_count = parts[5].parse().unwrap_or(1);

        let first_visit = parts[2]
            .parse::<i64>()
            .ok()
            .and_then(|ts| DateTime::from_timestamp(ts, 0));
        let last_visit = parts[4]
            .parse::<i64>()
            .ok()
            .and_then(|ts| DateTime::from_timestamp(ts, 0));

        Ok(Self {
            client_id,
            session_id: None,
            campaign_info: None,
            referrer: None,
            search_terms: None,
            page_views: Vec::new(),
            first_visit,
            last_visit,
            session_count,
        })
    }

    /// Decode legacy __utmz cookie (campaign tracking)
    ///
    /// Format: DOMAINID.TIMESTAMP.SESSIONCOUNT.CAMPAIGNCOUNT.utmcsr=SOURCE|utmccn=CAMPAIGN|...
    fn decode_utmz_cookie(cookie: &Cookie) -> Result<Self> {
        let parts: Vec<&str> = cookie.value.split('.').collect();

        if parts.len() < 4 {
            return Err(Error::ForensicError(
                "Invalid __utmz cookie format".to_string(),
            ));
        }

        // Parse campaign parameters
        let campaign_part = parts.get(4..).map(|p| p.join(".")).unwrap_or_default();
        let campaign_info = Self::parse_campaign_params(&campaign_part);

        Ok(Self {
            client_id: String::new(),
            session_id: None,
            campaign_info,
            referrer: None,
            search_terms: None,
            page_views: Vec::new(),
            first_visit: None,
            last_visit: Some(cookie.created_at),
            session_count: parts[2].parse().unwrap_or(1),
        })
    }

    /// Parse campaign parameters from __utmz
    fn parse_campaign_params(params: &str) -> Option<CampaignInfo> {
        let mut map: HashMap<String, String> = HashMap::new();

        for pair in params.split('|') {
            if let Some((key, value)) = pair.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }

        let source = map.get("utmcsr")?.clone();
        let medium = map.get("utmcmd")?.clone();

        Some(CampaignInfo {
            source,
            medium,
            name: map.get("utmccn").cloned(),
            term: map.get("utmctr").cloned(),
            content: map.get("utmcct").cloned(),
        })
    }

    /// Extract search terms that led to the site
    #[must_use]
    pub fn extract_search_terms(&self) -> Vec<String> {
        let mut terms = Vec::new();

        // From campaign info
        if let Some(ref campaign) = self.campaign_info {
            if let Some(ref term) = campaign.term {
                terms.push(term.clone());
            }
        }

        // From stored search terms
        if let Some(ref stored) = self.search_terms {
            terms.extend(stored.clone());
        }

        terms
    }

    /// Reconstruct user journey from GA data
    #[must_use]
    pub fn reconstruct_user_journey(&self) -> UserJourney {
        let pages = self.page_views.clone();
        let entry_page = pages.first().map(|p| p.url.clone());
        let exit_page = pages.last().map(|p| p.url.clone());

        let total_duration = pages.iter().filter_map(|p| p.time_on_page).sum();

        let is_bounce = pages.len() == 1;

        UserJourney {
            pages,
            entry_page,
            exit_page,
            total_duration,
            is_bounce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ga_cookie() {
        let cookie = Cookie {
            name: "_ga".to_string(),
            value: "GA1.2.1234567890.1609459200".to_string(),
            domain: Some("example.com".to_string()),
            ..Default::default()
        };

        let ga = GoogleAnalyticsCookie::decode(&cookie).unwrap();
        assert_eq!(ga.client_id, "1234567890.1609459200");
    }

    #[test]
    fn test_campaign_parsing() {
        let params = "utmcsr=google|utmccn=cpc|utmcmd=organic|utmctr=cookies";
        let campaign = GoogleAnalyticsCookie::parse_campaign_params(params).unwrap();

        assert_eq!(campaign.source, "google");
        assert_eq!(campaign.medium, "organic");
        assert_eq!(campaign.term, Some("cookies".to_string()));
    }
}
