//! Google Ad Tech Provider (ATP) List Management
//!
//! This module manages the official Google Ad Tech Provider (ATP) List, which contains
//! information about all Google advertising technology providers that can be referenced
//! in Additional Consent (AC) Strings.
//!
//! # Overview
//!
//! The Google ATP List is published at:
//! `https://storage.googleapis.com/gac/google-atp-list.json`
//!
//! This list contains:
//! - ATP unique IDs (numeric identifiers)
//! - ATP names (company/product names)
//! - ATP domains (associated web domains)
//!
//! # Usage
//!
//! ```no_run
//! # use icookforms::compliance::google_consent::GoogleATPList;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Fetch the latest ATP list from Google
//! let atp_list = GoogleATPList::fetch().await?;
//!
//! // Get a provider by ID
//! if let Some(provider) = atp_list.get_provider(35) {
//!     println!("Provider: {}", provider.name);
//! }
//!
//! // Create an index for fast lookups
//! let index = atp_list.create_index();
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Official Google Ad Tech Provider List
///
/// Contains all registered Google Ad Tech Providers with their IDs, names, and domains.
/// This list is used to validate Additional Consent (AC) String ATP IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleATPList {
    /// List of all registered Ad Tech Providers
    pub providers: Vec<AdTechProvider>,
}

/// Google Ad Tech Provider information
///
/// Represents a single Ad Tech Provider registered with Google.
///
/// # Fields
/// - `id`: Unique numeric identifier for the ATP
/// - `name`: Company or product name
/// - `domains`: List of associated web domains
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdTechProvider {
    /// Unique ATP identifier
    pub id: u16,

    /// Provider name (e.g., `Google Advertising Products`)
    pub name: String,

    /// Associated domains (e.g., `["doubleclick.net", "google.com"]`)
    pub domains: Vec<String>,
}

impl GoogleATPList {
    /// Creates a new empty ATP list
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::GoogleATPList;
    /// let list = GoogleATPList::new();
    /// assert!(list.providers.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Creates an ATP list with provided providers
    ///
    /// # Arguments
    /// * `providers` - Vector of `AdTechProvider` instances
    #[must_use]
    pub fn with_providers(providers: Vec<AdTechProvider>) -> Self {
        Self { providers }
    }

    /// Fetches the latest ATP list from Google's official source
    ///
    /// # Returns
    /// * `Ok(GoogleATPList)` if the fetch succeeds
    /// * `Err(ATPError)` if the fetch fails or the JSON is invalid
    ///
    /// # Examples
    /// ```no_run
    /// # use icookforms::compliance::google_consent::GoogleATPList;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let atp_list = GoogleATPList::fetch().await?;
    /// println!("Fetched {} providers", atp_list.providers.len());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "scanner")]
    pub async fn fetch() -> Result<Self, ATPError> {
        use reqwest;

        const ATP_LIST_URL: &str = "https://storage.googleapis.com/gac/google-atp-list.json";

        let response = reqwest::get(ATP_LIST_URL)
            .await
            .map_err(|e| ATPError::FetchError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ATPError::HttpError(response.status().as_u16()));
        }

        let list: GoogleATPList = response
            .json()
            .await
            .map_err(|e| ATPError::ParseError(e.to_string()))?;

        Ok(list)
    }

    /// Fetches ATP list with a custom timeout
    ///
    /// # Arguments
    /// * `timeout_secs` - Request timeout in seconds
    #[cfg(feature = "scanner")]
    pub async fn fetch_with_timeout(timeout_secs: u64) -> Result<Self, ATPError> {
        use reqwest;
        use std::time::Duration;

        const ATP_LIST_URL: &str = "https://storage.googleapis.com/gac/google-atp-list.json";

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| ATPError::FetchError(e.to_string()))?;

        let response = client
            .get(ATP_LIST_URL)
            .send()
            .await
            .map_err(|e| ATPError::FetchError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ATPError::HttpError(response.status().as_u16()));
        }

        let list: GoogleATPList = response
            .json()
            .await
            .map_err(|e| ATPError::ParseError(e.to_string()))?;

        Ok(list)
    }

    /// Loads ATP list from a JSON string
    ///
    /// Useful for testing or loading cached lists.
    ///
    /// # Arguments
    /// * `json` - JSON string containing the ATP list
    ///
    /// # Returns
    /// * `Ok(GoogleATPList)` if parsing succeeds
    /// * `Err(ATPError)` if the JSON is invalid
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::GoogleATPList;
    /// let json = r#"{"providers": [{"id": 1, "name": "Test", "domains": ["test.com"]}]}"#;
    /// let list = GoogleATPList::from_json(json).unwrap();
    /// assert_eq!(list.providers.len(), 1);
    /// ```
    #[must_use = "JSON parsing failure must be handled"]
    pub fn from_json(json: &str) -> Result<Self, ATPError> {
        serde_json::from_str(json).map_err(|e| ATPError::ParseError(e.to_string()))
    }

    /// Gets a provider by its ID
    ///
    /// # Arguments
    /// * `id` - The ATP ID to search for
    ///
    /// # Returns
    /// * `Some(&AdTechProvider)` if found
    /// * `None` if not found
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::{GoogleATPList, AdTechProvider};
    /// let providers = vec![
    ///     AdTechProvider { id: 1, name: "Test".to_string(), domains: vec![] },
    /// ];
    /// let list = GoogleATPList::with_providers(providers);
    /// assert!(list.get_provider(1).is_some());
    /// assert!(list.get_provider(999).is_none());
    /// ```
    #[must_use]
    pub fn get_provider(&self, id: u16) -> Option<&AdTechProvider> {
        self.providers.iter().find(|p| p.id == id)
    }

    /// Finds a provider by domain
    ///
    /// # Arguments
    /// * `domain` - Domain to search for (e.g., "doubleclick.net")
    ///
    /// # Returns
    /// Vector of providers that include this domain
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::{GoogleATPList, AdTechProvider};
    /// let providers = vec![
    ///     AdTechProvider {
    ///         id: 1,
    ///         name: "Test".to_string(),
    ///         domains: vec!["test.com".to_string()],
    ///     },
    /// ];
    /// let list = GoogleATPList::with_providers(providers);
    /// let found = list.find_by_domain("test.com");
    /// assert_eq!(found.len(), 1);
    /// ```
    #[must_use]
    pub fn find_by_domain(&self, domain: &str) -> Vec<&AdTechProvider> {
        self.providers
            .iter()
            .filter(|p| p.domains.iter().any(|d| d == domain))
            .collect()
    }

    /// Creates a `HashMap` index for fast ID lookups
    ///
    /// # Returns
    /// `HashMap` mapping ATP IDs to providers
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::{GoogleATPList, AdTechProvider};
    /// let providers = vec![
    ///     AdTechProvider { id: 1, name: "Test".to_string(), domains: vec![] },
    /// ];
    /// let list = GoogleATPList::with_providers(providers);
    /// let index = list.create_index();
    /// assert!(index.contains_key(&1));
    /// ```
    #[must_use]
    pub fn create_index(&self) -> HashMap<u16, &AdTechProvider> {
        self.providers.iter().map(|p| (p.id, p)).collect()
    }

    /// Creates a domain-to-provider index
    ///
    /// # Returns
    /// `HashMap` mapping domains to vectors of providers
    #[must_use]
    pub fn create_domain_index(&self) -> HashMap<String, Vec<&AdTechProvider>> {
        let mut index: HashMap<String, Vec<&AdTechProvider>> = HashMap::new();

        for provider in &self.providers {
            for domain in &provider.domains {
                index.entry(domain.clone()).or_default().push(provider);
            }
        }

        index
    }

    /// Returns all ATP IDs in the list
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::{GoogleATPList, AdTechProvider};
    /// let providers = vec![
    ///     AdTechProvider { id: 1, name: "Test1".to_string(), domains: vec![] },
    ///     AdTechProvider { id: 35, name: "Test35".to_string(), domains: vec![] },
    /// ];
    /// let list = GoogleATPList::with_providers(providers);
    /// assert_eq!(list.all_ids(), vec![1, 35]);
    /// ```
    #[must_use]
    pub fn all_ids(&self) -> Vec<u16> {
        self.providers.iter().map(|p| p.id).collect()
    }

    /// Returns the number of providers in the list
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Checks if the list is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Validates if an ATP ID exists in the list
    ///
    /// # Arguments
    /// * `id` - ATP ID to validate
    ///
    /// # Returns
    /// `true` if the ID exists, `false` otherwise
    #[must_use]
    pub fn is_valid_id(&self, id: u16) -> bool {
        self.get_provider(id).is_some()
    }
}

impl Default for GoogleATPList {
    fn default() -> Self {
        Self::new()
    }
}

impl AdTechProvider {
    /// Creates a new Ad Tech Provider
    ///
    /// # Arguments
    /// * `id` - Unique ATP identifier
    /// * `name` - Provider name
    /// * `domains` - Associated domains
    #[must_use]
    pub fn new(id: u16, name: String, domains: Vec<String>) -> Self {
        Self { id, name, domains }
    }

    /// Checks if this provider is associated with a specific domain
    #[must_use]
    pub fn has_domain(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| d == domain)
    }
}

/// Error type for ATP list operations
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ATPError {
    /// Failed to fetch the ATP list from Google
    #[error("Failed to fetch ATP list: {0}")]
    FetchError(String),

    /// HTTP error when fetching the list
    #[error("HTTP error {0} when fetching ATP list")]
    HttpError(u16),

    /// Failed to parse the ATP list JSON
    #[error("Failed to parse ATP list: {0}")]
    ParseError(String),

    /// ATP ID not found in the list
    #[error("ATP ID {0} not found in the list")]
    AtpNotFound(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Test Helper Functions
    // ========================================================================

    fn create_test_providers() -> Vec<AdTechProvider> {
        vec![
            AdTechProvider {
                id: 1,
                name: "Google Advertising Products".to_string(),
                domains: vec!["doubleclick.net".to_string(), "google.com".to_string()],
            },
            AdTechProvider {
                id: 35,
                name: "Google Analytics".to_string(),
                domains: vec!["google-analytics.com".to_string()],
            },
            AdTechProvider {
                id: 41,
                name: "YouTube".to_string(),
                domains: vec!["youtube.com".to_string(), "googlevideo.com".to_string()],
            },
            AdTechProvider {
                id: 101,
                name: "DoubleClick".to_string(),
                domains: vec!["doubleclick.net".to_string()],
            },
        ]
    }

    fn create_test_list() -> GoogleATPList {
        GoogleATPList::with_providers(create_test_providers())
    }

    // ========================================================================
    // GoogleATPList Creation Tests
    // ========================================================================

    #[test]
    fn test_new_empty_list() {
        let list = GoogleATPList::new();
        assert!(list.providers.is_empty());
        assert_eq!(list.len(), 0);
        assert!(list.is_empty());
    }

    #[test]
    fn test_with_providers() {
        let providers = create_test_providers();
        let list = GoogleATPList::with_providers(providers);
        assert_eq!(list.len(), 4);
        assert!(!list.is_empty());
    }

    // ========================================================================
    // Provider Lookup Tests
    // ========================================================================

    #[test]
    fn test_get_provider_found() {
        let list = create_test_list();
        let provider = list.get_provider(35).unwrap();
        assert_eq!(provider.id, 35);
        assert_eq!(provider.name, "Google Analytics");
    }

    #[test]
    fn test_get_provider_not_found() {
        let list = create_test_list();
        assert!(list.get_provider(999).is_none());
    }

    #[test]
    fn test_is_valid_id() {
        let list = create_test_list();
        assert!(list.is_valid_id(1));
        assert!(list.is_valid_id(35));
        assert!(list.is_valid_id(41));
        assert!(!list.is_valid_id(999));
    }

    // ========================================================================
    // Domain Lookup Tests
    // ========================================================================

    #[test]
    fn test_find_by_domain_single() {
        let list = create_test_list();
        let found = list.find_by_domain("google-analytics.com");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, 35);
    }

    #[test]
    fn test_find_by_domain_multiple() {
        let list = create_test_list();
        let found = list.find_by_domain("doubleclick.net");
        assert_eq!(found.len(), 2); // IDs 1 and 101
        let ids: Vec<u16> = found.iter().map(|p| p.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&101));
    }

    #[test]
    fn test_find_by_domain_not_found() {
        let list = create_test_list();
        let found = list.find_by_domain("unknown.com");
        assert!(found.is_empty());
    }

    // ========================================================================
    // Index Creation Tests
    // ========================================================================

    #[test]
    fn test_create_index() {
        let list = create_test_list();
        let index = list.create_index();

        assert_eq!(index.len(), 4);
        assert!(index.contains_key(&1));
        assert!(index.contains_key(&35));
        assert!(index.contains_key(&41));
        assert!(index.contains_key(&101));

        let provider = index.get(&35).unwrap();
        assert_eq!(provider.name, "Google Analytics");
    }

    #[test]
    fn test_create_domain_index() {
        let list = create_test_list();
        let index = list.create_domain_index();

        assert!(index.contains_key("doubleclick.net"));
        assert!(index.contains_key("google-analytics.com"));

        let providers = index.get("doubleclick.net").unwrap();
        assert_eq!(providers.len(), 2);
    }

    // ========================================================================
    // Utility Methods Tests
    // ========================================================================

    #[test]
    fn test_all_ids() {
        let list = create_test_list();
        let ids = list.all_ids();
        assert_eq!(ids, vec![1, 35, 41, 101]);
    }

    #[test]
    fn test_len_and_is_empty() {
        let empty_list = GoogleATPList::new();
        assert_eq!(empty_list.len(), 0);
        assert!(empty_list.is_empty());

        let list = create_test_list();
        assert_eq!(list.len(), 4);
        assert!(!list.is_empty());
    }

    // ========================================================================
    // JSON Parsing Tests
    // ========================================================================

    #[test]
    fn test_from_json_valid() {
        let json = r#"{
            "providers": [
                {
                    "id": 1,
                    "name": "Test Provider",
                    "domains": ["test.com"]
                }
            ]
        }"#;

        let list = GoogleATPList::from_json(json).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list.providers[0].id, 1);
        assert_eq!(list.providers[0].name, "Test Provider");
    }

    #[test]
    fn test_from_json_invalid() {
        let json = r#"{"invalid": "json"}"#;
        let result = GoogleATPList::from_json(json);
        assert!(matches!(result, Err(ATPError::ParseError(_))));
    }

    // ========================================================================
    // AdTechProvider Tests
    // ========================================================================

    #[test]
    fn test_provider_new() {
        let provider = AdTechProvider::new(1, "Test".to_string(), vec!["test.com".to_string()]);
        assert_eq!(provider.id, 1);
        assert_eq!(provider.name, "Test");
        assert_eq!(provider.domains.len(), 1);
    }

    #[test]
    fn test_provider_has_domain() {
        let provider = AdTechProvider {
            id: 1,
            name: "Test".to_string(),
            domains: vec!["test.com".to_string(), "example.com".to_string()],
        };

        assert!(provider.has_domain("test.com"));
        assert!(provider.has_domain("example.com"));
        assert!(!provider.has_domain("other.com"));
    }
}
