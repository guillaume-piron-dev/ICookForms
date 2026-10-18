//! Global Vendor List (GVL) implementation for IAB TCF 2.2
//!
//! The Global Vendor List is a JSON file maintained by IAB Europe that contains
//! information about all registered TCF vendors, including their purposes,
//! features, and legal bases.
//!
//! # Usage
//!
//! ```rust,no_run
//! use icookforms::compliance::iab_tcf::GlobalVendorList;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Fetch the latest GVL
//!     let gvl = GlobalVendorList::fetch_latest().await?;
//!     
//!     // Check vendor information
//!     if let Some(vendor) = gvl.get_vendor(35) {
//!         println!("Vendor: {}", vendor.name);
//!         println!("Purposes: {:?}", vendor.purposes);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # GVL Endpoints
//!
//! - Latest: `https://vendor-list.consensu.org/v2/vendor-list.json`
//! - Version: `https://vendor-list.consensu.org/v2/archives/vendor-list-v{VERSION}.json`
//!
//! Reference: IAB TCF v2.2 Specification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{Error, Result};

/// The Global Vendor List containing all registered TCF vendors
///
/// The GVL is updated regularly by IAB Europe and contains:
/// - Purposes and special purposes
/// - Features and special features
/// - All registered vendors with their declarations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalVendorList {
    /// GVL specification version (should be 2 for TCF v2.x)
    pub gvl_specification_version: u8,

    /// Vendor list version number
    pub vendor_list_version: u16,

    /// TCF policy version
    pub tcf_policy_version: u8,

    /// Last updated timestamp (ISO 8601 format)
    pub last_updated: String,

    /// Standard purposes (1-24)
    pub purposes: HashMap<u8, Purpose>,

    /// Special purposes (1-2)
    pub special_purposes: HashMap<u8, SpecialPurpose>,

    /// Features (1-3)
    pub features: HashMap<u8, Feature>,

    /// Special features (1-2)
    pub special_features: HashMap<u8, SpecialFeature>,

    /// All registered vendors
    pub vendors: HashMap<u16, Vendor>,
}

/// A standard TCF purpose
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Purpose {
    /// Purpose ID (1-24)
    pub id: u8,

    /// Purpose name
    pub name: String,

    /// User-friendly description
    pub description: String,

    /// Legal description
    pub description_legal: String,

    /// Whether this purpose requires user consent
    pub consentable: bool,

    /// Whether users have the right to object
    pub right_to_object: bool,
}

/// A special TCF purpose (cannot be objected to)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecialPurpose {
    /// Special purpose ID (1-2)
    pub id: u8,

    /// Special purpose name
    pub name: String,

    /// User-friendly description
    pub description: String,

    /// Legal description
    pub description_legal: String,
}

/// A standard TCF feature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Feature {
    /// Feature ID (1-3)
    pub id: u8,

    /// Feature name
    pub name: String,

    /// User-friendly description
    pub description: String,

    /// Legal description
    pub description_legal: String,
}

/// A special TCF feature (requires explicit user opt-in)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecialFeature {
    /// Special feature ID (1-2)
    pub id: u8,

    /// Special feature name
    pub name: String,

    /// User-friendly description
    pub description: String,

    /// Legal description
    pub description_legal: String,
}

/// A registered TCF vendor
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vendor {
    /// Vendor ID (unique)
    pub id: u16,

    /// Vendor name
    pub name: String,

    /// Purposes for which vendor requires consent
    pub purposes: Vec<u8>,

    /// Special purposes vendor uses
    pub special_purposes: Vec<u8>,

    /// Purposes for which vendor has legitimate interest
    pub leg_int_purposes: Vec<u8>,

    /// Purposes that can use either consent or legitimate interest
    pub flexible_purposes: Vec<u8>,

    /// Features vendor uses
    pub features: Vec<u8>,

    /// Special features vendor uses
    pub special_features: Vec<u8>,

    /// URL to vendor's privacy policy
    pub policy_url: String,

    /// Date vendor was deleted from GVL (if applicable)
    pub deleted_date: Option<String>,

    /// Overflow configuration
    #[serde(default)]
    pub overflow: Option<Overflow>,

    /// Maximum cookie age in seconds
    #[serde(default)]
    pub cookie_max_age_seconds: Option<u64>,

    /// Whether cookies are refreshed on each page load
    #[serde(default)]
    pub cookie_refresh: Option<bool>,

    /// Whether vendor uses cookies
    pub uses_cookies: bool,

    /// Whether vendor uses non-cookie access
    pub uses_non_cookie_access: bool,

    /// Data categories vendor collects
    pub data_declaration: Vec<u8>,

    /// Data retention periods per purpose
    #[serde(default)]
    pub data_retention: Option<DataRetention>,

    /// Standard retention period (TCF v2.2+)
    #[serde(default)]
    pub std_retention: Option<u16>,

    /// Localized URLs
    pub urls: Vec<VendorUrl>,
}

/// Vendor overflow configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overflow {
    /// HTTP GET limit for vendor
    pub http_get_limit: u16,
}

/// Data retention configuration per purpose
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRetention {
    /// Retention periods for standard purposes (purpose ID -> days)
    pub purposes: HashMap<u8, u16>,

    /// Retention periods for special purposes (purpose ID -> days)
    pub special_purposes: HashMap<u8, u16>,
}

/// Localized vendor URLs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorUrl {
    /// Language ID (ISO 639-1)
    pub lang_id: String,

    /// Privacy policy URL for this language
    pub privacy: String,

    /// Legitimate interest claim URL (optional)
    #[serde(default)]
    pub leg_int_claim: Option<String>,
}

impl GlobalVendorList {
    /// Base URL for GVL endpoints
    const BASE_URL: &'static str = "https://vendor-list.consensu.org/v2";

    /// Fetches the latest Global Vendor List from IAB
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network request fails
    /// - JSON parsing fails
    /// - Invalid GVL format
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use icookforms::compliance::iab_tcf::GlobalVendorList;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let gvl = GlobalVendorList::fetch_latest().await?;
    /// println!("GVL version: {}", gvl.vendor_list_version);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_latest() -> Result<Self> {
        let url = format!("{}/vendor-list.json", Self::BASE_URL);
        Self::fetch_from_url(&url).await
    }

    /// Fetches a specific version of the Global Vendor List
    ///
    /// # Arguments
    ///
    /// * `version` - The GVL version number to fetch
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use icookforms::compliance::iab_tcf::GlobalVendorList;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let gvl = GlobalVendorList::fetch_version(200).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_version(version: u16) -> Result<Self> {
        let url = format!("{}/archives/vendor-list-v{}.json", Self::BASE_URL, version);
        Self::fetch_from_url(&url).await
    }

    /// Internal method to fetch GVL from a URL
    async fn fetch_from_url(url: &str) -> Result<Self> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| Error::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::GVLFetchError(response.status().as_u16()));
        }

        let gvl: GlobalVendorList = response
            .json()
            .await
            .map_err(|e| Error::GVLParseError(e.to_string()))?;

        Ok(gvl)
    }

    /// Parses a GVL from JSON string
    ///
    /// # Arguments
    ///
    /// * `json` - JSON string containing the GVL
    ///
    /// # Example
    ///
    /// ```rust
    /// # use icookforms::compliance::iab_tcf::GlobalVendorList;
    /// let json = r#"{"gvlSpecificationVersion":2,"vendorListVersion":1,"tcfPolicyVersion":2,"lastUpdated":"2024-01-01T00:00:00Z","purposes":{},"specialPurposes":{},"features":{},"specialFeatures":{},"vendors":{}}"#;
    /// let gvl = GlobalVendorList::from_json(json)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::GVLParseError(e.to_string()))
    }

    /// Serializes the GVL to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Serializes the GVL to pretty-printed JSON
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Gets a vendor by ID
    ///
    /// # Example
    ///
    /// ```rust
    /// # use icookforms::compliance::iab_tcf::GlobalVendorList;
    /// # let gvl = GlobalVendorList::from_json(r#"{"gvlSpecificationVersion":2,"vendorListVersion":1,"tcfPolicyVersion":2,"lastUpdated":"2024-01-01T00:00:00Z","purposes":{},"specialPurposes":{},"features":{},"specialFeatures":{},"vendors":{}}"#)?;
    /// if let Some(vendor) = gvl.get_vendor(35) {
    ///     println!("Found vendor: {}", vendor.name);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn get_vendor(&self, vendor_id: u16) -> Option<&Vendor> {
        self.vendors.get(&vendor_id)
    }

    /// Checks if a vendor exists in the GVL
    #[must_use]
    pub fn has_vendor(&self, vendor_id: u16) -> bool {
        self.vendors.contains_key(&vendor_id)
    }

    /// Gets all active vendors (not deleted)
    #[must_use]
    pub fn get_active_vendors(&self) -> Vec<&Vendor> {
        self.vendors
            .values()
            .filter(|v| v.deleted_date.is_none())
            .collect()
    }

    /// Gets all vendor IDs
    #[must_use]
    pub fn get_vendor_ids(&self) -> Vec<u16> {
        self.vendors.keys().copied().collect()
    }

    /// Gets a purpose by ID
    #[must_use]
    pub fn get_purpose(&self, purpose_id: u8) -> Option<&Purpose> {
        self.purposes.get(&purpose_id)
    }

    /// Gets a special purpose by ID
    #[must_use]
    pub fn get_special_purpose(&self, purpose_id: u8) -> Option<&SpecialPurpose> {
        self.special_purposes.get(&purpose_id)
    }

    /// Gets a feature by ID
    #[must_use]
    pub fn get_feature(&self, feature_id: u8) -> Option<&Feature> {
        self.features.get(&feature_id)
    }

    /// Gets a special feature by ID
    #[must_use]
    pub fn get_special_feature(&self, feature_id: u8) -> Option<&SpecialFeature> {
        self.special_features.get(&feature_id)
    }

    /// Validates vendor IDs against the GVL
    ///
    /// Returns a list of unknown vendor IDs
    #[must_use]
    pub fn validate_vendor_ids(&self, vendor_ids: &[u16]) -> Vec<u16> {
        vendor_ids
            .iter()
            .filter(|&&id| !self.has_vendor(id))
            .copied()
            .collect()
    }
}

impl Vendor {
    /// Checks if vendor requires consent for a purpose
    #[must_use]
    pub fn requires_consent(&self, purpose_id: u8) -> bool {
        self.purposes.contains(&purpose_id)
    }

    /// Checks if vendor uses legitimate interest for a purpose
    #[must_use]
    pub fn uses_legitimate_interest(&self, purpose_id: u8) -> bool {
        self.leg_int_purposes.contains(&purpose_id)
    }

    /// Checks if vendor uses a special purpose
    #[must_use]
    pub fn uses_special_purpose(&self, purpose_id: u8) -> bool {
        self.special_purposes.contains(&purpose_id)
    }

    /// Checks if vendor can use either consent or LI for a purpose
    #[must_use]
    pub fn is_flexible_purpose(&self, purpose_id: u8) -> bool {
        self.flexible_purposes.contains(&purpose_id)
    }

    /// Checks if vendor is deleted
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.deleted_date.is_some()
    }

    /// Gets the privacy policy URL for a specific language
    #[must_use]
    pub fn get_privacy_url(&self, lang: &str) -> Option<&str> {
        self.urls
            .iter()
            .find(|u| u.lang_id.eq_ignore_ascii_case(lang))
            .map(|u| u.privacy.as_str())
            .or(Some(self.policy_url.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_gvl() -> GlobalVendorList {
        let mut vendors = HashMap::new();
        vendors.insert(
            1,
            Vendor {
                id: 1,
                name: "Test Vendor 1".to_string(),
                purposes: vec![1, 2, 3],
                special_purposes: vec![1],
                leg_int_purposes: vec![7, 8],
                flexible_purposes: vec![2],
                features: vec![1],
                special_features: vec![],
                policy_url: "https://example.com/privacy".to_string(),
                deleted_date: None,
                overflow: None,
                cookie_max_age_seconds: Some(31_536_000),
                cookie_refresh: Some(true),
                uses_cookies: true,
                uses_non_cookie_access: false,
                data_declaration: vec![1, 2, 3],
                data_retention: None,
                std_retention: Some(180),
                urls: vec![VendorUrl {
                    lang_id: "en".to_string(),
                    privacy: "https://example.com/en/privacy".to_string(),
                    leg_int_claim: None,
                }],
            },
        );

        GlobalVendorList {
            gvl_specification_version: 2,
            vendor_list_version: 1,
            tcf_policy_version: 2,
            last_updated: "2024-01-01T00:00:00Z".to_string(),
            purposes: HashMap::new(),
            special_purposes: HashMap::new(),
            features: HashMap::new(),
            special_features: HashMap::new(),
            vendors,
        }
    }

    #[test]
    fn test_gvl_creation() {
        let gvl = create_test_gvl();

        assert_eq!(gvl.gvl_specification_version, 2);
        assert_eq!(gvl.vendor_list_version, 1);
        assert_eq!(gvl.vendors.len(), 1);
    }

    #[test]
    fn test_get_vendor() {
        let gvl = create_test_gvl();

        let vendor = gvl.get_vendor(1);
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().name, "Test Vendor 1");

        let vendor = gvl.get_vendor(999);
        assert!(vendor.is_none());
    }

    #[test]
    fn test_has_vendor() {
        let gvl = create_test_gvl();

        assert!(gvl.has_vendor(1));
        assert!(!gvl.has_vendor(999));
    }

    #[test]
    fn test_get_active_vendors() {
        let gvl = create_test_gvl();
        let active = gvl.get_active_vendors();

        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_validate_vendor_ids() {
        let gvl = create_test_gvl();

        let valid = vec![1];
        let unknown = gvl.validate_vendor_ids(&valid);
        assert!(unknown.is_empty());

        let invalid = vec![1, 999, 1000];
        let unknown = gvl.validate_vendor_ids(&invalid);
        assert_eq!(unknown.len(), 2);
        assert!(unknown.contains(&999));
        assert!(unknown.contains(&1000));
    }

    #[test]
    fn test_vendor_requires_consent() {
        let gvl = create_test_gvl();
        let vendor = gvl.get_vendor(1).unwrap();

        assert!(vendor.requires_consent(1));
        assert!(vendor.requires_consent(2));
        assert!(!vendor.requires_consent(4));
    }

    #[test]
    fn test_vendor_uses_legitimate_interest() {
        let gvl = create_test_gvl();
        let vendor = gvl.get_vendor(1).unwrap();

        assert!(vendor.uses_legitimate_interest(7));
        assert!(vendor.uses_legitimate_interest(8));
        assert!(!vendor.uses_legitimate_interest(1));
    }

    #[test]
    fn test_vendor_special_purpose() {
        let gvl = create_test_gvl();
        let vendor = gvl.get_vendor(1).unwrap();

        assert!(vendor.uses_special_purpose(1));
        assert!(!vendor.uses_special_purpose(2));
    }

    #[test]
    fn test_vendor_flexible_purpose() {
        let gvl = create_test_gvl();
        let vendor = gvl.get_vendor(1).unwrap();

        assert!(vendor.is_flexible_purpose(2));
        assert!(!vendor.is_flexible_purpose(1));
    }

    #[test]
    fn test_vendor_privacy_url() {
        let gvl = create_test_gvl();
        let vendor = gvl.get_vendor(1).unwrap();

        let url = vendor.get_privacy_url("en");
        assert!(url.is_some());
        assert_eq!(url.unwrap(), "https://example.com/en/privacy");

        let url = vendor.get_privacy_url("fr");
        assert!(url.is_some());
        assert_eq!(url.unwrap(), "https://example.com/privacy"); // Fallback
    }

    #[test]
    fn test_json_serialization() -> Result<()> {
        let gvl = create_test_gvl();

        let json = gvl.to_json()?;
        let parsed = GlobalVendorList::from_json(&json)?;

        assert_eq!(gvl.vendor_list_version, parsed.vendor_list_version);
        assert_eq!(gvl.vendors.len(), parsed.vendors.len());

        Ok(())
    }
}
