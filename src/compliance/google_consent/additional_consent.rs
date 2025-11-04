//! Google Additional Consent Mode Implementation
//!
//! This module implements parsing, encoding, and validation for Google's Additional Consent (AC) String.
//! Additional Consent is a technical complement to IAB TCF v2.2 for managing Google Ad Tech Providers (ATPs)
//! that are not registered in the IAB Global Vendor List.
//!
//! # Overview
//!
//! Google's Additional Consent Mode manages consent for Google Ad Tech Providers (ATPs) that are
//! not included in the IAB Transparency & Consent Framework (TCF) Global Vendor List (GVL).
//!
//! # AC String Format
//!
//! ## Version 1 (Obsolete)
//! ```text
//! 1~<consented_atp_ids>
//! ```
//! Example: `1~1.35.41.101`
//!
//! ## Version 2 (Current, since December 2023)
//! ```text
//! 2~<consented_atp_ids>~dv.<disclosed_atp_ids>
//! ```
//! Example: `2~1.35.41.101~dv.9.21.81`
//!
//! # ATP IDs
//!
//! ATP IDs are unique identifiers for Google Ad Tech Providers.
//! The official list is published at: `https://storage.googleapis.com/gac/google-atp-list.json`
//!
//! # Specification
//!
//! - **Part 1**: Version number (1 or 2)
//! - **Part 2**: Dot-separated list of consented ATP IDs (can be empty)
//! - **Part 3**: (v2 only) Dot-separated list of disclosed ATP IDs prefixed with "dv."
//!
//! # Examples
//!
//! ```text
//! 2~1.35.41.101.250~dv.9.21.81.200
//! → Version 2
//! → Consented ATPs: 1, 35, 41, 101, 250
//! → Disclosed ATPs: 9, 21, 81, 200
//!
//! 2~~dv.1.35.41.101.250.9.21.81.200
//! → Version 2
//! → No consented ATPs
//! → All ATPs disclosed: 1, 35, 41, 101, 250, 9, 21, 81, 200
//!
//! 2~1.35~dv.41.101
//! → Version 2
//! → Consented ATPs: 1, 35
//! → Disclosed ATPs: 41, 101
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Additional Consent (AC) String structure
///
/// Represents the consent status for Google Ad Tech Providers (ATPs).
/// This structure is used to parse and encode the AC String found in cookies or URL parameters.
///
/// # Fields
///
/// - `version`: AC String version (1 or 2)
/// - `consented_atps`: List of ATP IDs with explicit user consent
/// - `disclosed_atps`: List of ATP IDs that were disclosed but not consented (v2 only)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ACString {
    /// AC String version
    /// - Version 1: Only consented ATPs (obsolete)
    /// - Version 2: Consented + Disclosed ATPs (current)
    pub version: u8,

    /// List of ATP IDs that have explicit user consent
    pub consented_atps: Vec<u16>,

    /// List of ATP IDs that were disclosed to the user but not consented
    /// Only used in version 2
    pub disclosed_atps: Vec<u16>,
}

impl ACString {
    /// Creates a new empty Additional Consent string with version 2
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ACString;
    /// let ac_string = ACString::new();
    /// assert_eq!(ac_string.version, 2);
    /// assert!(ac_string.consented_atps.is_empty());
    /// assert!(ac_string.disclosed_atps.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 2,
            consented_atps: Vec::new(),
            disclosed_atps: Vec::new(),
        }
    }

    /// Creates a new AC String version 2 with specified ATPs
    ///
    /// # Arguments
    /// * `consented` - List of consented ATP IDs
    /// * `disclosed` - List of disclosed ATP IDs
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ACString;
    /// let ac_string = ACString::with_atps(vec![1, 35], vec![41, 101]);
    /// assert_eq!(ac_string.consented_atps, vec![1, 35]);
    /// assert_eq!(ac_string.disclosed_atps, vec![41, 101]);
    /// ```
    #[must_use]
    pub fn with_atps(consented: Vec<u16>, disclosed: Vec<u16>) -> Self {
        Self {
            version: 2,
            consented_atps: consented,
            disclosed_atps: disclosed,
        }
    }

    /// Checks if a specific ATP has consent
    ///
    /// # Arguments
    /// * `atp_id` - The ATP ID to check
    ///
    /// # Returns
    /// `true` if the ATP is in the consented list, `false` otherwise
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ACString;
    /// let ac_string = ACString::with_atps(vec![1, 35, 41], vec![]);
    /// assert!(ac_string.has_consent(35));
    /// assert!(!ac_string.has_consent(101));
    /// ```
    #[must_use]
    pub fn has_consent(&self, atp_id: u16) -> bool {
        self.consented_atps.contains(&atp_id)
    }

    /// Checks if a specific ATP was disclosed
    ///
    /// # Arguments
    /// * `atp_id` - The ATP ID to check
    ///
    /// # Returns
    /// `true` if the ATP is in either consented or disclosed list, `false` otherwise
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ACString;
    /// let ac_string = ACString::with_atps(vec![1, 35], vec![41, 101]);
    /// assert!(ac_string.is_disclosed(35));  // In consented list
    /// assert!(ac_string.is_disclosed(101)); // In disclosed list
    /// assert!(!ac_string.is_disclosed(200)); // Not in any list
    /// ```
    #[must_use]
    pub fn is_disclosed(&self, atp_id: u16) -> bool {
        self.has_consent(atp_id) || self.disclosed_atps.contains(&atp_id)
    }

    /// Returns all ATP IDs (consented + disclosed) without duplicates, sorted
    ///
    /// # Returns
    /// A sorted vector of all unique ATP IDs
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ACString;
    /// let ac_string = ACString::with_atps(vec![1, 35], vec![41, 101, 1]);
    /// assert_eq!(ac_string.all_atps(), vec![1, 35, 41, 101]);
    /// ```
    #[must_use]
    pub fn all_atps(&self) -> Vec<u16> {
        let mut all = self.consented_atps.clone();
        all.extend_from_slice(&self.disclosed_atps);
        all.sort_unstable();
        all.dedup();
        all
    }

    /// Returns the number of consented ATPs
    #[must_use]
    pub fn consented_count(&self) -> usize {
        self.consented_atps.len()
    }

    /// Returns the number of disclosed ATPs
    #[must_use]
    pub fn disclosed_count(&self) -> usize {
        self.disclosed_atps.len()
    }

    /// Returns the total number of unique ATPs
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.all_atps().len()
    }

    /// Checks if the AC String is empty (no ATPs at all)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.consented_atps.is_empty() && self.disclosed_atps.is_empty()
    }

    /// Checks if this is a version 1 AC String (obsolete)
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.version == 1
    }

    /// Checks if all disclosed ATPs have consent
    #[must_use]
    pub fn all_disclosed_consented(&self) -> bool {
        if self.disclosed_atps.is_empty() {
            return true;
        }

        let consented_set: HashSet<u16> = self.consented_atps.iter().copied().collect();
        self.disclosed_atps
            .iter()
            .all(|&atp| consented_set.contains(&atp))
    }
}

impl Default for ACString {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses an Additional Consent (AC) String
///
/// # Format
///
/// Version 1: `1~<consented_atp_ids>`
/// Version 2: `2~<consented_atp_ids>~dv.<disclosed_atp_ids>`
///
/// # Arguments
/// * `ac_string` - The AC String to parse
///
/// # Returns
/// * `Ok(ACString)` if parsing succeeds
/// * `Err(ACError)` if the format is invalid
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::parse_ac_string;
/// // Version 2 - full format
/// let ac = parse_ac_string("2~1.35.41.101~dv.9.21.81").unwrap();
/// assert_eq!(ac.version, 2);
/// assert_eq!(ac.consented_atps, vec![1, 35, 41, 101]);
/// assert_eq!(ac.disclosed_atps, vec![9, 21, 81]);
///
/// // Version 1 - legacy
/// let ac = parse_ac_string("1~1.35.41.101").unwrap();
/// assert_eq!(ac.version, 1);
/// assert_eq!(ac.consented_atps, vec![1, 35, 41, 101]);
/// assert!(ac.disclosed_atps.is_empty());
/// ```
#[must_use = "AC string parsing failure must be handled"]
pub fn parse_ac_string(ac_string: &str) -> Result<ACString, ACError> {
    if ac_string.is_empty() {
        return Err(ACError::Empty);
    }

    // Split by '~' delimiter
    let parts: Vec<&str> = ac_string.split('~').collect();

    if parts.is_empty() {
        return Err(ACError::InvalidFormat("No parts found"));
    }

    // Parse version (Part 1)
    let version = parts[0]
        .parse::<u8>()
        .map_err(|_| ACError::InvalidVersion(parts[0].to_string()))?;

    if version != 1 && version != 2 {
        return Err(ACError::UnsupportedVersion(version));
    }

    // Parse consented ATPs (Part 2)
    let consented_atps = if parts.len() > 1 && !parts[1].is_empty() {
        parse_atp_list(parts[1])?
    } else {
        Vec::new()
    };

    // Parse disclosed ATPs (Part 3, v2 only)
    let disclosed_atps = if version == 2 && parts.len() > 2 && !parts[2].is_empty() {
        if !parts[2].starts_with("dv.") {
            return Err(ACError::InvalidDisclosedPrefix);
        }
        // Skip "dv." prefix
        parse_atp_list(&parts[2][3..])?
    } else {
        Vec::new()
    };

    Ok(ACString {
        version,
        consented_atps,
        disclosed_atps,
    })
}

/// Encodes an `ACString` into its string representation
///
/// # Arguments
/// * `ac` - The `ACString` to encode
///
/// # Returns
/// A string in the format appropriate for the version:
/// - Version 1: `1~<consented_atp_ids>`
/// - Version 2: `2~<consented_atp_ids>~dv.<disclosed_atp_ids>`
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::{ACString, encode_ac_string};
/// let ac = ACString::with_atps(vec![1, 35, 41], vec![9, 21]);
/// assert_eq!(encode_ac_string(&ac), "2~1.35.41~dv.9.21");
/// ```
#[must_use]
pub fn encode_ac_string(ac: &ACString) -> String {
    let mut parts = vec![ac.version.to_string()];

    // Part 2: Consented ATPs
    if ac.consented_atps.is_empty() {
        parts.push(String::new());
    } else {
        parts.push(encode_atp_list(&ac.consented_atps));
    }

    // Part 3: Disclosed ATPs (v2 only)
    if ac.version == 2 && !ac.disclosed_atps.is_empty() {
        parts.push(format!("dv.{}", encode_atp_list(&ac.disclosed_atps)));
    }

    parts.join("~")
}

/// Parses a dot-separated list of ATP IDs
///
/// # Arguments
/// * `list` - Dot-separated ATP IDs (e.g., "1.35.41.101")
///
/// # Returns
/// * `Ok(Vec<u16>)` with the parsed ATP IDs
/// * `Err(ACError)` if any ID is invalid
fn parse_atp_list(list: &str) -> Result<Vec<u16>, ACError> {
    list.split('.')
        .map(|s| {
            s.parse::<u16>()
                .map_err(|_| ACError::InvalidAtpId(s.to_string()))
        })
        .collect()
}

/// Encodes a list of ATP IDs into a dot-separated string
///
/// # Arguments
/// * `atps` - Vector of ATP IDs
///
/// # Returns
/// Dot-separated string (e.g., "1.35.41.101")
fn encode_atp_list(atps: &[u16]) -> String {
    atps.iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// Validates an AC String against the Google ATP List
///
/// # Arguments
/// * `ac` - The AC String to validate
/// * `valid_atp_ids` - Set of valid ATP IDs from the official Google ATP List
///
/// # Returns
/// * `Ok(())` if all ATP IDs are valid
/// * `Err(ACError)` if any ATP ID is not in the official list
pub fn validate_ac_string_atps<S: std::hash::BuildHasher>(
    ac: &ACString,
    valid_atp_ids: &HashSet<u16, S>,
) -> Result<(), ACError> {
    // Check consented ATPs
    for &atp_id in &ac.consented_atps {
        if !valid_atp_ids.contains(&atp_id) {
            return Err(ACError::UnknownAtpId(atp_id));
        }
    }

    // Check disclosed ATPs
    for &atp_id in &ac.disclosed_atps {
        if !valid_atp_ids.contains(&atp_id) {
            return Err(ACError::UnknownAtpId(atp_id));
        }
    }

    Ok(())
}

/// Error type for AC String parsing and validation
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ACError {
    /// The AC String is empty
    #[error("AC String is empty")]
    Empty,

    /// The AC String has an invalid format
    #[error("Invalid AC String format: {0}")]
    InvalidFormat(&'static str),

    /// The version is invalid (not a number)
    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    /// The version is not supported (must be 1 or 2)
    #[error("Unsupported AC String version: {0}")]
    UnsupportedVersion(u8),

    /// Disclosed ATPs (Part 3) must start with "dv."
    #[error("Disclosed ATPs must start with 'dv.' prefix")]
    InvalidDisclosedPrefix,

    /// An ATP ID is invalid (not a number)
    #[error("Invalid ATP ID: {0}")]
    InvalidAtpId(String),

    /// An ATP ID is not in the official Google ATP List
    #[error("Unknown ATP ID: {0} (not in official Google ATP List)")]
    UnknownAtpId(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ACString Creation Tests
    // ========================================================================

    #[test]
    fn test_ac_string_new() {
        let ac = ACString::new();
        assert_eq!(ac.version, 2);
        assert!(ac.consented_atps.is_empty());
        assert!(ac.disclosed_atps.is_empty());
    }

    #[test]
    fn test_ac_string_with_atps() {
        let ac = ACString::with_atps(vec![1, 35], vec![41, 101]);
        assert_eq!(ac.version, 2);
        assert_eq!(ac.consented_atps, vec![1, 35]);
        assert_eq!(ac.disclosed_atps, vec![41, 101]);
    }

    // ========================================================================
    // ACString Methods Tests
    // ========================================================================

    #[test]
    fn test_has_consent() {
        let ac = ACString::with_atps(vec![1, 35, 41], vec![101]);
        assert!(ac.has_consent(1));
        assert!(ac.has_consent(35));
        assert!(ac.has_consent(41));
        assert!(!ac.has_consent(101));
        assert!(!ac.has_consent(200));
    }

    #[test]
    fn test_is_disclosed() {
        let ac = ACString::with_atps(vec![1, 35], vec![41, 101]);
        assert!(ac.is_disclosed(1)); // In consented
        assert!(ac.is_disclosed(35)); // In consented
        assert!(ac.is_disclosed(41)); // In disclosed
        assert!(ac.is_disclosed(101)); // In disclosed
        assert!(!ac.is_disclosed(200)); // Not in any
    }

    #[test]
    fn test_all_atps() {
        let ac = ACString::with_atps(vec![1, 35], vec![41, 101, 1]); // 1 is duplicate
        assert_eq!(ac.all_atps(), vec![1, 35, 41, 101]);
    }

    #[test]
    fn test_counts() {
        let ac = ACString::with_atps(vec![1, 35, 41], vec![101, 200]);
        assert_eq!(ac.consented_count(), 3);
        assert_eq!(ac.disclosed_count(), 2);
        assert_eq!(ac.total_count(), 5);
    }

    #[test]
    fn test_is_empty() {
        let empty = ACString::new();
        assert!(empty.is_empty());

        let not_empty = ACString::with_atps(vec![1], vec![]);
        assert!(!not_empty.is_empty());
    }

    #[test]
    fn test_is_legacy() {
        let mut v1 = ACString::new();
        v1.version = 1;
        assert!(v1.is_legacy());

        let v2 = ACString::new();
        assert!(!v2.is_legacy());
    }

    // ========================================================================
    // Parsing Tests - Version 2
    // ========================================================================

    #[test]
    fn test_parse_v2_full() {
        let result = parse_ac_string("2~1.35.41.101~dv.9.21.81").unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.consented_atps, vec![1, 35, 41, 101]);
        assert_eq!(result.disclosed_atps, vec![9, 21, 81]);
    }

    #[test]
    fn test_parse_v2_no_consented() {
        let result = parse_ac_string("2~~dv.1.35.41.101").unwrap();
        assert_eq!(result.version, 2);
        assert!(result.consented_atps.is_empty());
        assert_eq!(result.disclosed_atps, vec![1, 35, 41, 101]);
    }

    #[test]
    fn test_parse_v2_no_disclosed() {
        let result = parse_ac_string("2~1.35.41.101").unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.consented_atps, vec![1, 35, 41, 101]);
        assert!(result.disclosed_atps.is_empty());
    }

    #[test]
    fn test_parse_v2_empty_parts() {
        let result = parse_ac_string("2~~").unwrap();
        assert_eq!(result.version, 2);
        assert!(result.consented_atps.is_empty());
        assert!(result.disclosed_atps.is_empty());
    }

    // ========================================================================
    // Parsing Tests - Version 1 (Legacy)
    // ========================================================================

    #[test]
    fn test_parse_v1_full() {
        let result = parse_ac_string("1~1.35.41.101").unwrap();
        assert_eq!(result.version, 1);
        assert_eq!(result.consented_atps, vec![1, 35, 41, 101]);
        assert!(result.disclosed_atps.is_empty());
    }

    #[test]
    fn test_parse_v1_empty_consented() {
        let result = parse_ac_string("1~").unwrap();
        assert_eq!(result.version, 1);
        assert!(result.consented_atps.is_empty());
        assert!(result.disclosed_atps.is_empty());
    }

    // ========================================================================
    // Parsing Error Tests
    // ========================================================================

    #[test]
    fn test_parse_empty_string() {
        let result = parse_ac_string("");
        assert!(matches!(result, Err(ACError::Empty)));
    }

    #[test]
    fn test_parse_invalid_version() {
        let result = parse_ac_string("x~1.35");
        assert!(matches!(result, Err(ACError::InvalidVersion(_))));
    }

    #[test]
    fn test_parse_unsupported_version() {
        let result = parse_ac_string("3~1.35");
        assert!(matches!(result, Err(ACError::UnsupportedVersion(3))));
    }

    #[test]
    fn test_parse_invalid_disclosed_prefix() {
        let result = parse_ac_string("2~1.35~41.101");
        assert!(matches!(result, Err(ACError::InvalidDisclosedPrefix)));
    }

    #[test]
    fn test_parse_invalid_atp_id() {
        let result = parse_ac_string("2~1.abc.35");
        assert!(matches!(result, Err(ACError::InvalidAtpId(_))));
    }

    // ========================================================================
    // Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_v2_full() {
        let ac = ACString::with_atps(vec![1, 35, 41], vec![9, 21]);
        assert_eq!(encode_ac_string(&ac), "2~1.35.41~dv.9.21");
    }

    #[test]
    fn test_encode_v2_no_consented() {
        let ac = ACString {
            version: 2,
            consented_atps: vec![],
            disclosed_atps: vec![1, 35],
        };
        assert_eq!(encode_ac_string(&ac), "2~~dv.1.35");
    }

    #[test]
    fn test_encode_v2_no_disclosed() {
        let ac = ACString::with_atps(vec![1, 35], vec![]);
        assert_eq!(encode_ac_string(&ac), "2~1.35");
    }

    #[test]
    fn test_encode_v1() {
        let ac = ACString {
            version: 1,
            consented_atps: vec![1, 35, 41],
            disclosed_atps: vec![], // Should be ignored for v1
        };
        assert_eq!(encode_ac_string(&ac), "1~1.35.41");
    }

    // ========================================================================
    // Roundtrip Tests (Parse -> Encode -> Parse)
    // ========================================================================

    #[test]
    fn test_roundtrip_v2_full() {
        let original = "2~1.35.41.101~dv.9.21.81";
        let parsed = parse_ac_string(original).unwrap();
        let encoded = encode_ac_string(&parsed);
        let reparsed = parse_ac_string(&encoded).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn test_roundtrip_v1() {
        let original = "1~1.35.41.101";
        let parsed = parse_ac_string(original).unwrap();
        let encoded = encode_ac_string(&parsed);
        let reparsed = parse_ac_string(&encoded).unwrap();
        assert_eq!(parsed, reparsed);
    }

    // ========================================================================
    // Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_valid_atps() {
        let ac = ACString::with_atps(vec![1, 35], vec![41]);
        let valid_ids: HashSet<u16> = vec![1, 35, 41, 101, 200].into_iter().collect();
        assert!(validate_ac_string_atps(&ac, &valid_ids).is_ok());
    }

    #[test]
    fn test_validate_unknown_consented_atp() {
        let ac = ACString::with_atps(vec![1, 999], vec![]);
        let valid_ids: HashSet<u16> = vec![1, 35, 41].into_iter().collect();
        let result = validate_ac_string_atps(&ac, &valid_ids);
        assert!(matches!(result, Err(ACError::UnknownAtpId(999))));
    }

    #[test]
    fn test_validate_unknown_disclosed_atp() {
        let ac = ACString::with_atps(vec![1], vec![999]);
        let valid_ids: HashSet<u16> = vec![1, 35, 41].into_iter().collect();
        let result = validate_ac_string_atps(&ac, &valid_ids);
        assert!(matches!(result, Err(ACError::UnknownAtpId(999))));
    }
}
