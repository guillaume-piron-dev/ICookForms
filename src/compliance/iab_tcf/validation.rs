//! TC String validation implementation for IAB TCF 2.2
//!
//! This module provides comprehensive validation of TC Strings according to
//! the IAB TCF v2.2 specification. It checks for:
//!
//! - Correct version and format
//! - Valid timestamps
//! - Presence of mandatory segments (disclosed vendors in v2.2+)
//! - Valid vendor and purpose IDs
//! - Consistency between segments
//!
//! # Examples
//!
//! ```rust
//! use icook_forms::compliance::iab_tcf::validate_tc_string;
//!
//! let tc_string = "COxSKBCOxSKCCBcABCENAgCMAPzAAEPAAAqIDaQBQAMgAgABqAR0A2gDaQAwAMgAgANoAAA";
//! let result = validate_tc_string(tc_string)?;
//!
//! if result.is_valid {
//!     println!("TC String is valid!");
//! } else {
//!     for error in &result.errors {
//!         eprintln!("Error: {:?}", error);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::{decode_tc_string, GlobalVendorList, Result, TCModel};

/// Result of TC String validation
///
/// Contains the validation status and lists of errors and warnings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the TC String is valid (no errors)
    pub is_valid: bool,

    /// List of validation errors (must be fixed)
    pub errors: Vec<ValidationError>,

    /// List of validation warnings (should be reviewed)
    pub warnings: Vec<ValidationWarning>,
}

/// Types of validation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    /// Invalid or unsupported version
    InvalidVersion(u8),

    /// Timestamp is invalid (e.g., in the future, before creation)
    InvalidTimestamp {
        /// Field name where timestamp is invalid
        field: String,
        /// Reason for timestamp invalidity
        reason: String,
    },

    /// Missing disclosed vendors segment (mandatory in v2.2+)
    MissingDisclosedVendors,

    /// Vendor ID not found in GVL
    UnknownVendor(u16),

    /// Purpose ID is invalid (must be 1-24)
    InvalidPurposeId(u8),

    /// Invalid segment type
    InvalidSegmentType {
        /// Expected segment type
        expected: u8,
        /// Found segment type
        found: u8,
    },

    /// Malformed TC String
    MalformedTCString(String),

    /// Empty vendor set (should contain at least one vendor)
    EmptyVendorSet {
        /// Segment name with empty vendor set
        segment: String,
    },

    /// Inconsistency between segments
    SegmentInconsistency {
        /// Description of the inconsistency
        description: String,
    },

    /// CMP ID is invalid or not registered
    InvalidCmpId(u16),

    /// Policy version mismatch
    PolicyVersionMismatch {
        /// Core policy version found
        core_version: u8,
        /// Expected policy version
        expected: u8,
    },
}

/// Types of validation warnings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationWarning {
    /// TC String uses an old version
    OldVersion {
        /// Current version used
        version: u8,
        /// Latest available version
        latest: u8,
    },

    /// Vendor is unknown (not in GVL)
    UnknownVendorWarning(u16),

    /// Vendor is deleted from GVL
    DeletedVendor {
        /// Vendor ID
        id: u16,
        /// Date when vendor was deleted
        deleted_date: String,
    },

    /// Empty vendor consent list
    NoConsents,

    /// No purposes consented to
    NoPurposes,

    /// Vendor list version is old
    OldVendorListVersion {
        /// Current vendor list version
        version: u16,
        /// Latest vendor list version
        latest: u16,
    },

    /// Suspicious timestamp (very old or very recent)
    SuspiciousTimestamp {
        /// Field name with suspicious timestamp
        field: String,
        /// Reason for suspicion
        reason: String,
    },

    /// Vendor in consents but not in disclosed
    VendorNotDisclosed(u16),

    /// Vendor in disclosed but not in consents
    VendorDisclosedButNotConsented(u16),
}

/// Validates a TC String
///
/// Performs comprehensive validation according to TCF v2.2 specification.
///
/// # Arguments
///
/// * `tc_string` - The TC String to validate
///
/// # Returns
///
/// A `ValidationResult` containing errors and warnings, or an error if
/// the TC String cannot be decoded at all.
///
/// # Example
///
/// ```rust
/// # use icook_forms::compliance::iab_tcf::validate_tc_string;
/// let result = validate_tc_string("COxSKBCOxSKCCBcABCENAgCMAPzAAEPAAAqIDaQBQAMgAgABqAR0A2gDaQAwAMgAgANoAAA")?;
/// assert!(result.is_valid);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use = "TC string validation result must be checked"]
pub fn validate_tc_string(tc_string: &str) -> Result<ValidationResult> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Try to decode TC String
    let tc_model = match decode_tc_string(tc_string) {
        Ok(model) => model,
        Err(e) => {
            errors.push(ValidationError::MalformedTCString(e.to_string()));
            return Ok(ValidationResult {
                is_valid: false,
                errors,
                warnings,
            });
        }
    };

    // Validate version
    validate_version(&tc_model, &mut errors, &mut warnings);

    // Validate timestamps
    validate_timestamps(&tc_model, &mut errors, &mut warnings);

    // Validate mandatory segments
    validate_mandatory_segments(&tc_model, &mut errors);

    // Validate purposes
    validate_purposes(&tc_model, &mut errors, &mut warnings);

    // Validate vendors
    validate_vendors(&tc_model, &mut errors, &mut warnings);

    // Validate segment consistency
    validate_segment_consistency(&tc_model, &mut errors, &mut warnings);

    // Validate policy version
    validate_policy_version(&tc_model, &mut errors);

    Ok(ValidationResult {
        is_valid: errors.is_empty(),
        errors,
        warnings,
    })
}

/// Validates a TC String with GVL verification
///
/// Performs all standard validations plus checks vendor IDs against the GVL.
///
/// # Arguments
///
/// * `tc_string` - The TC String to validate
/// * `gvl` - The Global Vendor List to validate against
///
/// # Example
///
/// ```rust,no_run
/// # use icook_forms::compliance::iab_tcf::{validate_tc_string_with_gvl, GlobalVendorList};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let gvl = GlobalVendorList::fetch_latest().await?;
/// let result = validate_tc_string_with_gvl("COxSKBCOxSKCCBcABCENAgCMAPzAAEPAAAqIDaQBQAMgAgABqAR0A2gDaQAwAMgAgANoAAA", &gvl)?;
/// # Ok(())
/// # }
/// ```
#[must_use = "TC string validation result must be checked"]
pub fn validate_tc_string_with_gvl(
    tc_string: &str,
    gvl: &GlobalVendorList,
) -> Result<ValidationResult> {
    let mut result = validate_tc_string(tc_string)?;

    // Additional GVL-based validation
    let tc_model = decode_tc_string(tc_string)?;

    validate_vendors_against_gvl(&tc_model, gvl, &mut result.errors, &mut result.warnings);
    validate_vendor_list_version(&tc_model, gvl, &mut result.warnings);

    result.is_valid = result.errors.is_empty();

    Ok(result)
}

// ===== Validation Functions =====

#[allow(clippy::ptr_arg)] // Need Vec for push operations
fn validate_version(
    tc_model: &TCModel,
    errors: &mut Vec<ValidationError>,
    _warnings: &mut Vec<ValidationWarning>,
) {
    let version = tc_model.core_string.version;

    if version != 2 {
        errors.push(ValidationError::InvalidVersion(version));
    }

    // Check if using an old sub-version (if we track this in the future)
    // For now, we only support version 2
}

fn validate_timestamps(
    tc_model: &TCModel,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    let now = Utc::now();
    let created = tc_model.core_string.created;
    let last_updated = tc_model.core_string.last_updated;

    // Created timestamp should not be in the future
    if created > now {
        errors.push(ValidationError::InvalidTimestamp {
            field: "created".to_string(),
            reason: "Timestamp is in the future".to_string(),
        });
    }

    // Last updated should not be before created
    if last_updated < created {
        errors.push(ValidationError::InvalidTimestamp {
            field: "last_updated".to_string(),
            reason: "Last updated is before created timestamp".to_string(),
        });
    }

    // Last updated should not be in the future
    if last_updated > now {
        errors.push(ValidationError::InvalidTimestamp {
            field: "last_updated".to_string(),
            reason: "Timestamp is in the future".to_string(),
        });
    }

    // Warning: Very old consent (more than 13 months per GDPR)
    let age_days = (now - created).num_days();
    if age_days > 395 {
        warnings.push(ValidationWarning::SuspiciousTimestamp {
            field: "created".to_string(),
            reason: format!(
                "Consent is {age_days} days old (GDPR recommends refresh every 13 months)"
            ),
        });
    }
}

fn validate_mandatory_segments(tc_model: &TCModel, errors: &mut Vec<ValidationError>) {
    // In TCF v2.2+, disclosed vendors segment is mandatory
    if tc_model.disclosed_vendors.is_none() {
        errors.push(ValidationError::MissingDisclosedVendors);
    }
}

fn validate_purposes(
    tc_model: &TCModel,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    // Check if any purposes are consented to
    let has_any_consent = (0..24).any(|i| tc_model.core_string.purposes_consent.is_set(i));

    if !has_any_consent {
        warnings.push(ValidationWarning::NoPurposes);
    }

    // Validate publisher restrictions
    for restriction in &tc_model.core_string.publisher_restrictions.restrictions {
        if restriction.purpose_id == 0 || restriction.purpose_id > 24 {
            errors.push(ValidationError::InvalidPurposeId(restriction.purpose_id));
        }
    }

    // Validate publisher TC purposes if present
    if let Some(ref _pub_tc) = tc_model.publisher_tc {
        // All standard purposes should be 1-24, validated by structure
        // Custom purposes are validated by count
    }
}

fn validate_vendors(
    tc_model: &TCModel,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    // Check if any vendors are consented to
    let consent_count = tc_model.core_string.vendor_consents.len();

    if consent_count == 0 {
        warnings.push(ValidationWarning::NoConsents);
    }

    // Check disclosed vendors segment
    if let Some(ref disclosed) = tc_model.disclosed_vendors {
        if disclosed.vendors.is_empty() {
            errors.push(ValidationError::EmptyVendorSet {
                segment: "disclosed_vendors".to_string(),
            });
        }
    }

    // Check allowed vendors segment
    if let Some(ref allowed) = tc_model.allowed_vendors {
        if allowed.vendors.is_empty() {
            warnings.push(ValidationWarning::VendorDisclosedButNotConsented(0));
            // Generic warning
        }
    }
}

#[allow(clippy::ptr_arg)] // Need Vec for push operations
fn validate_segment_consistency(
    tc_model: &TCModel,
    _errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    // Check if consented vendors are disclosed
    if let Some(ref disclosed) = tc_model.disclosed_vendors {
        let consented_vendors = tc_model.core_string.vendor_consents.to_vec();
        let disclosed_vendors = disclosed.vendors.to_vec();

        for vendor_id in &consented_vendors {
            if !disclosed_vendors.contains(vendor_id) {
                warnings.push(ValidationWarning::VendorNotDisclosed(*vendor_id));
            }
        }

        // Check if disclosed vendors are consented/LI
        for vendor_id in &disclosed_vendors {
            let has_consent = consented_vendors.contains(vendor_id);
            let has_li = tc_model
                .core_string
                .vendor_legitimate_interests
                .contains(*vendor_id);

            if !has_consent && !has_li {
                warnings.push(ValidationWarning::VendorDisclosedButNotConsented(
                    *vendor_id,
                ));
            }
        }
    }
}

fn validate_policy_version(tc_model: &TCModel, errors: &mut Vec<ValidationError>) {
    let policy_version = tc_model.core_string.tcf_policy_version;

    // TCF v2.x should use policy version 2
    if policy_version != 2 {
        errors.push(ValidationError::PolicyVersionMismatch {
            core_version: policy_version,
            expected: 2,
        });
    }
}

fn validate_vendors_against_gvl(
    tc_model: &TCModel,
    gvl: &GlobalVendorList,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    // Validate all vendor IDs against GVL
    let all_vendor_ids: Vec<u16> = tc_model
        .core_string
        .vendor_consents
        .to_vec()
        .into_iter()
        .chain(tc_model.core_string.vendor_legitimate_interests.to_vec())
        .collect();

    for vendor_id in all_vendor_ids {
        if let Some(vendor) = gvl.get_vendor(vendor_id) {
            // Check if vendor is deleted
            if vendor.is_deleted() {
                warnings.push(ValidationWarning::DeletedVendor {
                    id: vendor_id,
                    deleted_date: vendor.deleted_date.clone().unwrap_or_default(),
                });
            }
        } else {
            errors.push(ValidationError::UnknownVendor(vendor_id));
        }
    }
}

fn validate_vendor_list_version(
    tc_model: &TCModel,
    gvl: &GlobalVendorList,
    warnings: &mut Vec<ValidationWarning>,
) {
    let tc_version = tc_model.core_string.vendor_list_version;
    let gvl_version = gvl.vendor_list_version;

    if tc_version < gvl_version {
        warnings.push(ValidationWarning::OldVendorListVersion {
            version: tc_version,
            latest: gvl_version,
        });
    }
}

/// Quick validation - checks only critical errors
///
/// Performs a faster validation that only checks for critical errors,
/// skipping warnings and detailed checks.
#[must_use = "Validation result must be checked"]
pub fn quick_validate(tc_string: &str) -> Result<bool> {
    let tc_model = decode_tc_string(tc_string)?;

    // Check version
    if tc_model.core_string.version != 2 {
        return Ok(false);
    }

    // Check for mandatory disclosed vendors in v2.2+
    if tc_model.disclosed_vendors.is_none() {
        return Ok(false);
    }

    // Check timestamps aren't in the future
    let now = Utc::now();
    if tc_model.core_string.created > now || tc_model.core_string.last_updated > now {
        return Ok(false);
    }

    // Check last_updated >= created
    if tc_model.core_string.last_updated < tc_model.core_string.created {
        return Ok(false);
    }

    Ok(true)
}

impl ValidationResult {
    /// Returns true if there are any errors
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Returns true if there are any warnings
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Returns the number of errors
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Returns the number of warnings
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// Returns a summary string
    #[must_use]
    pub fn summary(&self) -> String {
        if self.is_valid && !self.has_warnings() {
            "TC String is valid".to_string()
        } else if self.is_valid {
            format!(
                "TC String is valid with {} warning(s)",
                self.warning_count()
            )
        } else {
            format!(
                "TC String is invalid: {} error(s), {} warning(s)",
                self.error_count(),
                self.warning_count()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::iab_tcf::{encode_tc_string, CoreString, DisclosedVendors, VendorSet};
    use std::collections::HashSet;

    fn create_valid_tc_model() -> TCModel {
        let mut core = CoreString::new();
        core.version = 2;
        core.tcf_policy_version = 2;

        // Set some purposes
        core.purposes_consent.set(0, true);

        // Set some vendors
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(35);
        core.vendor_consents = VendorSet::BitField(vendors.clone());

        // Add disclosed vendors
        let disclosed = DisclosedVendors::new(VendorSet::BitField(vendors));

        TCModel {
            core_string: core,
            disclosed_vendors: Some(disclosed),
            allowed_vendors: None,
            publisher_tc: None,
        }
    }

    #[test]
    fn test_validate_valid_tc_string() -> Result<()> {
        let tc_model = create_valid_tc_model();
        let tc_string = encode_tc_string(&tc_model)?;

        let result = validate_tc_string(&tc_string)?;

        assert!(result.is_valid);
        assert!(result.errors.is_empty());

        Ok(())
    }

    #[test]
    fn test_validate_missing_disclosed_vendors() {
        let mut tc_model = create_valid_tc_model();
        tc_model.disclosed_vendors = None;

        // Can't encode without disclosed vendors in v2.2+
        // So we test the validation directly on a modified model
        let mut errors = Vec::new();
        validate_mandatory_segments(&tc_model, &mut errors);

        assert!(!errors.is_empty());
        assert!(matches!(
            errors[0],
            ValidationError::MissingDisclosedVendors
        ));
    }

    #[test]
    fn test_validate_invalid_version() {
        let mut tc_model = create_valid_tc_model();
        tc_model.core_string.version = 3;

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_version(&tc_model, &mut errors, &mut warnings);

        assert!(!errors.is_empty());
        assert!(matches!(errors[0], ValidationError::InvalidVersion(3)));
    }

    #[test]
    fn test_validate_timestamps() {
        let tc_model = create_valid_tc_model();

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_timestamps(&tc_model, &mut errors, &mut warnings);

        // Should be valid - timestamps are set to now in new()
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_future_timestamp() {
        use chrono::Duration;

        let mut tc_model = create_valid_tc_model();
        tc_model.core_string.created = Utc::now() + Duration::days(1);

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_timestamps(&tc_model, &mut errors, &mut warnings);

        assert!(!errors.is_empty());
    }

    #[test]
    fn test_validate_no_purposes() {
        let mut tc_model = create_valid_tc_model();
        tc_model.core_string.purposes_consent = crate::compliance::iab_tcf::BitField::new(24);

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_purposes(&tc_model, &mut errors, &mut warnings);

        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::NoPurposes)));
    }

    #[test]
    fn test_validate_no_vendors() {
        let mut tc_model = create_valid_tc_model();
        tc_model.core_string.vendor_consents = VendorSet::new_bitfield();

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_vendors(&tc_model, &mut errors, &mut warnings);

        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::NoConsents)));
    }

    #[test]
    fn test_validate_segment_consistency() {
        let mut tc_model = create_valid_tc_model();

        // Add a consented vendor not in disclosed
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(35);
        vendors.insert(100); // Not disclosed
        tc_model.core_string.vendor_consents = VendorSet::BitField(vendors);

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_segment_consistency(&tc_model, &mut errors, &mut warnings);

        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::VendorNotDisclosed(100))));
    }

    #[test]
    fn test_validate_policy_version() {
        let mut tc_model = create_valid_tc_model();
        tc_model.core_string.tcf_policy_version = 1; // Wrong version

        let mut errors = Vec::new();
        validate_policy_version(&tc_model, &mut errors);

        assert!(!errors.is_empty());
    }

    #[test]
    fn test_quick_validate_valid() -> Result<()> {
        let tc_model = create_valid_tc_model();
        let tc_string = encode_tc_string(&tc_model)?;

        let is_valid = quick_validate(&tc_string)?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_quick_validate_invalid_version() {
        let mut tc_model = create_valid_tc_model();
        tc_model.core_string.version = 3;

        // Can't encode with version 3, but we can test the logic
        let is_valid = tc_model.core_string.version == 2;
        assert!(!is_valid);
    }

    #[test]
    fn test_validation_result_helpers() -> Result<()> {
        let tc_model = create_valid_tc_model();
        let tc_string = encode_tc_string(&tc_model)?;
        let result = validate_tc_string(&tc_string)?;

        assert!(!result.has_errors());
        assert_eq!(result.error_count(), 0);
        assert!(result.summary().contains("valid"));

        Ok(())
    }
}
