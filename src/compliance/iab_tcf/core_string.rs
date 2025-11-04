//! Core String structures and types for IAB TCF 2.2
//!
//! This module contains the fundamental data structures representing the IAB TCF 2.2
//! Core String, which is the mandatory first segment of any TC String. It includes:
//!
//! - `CoreString`: The main structure containing all consent and metadata
//! - `PublisherRestrictions`: Publisher-specific restrictions on vendor purposes
//! - `RestrictionType`: Types of restrictions that can be applied
//!
//! # Specification
//!
//! The Core String contains:
//! - CMP and consent metadata (timestamps, IDs, versions)
//! - Consent choices for purposes and special features
//! - Vendor consent and legitimate interest sets
//! - Publisher-specific restrictions
//!
//! Reference: IAB TCF v2.2 Specification
//! <https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework>

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{BitField, Error, Result, VendorSet};

/// Represents a complete IAB TCF 2.2 TC String model
///
/// A TC String consists of multiple segments:
/// - Core String (mandatory)
/// - Disclosed Vendors (mandatory in v2.2+)
/// - Allowed Vendors (optional)
/// - Publisher TC (optional)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TCModel {
    /// The core consent string (mandatory)
    pub core_string: CoreString,

    /// Disclosed vendors segment (mandatory in TCF v2.2+)
    pub disclosed_vendors: Option<DisclosedVendors>,

    /// Allowed vendors segment (optional)
    pub allowed_vendors: Option<AllowedVendors>,

    /// Publisher TC segment (optional)
    pub publisher_tc: Option<PublisherTC>,
}

/// Core String - The mandatory first segment of a TC String
///
/// Contains all essential consent information including:
/// - Version and timestamps
/// - CMP identification
/// - Policy version
/// - Purpose consents and legitimate interests
/// - Vendor consents and legitimate interests
/// - Publisher restrictions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreString {
    // ===== Metadata =====
    /// TCF version number (must be 2 for TCF v2.x)
    pub version: u8,

    /// Timestamp when the consent was first created (UTC)
    pub created: DateTime<Utc>,

    /// Timestamp when the consent was last updated (UTC)
    pub last_updated: DateTime<Utc>,

    // ===== CMP Identification =====
    /// IAB assigned CMP ID number (12 bits: 1-4095)
    pub cmp_id: u16,

    /// CMP version number (12 bits: 1-4095)
    pub cmp_version: u16,

    /// Screen number in the CMP where consent was given (6 bits: 0-63)
    pub consent_screen: u8,

    /// Two-letter ISO 639-1 language code in which the CMP UI was presented
    pub consent_language: String,

    // ===== Policy Version =====
    /// Version of the Global Vendor List used (12 bits: 1-4095)
    pub vendor_list_version: u16,

    /// Version of the TCF policy to which the CMP is adhering (6 bits)
    pub tcf_policy_version: u8,

    // ===== Consent Scope =====
    /// Whether the signals are for service-specific storage (true) or shared (false)
    pub is_service_specific: bool,

    /// Whether the CMP is using non-standard texts for purposes or special features
    pub use_non_standard_texts: bool,

    // ===== Special Features =====
    /// User's opt-in status for special features 1-12
    /// Bit 0 = Special Feature 1, Bit 11 = Special Feature 12
    pub special_feature_opt_ins: BitField,

    // ===== Purposes =====
    /// User's consent status for purposes 1-24
    /// Bit 0 = Purpose 1, Bit 23 = Purpose 24
    pub purposes_consent: BitField,

    /// User's legitimate interest transparency status for purposes 1-24
    /// Bit 0 = Purpose 1, Bit 23 = Purpose 24
    pub purposes_li_transparency: BitField,

    /// Whether Purpose 1 was NOT disclosed at all
    /// true = Purpose 1 was not disclosed
    /// false = Purpose 1 was disclosed
    pub purpose_one_treatment: bool,

    // ===== Publisher =====
    /// Two-letter ISO 3166-1 alpha-2 country code of the publisher
    pub publisher_cc: String,

    // ===== Vendors =====
    /// Vendor consent section - which vendors have been consented to
    pub vendor_consents: VendorSet,

    /// Vendor legitimate interest section - which vendors have legitimate interest transparency
    pub vendor_legitimate_interests: VendorSet,

    // ===== Publisher Restrictions =====
    /// Publisher restrictions on how vendors can use purposes
    pub publisher_restrictions: PublisherRestrictions,
}

/// Collection of publisher restrictions
///
/// Publishers can restrict how specific vendors use specific purposes,
/// overriding the vendor's declared legal basis in the GVL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherRestrictions {
    /// Number of restrictions (12 bits: 0-4095)
    pub num_restrictions: u16,

    /// List of individual restrictions
    pub restrictions: Vec<PublisherRestriction>,
}

impl PublisherRestrictions {
    /// Creates an empty set of publisher restrictions
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_restrictions: 0,
            restrictions: Vec::new(),
        }
    }

    /// Creates publisher restrictions with a pre-allocated capacity
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            num_restrictions: 0,
            restrictions: Vec::with_capacity(capacity),
        }
    }

    /// Adds a new restriction
    pub fn add_restriction(&mut self, restriction: PublisherRestriction) {
        self.restrictions.push(restriction);
        #[allow(clippy::cast_possible_truncation)]
        let num = self.restrictions.len() as u16;
        self.num_restrictions = num;
    }

    /// Gets all restrictions for a specific purpose
    #[must_use]
    pub fn get_restrictions_for_purpose(&self, purpose_id: u8) -> Vec<&PublisherRestriction> {
        self.restrictions
            .iter()
            .filter(|r| r.purpose_id == purpose_id)
            .collect()
    }

    /// Checks if a vendor is restricted for a specific purpose
    #[must_use]
    pub fn is_vendor_restricted(&self, purpose_id: u8, vendor_id: u16) -> Option<RestrictionType> {
        self.restrictions
            .iter()
            .find(|r| r.purpose_id == purpose_id && r.vendors.contains(vendor_id))
            .map(|r| r.restriction_type)
    }

    /// Returns the number of restrictions
    #[must_use]
    pub fn len(&self) -> usize {
        self.restrictions.len()
    }

    /// Checks if there are no restrictions
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.restrictions.is_empty()
    }
}

impl Default for PublisherRestrictions {
    fn default() -> Self {
        Self::new()
    }
}

/// A single publisher restriction
///
/// Defines how a specific purpose can be used by a set of vendors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherRestriction {
    /// Purpose ID (8 bits: 1-24)
    pub purpose_id: u8,

    /// Type of restriction applied
    pub restriction_type: RestrictionType,

    /// Set of vendors to which this restriction applies
    pub vendors: VendorSet,
}

impl PublisherRestriction {
    /// Creates a new publisher restriction
    pub fn new(
        purpose_id: u8,
        restriction_type: RestrictionType,
        vendors: VendorSet,
    ) -> Result<Self> {
        if purpose_id == 0 || purpose_id > 24 {
            return Err(Error::InvalidPurposeId(purpose_id));
        }

        Ok(Self {
            purpose_id,
            restriction_type,
            vendors,
        })
    }

    /// Checks if a specific vendor is included in this restriction
    #[must_use]
    pub fn applies_to_vendor(&self, vendor_id: u16) -> bool {
        self.vendors.contains(vendor_id)
    }
}

/// Type of restriction a publisher can place on a vendor's use of a purpose
///
/// Publishers can override the legal basis a vendor declared in the GVL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RestrictionType {
    /// Purpose is not allowed for this vendor at all
    NotAllowed = 0,

    /// Purpose requires consent (even if vendor declared legitimate interest in GVL)
    RequireConsent = 1,

    /// Purpose requires legitimate interest (even if vendor declared consent in GVL)
    RequireLegitimateInterest = 2,
}

impl RestrictionType {
    /// Converts from a numeric value to `RestrictionType`
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(RestrictionType::NotAllowed),
            1 => Ok(RestrictionType::RequireConsent),
            2 => Ok(RestrictionType::RequireLegitimateInterest),
            _ => Err(Error::InvalidRestrictionType(value)),
        }
    }

    /// Converts `RestrictionType` to numeric value
    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Disclosed Vendors segment
///
/// Lists all vendors that were disclosed to the user in the CMP UI.
/// This segment is mandatory in TCF v2.2+.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisclosedVendors {
    /// Segment type identifier (always 1 for disclosed vendors)
    pub segment_type: u8,

    /// Set of vendor IDs that were disclosed
    pub vendors: VendorSet,
}

impl DisclosedVendors {
    /// Creates a new `DisclosedVendors` segment
    #[must_use]
    pub fn new(vendors: VendorSet) -> Self {
        Self {
            segment_type: 1,
            vendors,
        }
    }

    /// Checks if a vendor was disclosed
    #[must_use]
    pub fn is_vendor_disclosed(&self, vendor_id: u16) -> bool {
        self.vendors.contains(vendor_id)
    }
}

/// Allowed Vendors segment
///
/// Lists vendors that are allowed to operate on the publisher's property.
/// This is a subset of the GVL and is optional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllowedVendors {
    /// Segment type identifier (always 2 for allowed vendors)
    pub segment_type: u8,

    /// Set of vendor IDs that are allowed
    pub vendors: VendorSet,
}

impl AllowedVendors {
    /// Creates a new `AllowedVendors` segment
    #[must_use]
    pub fn new(vendors: VendorSet) -> Self {
        Self {
            segment_type: 2,
            vendors,
        }
    }

    /// Checks if a vendor is allowed
    #[must_use]
    pub fn is_vendor_allowed(&self, vendor_id: u16) -> bool {
        self.vendors.contains(vendor_id)
    }
}

/// Publisher TC segment
///
/// Contains the publisher's own transparency and consent signals for
/// standard and custom purposes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherTC {
    /// Segment type identifier (always 3 for publisher TC)
    pub segment_type: u8,

    /// Publisher's consent status for standard purposes 1-24
    pub pub_purposes_consent: BitField,

    /// Publisher's legitimate interest transparency for standard purposes 1-24
    pub pub_purposes_li_transparency: BitField,

    /// Number of custom purposes (6 bits: 0-63)
    pub num_custom_purposes: u8,

    /// Publisher's consent status for custom purposes
    pub custom_purposes_consent: BitField,

    /// Publisher's legitimate interest transparency for custom purposes
    pub custom_purposes_li_transparency: BitField,
}

impl PublisherTC {
    /// Creates a new `PublisherTC` segment with standard purposes only
    #[must_use]
    pub fn new(pub_purposes_consent: BitField, pub_purposes_li_transparency: BitField) -> Self {
        Self {
            segment_type: 3,
            pub_purposes_consent,
            pub_purposes_li_transparency,
            num_custom_purposes: 0,
            custom_purposes_consent: BitField::new(0),
            custom_purposes_li_transparency: BitField::new(0),
        }
    }

    /// Creates a new `PublisherTC` segment with custom purposes
    #[must_use]
    pub fn with_custom_purposes(
        pub_purposes_consent: BitField,
        pub_purposes_li_transparency: BitField,
        custom_purposes_consent: BitField,
        custom_purposes_li_transparency: BitField,
    ) -> Self {
        let num_custom = custom_purposes_consent.len();

        #[allow(clippy::cast_possible_truncation)]
        let num_custom_purposes = num_custom as u8;

        Self {
            segment_type: 3,
            pub_purposes_consent,
            pub_purposes_li_transparency,
            num_custom_purposes,
            custom_purposes_consent,
            custom_purposes_li_transparency,
        }
    }

    /// Checks if publisher has consent for a standard purpose
    #[must_use]
    pub fn has_purpose_consent(&self, purpose_id: u8) -> bool {
        if purpose_id == 0 || purpose_id > 24 {
            return false;
        }
        self.pub_purposes_consent.is_set((purpose_id - 1) as usize)
    }

    /// Checks if publisher has custom purpose consent
    #[must_use]
    pub fn has_custom_purpose_consent(&self, custom_purpose_id: u8) -> bool {
        if custom_purpose_id as usize >= self.num_custom_purposes as usize {
            return false;
        }
        self.custom_purposes_consent
            .is_set(custom_purpose_id as usize)
    }
}

impl CoreString {
    /// Creates a new `CoreString` with default values
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();

        Self {
            version: 2,
            created: now,
            last_updated: now,
            cmp_id: 0,
            cmp_version: 0,
            consent_screen: 0,
            consent_language: "EN".to_string(),
            vendor_list_version: 0,
            tcf_policy_version: 2,
            is_service_specific: false,
            use_non_standard_texts: false,
            special_feature_opt_ins: BitField::new(12),
            purposes_consent: BitField::new(24),
            purposes_li_transparency: BitField::new(24),
            purpose_one_treatment: false,
            publisher_cc: "AA".to_string(),
            vendor_consents: VendorSet::new_bitfield(),
            vendor_legitimate_interests: VendorSet::new_bitfield(),
            publisher_restrictions: PublisherRestrictions::new(),
        }
    }

    /// Checks if consent is given for a specific purpose
    #[must_use]
    pub fn has_purpose_consent(&self, purpose_id: u8) -> bool {
        if purpose_id == 0 || purpose_id > 24 {
            return false;
        }
        self.purposes_consent.is_set((purpose_id - 1) as usize)
    }

    /// Checks if legitimate interest transparency is established for a purpose
    #[must_use]
    pub fn has_purpose_li_transparency(&self, purpose_id: u8) -> bool {
        if purpose_id == 0 || purpose_id > 24 {
            return false;
        }
        self.purposes_li_transparency
            .is_set((purpose_id - 1) as usize)
    }

    /// Checks if user has opted in to a special feature
    #[must_use]
    pub fn has_special_feature_opt_in(&self, feature_id: u8) -> bool {
        if feature_id == 0 || feature_id > 12 {
            return false;
        }
        self.special_feature_opt_ins
            .is_set((feature_id - 1) as usize)
    }

    /// Checks if a vendor has user consent
    #[must_use]
    pub fn has_vendor_consent(&self, vendor_id: u16) -> bool {
        self.vendor_consents.contains(vendor_id)
    }

    /// Checks if a vendor has legitimate interest transparency established
    #[must_use]
    pub fn has_vendor_li_transparency(&self, vendor_id: u16) -> bool {
        self.vendor_legitimate_interests.contains(vendor_id)
    }
}

impl Default for CoreString {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_core_string_creation() {
        let core = CoreString::new();

        assert_eq!(core.version, 2);
        assert_eq!(core.tcf_policy_version, 2);
        assert_eq!(core.consent_language, "EN");
        assert!(!core.is_service_specific);
    }

    #[test]
    fn test_purpose_consent() {
        let mut core = CoreString::new();
        core.purposes_consent.set(0, true); // Purpose 1
        core.purposes_consent.set(1, true); // Purpose 2

        assert!(core.has_purpose_consent(1));
        assert!(core.has_purpose_consent(2));
        assert!(!core.has_purpose_consent(3));
        assert!(!core.has_purpose_consent(0));
        assert!(!core.has_purpose_consent(25));
    }

    #[test]
    fn test_special_feature_opt_in() {
        let mut core = CoreString::new();
        core.special_feature_opt_ins.set(0, true); // Feature 1
        core.special_feature_opt_ins.set(4, true); // Feature 5

        assert!(core.has_special_feature_opt_in(1));
        assert!(core.has_special_feature_opt_in(5));
        assert!(!core.has_special_feature_opt_in(2));
        assert!(!core.has_special_feature_opt_in(0));
        assert!(!core.has_special_feature_opt_in(13));
    }

    #[test]
    fn test_vendor_consent() {
        let mut core = CoreString::new();
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(35);
        vendors.insert(100);
        core.vendor_consents = VendorSet::BitField(vendors);

        assert!(core.has_vendor_consent(1));
        assert!(core.has_vendor_consent(35));
        assert!(core.has_vendor_consent(100));
        assert!(!core.has_vendor_consent(2));
        assert!(!core.has_vendor_consent(999));
    }

    #[test]
    fn test_publisher_restrictions_creation() {
        let restrictions = PublisherRestrictions::new();

        assert_eq!(restrictions.num_restrictions, 0);
        assert!(restrictions.is_empty());
    }

    #[test]
    fn test_publisher_restriction_add() -> Result<()> {
        let mut restrictions = PublisherRestrictions::new();

        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(2);
        let vendor_set = VendorSet::BitField(vendors);

        let restriction =
            PublisherRestriction::new(1, RestrictionType::RequireConsent, vendor_set)?;

        restrictions.add_restriction(restriction);

        assert_eq!(restrictions.len(), 1);
        assert_eq!(restrictions.num_restrictions, 1);

        Ok(())
    }

    #[test]
    fn test_publisher_restriction_query() -> Result<()> {
        let mut restrictions = PublisherRestrictions::new();

        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(2);
        let vendor_set = VendorSet::BitField(vendors);

        let restriction = PublisherRestriction::new(1, RestrictionType::NotAllowed, vendor_set)?;

        restrictions.add_restriction(restriction);

        assert_eq!(
            restrictions.is_vendor_restricted(1, 1),
            Some(RestrictionType::NotAllowed)
        );
        assert_eq!(
            restrictions.is_vendor_restricted(1, 2),
            Some(RestrictionType::NotAllowed)
        );
        assert_eq!(restrictions.is_vendor_restricted(1, 3), None);
        assert_eq!(restrictions.is_vendor_restricted(2, 1), None);

        Ok(())
    }

    #[test]
    fn test_restriction_type_conversion() -> Result<()> {
        assert_eq!(RestrictionType::from_u8(0)?, RestrictionType::NotAllowed);
        assert_eq!(
            RestrictionType::from_u8(1)?,
            RestrictionType::RequireConsent
        );
        assert_eq!(
            RestrictionType::from_u8(2)?,
            RestrictionType::RequireLegitimateInterest
        );

        assert!(RestrictionType::from_u8(3).is_err());

        Ok(())
    }

    #[test]
    fn test_disclosed_vendors() {
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(35);
        let vendor_set = VendorSet::BitField(vendors);

        let disclosed = DisclosedVendors::new(vendor_set);

        assert_eq!(disclosed.segment_type, 1);
        assert!(disclosed.is_vendor_disclosed(1));
        assert!(disclosed.is_vendor_disclosed(35));
        assert!(!disclosed.is_vendor_disclosed(100));
    }

    #[test]
    fn test_allowed_vendors() {
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(2);
        let vendor_set = VendorSet::BitField(vendors);

        let allowed = AllowedVendors::new(vendor_set);

        assert_eq!(allowed.segment_type, 2);
        assert!(allowed.is_vendor_allowed(1));
        assert!(allowed.is_vendor_allowed(2));
        assert!(!allowed.is_vendor_allowed(3));
    }

    #[test]
    fn test_publisher_tc_standard_purposes() {
        let mut consent = BitField::new(24);
        consent.set(0, true); // Purpose 1
        consent.set(2, true); // Purpose 3

        let mut li_transparency = BitField::new(24);
        li_transparency.set(1, true); // Purpose 2

        let pub_tc = PublisherTC::new(consent, li_transparency);

        assert_eq!(pub_tc.segment_type, 3);
        assert_eq!(pub_tc.num_custom_purposes, 0);
        assert!(pub_tc.has_purpose_consent(1));
        assert!(pub_tc.has_purpose_consent(3));
        assert!(!pub_tc.has_purpose_consent(2));
    }

    #[test]
    fn test_publisher_tc_custom_purposes() {
        let pub_consent = BitField::new(24);
        let pub_li = BitField::new(24);

        let mut custom_consent = BitField::new(5);
        custom_consent.set(0, true); // Custom 1
        custom_consent.set(2, true); // Custom 3

        let custom_li = BitField::new(5);

        let pub_tc =
            PublisherTC::with_custom_purposes(pub_consent, pub_li, custom_consent, custom_li);

        assert_eq!(pub_tc.num_custom_purposes, 5);
        assert!(pub_tc.has_custom_purpose_consent(0));
        assert!(pub_tc.has_custom_purpose_consent(2));
        assert!(!pub_tc.has_custom_purpose_consent(1));
        assert!(!pub_tc.has_custom_purpose_consent(5));
    }

    #[test]
    fn test_invalid_purpose_id() {
        let vendor_set = VendorSet::new_bitfield();

        let result = PublisherRestriction::new(0, RestrictionType::NotAllowed, vendor_set.clone());
        assert!(result.is_err());

        let result = PublisherRestriction::new(25, RestrictionType::NotAllowed, vendor_set);
        assert!(result.is_err());
    }
}
