//! Additional TC String segments implementation
//!
//! This module re-exports the segment structures that are defined in `core_string.rs`
//! and provides additional utilities for working with TC String segments.
//!
//! # Segments
//!
//! A complete TC String can contain up to 4 segments:
//!
//! 1. **Core String** (mandatory) - Contains all essential consent data
//! 2. **Disclosed Vendors** (mandatory in v2.2+) - Vendors shown to the user
//! 3. **Allowed Vendors** (optional) - Publisher-filtered vendor list
//! 4. **Publisher TC** (optional) - Publisher's own consent signals
//!
//! # Example
//!
//! ```rust
//! use icookforms::compliance::iab_tcf::{DisclosedVendors, VendorSet};
//! use std::collections::HashSet;
//!
//! // Create disclosed vendors segment
//! let mut vendors = HashSet::new();
//! vendors.insert(1);
//! vendors.insert(35);
//! let disclosed = DisclosedVendors::new(VendorSet::BitField(vendors));
//!
//! // Check if vendor was disclosed
//! assert!(disclosed.is_vendor_disclosed(1));
//! ```

use serde::{Deserialize, Serialize};

use super::{BitField, Error, Result, VendorRange, VendorSet};

// Re-export segment types from core_string
pub use super::core_string::{AllowedVendors, DisclosedVendors, PublisherTC};

/// Utilities for working with TC String segments
pub struct SegmentUtils;

impl SegmentUtils {
    /// Creates a `DisclosedVendors` segment from a list of vendor IDs
    ///
    /// Automatically chooses the optimal encoding (`BitField` or Range).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use icookforms::compliance::iab_tcf::SegmentUtils;
    /// let vendors = vec![1, 2, 3, 35, 41];
    /// let disclosed = SegmentUtils::create_disclosed_vendors(&vendors);
    /// ```
    #[must_use]
    pub fn create_disclosed_vendors(vendor_ids: &[u16]) -> DisclosedVendors {
        let vendor_set = VendorSet::from_vec(vendor_ids, false);
        DisclosedVendors::new(vendor_set)
    }

    /// Creates an `AllowedVendors` segment from a list of vendor IDs
    ///
    /// Automatically chooses the optimal encoding (`BitField` or Range).
    #[must_use]
    pub fn create_allowed_vendors(vendor_ids: &[u16]) -> AllowedVendors {
        let vendor_set = VendorSet::from_vec(vendor_ids, false);
        AllowedVendors::new(vendor_set)
    }

    /// Creates a `PublisherTC` segment with standard purposes only
    pub fn create_publisher_tc(
        consented_purposes: Vec<u8>,
        li_purposes: Vec<u8>,
    ) -> Result<PublisherTC> {
        let mut consent = BitField::new(24);
        for purpose_id in consented_purposes {
            if purpose_id == 0 || purpose_id > 24 {
                return Err(Error::InvalidPurposeId(purpose_id));
            }
            consent.set((purpose_id - 1) as usize, true);
        }

        let mut li = BitField::new(24);
        for purpose_id in li_purposes {
            if purpose_id == 0 || purpose_id > 24 {
                return Err(Error::InvalidPurposeId(purpose_id));
            }
            li.set((purpose_id - 1) as usize, true);
        }

        Ok(PublisherTC::new(consent, li))
    }

    /// Creates a `PublisherTC` segment with custom purposes
    pub fn create_publisher_tc_with_custom(
        consented_purposes: Vec<u8>,
        li_purposes: Vec<u8>,
        custom_consented: Vec<u8>,
        custom_li: Vec<u8>,
    ) -> Result<PublisherTC> {
        let mut consent = BitField::new(24);
        for purpose_id in consented_purposes {
            if purpose_id == 0 || purpose_id > 24 {
                return Err(Error::InvalidPurposeId(purpose_id));
            }
            consent.set((purpose_id - 1) as usize, true);
        }

        let mut li = BitField::new(24);
        for purpose_id in li_purposes {
            if purpose_id == 0 || purpose_id > 24 {
                return Err(Error::InvalidPurposeId(purpose_id));
            }
            li.set((purpose_id - 1) as usize, true);
        }

        let max_custom = custom_consented
            .iter()
            .chain(custom_li.iter())
            .max()
            .copied()
            .unwrap_or(0);

        let mut custom_consent = BitField::new(max_custom as usize + 1);
        for custom_id in custom_consented {
            custom_consent.set(custom_id as usize, true);
        }

        let mut custom_li_field = BitField::new(max_custom as usize + 1);
        for custom_id in custom_li {
            custom_li_field.set(custom_id as usize, true);
        }

        Ok(PublisherTC::with_custom_purposes(
            consent,
            li,
            custom_consent,
            custom_li_field,
        ))
    }
}

/// Segment analysis utilities
pub struct SegmentAnalyzer;

impl SegmentAnalyzer {
    /// Analyzes a `DisclosedVendors` segment
    #[must_use]
    pub fn analyze_disclosed_vendors(disclosed: &DisclosedVendors) -> SegmentAnalysis {
        let vendor_ids = disclosed.vendors.to_vec();
        let max_id = disclosed.vendors.max_vendor_id().unwrap_or(0);

        SegmentAnalysis {
            segment_type: 1,
            vendor_count: vendor_ids.len(),
            max_vendor_id: max_id,
            encoding_type: match &disclosed.vendors {
                VendorSet::BitField(_) => EncodingType::BitField,
                VendorSet::Range(_) => EncodingType::Range,
            },
            estimated_size_bytes: estimate_segment_size(&disclosed.vendors),
        }
    }

    /// Analyzes an `AllowedVendors` segment
    #[must_use]
    pub fn analyze_allowed_vendors(allowed: &AllowedVendors) -> SegmentAnalysis {
        let vendor_ids = allowed.vendors.to_vec();
        let max_id = allowed.vendors.max_vendor_id().unwrap_or(0);

        SegmentAnalysis {
            segment_type: 2,
            vendor_count: vendor_ids.len(),
            max_vendor_id: max_id,
            encoding_type: match &allowed.vendors {
                VendorSet::BitField(_) => EncodingType::BitField,
                VendorSet::Range(_) => EncodingType::Range,
            },
            estimated_size_bytes: estimate_segment_size(&allowed.vendors),
        }
    }

    /// Analyzes a `PublisherTC` segment
    #[must_use]
    pub fn analyze_publisher_tc(publisher: &PublisherTC) -> PublisherTCAnalysis {
        let consented_purposes = count_set_bits(&publisher.pub_purposes_consent);
        let li_purposes = count_set_bits(&publisher.pub_purposes_li_transparency);
        let custom_consented = count_set_bits(&publisher.custom_purposes_consent);
        let custom_li = count_set_bits(&publisher.custom_purposes_li_transparency);

        PublisherTCAnalysis {
            segment_type: 3,
            num_consented_purposes: consented_purposes,
            num_li_purposes: li_purposes,
            num_custom_purposes: publisher.num_custom_purposes,
            num_custom_consented: custom_consented,
            num_custom_li: custom_li,
            estimated_size_bytes: 3 + 3 + 3 + 1 + // Fixed fields
                if publisher.num_custom_purposes > 0 {
                    (publisher.num_custom_purposes as usize * 2).div_ceil(8)
                } else {
                    0
                },
        }
    }
}

/// Result of segment analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentAnalysis {
    /// Segment type (1=Disclosed, 2=Allowed)
    pub segment_type: u8,

    /// Number of vendors in the segment
    pub vendor_count: usize,

    /// Maximum vendor ID
    pub max_vendor_id: u16,

    /// Encoding type used
    pub encoding_type: EncodingType,

    /// Estimated size in bytes
    pub estimated_size_bytes: usize,
}

/// Result of Publisher TC analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherTCAnalysis {
    /// Segment type (always 3)
    pub segment_type: u8,

    /// Number of standard purposes with consent
    pub num_consented_purposes: usize,

    /// Number of standard purposes with LI
    pub num_li_purposes: usize,

    /// Total number of custom purposes
    pub num_custom_purposes: u8,

    /// Number of custom purposes with consent
    pub num_custom_consented: usize,

    /// Number of custom purposes with LI
    pub num_custom_li: usize,

    /// Estimated size in bytes
    pub estimated_size_bytes: usize,
}

/// Type of encoding used for vendors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodingType {
    /// `BitField` encoding (one bit per vendor)
    BitField,

    /// Range encoding (start-end ranges)
    Range,
}

/// Estimates the size of a vendor segment in bytes
fn estimate_segment_size(vendor_set: &VendorSet) -> usize {
    match vendor_set {
        VendorSet::BitField(_) => {
            let max_id = vendor_set.max_vendor_id().unwrap_or(0);
            // 3 bits (segment type) + 16 bits (max ID) + 1 bit (encoding) + max_id bits
            (3 + 16 + 1 + max_id as usize).div_ceil(8)
        }
        VendorSet::Range(ranges) => {
            // 3 bits (segment type) + 16 bits (max ID) + 1 bit (encoding) + 12 bits (count)
            let mut bits: usize = 3 + 16 + 1 + 12;

            for range in ranges {
                bits += match range {
                    VendorRange::Single(_) => 1 + 16,        // is_range + vendor_id
                    VendorRange::Range(_, _) => 1 + 16 + 16, // is_range + start + end
                };
            }

            bits.div_ceil(8)
        }
    }
}

/// Counts the number of set bits in a `BitField`
fn count_set_bits(field: &BitField) -> usize {
    (0..field.len()).filter(|&i| field.is_set(i)).count()
}

/// Segment validation utilities
pub struct SegmentValidator;

impl SegmentValidator {
    /// Validates a `DisclosedVendors` segment
    pub fn validate_disclosed_vendors(disclosed: &DisclosedVendors) -> Result<()> {
        if disclosed.segment_type != 1 {
            return Err(Error::InvalidSegmentType(disclosed.segment_type, 1));
        }

        if disclosed.vendors.is_empty() {
            return Err(Error::EmptyVendorSet);
        }

        Ok(())
    }

    /// Validates an `AllowedVendors` segment
    pub fn validate_allowed_vendors(allowed: &AllowedVendors) -> Result<()> {
        if allowed.segment_type != 2 {
            return Err(Error::InvalidSegmentType(allowed.segment_type, 2));
        }

        if allowed.vendors.is_empty() {
            return Err(Error::EmptyVendorSet);
        }

        Ok(())
    }

    /// Validates a `PublisherTC` segment
    pub fn validate_publisher_tc(publisher: &PublisherTC) -> Result<()> {
        if publisher.segment_type != 3 {
            return Err(Error::InvalidSegmentType(publisher.segment_type, 3));
        }

        if publisher.num_custom_purposes > 0 {
            if publisher.custom_purposes_consent.len() != publisher.num_custom_purposes as usize {
                return Err(Error::InvalidCustomPurposeCount);
            }
            if publisher.custom_purposes_li_transparency.len()
                != publisher.num_custom_purposes as usize
            {
                return Err(Error::InvalidCustomPurposeCount);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_disclosed_vendors() {
        let vendors = vec![1, 2, 3, 35, 41];
        let disclosed = SegmentUtils::create_disclosed_vendors(&vendors);

        assert_eq!(disclosed.segment_type, 1);
        assert!(disclosed.is_vendor_disclosed(1));
        assert!(disclosed.is_vendor_disclosed(35));
        assert!(!disclosed.is_vendor_disclosed(100));
    }

    #[test]
    fn test_create_allowed_vendors() {
        let vendors = vec![1, 5, 10];
        let allowed = SegmentUtils::create_allowed_vendors(&vendors);

        assert_eq!(allowed.segment_type, 2);
        assert!(allowed.is_vendor_allowed(1));
        assert!(allowed.is_vendor_allowed(5));
        assert!(!allowed.is_vendor_allowed(2));
    }

    #[test]
    fn test_create_publisher_tc() -> Result<()> {
        let consented = vec![1, 2, 3];
        let li = vec![7, 8];
        let pub_tc = SegmentUtils::create_publisher_tc(consented, li)?;

        assert_eq!(pub_tc.segment_type, 3);
        assert!(pub_tc.has_purpose_consent(1));
        assert!(pub_tc.has_purpose_consent(2));
        assert!(!pub_tc.has_purpose_consent(4));

        Ok(())
    }

    #[test]
    fn test_create_publisher_tc_with_custom() -> Result<()> {
        let consented = vec![1, 2];
        let li = vec![7];
        let custom_consented = vec![0, 1];
        let custom_li = vec![2];

        let pub_tc = SegmentUtils::create_publisher_tc_with_custom(
            consented,
            li,
            custom_consented,
            custom_li,
        )?;

        assert_eq!(pub_tc.segment_type, 3);
        assert!(pub_tc.has_custom_purpose_consent(0));
        assert!(pub_tc.has_custom_purpose_consent(1));
        assert!(!pub_tc.has_custom_purpose_consent(3));

        Ok(())
    }

    #[test]
    fn test_invalid_purpose_id() {
        let result = SegmentUtils::create_publisher_tc(vec![0], vec![]);
        assert!(result.is_err());

        let result = SegmentUtils::create_publisher_tc(vec![25], vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_disclosed_vendors() {
        let vendors = vec![1, 2, 3, 4, 5];
        let disclosed = SegmentUtils::create_disclosed_vendors(&vendors);

        let analysis = SegmentAnalyzer::analyze_disclosed_vendors(&disclosed);

        assert_eq!(analysis.segment_type, 1);
        assert_eq!(analysis.vendor_count, 5);
        assert_eq!(analysis.max_vendor_id, 5);
    }

    #[test]
    fn test_analyze_allowed_vendors() {
        let vendors = vec![1, 100, 200];
        let allowed = SegmentUtils::create_allowed_vendors(&vendors);

        let analysis = SegmentAnalyzer::analyze_allowed_vendors(&allowed);

        assert_eq!(analysis.segment_type, 2);
        assert_eq!(analysis.vendor_count, 3);
        assert_eq!(analysis.max_vendor_id, 200);
    }

    #[test]
    fn test_analyze_publisher_tc() -> Result<()> {
        let consented = vec![1, 2, 3];
        let li = vec![7, 8];
        let pub_tc = SegmentUtils::create_publisher_tc(consented, li)?;

        let analysis = SegmentAnalyzer::analyze_publisher_tc(&pub_tc);

        assert_eq!(analysis.segment_type, 3);
        assert_eq!(analysis.num_consented_purposes, 3);
        assert_eq!(analysis.num_li_purposes, 2);
        assert_eq!(analysis.num_custom_purposes, 0);

        Ok(())
    }

    #[test]
    fn test_validate_disclosed_vendors() {
        let vendors = vec![1, 2];
        let disclosed = SegmentUtils::create_disclosed_vendors(&vendors);

        let result = SegmentValidator::validate_disclosed_vendors(&disclosed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_allowed_vendors() {
        let vendors = vec![1, 2];
        let allowed = SegmentUtils::create_allowed_vendors(&vendors);

        let result = SegmentValidator::validate_allowed_vendors(&allowed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_publisher_tc() -> Result<()> {
        let pub_tc = SegmentUtils::create_publisher_tc(vec![1], vec![2])?;

        let result = SegmentValidator::validate_publisher_tc(&pub_tc);
        assert!(result.is_ok());

        Ok(())
    }
}
