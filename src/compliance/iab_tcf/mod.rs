//! # IAB TCF 2.2 Implementation
//!
//! Complete implementation of IAB Transparency & Consent Framework v2.2
//!
//! This module provides production-ready parsing, encoding, and validation
//! of TC Strings (Transparency & Consent Strings) according to IAB TCF v2.2
//! specification.
//!
//! ## Features
//!
//! - **Complete TC String parsing** - Decode all segments (Core, Disclosed, Allowed, Publisher)
//! - **TC String encoding** - Create valid TC Strings programmatically
//! - **Base64url encoding/decoding** - RFC 4648 compliant
//! - **Bit-level operations** - Efficient `BitReader` and `BitWriter`
//! - **Global Vendor List integration** - Fetch and validate against GVL
//! - **Comprehensive validation** - Check TC String conformity to spec
//! - **IAB TCF v2.2** - Implements the TCF v2.2 TC String format
//!
//! ## Example
//!
//! ```rust
//! use icookforms::compliance::iab_tcf::{decode_tc_string, validate_tc_string};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Decode a TC String
//! let tc_string = "COxSKBCOxSKCCBcABCENAgCMAPzAAEPAAAqIDaQBQAMgAgABqAR0A2gDaQAwAMgAgANoAAA";
//! let tc_model = decode_tc_string(tc_string)?;
//!
//! assert_eq!(tc_model.core_string.version, 2);
//!
//! // Check vendor and purpose consent
//! let vendor_35 = tc_model.core_string.has_vendor_consent(35);
//! let purpose_1 = tc_model.core_string.has_purpose_consent(1);
//! println!("vendor 35: {vendor_35}, purpose 1: {purpose_1}");
//!
//! // Validate TC String (this example string has no Disclosed Vendors
//! // segment, which TCF v2.2 makes mandatory, so it is reported invalid)
//! let validation = validate_tc_string(tc_string)?;
//! for error in &validation.errors {
//!     println!("{error:?}");
//! }
//! # Ok(())
//! # }
//! ```

pub mod bit_reader;
pub mod bit_writer;
pub mod core_string;
pub mod gvl;
pub mod segments;
pub mod tc_string;
pub mod validation;
pub mod vendor_set;

// Re-exports for easy access
pub use bit_reader::BitReader;
pub use bit_writer::BitWriter;

pub use core_string::{
    AllowedVendors, CoreString, DisclosedVendors, PublisherRestriction, PublisherRestrictions,
    PublisherTC, RestrictionType, TCModel,
};

pub use gvl::{
    DataRetention, Feature, GlobalVendorList, Purpose, SpecialFeature, SpecialPurpose, Vendor,
    VendorUrl,
};

pub use tc_string::{decode_tc_string, encode_tc_string};

pub use validation::{
    quick_validate, validate_tc_string, validate_tc_string_with_gvl, ValidationError,
    ValidationResult, ValidationWarning,
};

pub use vendor_set::{VendorRange, VendorSet};

pub use segments::{
    EncodingType, PublisherTCAnalysis, SegmentAnalysis, SegmentAnalyzer, SegmentUtils,
    SegmentValidator,
};

use serde::{Deserialize, Serialize};
use std::fmt;

/// Error types for IAB TCF operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid TC String format
    #[error("Invalid TC String: {0}")]
    InvalidTCString(String),

    /// Unsupported TCF version number
    #[error("Unsupported TCF version: {0}")]
    UnsupportedVersion(u8),

    /// End of data reached unexpectedly during parsing
    #[error("End of data reached unexpectedly")]
    EndOfData,

    /// Too many bits requested from bit reader
    #[error("Too many bits requested: {0} (maximum 64)")]
    TooManyBits(u8),

    /// Base64 decoding failed
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),

    /// Invalid timestamp value
    #[error("Invalid timestamp: {0} deciseconds")]
    InvalidTimestamp(u64),

    /// Missing disclosed vendors segment (required in TCF v2.2+)
    #[error("Missing disclosed vendors segment (required in TCF v2.2+)")]
    MissingDisclosedVendors,

    /// Unknown segment type identifier
    #[error("Unknown segment type: {0}")]
    UnknownSegmentType(u8),

    /// Invalid segment type - expected vs found
    #[error("Invalid segment type: expected {1}, found {0}")]
    InvalidSegmentType(u8, u8),

    /// Invalid language code format
    #[error("Invalid language code: {0}")]
    InvalidLanguageCode(String),

    /// Invalid language encoding value
    #[error("Invalid language encoding: {0}")]
    InvalidLanguageEncoding(u64),

    /// Invalid purpose ID - must be in valid range
    #[error("Invalid purpose ID: {0} (must be 1-24)")]
    InvalidPurposeId(u8),

    /// Invalid restriction type value
    #[error("Invalid restriction type: {0}")]
    InvalidRestrictionType(u8),

    /// Empty vendor set where vendors are required
    #[error("Empty vendor set")]
    EmptyVendorSet,

    /// Invalid count of custom purposes
    #[error("Invalid custom purpose count")]
    InvalidCustomPurposeCount,

    /// UTF-8 string encoding error
    #[error("UTF-8 encoding error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Input/Output operation error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Network operation error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Global Vendor List fetch error
    #[error("GVL fetch error: HTTP {0}")]
    GVLFetchError(u16),

    /// Global Vendor List parsing error
    #[error("GVL parse error: {0}")]
    GVLParseError(String),

    /// JSON serialization/deserialization error
    #[error("JSON serialization error: {0}")]
    SerializationError(String),

    /// JSON processing error from `serde_json`
    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Result type for IAB TCF operations
pub type Result<T> = std::result::Result<T, Error>;

/// `BitField` structure for managing purposes and special features
///
/// A `BitField` represents a fixed-size array of boolean values, typically used
/// for encoding consent status for purposes (24 bits) or special features (12 bits).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitField {
    bits: Vec<bool>,
}

impl BitField {
    /// Creates a new `BitField` with the specified size
    ///
    /// # Example
    ///
    /// ```rust
    /// use icookforms::compliance::iab_tcf::BitField;
    ///
    /// let field = BitField::new(24); // For 24 purposes
    /// assert_eq!(field.len(), 24);
    /// ```
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            bits: vec![false; size],
        }
    }

    /// Sets the bit at the specified index
    ///
    /// # Example
    ///
    /// ```rust
    /// use icookforms::compliance::iab_tcf::BitField;
    ///
    /// let mut field = BitField::new(24);
    /// field.set(0, true); // Purpose 1 consented
    /// field.set(1, true); // Purpose 2 consented
    /// ```
    pub fn set(&mut self, index: usize, value: bool) {
        if index < self.bits.len() {
            self.bits[index] = value;
        }
    }

    /// Gets the bit value at the specified index
    ///
    /// Returns `false` if the index is out of bounds.
    #[must_use]
    pub fn get(&self, index: usize) -> bool {
        self.bits.get(index).copied().unwrap_or(false)
    }

    /// Checks if the bit at the specified index is set
    ///
    /// This is an alias for `get()` for more readable code.
    #[must_use]
    pub fn is_set(&self, index: usize) -> bool {
        self.get(index)
    }

    /// Returns the number of bits in the field
    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Checks if the `BitField` is empty (size = 0)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Returns an iterator over set bit indices
    ///
    /// # Example
    ///
    /// ```rust
    /// use icookforms::compliance::iab_tcf::BitField;
    ///
    /// let mut field = BitField::new(10);
    /// field.set(1, true);
    /// field.set(3, true);
    /// field.set(7, true);
    ///
    /// let set_bits: Vec<usize> = field.iter_set().collect();
    /// assert_eq!(set_bits, vec![1, 3, 7]);
    /// ```
    #[must_use = "Iterator must be used"]
    pub fn iter_set(&self) -> impl Iterator<Item = usize> + '_ {
        self.bits
            .iter()
            .enumerate()
            .filter_map(|(i, &bit)| if bit { Some(i) } else { None })
    }

    /// Converts the `BitField` to a vector of bytes
    ///
    /// Bits are packed into bytes, MSB first.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; self.bits.len().div_ceil(8)];
        for (i, &bit) in self.bits.iter().enumerate() {
            if bit {
                bytes[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        bytes
    }

    /// Creates a `BitField` from a vector of bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte array to decode
    /// * `size` - The number of bits to extract
    #[must_use]
    pub fn from_bytes(bytes: &[u8], size: usize) -> Self {
        let mut bits = vec![false; size];
        for (i, bit) in bits.iter_mut().enumerate().take(size) {
            if i < bytes.len() * 8 {
                *bit = (bytes[i / 8] & (1 << (7 - (i % 8)))) != 0;
            }
        }
        Self { bits }
    }
}

impl fmt::Display for BitField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitField(")?;
        for (i, &bit) in self.bits.iter().enumerate() {
            write!(f, "{}", if bit { '1' } else { '0' })?;
            if (i + 1) % 8 == 0 && i + 1 < self.bits.len() {
                write!(f, " ")?;
            }
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitfield_basic_operations() {
        let mut field = BitField::new(24);
        field.set(0, true);
        field.set(5, true);
        field.set(23, true);

        assert!(field.get(0));
        assert!(field.get(5));
        assert!(field.get(23));
        assert!(!field.get(1));
    }

    #[test]
    fn test_bitfield_iter_set() {
        let mut field = BitField::new(10);
        field.set(1, true);
        field.set(3, true);
        field.set(7, true);

        let set_bits: Vec<usize> = field.iter_set().collect();
        assert_eq!(set_bits, vec![1, 3, 7]);
    }

    #[test]
    fn test_bitfield_to_bytes() {
        let mut field = BitField::new(8);
        field.set(0, true); // 10000000
        field.set(7, true); // 10000001

        let bytes = field.to_bytes();
        assert_eq!(bytes, vec![0b1000_0001]);
    }

    #[test]
    fn test_bitfield_from_bytes() {
        let bytes = vec![0b1000_0001];
        let field = BitField::from_bytes(&bytes, 8);

        assert!(field.get(0));
        assert!(field.get(7));
        assert!(!field.get(1));
    }
}
