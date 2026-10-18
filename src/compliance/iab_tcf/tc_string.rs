//! TC String encoding and decoding implementation for IAB TCF 2.2
//!
//! This module provides the core functionality for encoding and decoding
//! Transparency & Consent Strings according to the IAB TCF v2.2 specification.
//!
//! # TC String Format
//!
//! A TC String consists of multiple segments separated by dots:
//! ```text
//! <CoreString>.<DisclosedVendors>.<AllowedVendors>.<PublisherTC>
//! ```
//!
//! - **`CoreString`**: Mandatory - Contains all essential consent data
//! - **`DisclosedVendors`**: Mandatory in v2.2+ - Lists disclosed vendors
//! - **`AllowedVendors`**: Optional - Publisher-filtered vendor list
//! - **`PublisherTC`**: Optional - Publisher's own consent signals
//!
//! # Examples
//!
//! ```rust
//! use icookforms::compliance::iab_tcf::{decode_tc_string, encode_tc_string, SegmentUtils};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Decode a TC String
//! let tc_string = "COxSKBCOxSKCCBcABCENAgCMAPzAAEPAAAqIDaQBQAMgAgABqAR0A2gDaQAwAMgAgANoAAA";
//! let mut tc_model = decode_tc_string(tc_string)?;
//!
//! // Check consent
//! let has_consent = tc_model.core_string.has_vendor_consent(35);
//!
//! // TCF v2.2 requires a Disclosed Vendors segment before encoding
//! tc_model.disclosed_vendors = Some(SegmentUtils::create_disclosed_vendors(&[35]));
//!
//! // Encode back to TC String
//! let encoded = encode_tc_string(&tc_model)?;
//! assert!(decode_tc_string(&encoded)?.disclosed_vendors.is_some());
//! # Ok(())
//! # }
//! ```
//!
//! Reference: IAB TCF v2.2 Specification

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};

use super::{
    AllowedVendors, BitField, BitReader, BitWriter, CoreString, DisclosedVendors, Error,
    PublisherRestriction, PublisherRestrictions, PublisherTC, RestrictionType, Result, TCModel,
    VendorRange, VendorSet,
};

/// Decodes a complete TC String into a `TCModel`
///
/// # Arguments
///
/// * `tc_string` - The base64url-encoded TC String
///
/// # Returns
///
/// A `TCModel` containing the decoded consent data, or an error if the string is invalid.
///
/// # Errors
///
/// Returns an error if:
/// - The TC String is malformed or empty
/// - Base64 decoding fails
/// - Any field contains invalid data
/// - The version is not supported (must be 2)
///
/// # Example
///
/// ```rust
/// # use icookforms::compliance::iab_tcf::decode_tc_string;
/// let tc_model = decode_tc_string("COxSKBCOxSKCCBcABCENAgCMAPzAAEPAAAqIDaQBQAMgAgABqAR0A2gDaQAwAMgAgANoAAA")?;
/// assert_eq!(tc_model.core_string.version, 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use = "TC string decoding failure must be handled"]
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
pub fn decode_tc_string(tc_string: &str) -> Result<TCModel> {
    if tc_string.is_empty() {
        return Err(Error::InvalidTCString("Empty TC String".to_string()));
    }

    // Split segments by '.'
    let segments: Vec<&str> = tc_string.split('.').collect();

    if segments.is_empty() {
        return Err(Error::InvalidTCString("No segments found".to_string()));
    }

    // Decode Core String (segment 0 - mandatory)
    let core_string = decode_core_string(segments[0])?;

    let mut tc_model = TCModel {
        core_string,
        disclosed_vendors: None,
        allowed_vendors: None,
        publisher_tc: None,
    };

    // Decode additional segments
    for segment in segments.iter().skip(1) {
        let segment_type = detect_segment_type(segment)?;

        match segment_type {
            1 => tc_model.disclosed_vendors = Some(decode_disclosed_vendors(segment)?),
            2 => tc_model.allowed_vendors = Some(decode_allowed_vendors(segment)?),
            3 => tc_model.publisher_tc = Some(decode_publisher_tc(segment)?),
            _ => return Err(Error::UnknownSegmentType(segment_type)),
        }
    }

    Ok(tc_model)
}

/// Encodes a `TCModel` into a TC String
///
/// # Arguments
///
/// * `tc_model` - The consent model to encode
///
/// # Returns
///
/// A base64url-encoded TC String, or an error if encoding fails.
///
/// # Errors
///
/// Returns an error if:
/// - Required segments are missing (e.g., disclosed vendors in v2.2+)
/// - Any field contains invalid data
/// - Encoding operations fail
///
/// # Example
///
/// ```rust
/// # use icookforms::compliance::iab_tcf::{decode_tc_string, encode_tc_string, SegmentUtils};
/// # let mut tc_model = decode_tc_string("COxSKBCOxSKCCBcABCENAgCMAPzAAEPAAAqIDaQBQAMgAgABqAR0A2gDaQAwAMgAgANoAAA")?;
/// tc_model.disclosed_vendors = Some(SegmentUtils::create_disclosed_vendors(&[35]));
/// let tc_string = encode_tc_string(&tc_model)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use = "TC string encoding failure must be handled"]
pub fn encode_tc_string(tc_model: &TCModel) -> Result<String> {
    let mut segments = Vec::new();

    // Encode Core String (mandatory)
    segments.push(encode_core_string(&tc_model.core_string)?);

    // Encode Disclosed Vendors (mandatory in v2.2+)
    if let Some(ref disclosed) = tc_model.disclosed_vendors {
        segments.push(encode_disclosed_vendors(disclosed)?);
    } else {
        // In TCF v2.2+, disclosed vendors segment is mandatory
        return Err(Error::MissingDisclosedVendors);
    }

    // Encode optional segments
    if let Some(ref allowed) = tc_model.allowed_vendors {
        segments.push(encode_allowed_vendors(allowed)?);
    }

    if let Some(ref publisher) = tc_model.publisher_tc {
        segments.push(encode_publisher_tc(publisher)?);
    }

    // Join segments with '.'
    Ok(segments.join("."))
}

/// Decodes the Core String segment
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_core_string(core_str: &str) -> Result<CoreString> {
    // Base64url decode
    let bytes = base64_url_decode(core_str)?;

    // Create BitReader
    let mut reader = BitReader::new(&bytes);

    // Read version (6 bits)
    let version = reader.read_bits(6)? as u8;
    if version != 2 {
        return Err(Error::UnsupportedVersion(version));
    }

    // Read timestamps (36 bits each)
    let created = decode_datetime(reader.read_bits(36)?)?;
    let last_updated = decode_datetime(reader.read_bits(36)?)?;

    // Read CMP identification (12 bits each)
    let cmp_id = reader.read_bits(12)? as u16;
    let cmp_version = reader.read_bits(12)? as u16;

    // Read consent screen (6 bits)
    let consent_screen = reader.read_bits(6)? as u8;

    // Read consent language (12 bits)
    let consent_language = decode_language(reader.read_bits(12)?)?;

    // Read vendor list version (12 bits)
    let vendor_list_version = reader.read_bits(12)? as u16;

    // Read TCF policy version (6 bits)
    let tcf_policy_version = reader.read_bits(6)? as u8;

    // Read flags (1 bit each)
    let is_service_specific = reader.read_bit()?;
    let use_non_standard_texts = reader.read_bit()?;

    // Read special features opt-ins (12 bits)
    let special_feature_opt_ins = reader.read_bitfield(12)?;

    // Read purposes consent (24 bits)
    let purposes_consent = reader.read_bitfield(24)?;

    // Read purposes legitimate interest transparency (24 bits)
    let purposes_li_transparency = reader.read_bitfield(24)?;

    // Read purpose one treatment (1 bit)
    let purpose_one_treatment = reader.read_bit()?;

    // Read publisher country code (12 bits)
    let publisher_cc = decode_language(reader.read_bits(12)?)?;

    // Read vendor consent section
    let vendor_consents = decode_vendor_section(&mut reader)?;

    // Read vendor legitimate interest section
    let vendor_legitimate_interests = decode_vendor_section(&mut reader)?;

    // Read publisher restrictions (if remaining bits)
    let publisher_restrictions = if reader.has_remaining() {
        decode_publisher_restrictions(&mut reader)?
    } else {
        PublisherRestrictions::new()
    };

    Ok(CoreString {
        version,
        created,
        last_updated,
        cmp_id,
        cmp_version,
        consent_screen,
        consent_language,
        vendor_list_version,
        tcf_policy_version,
        is_service_specific,
        use_non_standard_texts,
        special_feature_opt_ins,
        purposes_consent,
        purposes_li_transparency,
        purpose_one_treatment,
        publisher_cc,
        vendor_consents,
        vendor_legitimate_interests,
        publisher_restrictions,
    })
}

/// Encodes a Core String
fn encode_core_string(core: &CoreString) -> Result<String> {
    let mut writer = BitWriter::new();

    // Write version (6 bits)
    writer.write_bits(u64::from(core.version), 6)?;

    // Write timestamps (36 bits each)
    writer.write_bits(encode_datetime(core.created), 36)?;
    writer.write_bits(encode_datetime(core.last_updated), 36)?;

    // Write CMP identification (12 bits each)
    writer.write_bits(u64::from(core.cmp_id), 12)?;
    writer.write_bits(u64::from(core.cmp_version), 12)?;

    // Write consent screen (6 bits)
    writer.write_bits(u64::from(core.consent_screen), 6)?;

    // Write consent language (12 bits)
    writer.write_bits(encode_language(&core.consent_language)?, 12)?;

    // Write vendor list version (12 bits)
    writer.write_bits(u64::from(core.vendor_list_version), 12)?;

    // Write TCF policy version (6 bits)
    writer.write_bits(u64::from(core.tcf_policy_version), 6)?;

    // Write flags (1 bit each)
    writer.write_bit(core.is_service_specific)?;
    writer.write_bit(core.use_non_standard_texts)?;

    // Write special features opt-ins (12 bits)
    write_bitfield(&mut writer, &core.special_feature_opt_ins, 12)?;

    // Write purposes consent (24 bits)
    write_bitfield(&mut writer, &core.purposes_consent, 24)?;

    // Write purposes LI transparency (24 bits)
    write_bitfield(&mut writer, &core.purposes_li_transparency, 24)?;

    // Write purpose one treatment (1 bit)
    writer.write_bit(core.purpose_one_treatment)?;

    // Write publisher country code (12 bits)
    writer.write_bits(encode_language(&core.publisher_cc)?, 12)?;

    // Write vendor consent section
    encode_vendor_section(&mut writer, &core.vendor_consents)?;

    // Write vendor legitimate interest section
    encode_vendor_section(&mut writer, &core.vendor_legitimate_interests)?;

    // Write publisher restrictions
    encode_publisher_restrictions(&mut writer, &core.publisher_restrictions)?;

    // Convert to base64url
    let bytes = writer.to_bytes();
    Ok(base64_url_encode(&bytes))
}

/// Decodes a vendor section (consent or legitimate interest)
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_vendor_section(reader: &mut BitReader) -> Result<VendorSet> {
    // Read max vendor ID (16 bits)
    let max_vendor_id = reader.read_bits(16)? as u16;

    // Read encoding type (1 bit)
    let is_range_encoding = reader.read_bit()?;

    if is_range_encoding {
        decode_vendor_range(reader, max_vendor_id)
    } else {
        decode_vendor_bitfield(reader, max_vendor_id)
    }
}

/// Decodes vendors using `BitField` encoding
fn decode_vendor_bitfield(reader: &mut BitReader, max_vendor_id: u16) -> Result<VendorSet> {
    use std::collections::HashSet;
    let mut vendors = HashSet::new();

    for vendor_id in 1..=max_vendor_id {
        if reader.read_bit()? {
            vendors.insert(vendor_id);
        }
    }

    Ok(VendorSet::BitField(vendors))
}

/// Decodes vendors using Range encoding
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_vendor_range(reader: &mut BitReader, _max_vendor_id: u16) -> Result<VendorSet> {
    // Read number of entries (12 bits)
    let num_entries = reader.read_bits(12)? as u16;
    let mut ranges = Vec::new();

    for _ in 0..num_entries {
        let is_range = reader.read_bit()?;

        if is_range {
            let start_id = reader.read_bits(16)? as u16;
            let end_id = reader.read_bits(16)? as u16;
            ranges.push(VendorRange::Range(start_id, end_id));
        } else {
            let vendor_id = reader.read_bits(16)? as u16;
            ranges.push(VendorRange::Single(vendor_id));
        }
    }

    Ok(VendorSet::Range(ranges))
}

/// Encodes a vendor section
fn encode_vendor_section(writer: &mut BitWriter, vendor_set: &VendorSet) -> Result<()> {
    let max_vendor_id = vendor_set.max_vendor_id().unwrap_or(0);

    // Write max vendor ID (16 bits)
    writer.write_bits(u64::from(max_vendor_id), 16)?;

    match vendor_set {
        VendorSet::BitField(vendors) => {
            // Write encoding type: 0 = BitField (1 bit)
            writer.write_bit(false)?;

            // Write vendor bits
            for vendor_id in 1..=max_vendor_id {
                writer.write_bit(vendors.contains(&vendor_id))?;
            }
        }
        VendorSet::Range(ranges) => {
            // Write encoding type: 1 = Range (1 bit)
            writer.write_bit(true)?;

            // Write number of entries (12 bits)
            writer.write_bits(ranges.len() as u64, 12)?;

            // Write each range
            for range in ranges {
                match range {
                    VendorRange::Single(id) => {
                        writer.write_bit(false)?; // is_range = false
                        writer.write_bits(u64::from(*id), 16)?;
                    }
                    VendorRange::Range(start, end) => {
                        writer.write_bit(true)?; // is_range = true
                        writer.write_bits(u64::from(*start), 16)?;
                        writer.write_bits(u64::from(*end), 16)?;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Decodes publisher restrictions
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_publisher_restrictions(reader: &mut BitReader) -> Result<PublisherRestrictions> {
    // Read number of restrictions (12 bits)
    let num_restrictions = reader.read_bits(12)? as u16;
    let mut restrictions = PublisherRestrictions::with_capacity(num_restrictions as usize);

    for _ in 0..num_restrictions {
        // Read purpose ID (6 bits)
        let purpose_id = reader.read_bits(6)? as u8;

        // Read restriction type (2 bits)
        let restriction_type_val = reader.read_bits(2)? as u8;
        let restriction_type = RestrictionType::from_u8(restriction_type_val)?;

        // Read vendor section
        let vendors = decode_vendor_section(reader)?;

        let restriction = PublisherRestriction::new(purpose_id, restriction_type, vendors)?;
        restrictions.add_restriction(restriction);
    }

    Ok(restrictions)
}

/// Encodes publisher restrictions
fn encode_publisher_restrictions(
    writer: &mut BitWriter,
    restrictions: &PublisherRestrictions,
) -> Result<()> {
    // Write number of restrictions (12 bits)
    writer.write_bits(u64::from(restrictions.num_restrictions), 12)?;

    // Write each restriction
    for restriction in &restrictions.restrictions {
        // Write purpose ID (6 bits)
        writer.write_bits(u64::from(restriction.purpose_id), 6)?;

        // Write restriction type (2 bits)
        writer.write_bits(u64::from(restriction.restriction_type.to_u8()), 2)?;

        // Write vendor section
        encode_vendor_section(writer, &restriction.vendors)?;
    }

    Ok(())
}

/// Detects the segment type from a segment string
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn detect_segment_type(segment: &str) -> Result<u8> {
    // Decode segment to read first 3 bits
    let bytes = base64_url_decode(segment)?;
    let mut reader = BitReader::new(&bytes);

    let segment_type = reader.read_bits(3)? as u8;
    Ok(segment_type)
}

/// Decodes a Disclosed Vendors segment
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_disclosed_vendors(segment: &str) -> Result<DisclosedVendors> {
    let bytes = base64_url_decode(segment)?;
    let mut reader = BitReader::new(&bytes);

    // Read segment type (3 bits) - should be 1
    let segment_type = reader.read_bits(3)? as u8;
    if segment_type != 1 {
        return Err(Error::InvalidSegmentType(segment_type, 1));
    }

    // Read vendor section
    let vendors = decode_vendor_section(&mut reader)?;

    Ok(DisclosedVendors {
        segment_type,
        vendors,
    })
}

/// Encodes a Disclosed Vendors segment
fn encode_disclosed_vendors(disclosed: &DisclosedVendors) -> Result<String> {
    let mut writer = BitWriter::new();

    // Write segment type (3 bits)
    writer.write_bits(1, 3)?;

    // Write vendor section
    encode_vendor_section(&mut writer, &disclosed.vendors)?;

    let bytes = writer.to_bytes();
    Ok(base64_url_encode(&bytes))
}

/// Decodes an Allowed Vendors segment
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_allowed_vendors(segment: &str) -> Result<AllowedVendors> {
    let bytes = base64_url_decode(segment)?;
    let mut reader = BitReader::new(&bytes);

    // Read segment type (3 bits) - should be 2
    let segment_type = reader.read_bits(3)? as u8;
    if segment_type != 2 {
        return Err(Error::InvalidSegmentType(segment_type, 2));
    }

    // Read vendor section
    let vendors = decode_vendor_section(&mut reader)?;

    Ok(AllowedVendors {
        segment_type,
        vendors,
    })
}

/// Encodes an Allowed Vendors segment
fn encode_allowed_vendors(allowed: &AllowedVendors) -> Result<String> {
    let mut writer = BitWriter::new();

    // Write segment type (3 bits)
    writer.write_bits(2, 3)?;

    // Write vendor section
    encode_vendor_section(&mut writer, &allowed.vendors)?;

    let bytes = writer.to_bytes();
    Ok(base64_url_encode(&bytes))
}

/// Decodes a Publisher TC segment
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_publisher_tc(segment: &str) -> Result<PublisherTC> {
    let bytes = base64_url_decode(segment)?;
    let mut reader = BitReader::new(&bytes);

    // Read segment type (3 bits) - should be 3
    let segment_type = reader.read_bits(3)? as u8;
    if segment_type != 3 {
        return Err(Error::InvalidSegmentType(segment_type, 3));
    }

    // Read publisher purposes consent (24 bits)
    let pub_purposes_consent = reader.read_bitfield(24)?;

    // Read publisher purposes LI transparency (24 bits)
    let pub_purposes_li_transparency = reader.read_bitfield(24)?;

    // Read number of custom purposes (6 bits)
    let num_custom_purposes = reader.read_bits(6)? as u8;

    // Read custom purposes consent
    let custom_purposes_consent = if num_custom_purposes > 0 {
        reader.read_bitfield(num_custom_purposes as usize)?
    } else {
        BitField::new(0)
    };

    // Read custom purposes LI transparency
    let custom_purposes_li_transparency = if num_custom_purposes > 0 {
        reader.read_bitfield(num_custom_purposes as usize)?
    } else {
        BitField::new(0)
    };

    Ok(PublisherTC {
        segment_type,
        pub_purposes_consent,
        pub_purposes_li_transparency,
        num_custom_purposes,
        custom_purposes_consent,
        custom_purposes_li_transparency,
    })
}

/// Encodes a Publisher TC segment
fn encode_publisher_tc(publisher: &PublisherTC) -> Result<String> {
    let mut writer = BitWriter::new();

    // Write segment type (3 bits)
    writer.write_bits(3, 3)?;

    // Write publisher purposes consent (24 bits)
    write_bitfield(&mut writer, &publisher.pub_purposes_consent, 24)?;

    // Write publisher purposes LI transparency (24 bits)
    write_bitfield(&mut writer, &publisher.pub_purposes_li_transparency, 24)?;

    // Write number of custom purposes (6 bits)
    writer.write_bits(u64::from(publisher.num_custom_purposes), 6)?;

    // Write custom purposes consent
    if publisher.num_custom_purposes > 0 {
        write_bitfield(
            &mut writer,
            &publisher.custom_purposes_consent,
            publisher.num_custom_purposes as usize,
        )?;
    }

    // Write custom purposes LI transparency
    if publisher.num_custom_purposes > 0 {
        write_bitfield(
            &mut writer,
            &publisher.custom_purposes_li_transparency,
            publisher.num_custom_purposes as usize,
        )?;
    }

    let bytes = writer.to_bytes();
    Ok(base64_url_encode(&bytes))
}

// ===== Utility Functions =====

/// Encodes a `DateTime` to deciseconds since Unix epoch
///
/// TCF timestamps are stored as deciseconds (1/10 second) since epoch.
#[allow(clippy::cast_sign_loss)] // Timestamps after epoch are positive
fn encode_datetime(dt: DateTime<Utc>) -> u64 {
    (dt.timestamp() * 10) as u64
}

/// Decodes deciseconds since epoch to `DateTime`
#[allow(clippy::cast_possible_wrap)] // Timestamp range fits in i64
fn decode_datetime(deciseconds: u64) -> Result<DateTime<Utc>> {
    let seconds = (deciseconds / 10) as i64;
    Utc.timestamp_opt(seconds, 0)
        .single()
        .ok_or(Error::InvalidTimestamp(deciseconds))
}

/// Encodes a two-letter language code to 12 bits
///
/// Converts ISO 639-1 language codes like "EN", "FR" to 12-bit values.
/// Each letter is encoded as 6 bits (A=0, B=1, ... Z=25).
fn encode_language(lang: &str) -> Result<u64> {
    if lang.len() != 2 {
        return Err(Error::InvalidLanguageCode(lang.to_string()));
    }

    let bytes = lang.as_bytes();
    let first = bytes[0].to_ascii_uppercase();
    let second = bytes[1].to_ascii_uppercase();

    if !first.is_ascii_uppercase() || !second.is_ascii_uppercase() {
        return Err(Error::InvalidLanguageCode(lang.to_string()));
    }

    let value = u64::from(first - b'A') << 6 | u64::from(second - b'A');
    Ok(value)
}

/// Decodes 12 bits to a two-letter language code
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for IAB TCF spec compliance
fn decode_language(value: u64) -> Result<String> {
    let first = ((value >> 6) & 0x3F) as u8;
    let second = (value & 0x3F) as u8;

    if first > 25 || second > 25 {
        return Err(Error::InvalidLanguageEncoding(value));
    }

    let first_char = (first + b'A') as char;
    let second_char = (second + b'A') as char;

    Ok(format!("{first_char}{second_char}"))
}

/// Encodes bytes to base64url (no padding)
fn base64_url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url string to bytes
fn base64_url_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Base64DecodeError(e.to_string()))
}

/// Writes a `BitField` with a specific size
fn write_bitfield(writer: &mut BitWriter, field: &BitField, size: usize) -> Result<()> {
    for i in 0..size {
        writer.write_bit(field.get(i))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn create_test_core_string() -> CoreString {
        let mut core = CoreString::new();
        core.version = 2;
        core.cmp_id = 1;
        core.cmp_version = 1;
        core.vendor_list_version = 100;
        core.tcf_policy_version = 2;

        // Set some purposes
        core.purposes_consent.set(0, true); // Purpose 1
        core.purposes_consent.set(1, true); // Purpose 2

        // Set some vendors
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(35);
        core.vendor_consents = VendorSet::BitField(vendors);

        core
    }

    #[test]
    fn test_encode_decode_datetime() -> Result<()> {
        let dt = Utc::now();
        let encoded = encode_datetime(dt);
        let decoded = decode_datetime(encoded)?;

        // Should be equal within 1 second (deciseconds precision)
        assert_eq!(dt.timestamp(), decoded.timestamp());
        Ok(())
    }

    #[test]
    fn test_encode_decode_language() -> Result<()> {
        let lang = "EN";
        let encoded = encode_language(lang)?;
        let decoded = decode_language(encoded)?;
        assert_eq!(lang, decoded);

        let lang = "FR";
        let encoded = encode_language(lang)?;
        let decoded = decode_language(encoded)?;
        assert_eq!(lang, decoded);

        Ok(())
    }

    #[test]
    fn test_invalid_language() {
        assert!(encode_language("E").is_err());
        assert!(encode_language("ENG").is_err());
        assert!(encode_language("12").is_err());
    }

    #[test]
    fn test_base64_encode_decode() -> Result<()> {
        let data = b"Hello, World!";
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded)?;
        assert_eq!(data, decoded.as_slice());
        Ok(())
    }

    #[test]
    fn test_encode_decode_core_string() -> Result<()> {
        let core = create_test_core_string();
        let encoded = encode_core_string(&core)?;
        let decoded = decode_core_string(&encoded)?;

        assert_eq!(core.version, decoded.version);
        assert_eq!(core.cmp_id, decoded.cmp_id);
        assert_eq!(core.vendor_list_version, decoded.vendor_list_version);

        Ok(())
    }

    #[test]
    fn test_encode_decode_bitfield_vendors() -> Result<()> {
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(5);
        vendors.insert(10);
        let vendor_set = VendorSet::BitField(vendors.clone());

        let mut writer = BitWriter::new();
        encode_vendor_section(&mut writer, &vendor_set)?;
        let bytes = writer.to_bytes();

        let mut reader = BitReader::new(&bytes);
        let decoded = decode_vendor_section(&mut reader)?;

        assert_eq!(vendor_set, decoded);
        Ok(())
    }

    #[test]
    fn test_encode_decode_range_vendors() -> Result<()> {
        let ranges = vec![
            VendorRange::Single(1),
            VendorRange::Range(3, 5),
            VendorRange::Single(10),
        ];
        let vendor_set = VendorSet::Range(ranges);

        let mut writer = BitWriter::new();
        encode_vendor_section(&mut writer, &vendor_set)?;
        let bytes = writer.to_bytes();

        let mut reader = BitReader::new(&bytes);
        let decoded = decode_vendor_section(&mut reader)?;

        assert_eq!(vendor_set, decoded);
        Ok(())
    }

    #[test]
    fn test_encode_decode_publisher_restrictions() -> Result<()> {
        let mut restrictions = PublisherRestrictions::new();

        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(2);
        let restriction = PublisherRestriction::new(
            1,
            RestrictionType::RequireConsent,
            VendorSet::BitField(vendors),
        )?;
        restrictions.add_restriction(restriction);

        let mut writer = BitWriter::new();
        encode_publisher_restrictions(&mut writer, &restrictions)?;
        let bytes = writer.to_bytes();

        let mut reader = BitReader::new(&bytes);
        let decoded = decode_publisher_restrictions(&mut reader)?;

        assert_eq!(restrictions.len(), decoded.len());
        Ok(())
    }

    #[test]
    fn test_encode_decode_disclosed_vendors() -> Result<()> {
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(35);
        let disclosed = DisclosedVendors::new(VendorSet::BitField(vendors));

        let encoded = encode_disclosed_vendors(&disclosed)?;
        let decoded = decode_disclosed_vendors(&encoded)?;

        assert_eq!(disclosed, decoded);
        Ok(())
    }

    #[test]
    fn test_encode_decode_allowed_vendors() -> Result<()> {
        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(2);
        let allowed = AllowedVendors::new(VendorSet::BitField(vendors));

        let encoded = encode_allowed_vendors(&allowed)?;
        let decoded = decode_allowed_vendors(&encoded)?;

        assert_eq!(allowed, decoded);
        Ok(())
    }

    #[test]
    fn test_encode_decode_publisher_tc() -> Result<()> {
        let mut consent = BitField::new(24);
        consent.set(0, true);

        let li = BitField::new(24);

        let pub_tc = PublisherTC::new(consent, li);

        let encoded = encode_publisher_tc(&pub_tc)?;
        let decoded = decode_publisher_tc(&encoded)?;

        assert_eq!(pub_tc, decoded);
        Ok(())
    }

    #[test]
    fn test_encode_decode_full_tc_string() -> Result<()> {
        let core = create_test_core_string();

        let mut vendors = HashSet::new();
        vendors.insert(1);
        vendors.insert(35);
        let disclosed = DisclosedVendors::new(VendorSet::BitField(vendors));

        let tc_model = TCModel {
            core_string: core,
            disclosed_vendors: Some(disclosed),
            allowed_vendors: None,
            publisher_tc: None,
        };

        let encoded = encode_tc_string(&tc_model)?;
        let decoded = decode_tc_string(&encoded)?;

        assert_eq!(tc_model.core_string.version, decoded.core_string.version);
        assert!(decoded.disclosed_vendors.is_some());

        Ok(())
    }

    #[test]
    fn test_roundtrip_complete() -> Result<()> {
        let mut core = create_test_core_string();

        // Add legitimate interests
        let mut li_vendors = HashSet::new();
        li_vendors.insert(2);
        li_vendors.insert(3);
        core.vendor_legitimate_interests = VendorSet::BitField(li_vendors);

        // Add publisher restrictions
        let mut restrictions = PublisherRestrictions::new();
        let mut rest_vendors = HashSet::new();
        rest_vendors.insert(1);
        let restriction = PublisherRestriction::new(
            2,
            RestrictionType::NotAllowed,
            VendorSet::BitField(rest_vendors),
        )?;
        restrictions.add_restriction(restriction);
        core.publisher_restrictions = restrictions;

        let mut disclosed_vendors = HashSet::new();
        disclosed_vendors.insert(1);
        disclosed_vendors.insert(35);
        let disclosed = DisclosedVendors::new(VendorSet::BitField(disclosed_vendors));

        let tc_model = TCModel {
            core_string: core,
            disclosed_vendors: Some(disclosed),
            allowed_vendors: None,
            publisher_tc: None,
        };

        let encoded = encode_tc_string(&tc_model)?;
        let decoded = decode_tc_string(&encoded)?;

        // Verify all components
        assert_eq!(tc_model.core_string.version, decoded.core_string.version);
        assert_eq!(tc_model.core_string.cmp_id, decoded.core_string.cmp_id);
        assert!(decoded.disclosed_vendors.is_some());
        assert!(decoded.core_string.has_vendor_consent(1));
        assert!(decoded.core_string.has_vendor_li_transparency(2));

        Ok(())
    }

    #[test]
    fn test_missing_disclosed_vendors_error() {
        let core = create_test_core_string();
        let tc_model = TCModel {
            core_string: core,
            disclosed_vendors: None, // Missing!
            allowed_vendors: None,
            publisher_tc: None,
        };

        let result = encode_tc_string(&tc_model);
        assert!(matches!(result, Err(Error::MissingDisclosedVendors)));
    }

    #[test]
    fn test_invalid_version() {
        let mut core = create_test_core_string();
        core.version = 3; // Invalid version

        let encoded = encode_core_string(&core).unwrap();
        let result = decode_core_string(&encoded);

        assert!(matches!(result, Err(Error::UnsupportedVersion(3))));
    }

    #[test]
    fn test_segment_type_detection() -> Result<()> {
        let mut vendors = HashSet::new();
        vendors.insert(1);

        let disclosed = DisclosedVendors::new(VendorSet::BitField(vendors.clone()));
        let allowed = AllowedVendors::new(VendorSet::BitField(vendors.clone()));
        let pub_tc = PublisherTC::new(BitField::new(24), BitField::new(24));

        let disclosed_str = encode_disclosed_vendors(&disclosed)?;
        let allowed_str = encode_allowed_vendors(&allowed)?;
        let pub_tc_str = encode_publisher_tc(&pub_tc)?;

        assert_eq!(detect_segment_type(&disclosed_str)?, 1);
        assert_eq!(detect_segment_type(&allowed_str)?, 2);
        assert_eq!(detect_segment_type(&pub_tc_str)?, 3);

        Ok(())
    }
}
