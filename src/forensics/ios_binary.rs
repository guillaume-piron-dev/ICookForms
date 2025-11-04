//! # iOS Binary Cookie Parser
//!
//! Parser for iOS binarycookies file format.
//! iOS stores cookies in a proprietary binary format called "binarycookies".
//! This module decodes that format for forensic analysis.
//!
//! ## Format
//!
//! The binarycookies format (discovered through reverse engineering):
//! - Magic bytes: "cook" (0x636F6F6B)
//! - Number of pages (4 bytes, big-endian)
//! - Page sizes array
//! - Pages containing cookies
//! - Checksums
//!
//! ## References
//!
//! - Research paper: DOI: 10.1111/1556-4029.15499
//! - CCL-Forensics analysis
//! - Apple's CFHTTPCookies.c source (limited availability)

use crate::types::{Cookie, Error, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

/// iOS binary cookie parser
pub struct IosBinaryCookieParser;

/// Magic bytes for binarycookies format
const MAGIC_BYTES: &[u8] = b"cook";

/// iOS cookie metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosCookieMetadata {
    /// Cookie flags
    pub flags: u32,

    /// Unknown field 1 (for forensic completeness)
    pub unknown1: u32,

    /// Unknown field 2 (for forensic completeness)
    pub unknown2: u32,

    /// URL offset
    pub url_offset: u32,

    /// Name offset
    pub name_offset: u32,

    /// Path offset
    pub path_offset: u32,

    /// Value offset
    pub value_offset: u32,

    /// Expiration date (Mac absolute time)
    pub expiration_date: f64,

    /// Creation date (Mac absolute time)
    pub creation_date: f64,
}

impl IosBinaryCookieParser {
    /// Parse iOS binarycookies file
    ///
    /// # Arguments
    ///
    /// * `data` - Raw binary data from iOS binarycookies file
    ///
    /// # Returns
    ///
    /// Vector of parsed cookies with full metadata
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File is not a valid binarycookies format
    /// - File is corrupted
    /// - Unsupported version
    pub fn parse_binary_cookie_file(data: &[u8]) -> Result<Vec<Cookie>> {
        let mut cursor = Cursor::new(data);

        // Verify magic bytes
        let mut magic = [0u8; 4];
        cursor
            .read_exact(&mut magic)
            .map_err(|e| Error::ForensicError(format!("Failed to read magic bytes: {e}")))?;

        if magic != MAGIC_BYTES {
            return Err(Error::ForensicError(
                "Invalid binarycookies format: wrong magic bytes".to_string(),
            ));
        }

        // Read number of pages
        let num_pages = Self::read_u32_be(&mut cursor)?;

        // Read page sizes
        let mut page_sizes = Vec::with_capacity(num_pages as usize);
        for _ in 0..num_pages {
            page_sizes.push(Self::read_u32_be(&mut cursor)?);
        }

        // Parse each page
        let mut all_cookies = Vec::new();
        for page_size in page_sizes {
            let page_data = Self::read_bytes(&mut cursor, page_size as usize)?;
            let cookies = Self::parse_page(&page_data)?;
            all_cookies.extend(cookies);
        }

        Ok(all_cookies)
    }

    /// Parse a single page
    fn parse_page(data: &[u8]) -> Result<Vec<Cookie>> {
        let mut cursor = Cursor::new(data);

        // Page header (0x00000100 magic)
        let page_magic = Self::read_u32_le(&mut cursor)?;
        if page_magic != 0x0000_0100 {
            return Err(Error::ForensicError(format!(
                "Invalid page magic: 0x{page_magic:08X}"
            )));
        }

        // Number of cookies in this page
        let num_cookies = Self::read_u32_le(&mut cursor)?;

        // Cookie offsets
        let mut cookie_offsets = Vec::with_capacity(num_cookies as usize);
        for _ in 0..num_cookies {
            cookie_offsets.push(Self::read_u32_le(&mut cursor)?);
        }

        // Parse each cookie
        let mut cookies = Vec::new();
        for offset in cookie_offsets {
            let cookie = Self::parse_cookie_at_offset(data, offset as usize)?;
            cookies.push(cookie);
        }

        Ok(cookies)
    }

    /// Parse cookie at specific offset
    fn parse_cookie_at_offset(data: &[u8], offset: usize) -> Result<Cookie> {
        let mut cursor = Cursor::new(&data[offset..]);

        // Read cookie size
        let _cookie_size = Self::read_u32_le(&mut cursor)?;

        // Read metadata
        let metadata = Self::read_cookie_metadata(&mut cursor)?;

        // Read strings
        let url = Self::read_string_at_offset(data, offset + metadata.url_offset as usize)?;
        let name = Self::read_string_at_offset(data, offset + metadata.name_offset as usize)?;
        let path = Self::read_string_at_offset(data, offset + metadata.path_offset as usize)?;
        let value = Self::read_string_at_offset(data, offset + metadata.value_offset as usize)?;

        // Extract domain from URL
        let domain = Self::extract_domain(&url);

        // Convert Mac absolute time to Unix timestamp
        let created_at = Self::mac_time_to_datetime(metadata.creation_date);
        let expires = Some(Self::mac_time_to_datetime(metadata.expiration_date));

        // Parse flags for attributes
        let secure = (metadata.flags & 0x01) != 0;
        let http_only = (metadata.flags & 0x04) != 0;

        Ok(Cookie {
            name,
            value,
            domain: Some(domain),
            path: Some(path),
            secure,
            http_only,
            same_site: None,
            expires,
            max_age: None,
            created_at,
            size: 0,
            extensions: std::collections::HashMap::new(),
            is_third_party: false,
            source_url: None,
            category: None,
        })
    }

    /// Read cookie metadata structure
    fn read_cookie_metadata(cursor: &mut Cursor<&[u8]>) -> Result<IosCookieMetadata> {
        Ok(IosCookieMetadata {
            unknown1: Self::read_u32_le(cursor)?,
            unknown2: Self::read_u32_le(cursor)?,
            flags: Self::read_u32_le(cursor)?,
            url_offset: Self::read_u32_le(cursor)?,
            name_offset: Self::read_u32_le(cursor)?,
            path_offset: Self::read_u32_le(cursor)?,
            value_offset: Self::read_u32_le(cursor)?,
            expiration_date: Self::read_f64_le(cursor)?,
            creation_date: Self::read_f64_le(cursor)?,
        })
    }

    /// Read null-terminated string at offset
    fn read_string_at_offset(data: &[u8], offset: usize) -> Result<String> {
        let mut end = offset;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }

        String::from_utf8(data[offset..end].to_vec())
            .map_err(|e| Error::ForensicError(format!("Invalid UTF-8 in cookie string: {e}")))
    }

    /// Extract domain from URL
    fn extract_domain(url: &str) -> String {
        url.split("//")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .unwrap_or(url)
            .to_string()
    }

    /// Convert Mac absolute time to `DateTime`
    /// Mac time is seconds since 2001-01-01 00:00:00
    #[allow(clippy::cast_possible_truncation)] // Mac timestamps fit in i64 range
    fn mac_time_to_datetime(mac_time: f64) -> DateTime<Utc> {
        const MAC_EPOCH_UNIX_TIMESTAMP: i64 = 978_307_200; // 2001-01-01 in Unix time
        let unix_timestamp = MAC_EPOCH_UNIX_TIMESTAMP + mac_time as i64;
        Utc.timestamp_opt(unix_timestamp, 0).unwrap()
    }

    // Helper functions for reading binary data

    fn read_u32_be(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
        let mut buf = [0u8; 4];
        cursor
            .read_exact(&mut buf)
            .map_err(|e| Error::ForensicError(format!("Failed to read u32: {e}")))?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_u32_le(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
        let mut buf = [0u8; 4];
        cursor
            .read_exact(&mut buf)
            .map_err(|e| Error::ForensicError(format!("Failed to read u32: {e}")))?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_f64_le(cursor: &mut Cursor<&[u8]>) -> Result<f64> {
        let mut buf = [0u8; 8];
        cursor
            .read_exact(&mut buf)
            .map_err(|e| Error::ForensicError(format!("Failed to read f64: {e}")))?;
        Ok(f64::from_le_bytes(buf))
    }

    fn read_bytes(cursor: &mut Cursor<&[u8]>, count: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; count];
        cursor
            .read_exact(&mut buf)
            .map_err(|e| Error::ForensicError(format!("Failed to read {count} bytes: {e}")))?;
        Ok(buf)
    }

    /// Extract metadata without parsing full cookies
    ///
    /// Useful for quick analysis or when full parsing fails
    pub fn extract_metadata(_data: &[u8]) -> Result<Vec<IosCookieMetadata>> {
        // TODO: Implement metadata-only extraction
        todo!("Metadata extraction")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_mac_time_conversion() {
        // Test Mac epoch (2001-01-01)
        let mac_epoch = IosBinaryCookieParser::mac_time_to_datetime(0.0);
        assert_eq!(mac_epoch.year(), 2001);
        assert_eq!(mac_epoch.month(), 1);
        assert_eq!(mac_epoch.day(), 1);
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let invalid_data = b"invalid";
        let result = IosBinaryCookieParser::parse_binary_cookie_file(invalid_data);
        assert!(result.is_err());
    }
}
