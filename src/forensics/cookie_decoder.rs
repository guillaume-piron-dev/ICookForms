//! # Universal Cookie Decoder
//!
//! Decode various cookie value encodings: Base64, Hex, Unix timestamps, UUIDs, JSON, etc.

use crate::forensics::{DecodedCookie, EncodingType};
use crate::types::{Cookie, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;

/// Universal cookie decoder
pub struct CookieDecoder;

impl CookieDecoder {
    /// Decode cookie value (detect encoding automatically)
    pub fn decode(cookie: &Cookie) -> Result<DecodedCookie> {
        let value = &cookie.value;
        let mut encodings = Vec::new();
        let mut decoded_values = HashMap::new();

        // Try Base64
        if let Ok(decoded) = Self::try_base64(value) {
            encodings.push(EncodingType::Base64);
            decoded_values.insert("base64".to_string(), decoded);
        }

        // Try Hex
        if let Ok(decoded) = Self::try_hex(value) {
            encodings.push(EncodingType::Hex);
            decoded_values.insert("hex".to_string(), decoded);
        }

        // Check if Unix timestamp
        let (is_timestamp, timestamp) = Self::try_unix_timestamp(value);

        // Check if UUID
        let (is_guid, guid) = Self::try_uuid(value);

        // Try JSON
        let structured_data = Self::try_json(value);
        if structured_data.is_some() {
            encodings.push(EncodingType::Json);
        }

        if encodings.is_empty() {
            encodings.push(EncodingType::PlainText);
        }

        Ok(DecodedCookie {
            original: cookie.clone(),
            encodings,
            decoded_values,
            is_timestamp,
            timestamp,
            is_guid,
            guid,
            structured_data,
        })
    }

    fn try_base64(value: &str) -> Result<String> {
        general_purpose::STANDARD
            .decode(value)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| crate::types::Error::ForensicError("Not base64".to_string()))
    }

    fn try_hex(value: &str) -> Result<String> {
        hex::decode(value)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| crate::types::Error::ForensicError("Not hex".to_string()))
    }

    fn try_unix_timestamp(value: &str) -> (bool, Option<DateTime<Utc>>) {
        if let Ok(ts) = value.parse::<i64>() {
            if let Some(dt) = DateTime::from_timestamp(ts, 0) {
                return (true, Some(dt));
            }
        }
        (false, None)
    }

    fn try_uuid(value: &str) -> (bool, Option<String>) {
        if uuid::Uuid::parse_str(value).is_ok() {
            (true, Some(value.to_string()))
        } else {
            (false, None)
        }
    }

    fn try_json(value: &str) -> Option<Value> {
        serde_json::from_str(value).ok()
    }
}
