//! Cryptographic utilities for cookie security analysis
//!
//! This module provides comprehensive cryptographic operations needed for:
//! - Cookie signature verification
//! - Hash calculation and validation
//! - Secure token generation
//! - Data integrity checks
//! - HMAC operations
//! - Base64 encoding/decoding for cookie values

use crate::types::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Calculate SHA-256 hash of data
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// * Hexadecimal string representation of the hash
///
/// # Example
/// ```
/// # use icookforms::utils::crypto::sha256;
/// let hash = sha256(b"test data");
/// assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
/// ```
#[must_use]
pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate SHA-512 hash of data
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// * Hexadecimal string representation of the hash
#[must_use]
pub fn sha512(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate HMAC-SHA256
///
/// # Arguments
/// * `key` - The secret key
/// * `data` - The data to authenticate
///
/// # Returns
/// * Hexadecimal string representation of the HMAC
///
/// # Example
/// ```
/// # use icookforms::utils::crypto::hmac_sha256;
/// let hmac = hmac_sha256(b"secret_key", b"message").unwrap();
/// assert_eq!(hmac.len(), 64);
/// ```
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::generic(format!("Invalid key length: {e}")))?;
    mac.update(data);
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Calculate HMAC-SHA512
///
/// # Arguments
/// * `key` - The secret key
/// * `data` - The data to authenticate
///
/// # Returns
/// * Hexadecimal string representation of the HMAC
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<String> {
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|e| Error::generic(format!("Invalid key length: {e}")))?;
    mac.update(data);
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Verify HMAC-SHA256 signature
///
/// # Arguments
/// * `key` - The secret key used for signing
/// * `data` - The data that was signed
/// * `signature` - The hexadecimal HMAC signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], signature: &str) -> Result<bool> {
    let expected = hmac_sha256(key, data)?;
    Ok(constant_time_compare(&expected, signature))
}

/// Verify HMAC-SHA512 signature
///
/// # Arguments
/// * `key` - The secret key used for signing
/// * `data` - The data that was signed
/// * `signature` - The hexadecimal HMAC signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify_hmac_sha512(key: &[u8], data: &[u8], signature: &str) -> Result<bool> {
    let expected = hmac_sha512(key, data)?;
    Ok(constant_time_compare(&expected, signature))
}

/// Constant-time string comparison to prevent timing attacks
///
/// # Arguments
/// * `a` - First string
/// * `b` - Second string
///
/// # Returns
/// * `true` if strings are equal, `false` otherwise
///
/// # Security
/// This function compares strings in constant time to prevent timing attacks
/// that could leak information about the expected value.
#[must_use]
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }
    result == 0
}

/// Encode data to Base64 (standard encoding)
///
/// # Arguments
/// * `data` - The data to encode
///
/// # Returns
/// * Base64-encoded string
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode Base64 data (standard encoding)
///
/// # Arguments
/// * `encoded` - The Base64-encoded string
///
/// # Returns
/// * Decoded bytes or error if invalid Base64
pub fn base64_decode(encoded: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| Error::generic(format!("Base64 decode error: {e}")))
}

/// Encode data to Base64 URL-safe encoding (used in JWTs and cookies)
///
/// # Arguments
/// * `data` - The data to encode
///
/// # Returns
/// * URL-safe Base64-encoded string (no padding)
#[must_use]
pub fn base64_url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decode Base64 URL-safe encoding
///
/// # Arguments
/// * `encoded` - The URL-safe Base64-encoded string
///
/// # Returns
/// * Decoded bytes or error if invalid Base64
pub fn base64_url_decode(encoded: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| Error::generic(format!("Base64 URL decode error: {e}")))
}

/// Generate cryptographically secure random bytes
///
/// # Arguments
/// * `length` - Number of random bytes to generate
///
/// # Returns
/// * Vector of random bytes
///
/// # Security
/// Uses the system's CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
#[must_use]
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    // CORRECTED: Added explicit type annotation for gen()
    (0..length).map(|_| rng.gen::<u8>()).collect()
}

/// Generate secure random token as hexadecimal string
///
/// # Arguments
/// * `byte_length` - Number of random bytes (output will be 2x this in hex chars)
///
/// # Returns
/// * Hexadecimal string of random data
///
/// # Example
/// ```
/// # use icookforms::utils::crypto::generate_secure_token;
/// let token = generate_secure_token(32);
/// assert_eq!(token.len(), 64);
/// ```
#[must_use]
pub fn generate_secure_token(byte_length: usize) -> String {
    let bytes = generate_random_bytes(byte_length);
    hex::encode(bytes)
}

/// Generate secure random token as Base64 string
///
/// # Arguments
/// * `byte_length` - Number of random bytes
///
/// # Returns
/// * Base64-encoded random token
#[must_use]
pub fn generate_secure_token_base64(byte_length: usize) -> String {
    let bytes = generate_random_bytes(byte_length);
    base64_encode(&bytes)
}

/// Calculate checksum of cookie value for integrity verification
///
/// # Arguments
/// * `cookie_name` - Name of the cookie
/// * `cookie_value` - Value of the cookie
/// * `secret` - Optional secret key for additional security
///
/// # Returns
/// * Checksum string (SHA-256 hash)
#[must_use]
pub fn calculate_cookie_checksum(
    cookie_name: &str,
    cookie_value: &str,
    secret: Option<&str>,
) -> String {
    let data = match secret {
        Some(s) => format!("{cookie_name}:{cookie_value}:{s}"),
        None => format!("{cookie_name}:{cookie_value}"),
    };
    sha256(data.as_bytes())
}

/// Verify cookie checksum
///
/// # Arguments
/// * `cookie_name` - Name of the cookie
/// * `cookie_value` - Value of the cookie
/// * `expected_checksum` - Expected checksum to verify against
/// * `secret` - Optional secret key used during checksum calculation
///
/// # Returns
/// * `true` if checksum matches, `false` otherwise
#[must_use]
pub fn verify_cookie_checksum(
    cookie_name: &str,
    cookie_value: &str,
    expected_checksum: &str,
    secret: Option<&str>,
) -> bool {
    let calculated = calculate_cookie_checksum(cookie_name, cookie_value, secret);
    constant_time_compare(&calculated, expected_checksum)
}

/// Analyze cookie for cryptographic signatures
///
/// Detects common signature patterns in cookie values:
/// - JWT format (three base64 segments separated by dots)
/// - HMAC signatures (hex or base64)
/// - Hash-based signatures
///
/// # Arguments
/// * `cookie_value` - The cookie value to analyze
///
/// # Returns
/// * Vector of detected signature types
#[must_use]
pub fn detect_cookie_signatures(cookie_value: &str) -> Vec<String> {
    let mut signatures = Vec::new();

    // JWT pattern: xxx.yyy.zzz
    if cookie_value.split('.').count() == 3 {
        let parts: Vec<&str> = cookie_value.split('.').collect();
        if parts.iter().all(|p| is_base64_like(p)) {
            signatures.push("JWT".to_string());
        }
    }

    // HMAC-like hex signature (64 or 128 chars)
    if (cookie_value.len() == 64 || cookie_value.len() == 128)
        && cookie_value.chars().all(|c| c.is_ascii_hexdigit())
    {
        if cookie_value.len() == 64 {
            signatures.push("HMAC-SHA256-HEX".to_string());
        } else {
            signatures.push("HMAC-SHA512-HEX".to_string());
        }
    }

    // Base64-encoded signature (typical length ranges)
    if (32..=128).contains(&cookie_value.len()) && is_base64_like(cookie_value) {
        signatures.push("BASE64-SIGNATURE".to_string());
    }

    // Session token pattern (UUID-like or long random string)
    if cookie_value.len() >= 32
        && cookie_value
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-')
    {
        signatures.push("SESSION-TOKEN".to_string());
    }

    signatures
}

/// Check if string looks like Base64
fn is_base64_like(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')
}

/// Calculate entropy of a string (in bits)
///
/// Higher entropy indicates more randomness/security
///
/// # Arguments
/// * `data` - String to analyze
///
/// # Returns
/// * Entropy in bits per character
#[must_use]
pub fn calculate_entropy(data: &str) -> f64 {
    use std::collections::HashMap;

    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies: HashMap<char, usize> = HashMap::new();
    for c in data.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
    }

    #[allow(clippy::cast_precision_loss)]
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for count in frequencies.values() {
        #[allow(clippy::cast_precision_loss)]
        let probability = *count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy
}

/// Assess password/token strength based on entropy
///
/// # Arguments
/// * `token` - Token to assess
///
/// # Returns
/// * Strength rating: "WEAK", "MODERATE", "STRONG", "`VERY_STRONG`"
#[must_use]
pub fn assess_token_strength(token: &str) -> &'static str {
    let entropy = calculate_entropy(token);
    #[allow(clippy::cast_precision_loss)]
    let total_entropy = entropy * token.len() as f64;

    match total_entropy {
        e if e < 28.0 => "WEAK",     // < 28 bits
        e if e < 36.0 => "MODERATE", // 28-35 bits
        e if e < 60.0 => "STRONG",   // 36-59 bits
        _ => "VERY_STRONG",          // >= 60 bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"test");
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
                                    // Known SHA-256 hash of "test"
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        let hmac = hmac_sha256(b"secret", b"message").unwrap();
        assert_eq!(hmac.len(), 64);

        // Verify
        assert!(verify_hmac_sha256(b"secret", b"message", &hmac).unwrap());
        assert!(!verify_hmac_sha256(b"wrong", b"message", &hmac).unwrap());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hell"));
    }

    #[test]
    fn test_base64() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_base64_url() {
        let data = b"URL safe encoding test!";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('='));
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_random_generation() {
        let bytes1 = generate_random_bytes(32);
        let bytes2 = generate_random_bytes(32);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_secure_token() {
        let token = generate_secure_token(16);
        assert_eq!(token.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_cookie_checksum() {
        let checksum = calculate_cookie_checksum("session", "value123", Some("secret"));
        assert!(verify_cookie_checksum(
            "session",
            "value123",
            &checksum,
            Some("secret")
        ));
        assert!(!verify_cookie_checksum(
            "session",
            "value123",
            &checksum,
            Some("wrong")
        ));
    }

    #[test]
    fn test_detect_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let sigs = detect_cookie_signatures(jwt);
        assert!(sigs.contains(&"JWT".to_string()));
    }

    #[test]
    fn test_detect_hmac_hex() {
        let hmac = "a".repeat(64); // 64 hex chars
        let sigs = detect_cookie_signatures(&hmac);
        assert!(sigs.contains(&"HMAC-SHA256-HEX".to_string()));
    }

    #[test]
    fn test_entropy() {
        // Low entropy: repeated characters
        let low = calculate_entropy("aaaaaaaaaa");
        assert!(low < 0.1);

        // High entropy: random-looking string
        let high = calculate_entropy("x9K2mP4rL8nQ3vZ");
        assert!(high > 3.0);
    }

    #[test]
    fn test_token_strength() {
        // WEAK: < 28 bits total entropy
        // "weak" = 4 chars, 2.0 bits/char = 8.0 bits total
        assert_eq!(assess_token_strength("weak"), "WEAK");

        // MODERATE: 28-35 bits total entropy
        // "token12345" = 10 chars, 3.32 bits/char = 33.22 bits total
        assert_eq!(assess_token_strength("token12345"), "MODERATE");

        // STRONG: 36-59 bits total entropy
        // "random_tok12" = 12 chars, 3.42 bits/char = 41.02 bits total
        assert_eq!(assess_token_strength("random_tok12"), "STRONG");

        // VERY_STRONG: >= 60 bits total entropy
        // generate_secure_token(32) = 32 chars, high entropy (~5.2 bits/char * 32 = 166 bits)
        let very_strong = generate_secure_token(32);
        assert_eq!(assess_token_strength(&very_strong), "VERY_STRONG");
    }

    #[test]
    fn test_sha512() {
        let hash = sha512(b"test");
        assert_eq!(hash.len(), 128); // 64 bytes = 128 hex chars
    }

    #[test]
    fn test_hmac_sha512() {
        let hmac = hmac_sha512(b"secret", b"message").unwrap();
        assert_eq!(hmac.len(), 128);
        assert!(verify_hmac_sha512(b"secret", b"message", &hmac).unwrap());
    }
}
