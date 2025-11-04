//! Google Consent Mode V2 Implementation
//!
//! This module implements parsing, encoding, and validation for Google Consent Mode V2.
//! Consent Mode V2 is mandatory for EEA/UK as of March 2024.
//!
//! # Overview
//!
//! Google Consent Mode V2 includes 4 mandatory parameters:
//! - `ad_storage`: Storage of cookies for advertising
//! - `analytics_storage`: Storage of cookies for analytics
//! - `ad_user_data`: Sending user data to Google for advertising (NEW in v2)
//! - `ad_personalization`: Personalization of ads (NEW in v2)
//!
//! # Signal States
//!
//! Each parameter can have one of 7 states:
//! - `l`: Granted by default
//! - `m`: Granted after user update
//! - `n`: Denied by default
//! - `p`: Denied after user update
//! - `q`: No consent string
//! - `r`: Not required (regional)
//! - `t`: Partial consent
//!
//! # Format Specifications
//!
//! ## gcd Parameter (Consent Mode v2)
//! Format: `11<signal1>1<signal2>1<signal3>1<signal4>5`
//! Example: `11l1m1n1p5`
//!
//! ## gcs Parameter (Consent Mode v1 - Legacy)
//! Format: `G1<ad><analytics>`
//! Example: `G111` (all granted)

use serde::{Deserialize, Serialize};

/// Represents the consent state for a specific parameter
///
/// Each state indicates whether consent was granted or denied,
/// and whether it was set by default or explicitly by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsentState {
    /// Consent granted by default configuration (before user interaction)
    /// Character: 'l'
    GrantedDefault,

    /// Consent granted after user explicitly accepted
    /// Character: 'm'
    GrantedUpdate,

    /// Consent denied by default configuration (before user interaction)
    /// Character: 'n'
    DeniedDefault,

    /// Consent denied after user explicitly rejected
    /// Character: 'p'
    DeniedUpdate,

    /// No consent string available
    /// Character: 'q'
    NoConsentString,

    /// Consent not required for this region
    /// Character: 'r'
    NotRequired,

    /// Partial consent (some parameters granted, some denied)
    /// Character: 't'
    Partial,
}

impl ConsentState {
    /// Converts a character to a `ConsentState`
    ///
    /// # Arguments
    /// * `c` - Single character representing the consent state
    ///
    /// # Returns
    /// * `Some(ConsentState)` if the character is valid
    /// * `None` if the character is not recognized
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ConsentState;
    /// assert_eq!(ConsentState::from_char('l'), Some(ConsentState::GrantedDefault));
    /// assert_eq!(ConsentState::from_char('m'), Some(ConsentState::GrantedUpdate));
    /// assert_eq!(ConsentState::from_char('n'), Some(ConsentState::DeniedDefault));
    /// assert_eq!(ConsentState::from_char('x'), None);
    /// ```
    #[must_use]
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'l' => Some(Self::GrantedDefault),
            'm' => Some(Self::GrantedUpdate),
            'n' => Some(Self::DeniedDefault),
            'p' => Some(Self::DeniedUpdate),
            'q' => Some(Self::NoConsentString),
            'r' => Some(Self::NotRequired),
            't' => Some(Self::Partial),
            _ => None,
        }
    }

    /// Converts a `ConsentState` to its character representation
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ConsentState;
    /// assert_eq!(ConsentState::GrantedDefault.to_char(), 'l');
    /// assert_eq!(ConsentState::GrantedUpdate.to_char(), 'm');
    /// assert_eq!(ConsentState::DeniedDefault.to_char(), 'n');
    /// ```
    #[must_use]
    pub fn to_char(&self) -> char {
        match self {
            Self::GrantedDefault => 'l',
            Self::GrantedUpdate => 'm',
            Self::DeniedDefault => 'n',
            Self::DeniedUpdate => 'p',
            Self::NoConsentString => 'q',
            Self::NotRequired => 'r',
            Self::Partial => 't',
        }
    }

    /// Checks if the consent state represents granted consent
    ///
    /// Returns true for:
    /// - `GrantedDefault`
    /// - `GrantedUpdate`
    /// - `NotRequired`
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ConsentState;
    /// assert!(ConsentState::GrantedDefault.is_granted());
    /// assert!(ConsentState::GrantedUpdate.is_granted());
    /// assert!(ConsentState::NotRequired.is_granted());
    /// assert!(!ConsentState::DeniedDefault.is_granted());
    /// ```
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(
            self,
            Self::GrantedDefault | Self::GrantedUpdate | Self::NotRequired
        )
    }

    /// Checks if the consent state represents denied consent
    ///
    /// Returns true for:
    /// - `DeniedDefault`
    /// - `DeniedUpdate`
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ConsentState;
    /// assert!(ConsentState::DeniedDefault.is_denied());
    /// assert!(ConsentState::DeniedUpdate.is_denied());
    /// assert!(!ConsentState::GrantedDefault.is_denied());
    /// ```
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::DeniedDefault | Self::DeniedUpdate)
    }

    /// Checks if the consent was explicitly set by the user
    ///
    /// Returns true for:
    /// - `GrantedUpdate`
    /// - `DeniedUpdate`
    ///
    /// # Examples
    /// ```
    /// # use icookforms::compliance::google_consent::ConsentState;
    /// assert!(ConsentState::GrantedUpdate.is_user_action());
    /// assert!(ConsentState::DeniedUpdate.is_user_action());
    /// assert!(!ConsentState::GrantedDefault.is_user_action());
    /// ```
    #[must_use]
    pub fn is_user_action(&self) -> bool {
        matches!(self, Self::GrantedUpdate | Self::DeniedUpdate)
    }
}

/// Google Consent Mode V2 configuration
///
/// Contains the consent state for all 4 mandatory parameters.
/// This structure is used to parse and encode the `gcd` URL parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentModeV2 {
    /// Consent for storing cookies used for advertising purposes
    pub ad_storage: ConsentState,

    /// Consent for storing cookies used for analytics
    pub analytics_storage: ConsentState,

    /// Consent for sending user data to Google for advertising (NEW in v2)
    pub ad_user_data: ConsentState,

    /// Consent for ad personalization (NEW in v2)
    pub ad_personalization: ConsentState,
}

impl ConsentModeV2 {
    /// Creates a new `ConsentModeV2` with all parameters denied by default
    #[must_use]
    pub fn new_denied() -> Self {
        Self {
            ad_storage: ConsentState::DeniedDefault,
            analytics_storage: ConsentState::DeniedDefault,
            ad_user_data: ConsentState::DeniedDefault,
            ad_personalization: ConsentState::DeniedDefault,
        }
    }

    /// Creates a new `ConsentModeV2` with all parameters granted by default
    #[must_use]
    pub fn new_granted() -> Self {
        Self {
            ad_storage: ConsentState::GrantedDefault,
            analytics_storage: ConsentState::GrantedDefault,
            ad_user_data: ConsentState::GrantedDefault,
            ad_personalization: ConsentState::GrantedDefault,
        }
    }

    /// Checks if all parameters have granted consent
    #[must_use]
    pub fn is_fully_granted(&self) -> bool {
        self.ad_storage.is_granted()
            && self.analytics_storage.is_granted()
            && self.ad_user_data.is_granted()
            && self.ad_personalization.is_granted()
    }

    /// Checks if any parameter has granted consent
    #[must_use]
    pub fn is_partially_granted(&self) -> bool {
        self.ad_storage.is_granted()
            || self.analytics_storage.is_granted()
            || self.ad_user_data.is_granted()
            || self.ad_personalization.is_granted()
    }
}

/// Parses a `gcd` URL parameter into `ConsentModeV2`
///
/// # Format
/// `11<signal1>1<signal2>1<signal3>1<signal4>5`
///
/// # Arguments
/// * `gcd` - The gcd parameter value (e.g., "11l1m1n1p5")
///
/// # Returns
/// * `Ok(ConsentModeV2)` if parsing succeeds
/// * `Err(Error)` if the format is invalid
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::{parse_gcd_parameter, ConsentState};
/// let consent = parse_gcd_parameter("11l1m1n1p5").unwrap();
/// assert_eq!(consent.ad_storage, ConsentState::GrantedDefault);
/// assert_eq!(consent.analytics_storage, ConsentState::GrantedUpdate);
/// assert_eq!(consent.ad_user_data, ConsentState::DeniedDefault);
/// assert_eq!(consent.ad_personalization, ConsentState::DeniedUpdate);
/// ```
#[must_use = "GCD parameter parsing failure must be handled"]
pub fn parse_gcd_parameter(gcd: &str) -> Result<ConsentModeV2, GcdError> {
    // Validate prefix
    if !gcd.starts_with("11") {
        return Err(GcdError::InvalidPrefix);
    }

    // Validate suffix (can be 5, 3, or other numbers)
    let last_char = gcd.chars().last().ok_or(GcdError::Empty)?;
    if !last_char.is_ascii_digit() {
        return Err(GcdError::InvalidSuffix);
    }

    // Extract signal part: remove "11" prefix and last digit suffix
    let signal_part = &gcd[2..gcd.len() - 1];

    // Split by '1' separator
    let parts: Vec<&str> = signal_part.split('1').collect();

    if parts.len() != 4 {
        return Err(GcdError::InvalidSignalCount(parts.len()));
    }

    // Parse each signal
    let ad_storage = parse_consent_signal(parts[0])?;
    let analytics_storage = parse_consent_signal(parts[1])?;
    let ad_user_data = parse_consent_signal(parts[2])?;
    let ad_personalization = parse_consent_signal(parts[3])?;

    Ok(ConsentModeV2 {
        ad_storage,
        analytics_storage,
        ad_user_data,
        ad_personalization,
    })
}

/// Encodes a `ConsentModeV2` into a `gcd` parameter string
///
/// # Arguments
/// * `consent` - The consent configuration to encode
///
/// # Returns
/// A string in the format `11<signal1>1<signal2>1<signal3>1<signal4>5`
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::{ConsentModeV2, ConsentState, encode_gcd_parameter};
/// let consent = ConsentModeV2 {
///     ad_storage: ConsentState::GrantedDefault,
///     analytics_storage: ConsentState::GrantedUpdate,
///     ad_user_data: ConsentState::DeniedDefault,
///     ad_personalization: ConsentState::DeniedUpdate,
/// };
/// assert_eq!(encode_gcd_parameter(&consent), "11l1m1n1p5");
/// ```
#[must_use]
pub fn encode_gcd_parameter(consent: &ConsentModeV2) -> String {
    format!(
        "11{}1{}1{}1{}5",
        consent.ad_storage.to_char(),
        consent.analytics_storage.to_char(),
        consent.ad_user_data.to_char(),
        consent.ad_personalization.to_char()
    )
}

/// Parses a legacy `gcs` parameter (Consent Mode v1)
///
/// # Format
/// `G1<ad><analytics>` where each digit is 1 (granted) or 0 (denied)
///
/// # Arguments
/// * `gcs` - The gcs parameter value (e.g., "G111")
///
/// # Returns
/// * `Ok(ConsentModeV2)` with `ad_user_data` and `ad_personalization` set to `GrantedDefault`
/// * `Err(Error)` if the format is invalid
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::{parse_gcs_parameter, ConsentState};
/// let consent = parse_gcs_parameter("G111").unwrap();
/// assert_eq!(consent.ad_storage, ConsentState::GrantedUpdate);
/// assert_eq!(consent.analytics_storage, ConsentState::GrantedUpdate);
/// ```
#[must_use = "GCS parameter parsing failure must be handled"]
pub fn parse_gcs_parameter(gcs: &str) -> Result<ConsentModeV2, GcsError> {
    // Validate format: G1<ad><analytics>
    if !gcs.starts_with("G1") {
        return Err(GcsError::InvalidPrefix);
    }

    if gcs.len() < 4 {
        return Err(GcsError::TooShort);
    }

    let chars: Vec<char> = gcs.chars().collect();

    // Parse ad_storage (3rd character)
    let ad_storage = match chars.get(2) {
        Some('1') => ConsentState::GrantedUpdate,
        Some('0') => ConsentState::DeniedUpdate,
        _ => return Err(GcsError::InvalidSignal),
    };

    // Parse analytics_storage (4th character)
    let analytics_storage = match chars.get(3) {
        Some('1') => ConsentState::GrantedUpdate,
        Some('0') => ConsentState::DeniedUpdate,
        _ => return Err(GcsError::InvalidSignal),
    };

    // V1 doesn't have ad_user_data and ad_personalization, set to GrantedDefault
    Ok(ConsentModeV2 {
        ad_storage,
        analytics_storage,
        ad_user_data: ConsentState::GrantedDefault,
        ad_personalization: ConsentState::GrantedDefault,
    })
}

/// Parses a single consent signal character
fn parse_consent_signal(signal: &str) -> Result<ConsentState, GcdError> {
    if signal.len() != 1 {
        return Err(GcdError::InvalidSignalLength(signal.len()));
    }

    let c = signal.chars().next().unwrap();
    ConsentState::from_char(c).ok_or(GcdError::UnknownSignalChar(c))
}

/// Error type for gcd parameter parsing
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GcdError {
    /// The gcd string is empty
    #[error("gcd parameter is empty")]
    Empty,

    /// The gcd string must start with "11"
    #[error("gcd parameter must start with '11'")]
    InvalidPrefix,

    /// The gcd string must end with a digit
    #[error("gcd parameter must end with a digit")]
    InvalidSuffix,

    /// The gcd string must contain exactly 4 consent signals
    #[error("gcd parameter must contain 4 consent signals, found {0}")]
    InvalidSignalCount(usize),

    /// A consent signal must be exactly 1 character
    #[error("consent signal must be 1 character, found {0}")]
    InvalidSignalLength(usize),

    /// Unknown consent signal character
    #[error("unknown consent signal character: '{0}'")]
    UnknownSignalChar(char),
}

/// Error type for gcs parameter parsing
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GcsError {
    /// The gcs string must start with "G1"
    #[error("gcs parameter must start with 'G1'")]
    InvalidPrefix,

    /// The gcs string is too short
    #[error("gcs parameter too short (minimum 4 characters)")]
    TooShort,

    /// Invalid signal character (must be '0' or '1')
    #[error("gcs signal must be '0' or '1'")]
    InvalidSignal,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ConsentState Tests
    // ========================================================================

    #[test]
    fn test_consent_state_from_char() {
        assert_eq!(
            ConsentState::from_char('l'),
            Some(ConsentState::GrantedDefault)
        );
        assert_eq!(
            ConsentState::from_char('m'),
            Some(ConsentState::GrantedUpdate)
        );
        assert_eq!(
            ConsentState::from_char('n'),
            Some(ConsentState::DeniedDefault)
        );
        assert_eq!(
            ConsentState::from_char('p'),
            Some(ConsentState::DeniedUpdate)
        );
        assert_eq!(
            ConsentState::from_char('q'),
            Some(ConsentState::NoConsentString)
        );
        assert_eq!(
            ConsentState::from_char('r'),
            Some(ConsentState::NotRequired)
        );
        assert_eq!(ConsentState::from_char('t'), Some(ConsentState::Partial));
        assert_eq!(ConsentState::from_char('x'), None);
    }

    #[test]
    fn test_consent_state_to_char() {
        assert_eq!(ConsentState::GrantedDefault.to_char(), 'l');
        assert_eq!(ConsentState::GrantedUpdate.to_char(), 'm');
        assert_eq!(ConsentState::DeniedDefault.to_char(), 'n');
        assert_eq!(ConsentState::DeniedUpdate.to_char(), 'p');
        assert_eq!(ConsentState::NoConsentString.to_char(), 'q');
        assert_eq!(ConsentState::NotRequired.to_char(), 'r');
        assert_eq!(ConsentState::Partial.to_char(), 't');
    }

    #[test]
    fn test_consent_state_is_granted() {
        assert!(ConsentState::GrantedDefault.is_granted());
        assert!(ConsentState::GrantedUpdate.is_granted());
        assert!(ConsentState::NotRequired.is_granted());
        assert!(!ConsentState::DeniedDefault.is_granted());
        assert!(!ConsentState::DeniedUpdate.is_granted());
        assert!(!ConsentState::NoConsentString.is_granted());
        assert!(!ConsentState::Partial.is_granted());
    }

    #[test]
    fn test_consent_state_is_denied() {
        assert!(ConsentState::DeniedDefault.is_denied());
        assert!(ConsentState::DeniedUpdate.is_denied());
        assert!(!ConsentState::GrantedDefault.is_denied());
        assert!(!ConsentState::GrantedUpdate.is_denied());
    }

    #[test]
    fn test_consent_state_is_user_action() {
        assert!(ConsentState::GrantedUpdate.is_user_action());
        assert!(ConsentState::DeniedUpdate.is_user_action());
        assert!(!ConsentState::GrantedDefault.is_user_action());
        assert!(!ConsentState::DeniedDefault.is_user_action());
    }

    // ========================================================================
    // ConsentModeV2 Tests
    // ========================================================================

    #[test]
    fn test_consent_mode_v2_new_denied() {
        let consent = ConsentModeV2::new_denied();
        assert_eq!(consent.ad_storage, ConsentState::DeniedDefault);
        assert_eq!(consent.analytics_storage, ConsentState::DeniedDefault);
        assert_eq!(consent.ad_user_data, ConsentState::DeniedDefault);
        assert_eq!(consent.ad_personalization, ConsentState::DeniedDefault);
    }

    #[test]
    fn test_consent_mode_v2_new_granted() {
        let consent = ConsentModeV2::new_granted();
        assert_eq!(consent.ad_storage, ConsentState::GrantedDefault);
        assert_eq!(consent.analytics_storage, ConsentState::GrantedDefault);
        assert_eq!(consent.ad_user_data, ConsentState::GrantedDefault);
        assert_eq!(consent.ad_personalization, ConsentState::GrantedDefault);
    }

    #[test]
    fn test_consent_mode_v2_is_fully_granted() {
        let consent = ConsentModeV2::new_granted();
        assert!(consent.is_fully_granted());

        let mut partial = ConsentModeV2::new_granted();
        partial.ad_storage = ConsentState::DeniedDefault;
        assert!(!partial.is_fully_granted());
    }

    #[test]
    fn test_consent_mode_v2_is_partially_granted() {
        let fully_granted = ConsentModeV2::new_granted();
        assert!(fully_granted.is_partially_granted());

        let fully_denied = ConsentModeV2::new_denied();
        assert!(!fully_denied.is_partially_granted());

        let mut partial = ConsentModeV2::new_denied();
        partial.ad_storage = ConsentState::GrantedDefault;
        assert!(partial.is_partially_granted());
    }

    // ========================================================================
    // gcd Parameter Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_gcd_all_granted_default() {
        let result = parse_gcd_parameter("11l1l1l1l5").unwrap();
        assert_eq!(result.ad_storage, ConsentState::GrantedDefault);
        assert_eq!(result.analytics_storage, ConsentState::GrantedDefault);
        assert_eq!(result.ad_user_data, ConsentState::GrantedDefault);
        assert_eq!(result.ad_personalization, ConsentState::GrantedDefault);
    }

    #[test]
    fn test_parse_gcd_all_granted_update() {
        let result = parse_gcd_parameter("11m1m1m1m5").unwrap();
        assert_eq!(result.ad_storage, ConsentState::GrantedUpdate);
        assert_eq!(result.analytics_storage, ConsentState::GrantedUpdate);
        assert_eq!(result.ad_user_data, ConsentState::GrantedUpdate);
        assert_eq!(result.ad_personalization, ConsentState::GrantedUpdate);
    }

    #[test]
    fn test_parse_gcd_all_denied_default() {
        let result = parse_gcd_parameter("11n1n1n1n5").unwrap();
        assert_eq!(result.ad_storage, ConsentState::DeniedDefault);
        assert_eq!(result.analytics_storage, ConsentState::DeniedDefault);
        assert_eq!(result.ad_user_data, ConsentState::DeniedDefault);
        assert_eq!(result.ad_personalization, ConsentState::DeniedDefault);
    }

    #[test]
    fn test_parse_gcd_mixed_states() {
        let result = parse_gcd_parameter("11l1m1n1p5").unwrap();
        assert_eq!(result.ad_storage, ConsentState::GrantedDefault);
        assert_eq!(result.analytics_storage, ConsentState::GrantedUpdate);
        assert_eq!(result.ad_user_data, ConsentState::DeniedDefault);
        assert_eq!(result.ad_personalization, ConsentState::DeniedUpdate);
    }

    #[test]
    fn test_parse_gcd_invalid_prefix() {
        let result = parse_gcd_parameter("10l1l1l1l5");
        assert!(matches!(result, Err(GcdError::InvalidPrefix)));
    }

    #[test]
    fn test_parse_gcd_too_few_signals() {
        let result = parse_gcd_parameter("11l1l5");
        assert!(matches!(result, Err(GcdError::InvalidSignalCount(2))));
    }

    #[test]
    fn test_parse_gcd_unknown_signal() {
        let result = parse_gcd_parameter("11x1l1l1l5");
        assert!(matches!(result, Err(GcdError::UnknownSignalChar('x'))));
    }

    // ========================================================================
    // gcd Encoding Tests
    // ========================================================================

    #[test]
    fn test_encode_gcd_all_granted() {
        let consent = ConsentModeV2::new_granted();
        assert_eq!(encode_gcd_parameter(&consent), "11l1l1l1l5");
    }

    #[test]
    fn test_encode_gcd_all_denied() {
        let consent = ConsentModeV2::new_denied();
        assert_eq!(encode_gcd_parameter(&consent), "11n1n1n1n5");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = ConsentModeV2 {
            ad_storage: ConsentState::GrantedUpdate,
            analytics_storage: ConsentState::DeniedUpdate,
            ad_user_data: ConsentState::GrantedDefault,
            ad_personalization: ConsentState::NotRequired,
        };

        let encoded = encode_gcd_parameter(&original);
        let decoded = parse_gcd_parameter(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    // ========================================================================
    // gcs Parameter Parsing Tests (Legacy v1)
    // ========================================================================

    #[test]
    fn test_parse_gcs_all_granted() {
        let result = parse_gcs_parameter("G111").unwrap();
        assert_eq!(result.ad_storage, ConsentState::GrantedUpdate);
        assert_eq!(result.analytics_storage, ConsentState::GrantedUpdate);
        assert_eq!(result.ad_user_data, ConsentState::GrantedDefault);
        assert_eq!(result.ad_personalization, ConsentState::GrantedDefault);
    }

    #[test]
    fn test_parse_gcs_ads_only() {
        let result = parse_gcs_parameter("G110").unwrap();
        assert_eq!(result.ad_storage, ConsentState::GrantedUpdate);
        assert_eq!(result.analytics_storage, ConsentState::DeniedUpdate);
    }

    #[test]
    fn test_parse_gcs_analytics_only() {
        let result = parse_gcs_parameter("G101").unwrap();
        assert_eq!(result.ad_storage, ConsentState::DeniedUpdate);
        assert_eq!(result.analytics_storage, ConsentState::GrantedUpdate);
    }

    #[test]
    fn test_parse_gcs_all_denied() {
        let result = parse_gcs_parameter("G100").unwrap();
        assert_eq!(result.ad_storage, ConsentState::DeniedUpdate);
        assert_eq!(result.analytics_storage, ConsentState::DeniedUpdate);
    }

    #[test]
    fn test_parse_gcs_invalid_prefix() {
        let result = parse_gcs_parameter("G211");
        assert!(matches!(result, Err(GcsError::InvalidPrefix)));
    }

    #[test]
    fn test_parse_gcs_too_short() {
        let result = parse_gcs_parameter("G1");
        assert!(matches!(result, Err(GcsError::TooShort)));
    }
}
