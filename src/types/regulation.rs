//! Regulation types for compliance checking

use serde::{Deserialize, Serialize};
use std::fmt;

/// Privacy and data protection regulations
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Regulation {
    /// General Data Protection Regulation (EU)
    GDPR,

    /// UK GDPR (United Kingdom)
    UKGDPR,

    /// California Consumer Privacy Act
    CCPA,

    /// California Privacy Rights Act (enhanced CCPA)
    CPRA,

    /// Lei Geral de Proteção de Dados (Brazil)
    LGPD,

    /// Personal Information Protection and Electronic Documents Act (Canada)
    PIPEDA,

    /// Protection of Personal Information Act (South Africa)
    POPIA,

    /// Personal Data Protection Act (Singapore)
    PDPA,

    /// Privacy Act (Australia)
    PrivacyAct,

    /// ePrivacy Directive (EU)
    EPrivacy,

    /// Children's Online Privacy Protection Act (USA)
    COPPA,

    /// Health Insurance Portability and Accountability Act (USA)
    HIPAA,

    /// Payment Card Industry Data Security Standard
    PCIDSS,

    /// Virginia Consumer Data Protection Act
    VCDPA,

    /// Colorado Privacy Act
    CPA,

    /// Connecticut Data Privacy Act
    CTDPA,

    /// Utah Consumer Privacy Act
    UCPA,

    /// China Personal Information Protection Law
    PIPL,

    /// Japan Act on the Protection of Personal Information
    APPI,

    /// Korea Personal Information Protection Act
    PIPA,

    /// Thailand Personal Data Protection Act
    THPDPA,

    /// Indonesia Personal Data Protection
    IDPDP,

    /// Philippines Data Privacy Act
    PHDPA,

    /// New Zealand Privacy Act
    NZPA,

    /// Swiss Federal Act on Data Protection
    FADP,
}

impl fmt::Display for Regulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GDPR => write!(f, "GDPR (EU General Data Protection Regulation)"),
            Self::UKGDPR => write!(f, "UK GDPR"),
            Self::CCPA => write!(f, "CCPA (California Consumer Privacy Act)"),
            Self::CPRA => write!(f, "CPRA (California Privacy Rights Act)"),
            Self::LGPD => write!(f, "LGPD (Brazil)"),
            Self::PIPEDA => write!(f, "PIPEDA (Canada)"),
            Self::POPIA => write!(f, "POPIA (South Africa)"),
            Self::PDPA => write!(f, "PDPA (Singapore)"),
            Self::PrivacyAct => write!(f, "Privacy Act (Australia)"),
            Self::EPrivacy => write!(f, "ePrivacy Directive (EU)"),
            Self::COPPA => write!(f, "COPPA (Children's Online Privacy)"),
            Self::HIPAA => write!(f, "HIPAA (Health Insurance Portability)"),
            Self::PCIDSS => write!(f, "PCI DSS (Payment Card Industry)"),
            Self::VCDPA => write!(f, "VCDPA (Virginia)"),
            Self::CPA => write!(f, "CPA (Colorado)"),
            Self::CTDPA => write!(f, "CTDPA (Connecticut)"),
            Self::UCPA => write!(f, "UCPA (Utah)"),
            Self::PIPL => write!(f, "PIPL (China)"),
            Self::APPI => write!(f, "APPI (Japan)"),
            Self::PIPA => write!(f, "PIPA (Korea)"),
            Self::THPDPA => write!(f, "PDPA (Thailand)"),
            Self::IDPDP => write!(f, "PDP (Indonesia)"),
            Self::PHDPA => write!(f, "Data Privacy Act (Philippines)"),
            Self::NZPA => write!(f, "Privacy Act (New Zealand)"),
            Self::FADP => write!(f, "FADP (Switzerland)"),
        }
    }
}

impl Regulation {
    /// Get the short name/acronym
    #[must_use]
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::GDPR => "GDPR",
            Self::UKGDPR => "UK GDPR",
            Self::CCPA => "CCPA",
            Self::CPRA => "CPRA",
            Self::LGPD => "LGPD",
            Self::PIPEDA => "PIPEDA",
            Self::POPIA => "POPIA",
            Self::PDPA | Self::THPDPA => "PDPA",
            Self::PrivacyAct | Self::NZPA => "Privacy Act",
            Self::EPrivacy => "ePrivacy",
            Self::COPPA => "COPPA",
            Self::HIPAA => "HIPAA",
            Self::PCIDSS => "PCI DSS",
            Self::VCDPA => "VCDPA",
            Self::CPA => "CPA",
            Self::CTDPA => "CTDPA",
            Self::UCPA => "UCPA",
            Self::PIPL => "PIPL",
            Self::APPI => "APPI",
            Self::PIPA => "PIPA",
            Self::IDPDP => "PDP",
            Self::PHDPA => "DPA",
            Self::FADP => "FADP",
        }
    }

    /// Get the jurisdiction/region
    #[must_use]
    pub fn jurisdiction(&self) -> &'static str {
        match self {
            Self::GDPR | Self::EPrivacy => "European Union",
            Self::UKGDPR => "United Kingdom",
            Self::CCPA | Self::CPRA => "California, USA",
            Self::LGPD => "Brazil",
            Self::PIPEDA => "Canada",
            Self::POPIA => "South Africa",
            Self::PDPA => "Singapore",
            Self::PrivacyAct => "Australia",
            Self::COPPA | Self::HIPAA => "United States",
            Self::PCIDSS => "Global (Payment Cards)",
            Self::VCDPA => "Virginia, USA",
            Self::CPA => "Colorado, USA",
            Self::CTDPA => "Connecticut, USA",
            Self::UCPA => "Utah, USA",
            Self::PIPL => "China",
            Self::APPI => "Japan",
            Self::PIPA => "South Korea",
            Self::THPDPA => "Thailand",
            Self::IDPDP => "Indonesia",
            Self::PHDPA => "Philippines",
            Self::NZPA => "New Zealand",
            Self::FADP => "Switzerland",
        }
    }

    /// Get consent model (opt-in vs opt-out)
    #[must_use]
    pub fn consent_model(&self) -> ConsentModel {
        match self {
            Self::GDPR
            | Self::UKGDPR
            | Self::EPrivacy
            | Self::LGPD
            | Self::POPIA
            | Self::PDPA
            | Self::PIPL
            | Self::APPI
            | Self::PIPA
            | Self::THPDPA
            | Self::FADP => ConsentModel::OptIn,

            Self::CCPA | Self::CPRA | Self::VCDPA | Self::CPA | Self::CTDPA | Self::UCPA => {
                ConsentModel::OptOut
            }

            Self::PIPEDA
            | Self::PrivacyAct
            | Self::COPPA
            | Self::HIPAA
            | Self::PCIDSS
            | Self::IDPDP
            | Self::PHDPA
            | Self::NZPA => ConsentModel::Mixed,
        }
    }

    /// Check if regulation requires explicit consent for cookies
    #[must_use]
    pub fn requires_cookie_consent(&self) -> bool {
        matches!(
            self,
            Self::GDPR
                | Self::UKGDPR
                | Self::EPrivacy
                | Self::LGPD
                | Self::POPIA
                | Self::PDPA
                | Self::PIPL
                | Self::APPI
                | Self::PIPA
                | Self::THPDPA
                | Self::FADP
        )
    }

    /// Get maximum penalty/fine
    #[must_use]
    pub fn max_penalty(&self) -> Option<&'static str> {
        match self {
            Self::GDPR | Self::UKGDPR => Some("€20M or 4% of annual global revenue"),
            Self::CCPA | Self::CPRA => Some("$7,500 per intentional violation"),
            Self::LGPD => Some("R$ 50M per infraction"),
            Self::POPIA => Some("R 10M or up to 10 years imprisonment"),
            Self::PIPL => Some("¥50M or 5% of annual revenue"),
            Self::VCDPA => Some("$7,500 per violation"),
            Self::CPA => Some("$20,000 per violation"),
            Self::CTDPA => Some("$5,000 per violation"),
            _ => None,
        }
    }

    /// Check if regulation has extraterritorial reach
    #[must_use]
    pub fn is_extraterritorial(&self) -> bool {
        matches!(
            self,
            Self::GDPR | Self::CCPA | Self::CPRA | Self::PIPL | Self::LGPD
        )
    }

    /// Get official website/documentation URL
    #[must_use]
    pub fn official_url(&self) -> &'static str {
        match self {
            Self::GDPR => "https://gdpr.eu/",
            Self::UKGDPR => "https://ico.org.uk/for-organisations/guide-to-data-protection/",
            Self::CCPA => "https://oag.ca.gov/privacy/ccpa",
            Self::CPRA => "https://cppa.ca.gov/",
            Self::LGPD => "https://www.gov.br/anpd/",
            Self::PIPEDA => "https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/",
            Self::POPIA => "https://popia.co.za/",
            Self::PDPA => "https://www.pdpc.gov.sg/",
            Self::PrivacyAct => "https://www.oaic.gov.au/",
            Self::EPrivacy => "https://ec.europa.eu/digital-single-market/en/eprivacy-directive",
            Self::COPPA => "https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa",
            Self::HIPAA => "https://www.hhs.gov/hipaa/",
            Self::PCIDSS => "https://www.pcisecuritystandards.org/",
            Self::PIPL => "http://www.npc.gov.cn/",
            _ => "",
        }
    }

    /// Get all regulations applicable to a specific region
    #[must_use]
    pub fn for_region(region: Region) -> Vec<Self> {
        match region {
            Region::EU => vec![Self::GDPR, Self::EPrivacy],
            Region::UK => vec![Self::UKGDPR],
            Region::US => vec![
                Self::CCPA,
                Self::CPRA,
                Self::VCDPA,
                Self::CPA,
                Self::CTDPA,
                Self::UCPA,
                Self::COPPA,
                Self::HIPAA,
            ],
            Region::California => vec![Self::CCPA, Self::CPRA],
            Region::Brazil => vec![Self::LGPD],
            Region::Canada => vec![Self::PIPEDA],
            Region::SouthAfrica => vec![Self::POPIA],
            Region::Singapore => vec![Self::PDPA],
            Region::Australia => vec![Self::PrivacyAct],
            Region::China => vec![Self::PIPL],
            Region::Japan => vec![Self::APPI],
            Region::Korea => vec![Self::PIPA],
            Region::Thailand => vec![Self::THPDPA],
            Region::Switzerland => vec![Self::FADP],
            Region::Global => vec![Self::PCIDSS],
        }
    }
}

/// Consent model type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsentModel {
    /// Requires explicit opt-in (GDPR style)
    OptIn,
    /// Allows opt-out (CCPA style)
    OptOut,
    /// Mixed requirements
    Mixed,
}

impl fmt::Display for ConsentModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OptIn => write!(f, "Opt-In (Explicit Consent Required)"),
            Self::OptOut => write!(f, "Opt-Out (Right to Refuse)"),
            Self::Mixed => write!(f, "Mixed (Varies by Context)"),
        }
    }
}

/// Geographic regions for regulation applicability
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Region {
    /// European Union
    EU,
    /// United Kingdom
    UK,
    /// United States (federal)
    US,
    /// California specifically
    California,
    /// Brazil
    Brazil,
    /// Canada
    Canada,
    /// South Africa
    SouthAfrica,
    /// Singapore
    Singapore,
    /// Australia
    Australia,
    /// China
    China,
    /// Japan
    Japan,
    /// South Korea
    Korea,
    /// Thailand
    Thailand,
    /// Switzerland
    Switzerland,
    /// Global (applies everywhere)
    Global,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regulation_display() {
        assert!(Regulation::GDPR.to_string().contains("GDPR"));
        assert!(Regulation::CCPA.to_string().contains("California"));
    }

    #[test]
    fn test_consent_model() {
        assert_eq!(Regulation::GDPR.consent_model(), ConsentModel::OptIn);
        assert_eq!(Regulation::CCPA.consent_model(), ConsentModel::OptOut);
    }

    #[test]
    fn test_cookie_consent_requirement() {
        assert!(Regulation::GDPR.requires_cookie_consent());
        assert!(Regulation::LGPD.requires_cookie_consent());
        assert!(!Regulation::CCPA.requires_cookie_consent());
    }

    #[test]
    fn test_jurisdiction() {
        assert_eq!(Regulation::GDPR.jurisdiction(), "European Union");
        assert_eq!(Regulation::CCPA.jurisdiction(), "California, USA");
        assert_eq!(Regulation::LGPD.jurisdiction(), "Brazil");
    }

    #[test]
    fn test_max_penalty() {
        assert!(Regulation::GDPR.max_penalty().is_some());
        assert!(Regulation::CCPA.max_penalty().is_some());
    }

    #[test]
    fn test_extraterritorial() {
        assert!(Regulation::GDPR.is_extraterritorial());
        assert!(Regulation::CCPA.is_extraterritorial());
        assert!(!Regulation::COPPA.is_extraterritorial());
    }

    #[test]
    fn test_region_regulations() {
        let eu_regs = Regulation::for_region(Region::EU);
        assert!(eu_regs.contains(&Regulation::GDPR));
        assert!(eu_regs.contains(&Regulation::EPrivacy));

        let us_regs = Regulation::for_region(Region::US);
        assert!(us_regs.contains(&Regulation::CCPA));
        assert!(us_regs.contains(&Regulation::COPPA));
    }

    #[test]
    fn test_short_name() {
        assert_eq!(Regulation::GDPR.short_name(), "GDPR");
        assert_eq!(Regulation::CCPA.short_name(), "CCPA");
    }

    #[test]
    fn test_official_url() {
        assert!(!Regulation::GDPR.official_url().is_empty());
        assert!(Regulation::GDPR.official_url().starts_with("https://"));
    }
}
