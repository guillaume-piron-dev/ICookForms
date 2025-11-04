//! Compliance checking for cookies

use crate::types::{ComplianceIssue, Cookie, Regulation, Severity};

/// Check cookie compliance with a regulation
#[must_use]
pub fn check_compliance(cookie: &Cookie, regulation: Regulation) -> Vec<ComplianceIssue> {
    let mut issues = Vec::new();

    match regulation {
        Regulation::GDPR | Regulation::UKGDPR => {
            issues.extend(check_gdpr_compliance(cookie));
        }
        Regulation::CCPA | Regulation::CPRA => {
            issues.extend(check_ccpa_compliance(cookie));
        }
        _ => {
            // Other regulations - basic check
            if !cookie.secure {
                issues.push(ComplianceIssue::new(
                    Severity::Medium,
                    regulation,
                    "Missing Secure Flag",
                    format!("Cookie '{}' should use Secure flag", cookie.name),
                    "Cookies should be transmitted securely",
                ));
            }
        }
    }

    issues
}

/// Check GDPR compliance
fn check_gdpr_compliance(cookie: &Cookie) -> Vec<ComplianceIssue> {
    let mut issues = Vec::new();

    // GDPR requires explicit consent for non-essential cookies
    if !cookie.secure || !cookie.http_only {
        issues.push(
            ComplianceIssue::new(
                Severity::High,
                Regulation::GDPR,
                "GDPR Compliance Issue",
                format!(
                    "Cookie '{}' may not meet GDPR security requirements",
                    cookie.name
                ),
                "Article 5(1)(f) - Security of processing",
            )
            .with_article("Art. 5(1)(f)")
            .with_penalty("Up to €20M or 4% of annual global revenue"),
        );
    }

    issues
}

/// Check CCPA compliance
fn check_ccpa_compliance(cookie: &Cookie) -> Vec<ComplianceIssue> {
    let mut issues = Vec::new();

    // CCPA opt-out requirement for sale of personal information
    if cookie.is_third_party {
        issues.push(ComplianceIssue::new(
            Severity::Medium,
            Regulation::CCPA,
            "Third-Party Cookie",
            format!(
                "Third-party cookie '{}' may require opt-out mechanism",
                cookie.name
            ),
            "CCPA Section 1798.120 - Right to opt-out of sale",
        ));
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdpr_compliance() {
        let cookie = Cookie::new("test".to_string(), "value".to_string());
        let issues = check_compliance(&cookie, Regulation::GDPR);

        assert!(!issues.is_empty());
    }
}
