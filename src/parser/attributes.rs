//! Cookie attribute parsing utilities

use crate::types::{Cookie, SameSite};

/// Cookie attribute types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    /// Domain attribute
    Domain(String),
    /// Path attribute
    Path(String),
    /// Expires attribute
    Expires(String),
    /// Max-Age attribute
    MaxAge(i64),
    /// Secure flag
    Secure,
    /// `HttpOnly` flag
    HttpOnly,
    /// `SameSite` attribute
    SameSite(SameSite),
    /// Unknown/Extension attribute
    Extension(String, Option<String>),
}

impl Attribute {
    /// Apply this attribute to a cookie
    pub fn apply_to(&self, cookie: &mut Cookie) {
        match self {
            Attribute::Domain(d) => cookie.domain = Some(d.clone()),
            Attribute::Path(p) => cookie.path = Some(p.clone()),
            Attribute::MaxAge(age) => cookie.max_age = Some(*age),
            Attribute::Secure => cookie.secure = true,
            Attribute::HttpOnly => cookie.http_only = true,
            Attribute::SameSite(ss) => cookie.same_site = Some(*ss),
            Attribute::Expires(_) => {
                // Handled separately in parser
            }
            Attribute::Extension(name, value) => {
                cookie
                    .extensions
                    .insert(name.clone(), value.clone().unwrap_or_default());
            }
        }
    }

    /// Get attribute name
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Attribute::Domain(_) => "Domain",
            Attribute::Path(_) => "Path",
            Attribute::Expires(_) => "Expires",
            Attribute::MaxAge(_) => "Max-Age",
            Attribute::Secure => "Secure",
            Attribute::HttpOnly => "HttpOnly",
            Attribute::SameSite(_) => "SameSite",
            Attribute::Extension(name, _) => name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_apply() {
        let mut cookie = Cookie::new("test".to_string(), "value".to_string());

        let attr = Attribute::Secure;
        attr.apply_to(&mut cookie);
        assert!(cookie.secure);

        let attr = Attribute::Domain("example.com".to_string());
        attr.apply_to(&mut cookie);
        assert_eq!(cookie.domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_attribute_name() {
        assert_eq!(Attribute::Secure.name(), "Secure");
        assert_eq!(Attribute::HttpOnly.name(), "HttpOnly");
    }
}
