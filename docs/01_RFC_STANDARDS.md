# RFC 6265 & Cookie Standards - Référence Technique Complète

**Document de Référence pour ICOokForms**

Version: 1.0.0  
Date: 30 octobre 2025  
Classification: Documentation Technique - Top 0.1%

---

## TABLE DES MATIÈRES

1. [RFC 6265 Overview](#rfc-6265-overview)
2. [Cookie Anatomy](#cookie-anatomy)
3. [Set-Cookie Header](#set-cookie-header)
4. [Cookie Header](#cookie-header)
5. [Cookie Attributes](#cookie-attributes)
6. [Security Considerations](#security-considerations)
7. [Implementation Guidelines](#implementation-guidelines)

---

## RFC 6265 OVERVIEW

### Historique

**RFC 6265** (April 2011) - "HTTP State Management Mechanism"
- Auteur: A. Barth (U.C. Berkeley)
- Obsoletes: RFC 2965
- Status: Standards Track

**Evolution:**
- **Netscape specification** (1994) - Original cookie spec (informal)
- **RFC 2109** (February 1997) - Premier standard formel (peu implémenté)
- **RFC 2965** (October 2000) - Set-Cookie2 (abandonné)
- **RFC 6265** (April 2011) - Standard actuel (reflète implémentations réelles)
- **Draft RFC 6265bis** (En cours) - Évolutions futures

### Objectif RFC 6265

Documenter comment les cookies fonctionnent **réellement** dans les navigateurs et serveurs modernes, plutôt que de spécifier un comportement idéal non-implémenté.

**Citation RFC 6265:**
> "This specification describes how HTTP servers store state (called cookies) at HTTP user agents, letting the servers maintain a stateful session over the mostly stateless HTTP protocol."

---

## COOKIE ANATOMY

### Structure Générale

```
Set-Cookie: <cookie-name>=<cookie-value>; <attributes>
```

### Exemple Complet

```http
Set-Cookie: session_id=38afes7a8; 
            Domain=example.com; 
            Path=/; 
            Expires=Wed, 09 Jun 2026 10:18:14 GMT;
            Max-Age=2592000;
            Secure; 
            HttpOnly; 
            SameSite=Strict
```

### Cookie Name & Value

**RFC 6265 Section 4.1.1:**

**Cookie Name:**
```abnf
cookie-name = token
token       = 1*<any CHAR except CTLs or separators>
```

- **Caractères autorisés:** Alphanumériques, `-`, `_`, `.`
- **Interdits:** Espaces, `,`, `;`, `=`
- **Case-sensitive:** `SessionID` ≠ `sessionid`

**Cookie Value:**
```abnf
cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
```

- **Caractères autorisés:** Printable ASCII (0x21 to 0x7E) sauf `,`, `;`, `\`, `"`
- **Quotes optionnelles:** `"value"` ou `value`
- **Encoding recommandé:** Base64 pour données binaires ou complexes

**Exemples valides:**
```http
Set-Cookie: username=john_doe
Set-Cookie: token=aGVsbG8gd29ybGQ=
Set-Cookie: data="complex value with spaces"
```

---

## SET-COOKIE HEADER

### Syntaxe ABNF

```abnf
set-cookie-header = "Set-Cookie:" SP set-cookie-string
set-cookie-string = cookie-pair *( ";" SP cookie-av )
cookie-pair       = cookie-name "=" cookie-value
cookie-av         = expires-av / max-age-av / domain-av /
                    path-av / secure-av / httponly-av /
                    samesite-av / extension-av

expires-av  = "Expires=" sane-cookie-date
max-age-av  = "Max-Age=" non-zero-digit *DIGIT
domain-av   = "Domain=" domain-value
path-av     = "Path=" path-value
secure-av   = "Secure"
httponly-av = "HttpOnly"
samesite-av = "SameSite=" samesite-value
samesite-value = "Strict" / "Lax" / "None"
```

### Règles d'Implémentation Serveur

**RFC 6265 Section 4:**

1. **Un Set-Cookie par header:**
   ```http
   # ✅ CORRECT
   Set-Cookie: session=abc123; HttpOnly
   Set-Cookie: preferences=dark_mode; Path=/settings
   
   # ❌ INCORRECT (ne pas combiner)
   Set-Cookie: session=abc123, preferences=dark_mode
   ```

2. **Ordre des attributs:** Non significatif (mais convention existe)
   ```http
   # Les deux sont équivalents
   Set-Cookie: id=a3fWa; Secure; HttpOnly
   Set-Cookie: id=a3fWa; HttpOnly; Secure
   ```

3. **Attributs dupliqués:** Comportement indéfini (éviter)
   ```http
   # ⚠️ Ne pas faire
   Set-Cookie: id=a3fWa; Domain=example.com; Domain=sub.example.com
   ```

---

## COOKIE HEADER

### Syntaxe Client → Serveur

```abnf
cookie-header = "Cookie:" OWS cookie-string OWS
cookie-string = cookie-pair *( ";" SP cookie-pair )
```

**Exemple:**
```http
Cookie: session_id=abc123; user_prefs=dark_mode; lang=fr
```

### Règles Importantes

1. **Pas d'attributs retournés:**
   - Le client NE renvoie PAS: Domain, Path, Expires, etc.
   - Seulement: `name=value`

2. **Ordre non garanti:**
   ```rust
   // ❌ NE PAS compter sur l'ordre
   if cookies[0].name == "session" { ... } // UNSAFE!
   
   // ✅ Rechercher par nom
   if let Some(session) = cookies.get("session") { ... }
   ```

3. **Cookies dupliqués possibles:**
   ```http
   Cookie: name=value1; name=value2
   ```
   RFC 6265: "servers SHOULD NOT rely upon the order"

---

## COOKIE ATTRIBUTES

### 1. Domain Attribute

**RFC 6265 Section 4.1.2.3:**

**Syntaxe:**
```http
Set-Cookie: name=value; Domain=example.com
```

**Comportement:**

| Set-Cookie Domain | Cookie envoyé pour | Cookie PAS envoyé pour |
|-------------------|-------------------|----------------------|
| (absent) | example.com uniquement | sub.example.com |
| Domain=example.com | example.com, sub.example.com, deep.sub.example.com | other.com |
| Domain=.example.com | ✅ (même que sans `.`) | N/A |
| Domain=com | ❌ Public suffix (rejeté) | Partout |

**⚠️ IMPORTANT - Public Suffix List:**

Les navigateurs maintiennent une Public Suffix List pour empêcher:
```http
# ❌ Ces domaines seront REJETÉS
Set-Cookie: id=x; Domain=com
Set-Cookie: id=x; Domain=co.uk
Set-Cookie: id=x; Domain=github.io
```

**Implémentation Rust:**
```rust
use publicsuffix::List;

fn validate_cookie_domain(cookie_domain: &str, request_domain: &str) -> Result<()> {
    let list = List::fetch()?;
    
    // Rejeter public suffixes
    if list.parse_domain(cookie_domain)?.root().is_none() {
        return Err(Error::PublicSuffix);
    }
    
    // Valider domain matching
    if !domain_matches(cookie_domain, request_domain) {
        return Err(Error::DomainMismatch);
    }
    
    Ok(())
}
```

### 2. Path Attribute

**RFC 6265 Section 4.1.2.4:**

**Syntaxe:**
```http
Set-Cookie: name=value; Path=/app
```

**Règles de Matching:**

```rust
fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    // Exact match
    if cookie_path == request_path {
        return true;
    }
    
    // Cookie path is prefix AND next char is '/'
    if request_path.starts_with(cookie_path) {
        let next_char = request_path.chars().nth(cookie_path.len());
        return next_char == Some('/');
    }
    
    // Cookie path is prefix AND ends with '/'
    if cookie_path.ends_with('/') && request_path.starts_with(cookie_path) {
        return true;
    }
    
    false
}

// Examples:
assert!(path_matches("/", "/anything"));
assert!(path_matches("/app", "/app/page"));
assert!(!path_matches("/app", "/application"));
assert!(path_matches("/app/", "/app/page"));
```

**⚠️ Security Note:** Path n'est PAS une security boundary
```http
# ❌ NE PAS utiliser Path pour isolation de sécurité
Set-Cookie: admin_token=secret; Path=/admin  # Peut être lu par JS sur /
```

### 3. Expires Attribute

**RFC 6265 Section 4.1.2.1:**

**Syntaxe:**
```http
Set-Cookie: name=value; Expires=Wed, 09 Jun 2026 10:18:14 GMT
```

**Format Date:**
```abnf
cookie-date = *delimiter date-token-list *delimiter
date-token-list = date-token *( 1*delimiter date-token )

# Format préféré (HTTP-date):
Expires=Wed, 09 Jun 2026 10:18:14 GMT

# Formats également acceptés (legacy):
Expires=Wednesday, 09-Jun-26 10:18:14 GMT
Expires=Wed Jun 09 10:18:14 2026
```

**Parsing en Rust:**
```rust
use chrono::{DateTime, Utc};

fn parse_cookie_date(date_str: &str) -> Result<DateTime<Utc>> {
    // RFC 2616 (HTTP-date) - préféré
    if let Ok(dt) = DateTime::parse_from_rfc2822(date_str) {
        return Ok(dt.with_timezone(&Utc));
    }
    
    // Fallback formats
    // ... parsing logic
    
    Err(Error::InvalidDateFormat)
}
```

### 4. Max-Age Attribute

**RFC 6265 Section 4.1.2.2:**

**Syntaxe:**
```http
Set-Cookie: name=value; Max-Age=3600  # 1 hour
```

**Priorité:** Max-Age > Expires (si les deux présents)

**Valeurs:**
- `0` = Suppression immédiate
- `> 0` = Durée en secondes
- `< 0` = Cookie de session (non recommandé, utiliser absence d'Expires/Max-Age)

### 5. Secure Attribute

**RFC 6265 Section 4.1.2.5:**

**Syntaxe:**
```http
Set-Cookie: session_id=abc123; Secure
```

**Comportement:**
- Cookie envoyé SEULEMENT sur HTTPS
- Cookie ignoré sur HTTP
- Obligatoire pour SameSite=None

**⚠️ CRITICAL SECURITY:**
```http
# ❌ VULNÉRABLE - Cookie sans Secure
Set-Cookie: session=secret  # Peut être intercepté en HTTP!

# ✅ SÉCURISÉ
Set-Cookie: session=secret; Secure; HttpOnly; SameSite=Strict
```

**Validation:**
```rust
fn validate_secure_cookie(cookie: &Cookie, is_https: bool) -> Result<()> {
    if cookie.secure && !is_https {
        return Err(Error::SecureCookieOnHttp);
    }
    
    // WARN: Sensitive cookies without Secure
    if is_sensitive_cookie(&cookie.name) && !cookie.secure {
        warn!("Sensitive cookie '{}' without Secure flag", cookie.name);
    }
    
    Ok(())
}
```

### 6. HttpOnly Attribute

**RFC 6265 Section 4.1.2.6:**

**Syntaxe:**
```http
Set-Cookie: session_id=abc123; HttpOnly
```

**Protection contre XSS:**
```javascript
// Avec HttpOnly:
document.cookie;  // Ne contient PAS les cookies HttpOnly ✅

// Sans HttpOnly:
document.cookie;  // ❌ ACCESSIBLE PAR XSS!
```

**⚠️ CRITICAL: Obligatoire pour session cookies**
```http
# ✅ Session cookie sécurisé
Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Strict

# ❌ Session cookie vulnérable
Set-Cookie: session_id=abc123  # XSS peut voler le cookie!
```

### 7. SameSite Attribute

**RFC 6265bis (Draft):**

**Syntaxe:**
```http
Set-Cookie: name=value; SameSite=Strict
Set-Cookie: name=value; SameSite=Lax
Set-Cookie: name=value; SameSite=None; Secure  # None REQUIRE Secure
```

**Comportement:**

| SameSite Value | Cross-Site GET | Cross-Site POST | Cross-Site Image | Navigation Top-Level |
|----------------|----------------|-----------------|------------------|---------------------|
| **Strict** | ❌ Non | ❌ Non | ❌ Non | ❌ Non (puis Oui après) |
| **Lax** (défaut) | ❌ Non | ❌ Non | ❌ Non | ✅ Oui |
| **None** | ✅ Oui | ✅ Oui | ✅ Oui | ✅ Oui |

**Exemples:**
```http
# Strict - Pour cookies de session
Set-Cookie: session_id=x; SameSite=Strict; Secure; HttpOnly

# Lax - Pour cookies généraux (défaut moderne)
Set-Cookie: user_prefs=x; SameSite=Lax

# None - Pour embedded content, OAuth, etc.
Set-Cookie: oauth_state=x; SameSite=None; Secure
```

**⚠️ IMPORTANT - Défaut navigateur:**

Chrome 80+ (Feb 2020): Défaut = `Lax` si non spécifié  
Firefox 69+: Défaut = `Lax`  
Safari 13.1+: Défaut = `Lax`

**CSRF Protection:**
```rust
fn validate_same_site(cookie: &Cookie, request: &Request) -> Result<()> {
    match cookie.same_site {
        Some(SameSite::Strict) => {
            if request.is_cross_site() {
                return Err(Error::SameSiteViolation);
            }
        }
        Some(SameSite::Lax) => {
            if request.is_cross_site() && !request.is_top_level_navigation() {
                return Err(Error::SameSiteViolation);
            }
        }
        Some(SameSite::None) => {
            if !cookie.secure {
                return Err(Error::SameSiteNoneRequiresSecure);
            }
        }
        None => {
            // Défaut = Lax (navigateurs modernes)
        }
    }
    Ok(())
}
```

---

## SECURITY CONSIDERATIONS

### RFC 6265 Section 8 - Security

**Principales vulnérabilités:**

1. **Confidentiality**
   - Cookies transmis en clair sur HTTP
   - Solution: Always use `Secure` flag

2. **Integrity**
   - Cookies peuvent être modifiés
   - Solution: Cryptographic signatures

3. **Cross-Site Request Forgery (CSRF)**
   - Cookies automatiquement envoyés
   - Solution: `SameSite`, CSRF tokens

4. **Cross-Site Scripting (XSS)**
   - JavaScript peut lire cookies
   - Solution: `HttpOnly` flag

5. **Cookie Injection**
   - Sous-domaines peuvent set cookies
   - Solution: Validation stricte, prefix `__Host-`

### Cookie Prefixes (Sécurité Additionnelle)

**RFC 6265bis introduit:**

```http
# __Secure- prefix
Set-Cookie: __Secure-session=x; Secure; Path=/
# DOIT avoir Secure flag

# __Host- prefix  
Set-Cookie: __Host-session=x; Secure; Path=/; Domain absente
# DOIT avoir Secure, Path=/, PAS de Domain
```

**Validation:**
```rust
fn validate_cookie_prefix(name: &str, cookie: &Cookie) -> Result<()> {
    if name.starts_with("__Secure-") {
        if !cookie.secure {
            return Err(Error::SecurePrefixRequiresSecure);
        }
    }
    
    if name.starts_with("__Host-") {
        if !cookie.secure {
            return Err(Error::HostPrefixRequiresSecure);
        }
        if cookie.path != Some("/") {
            return Err(Error::HostPrefixRequiresRootPath);
        }
        if cookie.domain.is_some() {
            return Err(Error::HostPrefixForbidsDomain);
        }
    }
    
    Ok(())
}
```

---

## IMPLEMENTATION GUIDELINES

### Best Practices pour ICOokForms

```rust
/// Complete cookie structure suivant RFC 6265
#[derive(Debug, Clone)]
pub struct Cookie {
    // Core (RFC 6265 Section 4.1.1)
    pub name: String,
    pub value: String,
    
    // Attributes (RFC 6265 Section 4.1.2)
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub max_age: Option<i64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
    
    // Metadata
    pub size: usize,
    pub created_at: DateTime<Utc>,
    
    // RFC compliance
    pub rfc_violations: Vec<RfcViolation>,
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone)]
pub enum RfcViolation {
    InvalidCharactersInName,
    InvalidCharactersInValue,
    PublicSuffixDomain,
    MissingSecureWithSameSiteNone,
    InvalidDateFormat,
    NegativeMaxAge,
}

impl Cookie {
    /// Parse Set-Cookie header according to RFC 6265
    pub fn parse_set_cookie(header: &str) -> Result<Self> {
        // Implementation suivant RFC 6265 Section 5.2
        todo!()
    }
    
    /// Validate cookie against RFC 6265
    pub fn validate_rfc_compliance(&self) -> Vec<RfcViolation> {
        let mut violations = Vec::new();
        
        // Validate name
        if !Self::is_valid_cookie_name(&self.name) {
            violations.push(RfcViolation::InvalidCharactersInName);
        }
        
        // Validate value
        if !Self::is_valid_cookie_value(&self.value) {
            violations.push(RfcViolation::InvalidCharactersInValue);
        }
        
        // Validate SameSite=None requires Secure
        if self.same_site == Some(SameSite::None) && !self.secure {
            violations.push(RfcViolation::MissingSecureWithSameSiteNone);
        }
        
        // Validate Max-Age
        if let Some(max_age) = self.max_age {
            if max_age < 0 {
                violations.push(RfcViolation::NegativeMaxAge);
            }
        }
        
        violations
    }
    
    fn is_valid_cookie_name(name: &str) -> bool {
        // RFC 6265 Section 4.1.1: token
        name.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
        }) && !name.is_empty()
    }
    
    fn is_valid_cookie_value(value: &str) -> bool {
        // RFC 6265 Section 4.1.1: cookie-octet
        value.chars().all(|c| {
            let code = c as u32;
            code == 0x21 || (code >= 0x23 && code <= 0x2B) ||
            (code >= 0x2D && code <= 0x3A) ||
            (code >= 0x3C && code <= 0x5B) ||
            (code >= 0x5D && code <= 0x7E)
        })
    }
}
```

---

## RÉFÉRENCES

### Standards
- **RFC 6265:** https://datatracker.ietf.org/doc/html/rfc6265
- **RFC 6265bis (Draft):** https://httpwg.org/http-extensions/draft-ietf-httpbis-layered-cookies.html
- **Public Suffix List:** https://publicsuffix.org/

### Crates Rust
- **biscotti:** Cookie parsing avancé
- **cookie:** Standard cookie management
- **publicsuffix:** Public Suffix List

### Ressources
- OWASP Cookie Security
- MDN Set-Cookie documentation
- Chrome Cookie specification

---

**Document maintenu par:** L'équipe ICOokForms  
**Dernière mise à jour:** 30 octobre 2025  
**Next Review:** Q1 2026
