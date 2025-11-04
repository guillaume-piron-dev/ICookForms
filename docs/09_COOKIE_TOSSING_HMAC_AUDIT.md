# 09 - Cookie Tossing Mitigation & HMAC Audit Trail

**Documentation Production-Ready**

---

## 🎯 COOKIE TOSSING MITIGATION

### Définition

**Cookie Tossing** = Attaque où un attaqueur contrôle un sous-domaine et force des cookies sur le domaine parent.

### Mitigation #1 : __Host- Prefix

**Le plus efficace :**

```rust
pub fn is_cookie_tossing_safe(cookie: &Cookie) -> bool {
    if cookie.name.starts_with("__Host-") {
        // Vérifie conformité __Host-
        cookie.secure 
            && cookie.path == Some("/".to_string())
            && cookie.domain.is_none()
    } else if cookie.name.starts_with("__Secure-") {
        // Vérifie conformité __Secure-
        cookie.secure
    } else {
        false
    }
}
```

### Mitigation #2 : Configuration Serveur

**Nginx :**
```nginx
# CSP pour protection cookies
add_header Content-Security-Policy "default-src 'self'; script-src 'self';" always;

# Forcer HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Cookie avec Secure et SameSite
proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";
```

**Apache :**
```apache
# mod_headers.c
Header always set Content-Security-Policy "default-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# mod_session_cookie.c  
Session On
SessionCookieName session path=/;secure;httponly;samesite=strict
```

---

## 🔐 HMAC CHAIN IMPLEMENTATION

### Concept

Chaque log entry contient un HMAC qui dépend de l'entry précédente → chaîne tamper-proof.

### Implémentation Rust Complète

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: i64,
    pub action: String,
    pub details: String,
    pub previous_hash: Vec<u8>,
    pub current_hash: Vec<u8>,
}

pub struct AuditChain {
    key: Vec<u8>,
    entries: Vec<AuditLogEntry>,
}

impl AuditChain {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            entries: Vec::new(),
        }
    }
    
    pub fn add_entry(&mut self, action: String, details: String) -> Result<(), Error> {
        let timestamp = chrono::Utc::now().timestamp();
        
        // Hash précédent (ou vec vide si premier)
        let previous_hash = self.entries
            .last()
            .map(|e| e.current_hash.clone())
            .unwrap_or_default();
        
        // Calculer HMAC
        let mut mac = HmacSha256::new_from_slice(&self.key)?;
        mac.update(&previous_hash);
        mac.update(&timestamp.to_le_bytes());
        mac.update(action.as_bytes());
        mac.update(details.as_bytes());
        
        let current_hash = mac.finalize().into_bytes().to_vec();
        
        self.entries.push(AuditLogEntry {
            timestamp,
            action,
            details,
            previous_hash,
            current_hash,
        });
        
        Ok(())
    }
    
    pub fn verify_chain(&self) -> Result<bool, Error> {
        for (i, entry) in self.entries.iter().enumerate() {
            // Vérifier previous_hash
            if i > 0 {
                if entry.previous_hash != self.entries[i - 1].current_hash {
                    return Ok(false); // Chaîne cassée
                }
            }
            
            // Recalculer HMAC
            let mut mac = HmacSha256::new_from_slice(&self.key)?;
            mac.update(&entry.previous_hash);
            mac.update(&entry.timestamp.to_le_bytes());
            mac.update(entry.action.as_bytes());
            mac.update(entry.details.as_bytes());
            
            let computed_hash = mac.finalize().into_bytes().to_vec();
            
            if computed_hash != entry.current_hash {
                return Ok(false); // Hash invalide
            }
        }
        
        Ok(true)
    }
    
    pub fn save_to_file(&self, path: &str) -> Result<(), Error> {
        let json = serde_json::to_string_pretty(&self.entries)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    pub fn load_from_file(path: &str, key: Vec<u8>) -> Result<Self, Error> {
        let json = std::fs::read_to_string(path)?;
        let entries: Vec<AuditLogEntry> = serde_json::from_str(&json)?;
        Ok(Self { key, entries })
    }
}

// Utilisation
pub fn example_usage() -> Result<(), Error> {
    let key = vec![0; 32]; // Clé de 256 bits
    let mut chain = AuditChain::new(key);
    
    chain.add_entry("SCAN_STARTED".to_string(), "https://example.com".to_string())?;
    chain.add_entry("COOKIE_DETECTED".to_string(), "session_id=abc123".to_string())?;
    chain.add_entry("VULNERABILITY_FOUND".to_string(), "XSS in cookie value".to_string())?;
    
    // Vérifier intégrité
    let is_valid = chain.verify_chain()?;
    println!("Chain valid: {}", is_valid);
    
    // Sauvegarder
    chain.save_to_file("audit.json")?;
    
    Ok(())
}
```

### Key Rotation

```rust
pub struct KeyRotation {
    current_key: Vec<u8>,
    previous_keys: Vec<(DateTime<Utc>, Vec<u8>)>,
}

impl KeyRotation {
    pub fn rotate_key(&mut self) -> Vec<u8> {
        let new_key = generate_random_key();
        self.previous_keys.push((Utc::now(), self.current_key.clone()));
        self.current_key = new_key.clone();
        new_key
    }
    
    pub fn get_key_for_timestamp(&self, timestamp: DateTime<Utc>) -> &Vec<u8> {
        for (rotation_time, key) in self.previous_keys.iter().rev() {
            if timestamp >= *rotation_time {
                return key;
            }
        }
        &self.current_key
    }
}

fn generate_random_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}
```

---

## 📚 RÉFÉRENCES

**Cookie Tossing :**
- [Cookie Tossing Attacks](https://www.thomashouhou.com/post/cookie-tossing-attacks/)
- [RFC 6265bis __Host- prefix](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)

**HMAC Audit Trail :**
- [Secure Logging Cossack Labs](https://www.cossacklabs.com/blog/audit-logs-security/)
- [hmac crate](https://docs.rs/hmac)

---

**Document créé :** 01 novembre 2025
