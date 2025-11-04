# 08 - Rust ML Libraries for Cookie Anomaly Detection

**Documentation Production-Ready**

---

## 🎯 OBJECTIF

Implémenter la détection d'anomalies dans les cookies en Rust avec Isolation Forest et autres algorithmes ML.

---

## 📊 BIBLIOTHÈQUES RUST ML

### 1. extended-isolation-forest

**Meilleure option pour ICOokForms**

```toml
[dependencies]
extended-isolation-forest = "0.3"
rand = "0.8"
```

**Code complet :**

```rust
use extended_isolation_forest::{Forest, ForestOptions};
use rand::distributions::Uniform;
use rand::Rng;

// Features pour analyse cookies
#[derive(Debug, Clone)]
pub struct CookieFeatures {
    pub size_bytes: f64,
    pub lifetime_days: f64,
    pub domain_depth: f64,
    pub value_entropy: f64,
    pub update_frequency: f64,
}

impl CookieFeatures {
    pub fn to_array(&self) -> [f64; 5] {
        [
            self.size_bytes,
            self.lifetime_days,
            self.domain_depth,
            self.value_entropy,
            self.update_frequency,
        ]
    }
}

pub struct CookieAnomalyDetector {
    forest: Forest<f64, 5>,
}

impl CookieAnomalyDetector {
    pub fn train(training_data: &[CookieFeatures]) -> Self {
        let values: Vec<[f64; 5]> = training_data
            .iter()
            .map(|f| f.to_array())
            .collect();
        
        let options = ForestOptions {
            n_trees: 150,
            sample_size: 200,
            max_tree_depth: None,
            extension_level: 1,
        };
        
        let forest = Forest::from_slice(&values, &options).unwrap();
        
        Self { forest }
    }
    
    pub fn predict(&self, features: &CookieFeatures) -> f64 {
        self.forest.score(&features.to_array())
    }
    
    pub fn is_anomaly(&self, features: &CookieFeatures, threshold: f64) -> bool {
        self.predict(features) > threshold
    }
}

// Calcul features
pub fn extract_features(cookie: &Cookie) -> CookieFeatures {
    CookieFeatures {
        size_bytes: cookie.value.len() as f64,
        lifetime_days: calculate_lifetime_days(cookie),
        domain_depth: cookie.domain.as_ref().map(|d| d.matches('.').count() as f64).unwrap_or(0.0),
        value_entropy: calculate_entropy(&cookie.value),
        update_frequency: 0.0, // Nécessite historique
    }
}

fn calculate_entropy(s: &str) -> f64 {
    use std::collections::HashMap;
    
    if s.is_empty() {
        return 0.0;
    }
    
    let mut freq = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    
    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}
```

### 2. smartcore (Alternative)

```toml
[dependencies]
smartcore = "0.3"
```

**Support Random Forest uniquement (pas Isolation Forest directement)**

---

## 🔍 FEATURES POUR COOKIES

### Features Principales

1. **Size** - Taille en bytes
2. **Lifetime** - Durée de vie
3. **Domain depth** - Nombre de sous-domaines
4. **Entropy** - Entropie de la valeur
5. **Update frequency** - Fréquence de mise à jour
6. **Attribute count** - Nombre d'attributs
7. **Secure/HttpOnly flags** - Flags de sécurité

### Détection Anomalies

- Score > 0.6 = Suspect
- Score > 0.75 = Anomalie haute confiance

---

## 📚 RÉFÉRENCES

- [extended-isolation-forest](https://docs.rs/extended-isolation-forest)
- [smartcore](https://docs.rs/smartcore)
- [ndarray](https://docs.rs/ndarray) pour matrices

---

**Document créé :** 01 novembre 2025
