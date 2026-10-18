# ICOokForms

Outil en ligne de commande et bibliothèque Rust pour l'audit de cookies HTTP : sécurité, conformité réglementaire et analyse forensique.

[![Crates.io](https://img.shields.io/crates/v/icookforms.svg)](https://crates.io/crates/icookforms)
[![Documentation](https://docs.rs/icookforms/badge.svg)](https://docs.rs/icookforms)
[![CI](https://img.shields.io/github/actions/workflow/status/guillaume-piron-dev/ICookForms/ci.yml?branch=main&label=CI)](https://github.com/guillaume-piron-dev/ICookForms/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.83%2B-orange.svg)](https://www.rust-lang.org/)

*[English version](README_EN.md)*

---

## Présentation

**ICOokForms** extrait les cookies d'un site web, analyse leur configuration de sécurité, vérifie leur conformité à plusieurs réglementations de protection des données et fournit des outils d'analyse forensique (chronologie, cookies binaires iOS/Safari, cookies Google Analytics, collecte de preuves). Le projet inclut également un module expérimental de détection d'anomalies par machine learning.

Les vérifications de conformité sont des contrôles techniques heuristiques sur les cookies ; elles ne remplacent pas un audit juridique.

---

## Fonctionnalités

### Analyse forensique

#### Reconstruction de chronologie
- Reconstruction de la chronologie des événements à partir des cookies
- Détection d'anomalies temporelles
- Vérification de cohérence des timestamps
- Score de confiance pour chaque événement reconstruit

#### Parser de cookies binaires iOS / Safari
- Lecture des fichiers Apple `.binarycookies`
- Extraction des métadonnées (flags, expiration, création)
- Export JSON ou CSV

#### Analyse des cookies Google Analytics
- Extraction des client IDs et sessions
- Pages vues et parcours utilisateur
- Termes de recherche et informations de campagne (source, medium, name, term, content)

#### Collecte de preuves (chain-of-custody)
- Collecte des cookies avec traçabilité (chain-of-custody)
- Empreinte SHA-256 pour le contrôle d'intégrité
- Horodatage de la collecte
- Métadonnées d'enquête (enquêteur, numéro de dossier)

#### Décodeur de valeurs
- Décodage **Base64**, **Hex**, **URL encoding**
- Détection de **timestamps** Unix et ISO
- Reconnaissance des **UUID**
- Détection de données structurées (JSON)

### Machine learning (expérimental)

#### Entraînement de modèles
- Entraînement d'un modèle **Isolation Forest** sur un jeu de cookies de référence
- Paramètres configurables (nombre d'arbres, taille d'échantillon, seed)
- Sauvegarde et réutilisation des modèles entraînés

#### Détection d'anomalies
- Score d'anomalie par cookie
- Sévérité (Low, Medium, High, Critical)
- Explication des raisons de chaque détection

#### Analyse comportementale
- Comparaison avec une baseline de référence
- Détection de déviations

#### Reconnaissance de patterns
- Reconnaissance de patterns connus (tracking, fingerprinting, motifs malveillants)
- Classification par type de menace

#### Détection heuristique d'attaques inconnues (« zero-day »)
- Analyse heuristique des cookies inhabituels
- Niveau d'agressivité configurable (1-5) ; un niveau élevé augmente les faux positifs

### Sécurité
Détection des configurations de cookies qui exposent à des attaques courantes :
- **Secure** absent : exposition aux interceptions (MITM)
- **HttpOnly** absent : exposition au vol par XSS
- **SameSite** absent ou permissif : exposition au CSRF
- Risque de **fixation de session**
- **Valeurs prédictibles** facilitant le détournement de session
- **Données sensibles** stockées en clair dans les cookies

### Conformité réglementaire
Réglementations disponibles dans la CLI (`icookforms compliance --regulation <...>`) :
- **GDPR** (Union européenne)
- **CCPA** et **CPRA** (Californie)
- **LGPD** (Brésil)
- **PIPEDA** (Canada)
- **POPIA** (Afrique du Sud)

L'API Rust (`ComplianceChecker`) propose aussi des contrôles pour : UK GDPR, directive ePrivacy, PDPA (Singapour), Privacy Act (Australie), APPI (Japon), COPPA, HIPAA et les lois des États américains VCDPA, CPA, CTDPA et UCPA.

Également disponibles dans la bibliothèque : décodage et validation des chaînes **IAB TCF 2.2** et détection de **Google Consent Mode v2**.

### Parsing RFC 6265
- Parsing des en-têtes `Set-Cookie` selon la **RFC 6265**, avec prise en compte de la **RFC 6265bis**
- Attributs : Domain, Path, Secure, HttpOnly, SameSite, Expires, Max-Age
- Validation et détection d'attributs manquants ou mal configurés
- Distinction des cookies first-party et third-party

### Plateformes
- CI configurée sur Linux, Windows et macOS (GitHub Actions)
- Dockerfile fourni pour une construction locale de l'image

---

## Installation

### Via Cargo
```bash
# Installation depuis crates.io
cargo install icookforms

# Vérifier l'installation
icookforms --version
```

### Compilation depuis les sources
```bash
# Cloner le repository
git clone https://github.com/guillaume-piron-dev/ICookForms.git
cd ICookForms

# Compiler en mode release
cargo build --release

# Exécuter les tests
cargo test

# Installer localement
cargo install --path .
```

### Via Docker (image locale)
Aucune image n'est publiée sur un registre pour l'instant (publication prévue). L'image se construit à partir du `Dockerfile` du repository :
```bash
# Construire l'image
docker build -t icookforms .

# Exécuter ICOokForms
docker run --rm icookforms scan --url https://example.com
```

---

## Utilisation

### Aide et informations

```bash
# Afficher l'aide générale
icookforms --help

# Afficher la version
icookforms --version

# Aide pour une commande spécifique
icookforms scan --help
icookforms forensics --help
icookforms ml --help
```

---

### Scan : extraction de cookies

#### Scan simple
```bash
# Scanner un site web
icookforms scan --url https://example.com

# Scanner avec sortie JSON
icookforms scan --url https://example.com --output cookies.json --format json
```

#### Crawl et redirections
```bash
# Explorer plusieurs pages
icookforms scan --url https://example.com --crawl --max-pages 100

# Suivre les redirections
icookforms scan --url https://example.com --follow-redirects --max-redirects 10
```

#### Configuration réseau
```bash
# Utiliser un proxy
icookforms scan --url https://example.com --proxy http://proxy.local:8080

# Timeout personnalisé
icookforms scan --url https://example.com --timeout 60

# User-Agent personnalisé
icookforms scan --url https://example.com --user-agent "ICOokForms/0.1 Security Audit"

# Limiter le débit de requêtes
icookforms scan --url https://example.com --rate-limit 5
```

#### Mode verbose
```bash
# Affichage détaillé pour le débogage
icookforms scan --url https://example.com --verbose --no-color
```

---

### Analyze : analyse de sécurité

```bash
# Analyse complète
icookforms analyze --input cookies.json

# Analyse avec rapport détaillé
icookforms analyze --input cookies.json --verbose --output security_report.json

# Limiter l'analyse à certains volets
icookforms analyze --input cookies.json --security --tracking

# Analyse de conformité sur plusieurs régulations
icookforms analyze --input cookies.json --compliance --regulations gdpr,ccpa,lgpd

# Afficher uniquement à partir d'une sévérité donnée
icookforms analyze --input cookies.json --min-severity high
```

---

### Compliance : conformité réglementaire

```bash
# Vérifier la conformité GDPR (EU)
icookforms compliance --input cookies.json --regulation gdpr

# Vérifier la conformité CCPA (Californie)
icookforms compliance --input cookies.json --regulation ccpa

# Mode strict (les avertissements comptent comme des échecs)
icookforms compliance --input cookies.json --regulation lgpd --strict

# Analyse du mécanisme de consentement d'un site
icookforms compliance --input cookies.json --check-consent --url https://example.com

# Rapport de conformité détaillé
icookforms compliance --input cookies.json --regulation gdpr --verbose --output gdpr_audit.json
```

---

### Report : génération de rapports

```bash
# Rapport HTML
icookforms report --input results.json --format html --output report.html

# Rapport PDF avec résumé et recommandations
icookforms report --input results.json --format pdf --output executive_report.pdf --summary --recommendations

# Rapport JSON pour traitement automatisé
icookforms report --input results.json --format json --output detailed_report.json

# Export CSV
icookforms report --input results.json --format csv --output data.csv

# En-tête personnalisé
icookforms report --input results.json --title "Audit cookies" --company "ACME" --auditor "Jane Doe"
```

---

### Forensics : analyse forensique

#### Reconstruction de chronologie
```bash
# Reconstruire la chronologie des événements
icookforms forensics timeline --input cookies.json --output timeline.json

# Avec détection d'anomalies
icookforms forensics timeline --input cookies.json --show-anomalies --threshold 0.7
```

#### Parser de cookies binaires iOS / Safari
```bash
# Parser un fichier Cookies.binarycookies
icookforms forensics ios-binary --input Cookies.binarycookies --output ios_cookies.json

# Extraire uniquement les métadonnées
icookforms forensics ios-binary --input Cookies.binarycookies --metadata-only
```

#### Analyse Google Analytics
```bash
# Analyse des cookies Google Analytics
icookforms forensics google-analytics --input cookies.json --output ga_analysis.json

# Extraire le parcours utilisateur
icookforms forensics google-analytics --input cookies.json --user-journey --output journey.json

# Extraire les termes de recherche
icookforms forensics google-analytics --input cookies.json --search-terms

# Analyse complète
icookforms forensics google-analytics --input cookies.json --user-journey --search-terms --output full_ga.json
```

#### Rapport forensique complet
```bash
# Générer un rapport forensique
icookforms forensics full-report --input cookies.json --output forensic_report.pdf

# Avec les données brutes
icookforms forensics full-report --input cookies.json --include-raw --output complete_report.pdf

# Avec un fuseau horaire
icookforms forensics full-report --input cookies.json --timezone "Europe/Paris" --output report_fr.pdf
```

#### Collecte de preuves
```bash
# Collecter des preuves avec chain-of-custody
icookforms forensics evidence --input cookies.json --output evidence_dir/ --chain-of-custody

# Avec les informations d'enquête
icookforms forensics evidence \
  --input cookies.json \
  --output evidence/ \
  --investigator "John Doe" \
  --case-number "CASE-001" \
  --chain-of-custody
```

#### Décodage de valeurs
```bash
# Décoder tous les cookies
icookforms forensics decode --input cookies.json --output decoded.json

# Décoder un cookie spécifique
icookforms forensics decode --input cookies.json --cookie-name "_ga" --output ga_decoded.json

# Décodage détaillé
icookforms forensics decode --input cookies.json --verbose
```

---

### ML : détection d'anomalies (expérimental)

#### Entraînement
```bash
# Entraîner un modèle sur des cookies de référence
icookforms ml train --dataset normal_cookies.json --output model.bin

# Entraînement avec paramètres
icookforms ml train \
  --dataset baseline_cookies.json \
  --output trained_model.bin \
  --n-trees 200 \
  --sample-size 512 \
  --seed 42
```

#### Détection
```bash
# Détecter des anomalies avec un modèle entraîné
icookforms ml detect --input cookies.json --model trained_model.bin

# Seuil personnalisé
icookforms ml detect --input cookies.json --threshold 0.8 --output anomalies.json

# Uniquement les anomalies de sévérité élevée
icookforms ml detect --input cookies.json --high-severity-only

# Détection avec rapport JSON
icookforms ml detect \
  --input suspicious_cookies.json \
  --model production_model.bin \
  --threshold 0.75 \
  --output ml_report.json \
  --format json
```

#### Analyse comportementale
```bash
# Analyser le comportement des cookies
icookforms ml analyze --input cookies.json --output behavioral_analysis.json

# Comparaison avec une baseline
icookforms ml analyze \
  --input current_cookies.json \
  --baseline normal_baseline.json \
  --output deviations.json
```

#### Reconnaissance de patterns
```bash
# Reconnaître des patterns connus
icookforms ml patterns --input cookies.json --output patterns.json

# Uniquement les patterns malveillants
icookforms ml patterns --input cookies.json --malicious-only
```

#### Détection heuristique « zero-day »
```bash
# Détection avec niveau d'agressivité par défaut
icookforms ml zero-day --input cookies.json --output zero_days.json

# Niveau modéré
icookforms ml zero-day --input cookies.json --aggressiveness 3

# Niveau maximal (plus de faux positifs)
icookforms ml zero-day --input cookies.json --aggressiveness 5 --output high_alert.json
```

---

### Options globales

```bash
# Format de sortie : human (défaut), json, yaml, csv
icookforms scan --url https://example.com --format json

# Mode verbose
icookforms scan --url https://example.com --verbose

# Désactiver les couleurs (CI/CD)
icookforms scan --url https://example.com --no-color

# Combiner plusieurs options
icookforms scan \
  --url https://example.com \
  --verbose \
  --format json \
  --output results.json \
  --no-color
```

---

## Utilisation en tant que bibliothèque Rust

### Exemple simple

```rust
use icookforms::{Analyzer, ScanConfig, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Scanner un site web
    let scanner = Scanner::new(ScanConfig::default())?;
    let scan_result = scanner.scan("https://example.com").await?;

    // Analyser les cookies
    let analyzer = Analyzer::new();
    let analysis = analyzer.analyze_batch(&scan_result.cookies);

    println!("Cookies trouvés : {}", scan_result.cookies.len());
    println!("Problèmes de sécurité : {}", analysis.security_issues.len());
    println!("Problèmes de conformité : {}", analysis.compliance_issues.len());

    Ok(())
}
```

### Détection d'anomalies

```rust
use icookforms::{AnomalySeverity, Cookie, MLAnalyzer, MLConfig, ScanConfig, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Cookies considérés comme normaux, utilisés comme référence
    let baseline_cookies: Vec<Cookie> = load_baseline()?;

    let scanner = Scanner::new(ScanConfig::default())?;
    let scan_result = scanner.scan("https://example.com").await?;

    let ml_config = MLConfig {
        anomaly_threshold: 0.8,
        enable_zero_day_detection: true,
        ..Default::default()
    };
    let mut ml_analyzer = MLAnalyzer::with_config(&ml_config);

    // Entraîner sur la baseline puis détecter
    ml_analyzer.train(&baseline_cookies)?;
    let anomalies = ml_analyzer.detect(&scan_result.cookies)?;

    for anomaly in anomalies
        .iter()
        .filter(|a| a.severity == AnomalySeverity::Critical)
    {
        eprintln!(
            "CRITIQUE : {} - {}",
            anomaly.cookie.name,
            anomaly.explanation.as_deref().unwrap_or("")
        );
    }

    Ok(())
}
```

### Analyse forensique

```rust
use icookforms::forensics::{ForensicAnalyzer, ForensicConfig};
use icookforms::Cookie;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cookies: Vec<Cookie> = load_cookies()?;

    let config = ForensicConfig {
        enable_chain_of_custody: true,
        include_raw_data: true,
        timezone: "UTC".to_string(),
        anomaly_threshold: 0.7,
    };
    let analyzer = ForensicAnalyzer::with_config(config);

    // Reconstruire la chronologie
    let timeline = analyzer.reconstruct_timeline(&cookies)?;
    println!(
        "Chronologie : {} événements sur {} heures",
        timeline.events.len(),
        timeline.duration.num_hours()
    );

    // Analyser les cookies Google Analytics
    for ga in analyzer.analyze_google_analytics(&cookies)? {
        println!("GA client ID : {} ({} pages vues)", ga.client_id, ga.page_views.len());
    }

    Ok(())
}
```

---

## Architecture

```
icookforms/
├── src/
│   ├── cli/              # Interface en ligne de commande
│   │   ├── commands/     #   scan, analyze, compliance, report, forensics, ml
│   │   └── output.rs     #   Formats de sortie (human, json, yaml, csv)
│   ├── scanner/          # Extraction de cookies HTTP/HTTPS (reqwest, scraper)
│   ├── parser/           # Parsing RFC 6265
│   │   ├── rfc6265.rs
│   │   ├── attributes.rs
│   │   └── validation.rs
│   ├── analyzer/         # Analyse de sécurité, conformité et tracking
│   │   ├── security.rs
│   │   ├── compliance.rs
│   │   └── tracking.rs
│   ├── compliance/       # Conformité réglementaire
│   │   ├── gdpr.rs
│   │   ├── ccpa.rs
│   │   ├── regulations.rs     # LGPD, PIPEDA, POPIA, CPRA, UK GDPR, ePrivacy, etc.
│   │   ├── consent.rs
│   │   ├── iab_tcf/           # IAB TCF 2.2
│   │   └── google_consent/    # Google Consent Mode v2
│   ├── forensics/        # Analyse forensique
│   │   ├── timeline.rs
│   │   ├── ios_binary.rs
│   │   ├── google_analytics.rs
│   │   ├── evidence_collector.rs
│   │   ├── cookie_decoder.rs
│   │   └── report_generator.rs
│   ├── ml_analyzer/      # Détection d'anomalies (expérimental)
│   │   ├── anomaly_detector.rs     # Isolation Forest
│   │   ├── behavioral_analysis.rs
│   │   ├── pattern_recognition.rs
│   │   ├── zero_day_detector.rs
│   │   ├── models/
│   │   └── training/
│   ├── reporter/         # Rapports HTML, PDF, JSON, CSV
│   ├── storage/          # Historique SQLite et cache sled
│   ├── types/            # Types de données (cookie, config, issue, report, regulation)
│   └── utils/            # Crypto, HTTP, temps, URL
├── tests/                # Tests d'intégration et property-based (proptest)
├── benches/              # Benchmarks Criterion
├── docs/                 # Documentation
└── examples/             # Exemples d'utilisation
```

---

## Documentation

### Documents du projet

- **[Vision du projet](docs/00_PROJECT_VISION.md)**
- **[Standards RFC 6265](docs/01_RFC_STANDARDS.md)**
- **[Implémentation IAB TCF 2.2](docs/06_IAB_TCF_2_2_IMPLEMENTATION_COMPLETE.md)**
- **[Google Consent Mode v2](docs/07_GOOGLE_CONSENT_MODE_V2_COMPLETE.md)**
- **[Bibliothèques ML Rust pour la détection d'anomalies](docs/08_RUST_ML_LIBRARIES_ANOMALY_DETECTION.md)**
- **[Cookie tossing et audit HMAC](docs/09_COOKIE_TOSSING_HMAC_AUDIT.md)**

### Checklists

- [GDPR Compliance Checklist](docs/checklists/GDPR_COMPLIANCE_CHECKLIST.md)
- [CCPA Compliance Checklist](docs/checklists/CCPA_COMPLIANCE_CHECKLIST.md)
- [General Compliance Checklist](docs/checklists/GENERAL_COMPLIANCE_CHECKLIST.md)
- [ISO 27001 Checklist](docs/checklists/ISO_27001_CHECKLIST.md)
- [ISO 27701 Checklist](docs/checklists/ISO_27701_CHECKLIST.md)

### Liens

- **[Documentation API](https://docs.rs/icookforms)** : référence de l'API Rust
- **[Changelog](CHANGELOG.md)** : historique des versions
- **[Guide de contribution](CONTRIBUTING.md)**

---

## Développement

### Prérequis

- **Rust 1.83+** (édition 2021)
- **Cargo**
- **Git**
- *(Optionnel)* **Docker**

### Workflow

```bash
# Compiler le projet
cargo build --release

# Exécuter les tests
cargo test

# Couverture de code
cargo tarpaulin --out Html

# Benchmarks
cargo bench

# Lint
cargo clippy -- -D warnings

# Formater le code
cargo fmt

# Générer la documentation
cargo doc --open

# Audit des dépendances
cargo audit
```

### Tests

```bash
# Tests unitaires
cargo test --lib

# Tests d'intégration
cargo test --test '*'

# Test spécifique
cargo test test_cookie_parsing

# Tests avec logs
RUST_LOG=debug cargo test
```

### Benchmarks

```bash
# Tous les benchmarks
cargo bench

# Benchmark spécifique
cargo bench --bench parser_bench

# Enregistrer une baseline
cargo bench -- --save-baseline main
```

---

## Contribution

Les contributions sont les bienvenues. Merci de lire le [guide de contribution](CONTRIBUTING.md).

### Standards de code

- Suivre les conventions de nommage Rust
- Exécuter `cargo fmt` avant chaque commit
- Exécuter `cargo clippy` et corriger les warnings
- Écrire des tests pour toute nouvelle fonctionnalité
- Documenter les APIs publiques avec rustdoc
- Ajouter des exemples pour les nouvelles fonctionnalités

### Processus

1. **Fork** du repository
2. **Créer** une branche (`git checkout -b feature/ma-fonctionnalite`)
3. **Commit** des changements (`git commit -m 'Add ma-fonctionnalite'`)
4. **Push** de la branche (`git push origin feature/ma-fonctionnalite`)
5. **Ouvrir** une Pull Request

---

## Licence

**ICOokForms** est distribué sous licence **Apache License 2.0**. Voir [LICENSE](LICENSE).

---

## Remerciements

ICOokForms s'appuie sur le travail de :

- la communauté Rust
- l'OWASP Foundation (standards de sécurité)
- le Mozilla Developer Network (documentation web)
- l'IETF (RFC 6265, RFC 6265bis)

---

## Support et contact

- **[Issues](https://github.com/guillaume-piron-dev/ICookForms/issues)** : bugs et demandes de fonctionnalités
- **[Pull Requests](https://github.com/guillaume-piron-dev/ICookForms/pulls)** : contributions
- **Email** : untelec.pro@gmail.com
- **GitHub** : [@guillaume-piron-dev](https://github.com/guillaume-piron-dev)

### Signaler un bug

Merci d'ouvrir une [issue](https://github.com/guillaume-piron-dev/ICookForms/issues/new) en indiquant :
- la version d'ICOokForms
- le système d'exploitation
- une description du problème
- les étapes pour le reproduire
- les logs d'erreur, le cas échéant

---

## Feuille de route

### Prévu
- [ ] Publication d'une image Docker sur un registre public
- [ ] Support WebAssembly (WASM)
- [ ] API REST pour l'intégration CI/CD
- [ ] Dashboard web
- [ ] Formats d'export supplémentaires (Excel, Word)
- [ ] Système de plugins
- [ ] Scan distribué
- [ ] Alertes (Slack, PagerDuty, email)
- [ ] Opérateur Kubernetes
- [ ] Modèles ML supplémentaires (autoencoder, LSTM)
- [ ] Version 1.0 avec API stabilisée
