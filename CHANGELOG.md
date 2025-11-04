# Changelog

All notable changes to ICOokForms will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-11-01

### Added
- 🎉 **Initial release** of ICOokForms - The World's Reference Cookie Audit Software
- 🔍 **Cookie Scanner** - HTTP/HTTPS scanning with reqwest + rustls
- 📜 **RFC 6265 Parser** - 100% compliant cookie parsing
- 🔒 **Security Analyzer** - Detection of 8 vulnerability types:
  - XSS (Cross-Site Scripting)
  - CSRF (Cross-Site Request Forgery)
  - Session Hijacking
  - Man-in-the-Middle (MITM)
  - Cookie Tampering
  - Session Fixation
  - Weak Cryptography
  - Missing Security Headers
- 📋 **Compliance Checker** - Support for 7 major regulations:
  - GDPR (EU)
  - CCPA/CPRA (California)
  - LGPD (Brazil)
  - POPIA (South Africa)
  - PIPEDA (Canada)
  - PDPA (Singapore)
  - ePrivacy Directive (EU)
- 🎯 **Tracking Detector** - Identification of 50+ tracking vendors
- 📊 **Professional Reports** - JSON, CSV, HTML, PDF export formats
- 💾 **Storage System** - SQLite database + LRU cache
- 🎨 **CLI Interface** - Rich terminal UI with colors and progress bars
- 🔐 **Cryptographic Utilities** - SHA256, SHA512, HMAC, Base64
- 🧪 **Comprehensive Testing** - 200+ unit tests, integration tests, benchmarks
- 📚 **Complete Documentation** - 6 technical documents (210KB)
- 🐳 **Docker Support** - Production-ready Dockerfile and docker-compose
- 🔄 **CI/CD** - GitHub Actions workflows for testing, release, and coverage
- ⚡ **High Performance** - Async/await, zero-copy parsing, concurrent analysis
- 🌍 **Multi-platform** - Linux, Windows, macOS, ARM support

### Security
- CVSS v3.1 scoring for vulnerabilities
- OWASP Top 10 coverage
- CWE/SANS Top 25 coverage
- Automatic security audit in CI/CD

### Performance
- Parser: <100μs per cookie
- Scanner: Async concurrent requests
- Analyzer: Parallel batch processing
- Cache: LRU with TTL for optimization

### Documentation
- Project Vision & Architecture
- RFC 6265 Standards Reference
- Security Vulnerabilities Guide
- Compliance (GDPR/CCPA) Guide
- Rust Architecture Documentation
- Testing Guide

## [0.1.0] - 2025-10-30

### Added
- Initial project structure
- Core types and error handling
- Basic cookie parsing prototype

---

## Version Naming Convention

- **Major (X.0.0)**: Breaking changes, major features
- **Minor (1.X.0)**: New features, backward compatible
- **Patch (1.0.X)**: Bug fixes, security patches

## Links

- [Homepage](https://github.com/guillaume-piron-dev/ICookForms)
- [Documentation](https://github.com/guillaume-piron-dev/ICookForms/tree/main/docs)
- [Issue Tracker](https://github.com/guillaume-piron-dev/ICookForms/issues)
- [Releases](https://github.com/guillaume-piron-dev/ICookForms/releases)

[Unreleased]: https://github.com/guillaume-piron-dev/ICookForms/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/guillaume-piron-dev/ICookForms/releases/tag/v1.0.0
[0.1.0]: https://github.com/guillaume-piron-dev/ICookForms/releases/tag/v0.1.0
