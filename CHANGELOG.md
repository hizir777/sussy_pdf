# 📝 Changelog

Tüm önem doğru değişiklikler bu dosyada belgelenir.

Format [Keep a Changelog](https://keepachangelog.com/) tarafından takip edilir ve [Semantic Versioning](https://semver.org/) kullanılır.

---

## [1.1.0] — April 5, 2026 (In Progress - Sprint 1)

### Added (Yeni)
- ✅ **JWT Token Authentication** — API endpoints'e token tabanlı authentication
- ✅ **API Key Management** — Secure API key generation & validation
- ✅ **Audit Logging** — Structured JSON logging for security events
- ✅ **Rate Limiting** — Per-IP/user rate limiting (slowapi)
- ✅ **Input Validation** — Enhanced SSRF/LFI prevention
- ✅ **PDF Encryption Support** — AES-128/256 decryption (pycryptodome)
- ✅ **Configuration Management** — Pydantic settings from .env
- ✅ **Development Documentation** — CONTRIBUTING.md, SECURITY.md, ROADMAP.md
- ✅ **GitHub Templates** — Issue/PR templates for standardized reporting
- ✅ **CI/CD Workflows** — Automated testing & quality checks
- ✅ **Test Suite** — pytest configuration with coverage reporting (pytest-cov)
- ✅ **Community Guidelines** — CODE_OF_CONDUCT.md

### Changed (Değişti)
- 🔄 Improved error handling in main.py
- 🔄 Enhanced logging across all modules
- 🔄 Better async file I/O support (aiofiles preparation)
- 🔄 Updated pyproject.toml with new dependencies

### Fixed (Düzeltildi)
- 🐛 CORS header handling for API endpoints
- 🐛 Improved PDF size validation
- 🐛 Fixed environment variable parsing

### Security (Güvenlik)
- 🔒 Added JWT token expiration (24 hours default)
- 🔒 Implemented SSRF URL validation
- 🔒 Added rate limiting to prevent abuse
- 🔒 Enhanced input sanitization (XSS prevention)
- 🔒 Secure API key generation (secrets)

### Deprecated (Kullanımdan Kalkan)
- None yet

### Removed (Kaldırılan)
- None yet

---

## [1.0.0] — January 1, 2026 (Current)

### Added (Initial Release)
- PDF static analysis (header, structure, metadata)
- Object tree building & relationship mapping
- Threat tag detection (16+ malicious indicators)
- JavaScript deobfuscation & string decoding
- Stream decompression (FlateDecode, ASCIIHex, ASCII85)
- Dynamic JavaScript emulation
- YARA rule matching
- Heuristic risk scoring (0-100)
- MITRE ATT&CK technique mapping
- Incremental update (shadow attack) detection
- IOC extraction & reporting
- Multiple output formats (JSON, HTML, Markdown)
- CLI interface with rich output
- FastAPI web dashboard
- Docker containerization
- Anti-evasion detection (VM/sandbox checks)

---

## [1.2.0] — May 2026 (Planned - Sprint 2)

### Planned
- 📌 Async PDF processing with aiofiles
- 📌 Batch analysis for 1000+ files
- 📌 Shellcode detection & exploit pattern matching
- 📌 CVE mapping (2020-2025)
- 📌 Performance optimizations
- 📌 Stream-based processing for large files
- 📌 Machine learning feature preparation

---

## [1.3.0] — June 2026 (Planned - Sprint 3)

### Planned
- 📌 Real-time threat feeds (Abuse.ch, MISP)
- 📌 VirusTotal API v3 integration
- 📌 Malware dataset integration (Contagio, AIDE)
- 📌 Advanced C2 detection engine
- 📌 SSL certificate analysis
- 📌 Slack/Teams reporting integration
- 📌 Multi-language support (EN/TR/ES)
- 📌 Compliance report templates (GDPR, HIPAA)

---

## [1.4.0] — July-August 2026 (Planned - Sprint 4)

### Planned
- 📌 Machine Learning model training
- 📌 Feature engineering (100+ features)
- 📌 Dataset curation (10K+ samples)
- 📌 Model evaluation & benchmarking
- 📌 ONNX model export

---

## [2.0.0] — September-October 2026 (Planned - Sprint 5)

### Planned
- 📌 Database integration (PostgreSQL, SQLite)
- 📌 Multi-user & multi-tenant support
- 📌 OAuth2 / OIDC authentication
- 📌 SAML 2.0 support
- 📌 Role-based access control (RBAC)
- 📌 Kubernetes deployment (Helm charts)
- 📌 Advanced audit logging & analytics
- 📌 Enterprise hardening & compliance
- 📌 SOC2 Type II readiness

---

## [2.1.0] — November-December 2026 (Planned - Sprint 6)

### Planned
- 📌 Trend analysis & malware clustering
- 📌 Neo4j graph database integration
- 📌 C2 network visualization
- 📌 Threat actor attribution
- 📌 Campaign tracking
- 📌 Auto-YARA rule generation
- 📌 MISP module
- 📌 Splunk integration

---

## Legend

- **Added** — Yeni özellikler
- **Changed** — Mevcut özelliklerde değişiklik
- **Fixed** — Hata düzeltmeleri
- **Deprecated** — Yakında kaldırılacak
- **Removed** — Kaldırılan özellikler
- **Security** — Güvenlik güncellemeleri

---

## Versioning

Sussy PDF [Semantic Versioning](https://semver.org/) takip eder:

```
MAJOR.MINOR.PATCH
  |      |      |
  |      |      └─ Patch: Hata düzeltmeleri
  |      └─ Minor: Yeni features (backward-compatible)
  └─ Major: Breaking changes
```

---

**Son Güncelleme:** April 5, 2026  
**Bakımcı:** @hizir777  
**İletişim:** maintainers@sussy-pdf.dev
