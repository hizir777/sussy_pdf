# 🛡️ Güvenlik Politikası (SECURITY.md)

## İçindekiler

1. [Bilinen Zafiyetler](#bilinen-zafiyetler)
2. [Güvenlik Raporlaması](#güvenlik-raporlaması)
3. [Security Best Practices](#security-best-practices)
4. [Bağımlılık Güvenliği](#bağımlılık-güvenliği)
5. [Kontainer & Deployment Güvenliği](#kontainer--deployment-güvenliği)

---

## ⚠️ Bilinen Zafiyetler

### v1.0.0 (Current)

| ID | Açıklama | Seviye | Durum | Düzeltme |
|----|----------|--------|-------|----------|
| SEC-001 | Web dashboard'da authentication yok | **YÜKSEK** | ⏳ Planning (Sprint 1) | API Key + JWT (v1.1.0) |
| SEC-002 | Girdilerde SSRF validation yok | **ORTA** | ⏳ Planning | URL whitelist (v1.1.0) |
| SEC-003 | DoS: Pathologic PDF infinite loop | **ORTA** | ⏳ Planning | Timeout + size limit (v1.1.0) |
| SEC-004 | Dashboard CORS açık (default) | **DÜŞÜK** | ⏳ Planning | Strict CORS policy (v1.1.0) |

**KULLANICILAR İÇİN:**
- ✅ CLI aracını **yerel ortamda** çalıştırın
- ✅ Web dashboard'ı **private network'te** deploy edin
- ⚠️ Genel internete expose **ETMEYİN** (Auth eklenene kadar)

---

## 🔐 Güvenlik Raporlaması

### ZAFIYYET BULDUNUz MU?

🛑 **LÜTFEN GITHUB'da PUBLIC ISSUE AÇMAYIN!**

Bunun yerine:

### Email ile Bildir

```
To: security@sussy-pdf.dev
Subject: [SECURITY] CVE-like vulnerability in v1.0.0

Body:
1. Zafiyyet tanımı
2. Etkilenen versiyonlar
3. PoC (Proof of Concept) ya da tekrarlanma adımları
4. Önerilen düzeltme (isteğe bağlı)
```

### PGP Şifrelemesi (İsteğe bağlı)

```bash
gpg --import security-public-key.asc
gpg --encrypt --armor --recipient security@sussy-pdf.dev report.txt
```

### Yanıt Zamanı

| Seviye | Yanıt Süresi | Patch Süresi |
|--------|-------------|-------------|
| **Kritik** | 24 saat | 7 gün |
| **Yüksek** | 48 saat | 14 gün |
| **Orta** | 5 gün | 30 gün |
| **Düşük** | 10 gün | 60 gün |

### Disclosure Policy

- ✅ Güvenlik tarafı sorumlu olarak adlandırılacaksa (CVSS ≥ 7.0)
- ✅ Patch release veya minor version bump
- ✅ Security advisory yayınlanacak
- ✅ Finder'a kredisi verilecek (ister anonim)

---

## 🔒 Security Best Practices

### 1. Input Validation

```python
# ✅ DOĞRU: Girdileri valide et
def analyze(file_path: str):
    # Magic bytes doğrula
    with open(file_path, 'rb') as f:
        magic = f.read(4)
    if magic != b'%PDF':
        raise ValueError("Invalid PDF file")
    
    # Boyut kontrol
    file_size = os.path.getsize(file_path)
    if file_size > 500 * 1024 * 1024:  # 500MB max
        raise ValueError("File too large")

# ❌ YANLIŞ: Girdileri sorgula
open(user_input)  # Direkten açma!
```

### 2. SSRF Prevention (Server-Side Request Forgery)

```python
# ✅ DOĞRU: URL validation
from urllib.parse import urlparse

def validate_monitor_url(url: str) -> bool:
    parsed = urlparse(url)
    
    # Whitelist protokoller
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Blacklist internal IPs
    blocked_ips = [
        '127.0.0.1', 'localhost',
        '169.254.169.254',  # AWS metadata
        '10.0.0.0/8',       # Private IPs
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    
    # IPAddress library ile kontrol
    hostname = parsed.hostname
    if hostname in blocked_ips:
        return False
    
    return True

# ❌ YANLIŞ: Validasyon olmadan Request
requests.get(user_url)  # Tehlikeli!
```

### 3. LFI Prevention (Local File Inclusion)

```python
# ✅ DOĞRU: File path validation
from pathlib import Path

def safe_read_file(rel_path: str) -> bytes:
    # Resolved path
    base = Path("/app/uploads")
    target = (base / rel_path).resolve()
    
    # Sandbox check
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal attempt")
    
    if target.exists():
        return target.read_bytes()
    
    raise FileNotFoundError

# ❌ YANLIŞ: Doğru validate olmadan okuma
open(user_path)  # file:// protokolü girilirse RCE!
```

### 4. Encryption & Passwords

```python
# ✅ DOĞRU: bcryptjs hashing
from bcryptjs import hashpw, checkpw, gensalt

password = "user_password"
hashed = hashpw(password.encode(), gensalt(rounds=10))
# Store hashed in database

# Verification
if checkpw(input_password.encode(), hashed):
    # Correct!
    pass

# ❌ YANLIŞ: Plain text password
user.password = "plaintext123"  # Hiçbir zaman!
```

### 5. Logging Security

```python
# ✅ DOĞRU: Sensitive data masking
import logging

logger = logging.getLogger(__name__)

def process_file(file_path, api_key):
    # Secrets'ı log etme
    logger.info(f"Processing file: {file_path}")
    logger.debug(f"API key starts with: {api_key[:4]}...")  # Masked
    
    # Hata logları info değil
    try:
        ...
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")  # No stack trace in prod

# ❌ YANLIŞ: Full secrets logging
logger.info(f"API key: {api_key}")  # Stack traces in prod
```

### 6. CORS Policy

```python
# ✅ DOĞRU: Strict CORS
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-domain.com"],  # Whitelist!
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# ❌ YANLIŞ: Open CORS
# allow_origins=["*"]  # NEVER!
```

### 7. Rate Limiting

```python
# ✅ DOĞRU: Per-IP rate limiting
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/analyze")
@limiter.limit("10/minute")  # 10 requests per minute
def analyze_api(file: UploadFile):
    ...

# ❌ YANLIŞ: Unlimited requests
# DoS attack susceptible!
```

### 8. Dependency Management

```bash
# ✅ DOĞRU: Pinned versions
pip freeze > requirements.txt
# Deterministic deployments!

# docker-compose.yml
image: python:3.10.5-slim
# Specific version!

# ❌ YANLIŞ: Floating versions
pip install requests  # Latest version (unpredictable)
FROM python:3  # Latest Python (could break!)
```

---

## 📦 Bağımlılık Güvenliği

### Güvenlik Scanning

```bash
# Safety — Python package vulnerability scanner
pip install safety
safety check

# Example output:
# [!] 38 packages have security vulnerabilities!
```

### Dependency Updates

```bash
# Check for outdated packages
pip list --outdated

# Update safely (minor/patch versions)
pip install --upgrade pdfminer.six
```

### Supply Chain Security

| Kontrol | Status | Notes |
|---------|--------|-------|
| **Pinned versions** | ✅ | `requirements.txt` |
| **Hash verification** | ✅ | `pip install -r requirements.txt --require-hashes` |
| **Lockfile** | ⏳ | poetry.lock (v1.1.0 planned) |
| **SBOM** | ⏳ | CycloneDX (v1.2.0 planned) |
| **Security scanning** | ⏳ | GitHub security alerts |

---

## 🐳 Kontainer & Deployment Güvenliği

### Docker Best Practices

```dockerfile
# ✅ DOĞRU: Security hardening

# Multi-stage build
FROM python:3.10-slim as builder
RUN apt-get update && apt-get install -y gcc
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.10-slim
RUN groupadd -r node && useradd -r -g node node
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --chown=node:node . /app
WORKDIR /app

# Non-root user
USER node

# Read-only filesystem
RUN chmod 555 /app

ENTRYPOINT ["python", "-m", "src.main", "serve"]

# ❌ YANLIŞ: Security issues

FROM python:3.10  # Latest (unpredictable)
RUN apt-get install curl vim wget  # Extra tools = bigger attack surface
COPY . .  # Ownership default (root)
RUN pip install -r requirements.txt  # Caching issues
# Default USER root — privilege escalation risk!
```

### Kubernetes Security

```yaml
# ✅ DOĞRU: K8s security context
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sussy-pdf-api
spec:
  template:
    spec:
      containers:
      - name: api
        image: sussy-pdf:1.0.0
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: 100Mi
```

---

## ✅ Güvenlik Checklist

Deployment öncesi:

- [ ] API authentication enabled (API keys + JWT)
- [ ] CORS restrictive (whitelist only)
- [ ] Rate limiting active
- [ ] Logging untuk sensitive events
- [ ] Input validation für user data
- [ ] HTTPS/TLS enforced (production)
- [ ] Database encryption (at rest)
- [ ] Secrets management (HashiCorp Vault, AWS Secrets Manager)
- [ ] Audit logging enabled
- [ ] Backup & disaster recovery plan
- [ ] Security scanning tools (trivy, snyk)
- [ ] Penetration testing (annual)

---

**Version:** 1.0 (April 2026)  
**Maintainer:** @hizir777  
**Last Updated:** April 5, 2026  
**Contact:** security@sussy-pdf.dev
