# 🔧 Sorun Giderme (Troubleshooting)

Sussy PDF ile sorunlarla karşılaştıysanız, bu rehber size yardımcı olsa diye hazırlanmıştır.

## 📋 İçindekiler

1. [Kurulum Sorunları](#kurulum-sorunları)
2. [Analiz Sorunları](#analiz-sorunları)
3. [Web Dashboard Sorunları](#web-dashboard-sorunları)
4. [Docker Sorunları](#docker-sorunları)
5. [Performans Sorunları](#performans-sorunları)
6. [Güvenlik Uyarıları](#güvenlik-uyarıları)

---

## 🔌 Kurulum Sorunları

### ❌ Python versiyonu < 3.10

**Semptom:** `ModuleNotFoundError` veya `SyntaxError`

```bash
# Kontrol et
python --version
# Çıktı: Python 3.9.x  ← TOO OLD
```

**Çözüm:**
```bash
# Python 3.10+ indir
# Windows: https://www.python.org/downloads/
# Ubuntu: sudo apt install python3.10 python3.10-venv
# macOS: brew install python@3.10

# Virtual environment kullan (3.10 ile)
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

### ❌ YARA compilation error (Windows)

**Semptom:**
```
error: Microsoft Visual C++ 14.0 or greater is required.
```

**Çözüm:**

```bash
# Option 1: Visual C++ Build Tools kur
# İndir: https://visualstudio.microsoft.com/downloads/
# "Desktop development with C++" seç

# Option 2: YARA kütüphanesini skip et (test için)
pip install -r requirements.txt
# yara-python line'ını comment out et
```

---

### ❌ venv activate hatası (PowerShell)

**Semptom:**
```
cannot be loaded because running scripts is disabled
```

**Çözüm:**
```powershell
# PowerShell'i Administrator olarak aç
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Sonra venv'i activate et
.venv\Scripts\Activate.ps1
```

---

### ❌ "pip: command not found"

**Semptom:** `pip install` çalışmıyor

**Çözüm:**
```bash
# Python pip modülünü çalıştır
python -m pip install -r requirements.txt

# Veya Python3 kullan
python3 -m pip install --upgrade pip
```

---

## 📄 Analiz Sorunları

### ❌ "Not a PDF file" hatası

**Semptom:**
```
ValueError: Not a valid PDF file (magic bytes mismatch)
```

**Çözüm:**

```bash
# 1. Dosya başını kontrol et
xxd file.pdf | head
# %PDF-1.7 ile başlamalı

# 2. Dosya corrupt mu kontrol et
file file.pdf
# Çıktı: application/pdf olmalı

# 3. Dosya tipi doğru mu?
# GER ÇEK: file.pdf ismi ama asında JPG ise
```

---

### ❌ "Timeout: PDF analysis took too long"

**Semptom:**
```
TimeoutError: Analysis exceeded 300 seconds
```

**Çözüm:**

```bash
# 1. Dosya boyutu kontrol et
ls -lh file.pdf
# >500MB ense problem

# 2. Timeout değerini artır
python -m src.main analyze file.pdf --timeout 600

# 3. Async processing kullan (v1.2.0+)
python -m src.main analyze file.pdf --async
```

---

### ❌ "PDF encryption: password required"

**Semptom:**
```
EncryptionError: This PDF is encrypted. Use --password flag
```

**Çözüm:**

```bash
# Şifre ile açmayı dene
python -m src.main analyze file.pdf --password "yourpassword"

# Şifreyi bilmiyorsanız
# → v1.2.0'da AES brute-force desteği gelecek
# → Şu an manuel şifre çözme gerekli
```

---

### ❌ "JavaScript emulation failed"

**Semptom:**
```
JSEmulator: Could not execute JavaScript payload
```

**Çözüm:**

```bash
# 1. JS obfuscation levels kontrol et
python -m src.main analyze file.pdf --verbose

# 2. Kodu manuel deobfuscate et
# → Çıktıda raw JS string'ini kopyala
# → Online deobfuscator kullan (jsbeautifier.org)

# 3. Report'taki "obfuscation_score" kontrol et
# < 50: Düşük obfuscation (decodable)
# > 80: Yüksek obfuscation (emulation limited)
```

---

## 🌐 Web Dashboard Sorunları

### ❌ "Connection refused: localhost:8443"

**Semptom:**
```
Error: Failed to connect to http://localhost:8443
```

**Çözüm:**

```bash
# 1. Server çalışıyor mu kontrol et
ps aux | grep "sussy"  # Çalışan processi bul
# veya Windows: tasklist | find "python"

# 2. Port başka bir process tarafından kullanılıyor mu?
netstat -tlnp | grep 8443  # Linux
netstat -ano | findstr 8443  # Windows

# 3. Explicit port belirt
python -m src.main serve --port 9000

# 4. Host 0.0.0.0 değilse, localhost'ı dene
python -m src.main serve --host localhost --port 8443
```

---

### ❌ "CORS error in browser"

**Semptom:**
```
Access to XMLHttpRequest at 'http://localhost:8443/api/analyze' 
from origin 'http://localhost:3000' has been blocked by CORS policy
```

**Çözüm:**

```python
# 1. FastAPI CORS middleware'i kontrol et
# src/main.py'da:

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8443"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Browser developer tools in Network tab kontrol et
# Response headers'ında Access-Control-Allow-Origin olmalı

# 3. Development modunda full CORS enable et (prod'da yapma!)
allow_origins=["*"]  # Only for DEV!
```

---

### ❌ "FileUploadError: file too large"

**Semptom:**
```
413 Payload Too Large
```

**Çözüm:**

```python
# main.py'da max upload size artır
from fastapi import File, UploadFile, Form

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB

@app.post("/api/analyze")
async def analyze_api(file: UploadFile = File(...)):
    if file.size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    ...
```

---

## 🐳 Docker Sorunları

### ❌ "docker: command not found"

**Çözüm:**

```bash
# Docker yükle
# Windows/Mac: https://docs.docker.com/desktop/
# Linux: 
#   sudo apt install docker.io docker-compose
#   sudo usermod -aG docker $USER
#   newgrp docker
```

---

### ❌ "Build fails: 'python3: not found' in container"

**Çözüm:**

```dockerfile
# Dockerfile'da base image kontrol et
FROM python:3.10-slim  # ✅ Doğru
# FROM alpine:latest    # ❌ Python yok!
```

---

### ❌ "Container başlıyor ama hemen durduğu"

**Çözüm:**

```bash
# Logs kontrol et
docker-compose logs -f sussy-pdf-api

# Örnek çıktı: "no such file or directory"
# → Docker'da binding volume yolu kontrol et

# docker-compose.yml:
volumes:
  - ./output:/app/output  # Host path mutlak olmalı
```

---

## ⚡ Performans Sorunları

### ❌ "Analiz çok yavaş (1 PDF = 30 saniye)"

**Semptom:** Large PDF'ler (>100MB) analizi çok uzun sürüyor

**Çözüm:**

```bash
# 1. Profiling yap
python -m cProfile -s cumtime -m src.main analyze large.pdf > profile.txt
# En çok zaman harcayan fonksiyonları bul

# 2. Stream decoder kontrol et
# src/deobfuscation/stream_decoder.py optimize et
# → Memory-mapped files kullan büyük streamler için

# 3. Async processing kullan (v1.2.0+)
python -m src.main batch-analyze *.pdf --workers 4
```

---

### ❌ "Hafıza tüketimi aşırı (analysis > 2GB RAM)"

**Semptom:** `MemoryError: unable to allocate...`

**Çözüm:**

```python
# 1. File mmap'ing kullan
import mmap

def read_large_file(path):
    with open(path, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return m[:]  # Lazy loading

# 2. Batch processing kullan
# → Split'e 100MB chunks, analyze separately

# 3. Garbage collection optimize et
import gc
gc.collect()
```

---

## 🔒 Güvenlik Uyarıları

### ⚠️ "Warning: Running without authentication"

**Açıklama:** Dashboard hiçbir kullanıcı doğrulaması olmadan çalışıyor

**Uyarı Seviyesi:** 🔴 **KRITIK** (Internet'te)

**Çözüm:**

```bash
# ✅ Yalnızca private network'te çalıştır
python -m src.main serve --host 192.168.1.100 --port 8443

# ✅ v1.1.0'da (Sprint 1): API Key auth eklenecek
# Until then: Manual firewall rules

# iptables örneği (Linux):
sudo iptables -A INPUT -p tcp --dport 8443 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8443 -j DROP
```

---

### ⚠️ "Report contains sensitive paths"

**Açıklama:** HTML report'ta mutlak dosya yolları görünüyor

**Örnek:**
```
Analyzed: C:\Users\admin\Documents\company_secrets.pdf
```

**Çözüm:**

```python
# reportdan path'i sil veya relativize et
import os

file_name = os.path.basename(file_path)  # Only filename
# Çıktı: "company_secrets.pdf"
```

---

## 📞 Daha Fazla Yardım?

Çözüm bulamadıysanız:

- **GitHub Issues:** [Yeni issue aç](https://github.com/hizir777/sussy_pdf/issues)
- **Discussions:** [Soru sor](https://github.com/hizir777/sussy_pdf/discussions)
- **Email:** maintainers@sussy-pdf.dev

---

**Version:** 1.0  
**Last Updated:** April 5, 2026
