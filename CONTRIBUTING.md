# 🤝 Geliştirici Rehberi — Contributing to Sussy PDF

Sussy PDF projelerine katkı yapmaktan dolayı teşekkür ederiz! Bu belgedeki projeyi nasıl geliştireceğiniz, test edeceğiniz ve pull request (PR) sunacağınız konusunda talimatlar bulunmaktadır.

## 📋 İçindekiler

1. [Başlangıç](#başlangıç)
2. [Ortam Kurulumu](#ortam-kurulumu)
3. [Kod Yazım Standartları](#kod-yazım-standartları)
4. [Test Yazma](#test-yazma)
5. [Commit Mesajları](#commit-mesajları)
6. [Pull Request Süreci](#pull-request-süreci)
7. [Raporlama](#raporlama)

---

## 🚀 Başlangıç

### Proje Yapısını Anlayın
```
sussy_pdf/
├── src/                    # Analiz motoru
│   ├── ingestion/          # Dosya alımı
│   ├── static_analysis/    # Yapısal analiz
│   ├── deobfuscation/      # Gizleme çözme
│   ├── dynamic_analysis/   # Dinamik analiz
│   ├── scoring/            # Puanlama ve skor
│   ├── reporting/          # Rapor üretimi
│   └── main.py             # CLI giriş noktası
├── tests/                  # Test modülleri
├── dashboard/              # Web arayüzü
├── docs/                   # Belgeler
├── specs/                  # YARA kuralları
└── docker/                 # Docker konfigü
```

### Hangi Alana Katkı Yapmak İstiyorsunuz?

- **🔍 PDF Analiz Iyileştirme:** `src/` klasöründe
- **⚡ Performans:** Async streams, caching
- **🛡️ Güvenlik:** Validation, encryption
- **📊 Raporlama:** UI/UX improvements
- **📝 Belgelendirme:** docs/ klasörü
- **🧪 Test:** tests/ klasörü

---

## 🛠️ Ortam Kurulumu

### 1. Repository'yi Fork & Clone Edin

```bash
# Fork et (GitHub UI)
# Sonra clone et:
git clone https://github.com/YOUR_USERNAME/sussy_pdf.git
cd sussy_pdf
git remote add upstream https://github.com/hizir777/sussy_pdf.git
```

### 2. Python Ortamı

```bash
# Python 3.10+ gerekli
python --version  # >= 3.10

# Sanal ortam oluştur
python -m venv .venv
.venv\Scripts\activate     # Windows
# source .venv/bin/activate  # Linux/macOS

# Dependencies kur (dev mode)
pip install -r requirements.txt
pip install -e ".[dev]"

# Ek dev tools
pip install pre-commit
pre-commit install  # (eğer .pre-commit-config.yaml varsa)
```

### 3. Çalışan Test Paketi

```bash
# Testleri çalıştır
pytest tests/ -v

# Coverage raporu
pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html
```

### 4. Docker (İsteğe bağlı)

```bash
docker-compose -f docker/docker-compose.yml build
docker-compose -f docker/docker-compose.yml up
```

---

## 📐 Kod Yazım Standartları

### Python Kod Tarzı (PEP 8)

```python
# ✅ DOĞRU
def analyze_pdf(file_path: str, timeout: int = 30) -> dict:
    """PDF dosyasını analiz et.
    
    Args:
        file_path: PDF dosyası yolu
        timeout: Analiz zaman aşımı (saniye)
        
    Returns:
        Analiz sonuçları sözlüğü
    """
    result = {}
    return result

# ❌ YANLIŞ
def analyzePDF(filePath, timeout=30):
    result = {}
    return result
```

### Zorunlu Standartlar

| Standart | Tool | Komut |
|----------|------|-------|
| **PEP 8** | ruff | `ruff check src/` |
| **Type Hints** | mypy | `mypy src/` (opsiyonel) |
| **Docstrings** | - | Google/NumPy style |
| **Line Length** | - | Max 100 karakter |
| **Import Ordering** | - | stdlib → third-party → local |

### Kontrol Listesi

```python
# BEFORE PR:
- [ ] `ruff check src/` hatasız
- [ ] `pytest tests/ -v` geçiyor
- [ ] `pytest tests/ --cov` ≥ 80%
- [ ] Type hints mevcut
- [ ] Docstring açık ve 1-sentence summary
- [ ] Log mesajları INFO+'da
```

### Logging Seviyesi

```python
import logging

logger = logging.getLogger(__name__)

logger.debug("Detaylı bilgi (geliştirici)")
logger.info("Genel bilgi (kullanıcı)")
logger.warning("Uyarı — sorun olmasa da dikkat et")
logger.error("Hata — işlem başarısız ama continue et")
logger.critical("Kritik — işlem durduruldu")
```

---

## 🧪 Test Yazma

### Test Yapısı

```
tests/
├── test_ingestion.py
├── test_parser.py
├── test_scoring.py
├── test_deobfuscation.py
├── test_tag_scanner.py
└── fixtures/
    ├── generate_fixtures.py
    ├── sample.normal.pdf
    ├── sample.malicious.pdf
    └── sample.encrypted.pdf
```

### Test Yazma Şablonu

```python
"""Test modülü: pdf_parser
Dosya: tests/test_parser.py
"""

import pytest
from src.static_analysis.pdf_parser import PDFParser


class TestPDFParser:
    """PDFParser sınıfı test grubu."""
    
    @pytest.fixture
    def parser(self):
        """Parser instance oluştur."""
        return PDFParser()
    
    @pytest.fixture
    def sample_pdf(self):
        """Test PDF yükle."""
        with open("tests/fixtures/sample.normal.pdf", "rb") as f:
            return f.read()
    
    def test_parse_valid_header(self, parser, sample_pdf):
        """Geçerli PDF header'ıını parse etmeli."""
        result = parser.parse(sample_pdf)
        assert result.header.is_valid
        assert result.header.version == "1.7"
    
    def test_parse_invalid_pdf(self, parser):
        """Geçersiz PDF dosyası hatasını yakalamalı."""
        with pytest.raises(ValueError):
            parser.parse(b"NOT A PDF FILE")
    
    @pytest.mark.parametrize("version", ["1.4", "1.7", "2.0"])
    def test_parse_versions(self, parser, version):
        """Farklı PDF versiyonlarını test et."""
        pdf = f"%PDF-{version}\n".encode()
        result = parser.parse(pdf)
        assert result.header.version == version
```

### Coverage Gereksinimleri

```bash
# 80% minimum coverage
pytest tests/ --cov=src --cov-report=term-missing --cov-fail-under=80

# Report oluştur
pytest tests/ --cov=src --cov-report=html
```

---

## 💬 Commit Mesajları

### Format: Conventional Commits

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Örnekler

```bash
# ✅ DOĞRU
git commit -m "feat(deobfuscation): Add XOR string decoder support

- Implement XOR pattern detection
- Support 1-256 byte keys
- Add 10 test cases

Closes #42"

# ❌ YANLIŞ
git commit -m "fixed stuff"
```

### Type Seçenekleri

| Type | Açıklama | Örnek |
|------|----------|-------|
| **feat** | Yeni özellik | `feat(scoring): add MITRE ATT&CK mapper` |
| **fix** | Hata düzeltme | `fix(parser): handle corrupt XRef table` |
| **docs** | Belgelendirme | `docs: update README with new API` |
| **test** | Test ekle/düzenle | `test(ingestion): add file format tests` |
| **refactor** | Kod yeniden düzenleme | `refactor(main): extract config logic` |
| **perf** | Performans iyileştirme | `perf: use async for large PDFs` |
| **chore** | Build, deps, CI | `chore: upgrade pytest to 8.0` |
| **security** | Güvenlik düzeltmesi | `security: fix SSRF validation` |

---

## 🔄 Pull Request Süreci

### Adım 1: Branch Oluştur

```bash
git fetch upstream
git checkout -b feature/your-feature-name upstream/main

# Örnek:
git checkout -b feature/pdf-encryption-support
```

### Adım 2: Geliştir & Commit

```bash
# Kodla...
git add src/
git commit -m "feat(security): add AES-256 PDF encryption support"

# Test et
pytest tests/ -v
```

### Adım 3: Push & PR

```bash
git push origin feature/your-feature-name
# GitHub'da "Create Pull Request" tıkla
```

### Adım 4: PR Şablonunu Doldur

```markdown
## Açıklama
Ne değişti ve neden?

## İlişkili Sorun (#)
Closes #123

## Kontrol Listesi
- [ ] Tests geçiyor (`pytest tests/ -v`)
- [ ] Code coverage ≥ 80%
- [ ] Docstrings eklendi
- [ ] Belgelendirme güncellendi
- [ ] Breaking changes açıklandı
```

### Adım 5: Gözden Geçirme & Merge

- Minimum 1 maintainer approval
- All checks pass (CI/CD)
- Squash & merge (tidy history)

---

## 🐛 Raporlama

### Bug Raporu

[GitHub Issues](https://github.com/hizir777/sussy_pdf/issues) başlığında şu template'i kullan:

```markdown
## Sorun Açıklaması
Kısaca açıkla.

## Tekrarlanma Adımları
1. Çalıştır: `python -m src.main analyze malware.pdf`
2. Gözlemle: [hata mesajı]

## Beklenen Davranış
Ne olması gerekiyordu?

## Ortam
- OS: Windows 11 / Ubuntu 22.04
- Python: 3.10
- Sussy PDF: v1.0.0
```

### Özellik İsteği

```markdown
## Özellik Açıklaması
Ne eklemek istiyorsunuz?

## Neden Gerekli?
İhtiyaç analizi / Use case

## Çözüm Önerisi (İsteğe bağlı)
Nasıl implement edilebilir?

## İlişkili Sorunlar
#123, #456
```

---

## 📚 İlgili Linkler

- **Ana README:** [README.md](../README.md)
- **Roadmap:** [ROADMAP.md](../ROADMAP.md)
- **Güvenlik:** [SECURITY.md](../SECURITY.md)
- **Kod Davranış Kuralları:** [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)

---

## ❓ Sorularınız mı var?

- Discussions: [GitHub Discussions](https://github.com/hizir777/sussy_pdf/discussions)
- Email: [maintainers@sussy-pdf.dev](mailto:maintainers@sussy-pdf.dev)
- IRC: #sussy-pdf on Libera.Chat

---

**Katkılarınız için teşekkürler! 💪**
