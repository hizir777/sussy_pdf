# 🔬 Sussy PDF — Şüpheli PDF Analiz Platformu

<div align="center">

**Görsel olarak masum görünen PDF dosyalarının arka planda nasıl bir "taşıyıcı" (dropper) olarak kullanılabileceğini tespit eden profesyonel analiz motoru.**

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED)](docker/Dockerfile)

</div>

---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────────────┐
│                   📥 Ingestion                       │
│         Hash • Magic Bytes • Metadata                │
├─────────────────────────────────────────────────────┤
│                  🔍 Static Analysis                  │
│    PDF Parser • Object Tree • Tag Scanner • XRef     │
├─────────────────────────────────────────────────────┤
│                🔓 De-obfuscation                     │
│   Stream Decode • String Decode • JS Deobf • AST    │
├─────────────────────────────────────────────────────┤
│                ⚡ Dynamic Analysis                   │
│        JS Emulation • Sandbox • Anti-Evasion         │
├─────────────────────────────────────────────────────┤
│                 📊 Scoring & Intel                   │
│   YARA • Heuristic Score • MITRE ATT&CK • Features │
├─────────────────────────────────────────────────────┤
│                  📄 Reporting                        │
│         IOC • HTML Report • JSON • Markdown          │
└─────────────────────────────────────────────────────┘
```

## 🚀 Kurulum

### Gereksinimler
- Python 3.10+
- Docker (opsiyonel, izole analiz için)

### Hızlı Başlangıç

```bash
# Repoyu klonla
git clone https://github.com/hizir777/sussy_pdf.git
cd sussy_pdf

# Sanal ortam oluştur
python -m venv .venv
.venv\Scripts\activate     # Windows
# source .venv/bin/activate  # Linux/macOS

# Bağımlılıkları kur
pip install -r requirements.txt
pip install -e ".[dev]"

# Çevresel değişkenleri ayarla
copy .env.example .env
# .env dosyasını düzenleyerek API anahtarlarını girin

# Test fixture'larını oluştur
python tests/fixtures/generate_fixtures.py
```

### Docker ile Çalıştırma

```bash
# Build
docker-compose -f docker/docker-compose.yml build

# Çalıştır
docker-compose -f docker/docker-compose.yml up
```

## 📋 Kullanım

### CLI ile Analiz

```bash
# Tam analiz
python -m src.main analyze suspicious_file.pdf

# Belirli format çıktı
python -m src.main analyze file.pdf --format json
python -m src.main analyze file.pdf --format html

# Çıktı dosyası belirt
python -m src.main analyze file.pdf -o report.html
```

### Web Dashboard

```bash
# Dashboard sunucusunu başlat
python -m src.main serve --port 8443

# Tarayıcıda aç: http://localhost:8443
```

### API

```bash
# POST ile PDF analiz et
curl -X POST http://localhost:8443/api/analyze \
  -F "file=@suspicious.pdf"
```

## 🧪 Testler

```bash
# Tüm testleri çalıştır
pytest tests/ -v

# Belirli modül testi
pytest tests/test_tag_scanner.py -v
```

## 📊 Tespit Edilen Tehdit Etiketleri

| Etiket | Seviye | Açıklama |
|--------|--------|----------|
| `/OpenAction` | 🔴 Kritik | Otomatik eylem tetikleyici |
| `/JS` / `/JavaScript` | 🔴 Kritik | Gömülü JavaScript kodu |
| `/Launch` | 🔴 Kritik | Harici uygulama başlatıcı |
| `/EmbeddedFiles` | 🟡 Yüksek | Gömülü dosyalar |
| `/URI` | 🟡 Yüksek | Dış URL referansı |
| `/XFA` | 🟠 Orta | XML Forms Architecture |
| `/JBIG2Decode` | 🟠 Orta | JBIG2 exploit vektörü |

## 🎯 MITRE ATT&CK Eşlemeleri

- **T1059.007** — JavaScript Execution
- **T1204.002** — User Execution: Malicious File
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1027** — Obfuscated Files or Information
- **T1105** — Ingress Tool Transfer

## 📁 Proje Yapısı

```
sussy_pdf/
├── src/                  # Analiz motoru kaynak kodu
│   ├── ingestion/        # Dosya alımı ve hash hesaplama
│   ├── static_analysis/  # PDF parser, tag scanner
│   ├── deobfuscation/    # Stream/string decode, JS deobf
│   ├── dynamic_analysis/ # JS emülasyon, sandbox
│   ├── scoring/          # YARA, heuristic, MITRE
│   └── reporting/        # IOC, rapor üretici
├── dashboard/            # Web arayüzü
├── docker/               # Docker yapılandırması
├── specs/                # YARA kuralları, puanlama matrisi
├── tests/                # Unit testler
└── docs/                 # Dokümantasyon
```

## 🔒 Güvenlik Notları

- Analiz araçları Docker container içinde izole çalışır
- Rootless container (least privilege prensibi)
- `.env` dosyası asla depoya gönderilmez
- VirusTotal API ücretsiz katman (4 istek/dk) destekli

## 📄 Lisans

MIT License — Detaylar için [LICENSE](LICENSE) dosyasına bakınız.
