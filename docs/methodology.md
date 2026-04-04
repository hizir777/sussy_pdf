# 📖 Analiz Metodolojisi

## Genel Bakış

Sussy PDF analiz platformu, **çok katmanlı savunma** (defense in depth) yaklaşımıyla PDF dosyalarını inceler. Her katman bir öncekinin bulgularını zenginleştirir.

## Analiz Pipeline'ı

```
📥 Dosya Alımı (Ingestion)
    ↓
🔍 Statik Analiz (Static Analysis)
    ↓
🔓 Gizleme Çözme (De-obfuscation)
    ↓
⚡ Dinamik Analiz (Dynamic Analysis)
    ↓
📊 Puanlama & İstihbarat (Scoring & Intel)
    ↓
📄 Raporlama (Reporting)
```

## Katmanlar

### 1. Dosya Alımı
- Magic bytes doğrulama (%PDF-)
- Kriptografik hash hesaplama (MD5, SHA1, SHA256)
- Dosya boyutu ve bütünlük kontrolü

### 2. Statik Analiz
- **PDF Anatomisi**: Header, Body, XRef, Trailer ayrıştırma
- **Tersine Okuma**: %%EOF'tan geriye doğru yapısal analiz
- **Nesne Ağacı**: Object Tree hiyerarşisi çıkarma
- **Etiket Tarama**: 16+ tehdit göstergesi etiket tarama
- **Artımlı Güncelleme**: Shadow Attack tespiti

### 3. Gizleme Çözme
- **Stream Dekompresyon**: FlateDecode, ASCIIHex, ASCII85, LZW
- **String Decode**: Hex, octal, unicode, charcode, ROT13, XOR
- **JS Deobfuscation**: eval/unescape çözme, string birleştirme
- **AST Analizi**: Polimorfik değişim tespiti

### 4. Dinamik Analiz
- **JS Emülasyonu**: Sahte Acrobat Reader ortamında kod çalıştırma
- **C2 Tespiti**: Ağ çağrıları ve komuta-kontrol adreslerini ayıklama
- **Anti-Evasion**: VM/Sandbox kaçınma rutinlerini deşifre etme

### 5. Puanlama
- **YARA**: Kural tabanlı imza eşleştirme
- **Sezgisel Skor**: 0-100 arası risk puanı
- **MITRE ATT&CK**: Teknik eşleme
- **Özellik Çıkarma**: 40+ istatistiksel özellik

### 6. Raporlama
- JSON, HTML, Markdown formatlarında kapsamlı rapor
- IOC (Indicator of Compromise) raporu
- VirusTotal entegrasyonu (opsiyonel)
