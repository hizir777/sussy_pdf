"""
heuristic_scorer.py — Sezgisel Risk Puanlama Motoru

Tüm analiz katmanlarından gelen verileri birleştirerek
0-100 arası nihai risk skoru hesaplar.
"""

from dataclasses import dataclass, field


@dataclass
class ScoreBreakdown:
    category: str
    points: int
    max_points: int
    details: str


@dataclass
class HeuristicScore:
    total_score: int = 0
    max_score: int = 100
    risk_level: str = "unknown"
    risk_color: str = "#808080"
    breakdown: list[ScoreBreakdown] = field(default_factory=list)
    verdict: str = ""
    recommendations: list[str] = field(default_factory=list)


class HeuristicScorer:
    """
    Sezgisel risk puanlama motoru.

    Puanlama Matrisi:
      0-25:  ✅ TEMİZ
      26-50: 🟠 ŞÜPHELİ
      51-75: 🟡 TEHLİKELİ
      76-100: 🔴 KRİTİK
    """

    def score(
        self,
        tag_scan_result=None,
        incremental_result=None,
        yara_result=None,
        emulation_result=None,
        metadata=None,
        deobfuscation_results=None,
    ) -> HeuristicScore:
        """Tüm verileri birleştirerek nihai skor hesapla."""
        hs = HeuristicScore()

        # 1. Tag Scan skoru (maks 40 puan)
        if tag_scan_result:
            pts = min(tag_scan_result.combined_risk_score // 3, 40)
            hs.breakdown.append(ScoreBreakdown(
                "Tehdit Etiketleri", pts, 40,
                f"{tag_scan_result.total_tags_found} etiket, "
                f"{tag_scan_result.critical_count} kritik",
            ))
            hs.total_score += pts

        # 2. YARA skoru (maks 30 puan)
        if yara_result and yara_result.matches:
            pts = min(yara_result.total_score // 4, 30)
            hs.breakdown.append(ScoreBreakdown(
                "YARA Kuralları", pts, 30,
                f"{len(yara_result.matches)} kural eşleşti",
            ))
            hs.total_score += pts

        # 3. Artımlı güncelleme (maks 10 puan)
        if incremental_result:
            pts = min(incremental_result.risk_score // 5, 10)
            hs.breakdown.append(ScoreBreakdown(
                "Yapısal Anomali", pts, 10,
                f"{incremental_result.eof_count} %%EOF",
            ))
            hs.total_score += pts

        # 4. Emülasyon (maks 15 puan)
        if emulation_result:
            em_pts = 0
            em_pts += len(emulation_result.shell_commands) * 5
            em_pts += len(emulation_result.c2_addresses) * 3
            em_pts += len(emulation_result.network_calls) * 2
            pts = min(em_pts, 15)
            hs.breakdown.append(ScoreBreakdown(
                "Dinamik Analiz", pts, 15,
                f"{len(emulation_result.behaviors)} davranış tespit edildi",
            ))
            hs.total_score += pts

        # 5. Metadata anomalileri (maks 5 puan)
        if metadata and metadata.suspicious_indicators:
            pts = min(len(metadata.suspicious_indicators) * 2, 5)
            hs.breakdown.append(ScoreBreakdown(
                "Metadata", pts, 5,
                f"{len(metadata.suspicious_indicators)} anomali",
            ))
            hs.total_score += pts

        # Normalize
        hs.total_score = min(hs.total_score, 100)

        # Risk seviyesi
        if hs.total_score >= 76:
            hs.risk_level = "critical"
            hs.risk_color = "#ff1744"
            hs.verdict = "🔴 KRİTİK — Bu dosya yüksek olasılıkla zararlı yazılım içeriyor!"
            hs.recommendations = [
                "Dosyayı AÇMAYIN.",
                "Dosyayı karantinaya alın.",
                "IOC bilgilerini güvenlik ekibinizle paylaşın.",
                "VirusTotal'e gönderin.",
            ]
        elif hs.total_score >= 51:
            hs.risk_level = "high"
            hs.risk_color = "#ff9100"
            hs.verdict = "🟡 TEHLİKELİ — Yüksek riskli unsurlar tespit edildi."
            hs.recommendations = [
                "Dosyayı sandbox ortamında açın.",
                "Göndericinin kimliğini doğrulayın.",
                "Detaylı dinamik analiz yapın.",
            ]
        elif hs.total_score >= 26:
            hs.risk_level = "medium"
            hs.risk_color = "#ffc400"
            hs.verdict = "🟠 ŞÜPHELİ — İnceleme gerektirir."
            hs.recommendations = [
                "Dikkatli olun, dosyayı izole ortamda inceleyin.",
                "Metadata ve yapısal anomalileri kontrol edin.",
            ]
        else:
            hs.risk_level = "low"
            hs.risk_color = "#00e676"
            hs.verdict = "✅ TEMİZ — Belirgin tehdit göstergesi bulunamadı."
            hs.recommendations = [
                "Dosya güvenli görünüyor.",
                "Yine de bilinmeyen kaynaklardan gelen dosyalara dikkat edin.",
            ]

        return hs
