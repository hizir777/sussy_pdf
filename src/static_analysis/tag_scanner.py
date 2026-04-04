"""
tag_scanner.py — Tehdit Göstergesi Etiket Tarayıcı
peepdf/pdfid tarzı analiz motoru.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TagMatch:
    tag: str
    threat_level: ThreatLevel
    count: int
    description: str
    technical_detail: str
    object_numbers: list[int] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)


@dataclass
class TagScanResult:
    total_tags_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    matches: list[TagMatch] = field(default_factory=list)
    combined_risk_score: int = 0
    verdict: str = "Temiz"


TAG_DATABASE = {
    "/OpenAction": {
        "level": ThreatLevel.CRITICAL, "score": 50,
        "description": "Belge açıldığında otomatik eylem tetikleyici",
        "technical": "Kullanıcıdan bağımsız zararlı yüklerin ana tetikleyicisi. /JS ile kritik.",
    },
    "/AA": {
        "level": ThreatLevel.CRITICAL, "score": 45,
        "description": "Ek eylem tetikleyici (Additional Actions)",
        "technical": "Sayfa değiştirme, fare hareketi gibi olaylara bağlı komutları tetikler.",
    },
    "/JS": {
        "level": ThreatLevel.CRITICAL, "score": 60,
        "description": "JavaScript kodu referansı",
        "technical": "Heap spraying ve bellek taşması zafiyetleri için kullanılan JS blokları.",
    },
    "/JavaScript": {
        "level": ThreatLevel.CRITICAL, "score": 60,
        "description": "JavaScript eylem tipi",
        "technical": "eval(), unescape(), String.fromCharCode() ile obfuscation kullanır.",
    },
    "/Launch": {
        "level": ThreatLevel.CRITICAL, "score": 80,
        "description": "Harici uygulama başlatıcı",
        "technical": "cmd.exe, powershell gibi harici uygulamaları başlatan en tehlikeli etiket.",
    },
    "/EmbeddedFiles": {
        "level": ThreatLevel.HIGH, "score": 35,
        "description": "Gömülü dosya(lar) içeriyor",
        "technical": "Zararlı makrolar içeren Word veya .exe dosyalarının gömülmesine olanak tanır.",
    },
    "/URI": {
        "level": ThreatLevel.HIGH, "score": 25,
        "description": "Dış URL referansı",
        "technical": "Kullanıcıyı zararlı web sitesine yönlendirebilir.",
    },
    "/SubmitForm": {
        "level": ThreatLevel.HIGH, "score": 30,
        "description": "Form gönderim eylemi",
        "technical": "PDF form verilerini uzak sunucuya gönderir. Veri sızdırma riski.",
    },
    "/ImportData": {
        "level": ThreatLevel.HIGH, "score": 30,
        "description": "Dış veri aktarımı",
        "technical": "Dış kaynaklardan veri import eder. Command injection riski.",
    },
    "/AcroForm": {
        "level": ThreatLevel.MEDIUM, "score": 15,
        "description": "Etkileşimli form nesnesi",
        "technical": "/SubmitForm veya /JS ile birlikte veri sızdırma aracı olabilir.",
    },
    "/RichMedia": {
        "level": ThreatLevel.MEDIUM, "score": 20,
        "description": "Flash/multimedya içeriği",
        "technical": "Flash (SWF) barındırır. Flash EOL olduğu için otomatik şüpheli.",
    },
    "/XFA": {
        "level": ThreatLevel.MEDIUM, "score": 20,
        "description": "XML Forms Architecture",
        "technical": "XFA formlar XXE ve JavaScript injection vektörleri açabilir.",
    },
    "/ObjStm": {
        "level": ThreatLevel.MEDIUM, "score": 15,
        "description": "Object Stream (nesne akışı)",
        "technical": "Nesneleri stream içinde sıkıştırarak tarayıcıları atlatır.",
    },
    "/JBIG2Decode": {
        "level": ThreatLevel.MEDIUM, "score": 25,
        "description": "JBIG2 görüntü dekoderi",
        "technical": "CVE-2021-30860 'FORCEDENTRY' gibi bellek taşması zafiyetleri.",
    },
    "/GoTo": {
        "level": ThreatLevel.LOW, "score": 5,
        "description": "Belge içi navigasyon",
        "technical": "Normalde zararsız, /GoToR ile dış belgeye yönlendirme yapabilir.",
    },
    "/GoToR": {
        "level": ThreatLevel.LOW, "score": 10,
        "description": "Uzak belge navigasyonu",
        "technical": "Dış PDF dosyasına yönlendirir. Supply chain saldırısı riski.",
    },
}


class TagScanner:
    """peepdf/pdfid benzeri tehdit etiket tarayıcı."""

    def __init__(self, custom_tags: dict | None = None):
        self.tag_db = TAG_DATABASE.copy()
        if custom_tags:
            self.tag_db.update(custom_tags)

    def scan(self, content: bytes) -> TagScanResult:
        result = TagScanResult()

        for tag, info in self.tag_db.items():
            tag_bytes = tag.encode()
            positions = self._find_positions(content, tag_bytes)
            if not positions:
                continue

            obj_numbers = self._find_containing_objects(content, positions)
            contexts = [self._extract_context(content, p) for p in positions[:5]]

            match = TagMatch(
                tag=tag, threat_level=info["level"], count=len(positions),
                description=info["description"], technical_detail=info["technical"],
                object_numbers=obj_numbers, contexts=contexts,
            )
            result.matches.append(match)
            result.total_tags_found += len(positions)
            result.combined_risk_score += info["score"] * len(positions)

            level_map = {
                ThreatLevel.CRITICAL: "critical_count", ThreatLevel.HIGH: "high_count",
                ThreatLevel.MEDIUM: "medium_count", ThreatLevel.LOW: "low_count",
            }
            attr = level_map.get(info["level"])
            if attr:
                setattr(result, attr, getattr(result, attr) + 1)

        result.combined_risk_score += self._check_combos(result.matches)
        result.verdict = self._verdict(result.combined_risk_score)
        return result

    def _find_positions(self, content: bytes, tag: bytes) -> list[int]:
        positions, start = [], 0
        while True:
            pos = content.find(tag, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + len(tag)
        return positions

    def _find_containing_objects(self, content: bytes, positions: list[int]) -> list[int]:
        obj_nums = []
        for pos in positions:
            area = content[max(0, pos - 200):pos]
            matches = list(re.finditer(rb"(\d+)\s+\d+\s+obj", area))
            if matches:
                obj_nums.append(int(matches[-1].group(1)))
        return list(set(obj_nums))

    def _extract_context(self, content: bytes, pos: int, window: int = 80) -> str:
        start = max(0, pos - window // 2)
        end = min(len(content), pos + window // 2)
        try:
            return content[start:end].decode("latin-1").replace("\n", "↵").replace("\r", "")
        except Exception:
            return content[start:end].hex()

    def _check_combos(self, matches: list[TagMatch]) -> int:
        extra = 0
        tags = {m.tag for m in matches}
        if "/OpenAction" in tags and ("/JS" in tags or "/JavaScript" in tags):
            extra += 50
        if "/Launch" in tags:
            for m in matches:
                if m.tag == "/Launch":
                    for ctx in m.contexts:
                        if any(c in ctx.lower() for c in ["cmd", "powershell", "wscript"]):
                            extra += 100
        if "/EmbeddedFiles" in tags and "/OpenAction" in tags:
            extra += 40
        return extra

    def _verdict(self, score: int) -> str:
        if score >= 76:
            return "🔴 KRİTİK — Aktif exploit/zararlı yazılım tespit edildi"
        if score >= 51:
            return "🟡 TEHLİKELİ — Yüksek riskli unsurlar mevcut"
        if score >= 26:
            return "🟠 ŞÜPHELİ — İnceleme gerektirir"
        if score > 0:
            return "🟢 DÜŞÜK RİSK — Küçük anomaliler"
        return "✅ TEMİZ — Şüpheli etiket bulunamadı"
