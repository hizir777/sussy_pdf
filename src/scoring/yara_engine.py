"""
yara_engine.py — YARA Kural Motoru

YARA kurallarını yükler ve PDF dosyaları üzerinde çalıştırır.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    rule_name: str
    description: str
    severity: str
    score: int
    mitre: str
    matched_strings: list[str] = field(default_factory=list)


@dataclass
class YaraResult:
    matches: list[YaraMatch] = field(default_factory=list)
    total_score: int = 0
    rules_loaded: int = 0
    errors: list[str] = field(default_factory=list)


class YaraEngine:
    """YARA kural motoru."""

    def __init__(self, rules_path: str = "specs/yara_rules"):
        self.rules_path = Path(rules_path)
        self.compiled_rules = None
        self._load_rules()

    def _load_rules(self):
        """YARA kurallarını derle."""
        if not YARA_AVAILABLE:
            return

        if not self.rules_path.exists():
            return

        rule_files = {}
        for yar_file in self.rules_path.glob("*.yar"):
            namespace = yar_file.stem
            rule_files[namespace] = str(yar_file)

        if rule_files:
            try:
                self.compiled_rules = yara.compile(filepaths=rule_files)
            except yara.Error as e:
                self.compiled_rules = None

    def scan(self, content: bytes) -> YaraResult:
        """İçeriği YARA kurallarıyla tara."""
        result = YaraResult()

        if not YARA_AVAILABLE:
            result.errors.append("yara-python kütüphanesi kurulu değil. pip install yara-python")
            return self._fallback_scan(content, result)

        if not self.compiled_rules:
            result.errors.append("YARA kuralları yüklenemedi.")
            return self._fallback_scan(content, result)

        try:
            matches = self.compiled_rules.match(data=content)
            for match in matches:
                meta = match.meta
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    description=meta.get("description", ""),
                    severity=meta.get("severity", "unknown"),
                    score=int(meta.get("score", 0)),
                    mitre=meta.get("mitre", ""),
                    matched_strings=[str(s) for s in match.strings[:10]],
                )
                result.matches.append(yara_match)
                result.total_score += yara_match.score
        except Exception as e:
            result.errors.append(f"YARA tarama hatası: {e}")

        return result

    def scan_file(self, file_path: str) -> YaraResult:
        """Dosyayı YARA kurallarıyla tara."""
        with open(file_path, "rb") as f:
            return self.scan(f.read())

    def _fallback_scan(self, content: bytes, result: YaraResult) -> YaraResult:
        """YARA yoksa basit string eşleştirme."""
        rules = [
            (b"/Launch", b"powershell", "PDF_Launch_PowerShell", "critical", 100, "T1059.001"),
            (b"/Launch", b"cmd.exe", "PDF_Launch_Cmd", "critical", 90, "T1059.001"),
            (b"/OpenAction", b"/JS", "PDF_OpenAction_JS", "critical", 90, "T1059.007"),
            (b"/EmbeddedFiles", b"MZ", "PDF_Embedded_PE", "critical", 100, "T1027.006"),
            (b"ADODB.Stream", b"SaveToFile", "PDF_ADODB_Download", "critical", 95, "T1105"),
        ]

        for sig1, sig2, name, severity, score, mitre in rules:
            if sig1 in content and sig2 in content:
                result.matches.append(YaraMatch(
                    rule_name=name, description=f"Fallback: {name}",
                    severity=severity, score=score, mitre=mitre,
                ))
                result.total_score += score

        return result
