"""
incremental_update.py — Artımlı Güncelleme (Incremental Updates) Kontrolü

Birden fazla %%EOF etiketini tespit ederek Shadow Attack ve
XRef tablosu manipülasyonu saldırılarını ortaya çıkarır.
"""

import re
from dataclasses import dataclass, field


@dataclass
class IncrementalUpdateResult:
    eof_count: int = 0
    eof_positions: list[int] = field(default_factory=list)
    xref_count: int = 0
    startxref_values: list[int] = field(default_factory=list)
    has_shadow_attack_risk: bool = False
    update_layers: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    risk_score: int = 0


class IncrementalUpdateChecker:
    """Artımlı güncelleme ve Shadow Attack tespit motoru."""

    def check(self, content: bytes) -> IncrementalUpdateResult:
        result = IncrementalUpdateResult()

        # %%EOF konumlarını bul
        pos = 0
        while True:
            idx = content.find(b"%%EOF", pos)
            if idx == -1:
                break
            result.eof_positions.append(idx)
            pos = idx + 5
        result.eof_count = len(result.eof_positions)

        # startxref değerlerini bul
        for match in re.finditer(rb"startxref\s+(\d+)", content):
            result.startxref_values.append(int(match.group(1)))

        # xref sayısı
        result.xref_count = len(re.findall(rb"\bxref\b", content))
        xref_stream_count = len(re.findall(rb"/Type\s*/XRef", content))
        result.xref_count += xref_stream_count

        # Risk değerlendirmesi
        if result.eof_count > 1:
            result.risk_score += 40
            result.warnings.append(
                f"⚠️ {result.eof_count} adet %%EOF tespit edildi — artımlı güncelleme var."
            )

            # Her güncelleme katmanını analiz et
            for i in range(result.eof_count):
                layer = {"layer": i + 1, "eof_offset": result.eof_positions[i]}
                if i < len(result.startxref_values):
                    layer["startxref"] = result.startxref_values[i]
                result.update_layers.append(layer)

            # Shadow Attack kontrolü: XRef tutarsızlığı
            if len(result.startxref_values) > 1:
                if result.startxref_values[-1] > result.startxref_values[0]:
                    result.has_shadow_attack_risk = True
                    result.risk_score += 60
                    result.warnings.append(
                        "🔴 Shadow Attack riski: Son XRef tablosu orijinalin "
                        "sonrasına yerleştirilmiş!"
                    )

        # %%EOF dosyanın sonunda mı?
        if result.eof_count > 0:
            last_eof = result.eof_positions[-1]
            remaining = content[last_eof + 5:].strip()
            if len(remaining) > 10:
                result.risk_score += 20
                result.warnings.append(
                    f"⚠️ Son %%EOF'tan sonra {len(remaining)} byte veri var — "
                    "ek veri gizlenmiş olabilir."
                )

        if result.eof_count == 0:
            result.risk_score += 10
            result.warnings.append("⚠️ %%EOF etiketi bulunamadı — bozuk dosya.")

        return result
