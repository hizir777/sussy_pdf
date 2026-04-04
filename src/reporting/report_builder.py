"""
report_builder.py — Ana Rapor Oluşturucu

Tüm analiz sonuçlarını HTML, JSON ve Markdown formatlarında
kapsamlı raporlara dönüştürür.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template


class ReportBuilder:
    """Analiz raporu oluşturucu."""

    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"

    def build_json(self, results: dict) -> str:
        """JSON raporu oluştur."""
        report = {
            "report_meta": {
                "tool": "Sussy PDF Analyzer",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "file_info": self._serialize_file_info(results.get("file_info")),
            "risk_score": self._serialize_score(results.get("score")),
            "static_analysis": {
                "structure": self._serialize_structure(results.get("structure")),
                "tags": self._serialize_tags(results.get("tags")),
                "incremental": self._serialize_incremental(results.get("incremental")),
            },
            "metadata": self._serialize_metadata(results.get("metadata")),
            "deobfuscation": {
                "streams_decoded": len(results.get("decoded_streams", [])),
                "js_deobfuscated": bool(results.get("js_deobfuscation")),
            },
            "dynamic_analysis": self._serialize_emulation(results.get("emulation")),
            "mitre_attack": self._serialize_mitre(results.get("mitre")),
            "ioc": results.get("ioc_json", "{}"),
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def build_html(self, results: dict) -> str:
        """HTML raporu oluştur."""
        template_path = self.template_dir / "report_template.html"
        if template_path.exists():
            with open(template_path, encoding="utf-8") as f:
                template = Template(f.read())
            return template.render(**self._prepare_template_data(results))
        return self._build_fallback_html(results)

    def build_markdown(self, results: dict) -> str:
        """Markdown raporu oluştur."""
        lines = []
        lines.append("# 🔬 Sussy PDF Analiz Raporu\n")
        lines.append(f"**Tarih:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")

        fi = results.get("file_info")
        if fi:
            lines.append("## 📋 Dosya Bilgileri\n")
            lines.append("| Alan | Değer |")
            lines.append("|------|-------|")
            lines.append(f"| Dosya Adı | `{fi.file_name}` |")
            lines.append(f"| Boyut | {fi.file_size_human} |")
            lines.append(f"| MD5 | `{fi.md5}` |")
            lines.append(f"| SHA256 | `{fi.sha256}` |")
            lines.append(f"| PDF Versiyonu | {fi.pdf_version or 'N/A'} |")
            lines.append("")

        score = results.get("score")
        if score:
            lines.append("## 📊 Risk Skoru\n")
            lines.append(f"**Skor:** {score.total_score}/100\n")
            lines.append(f"**Karar:** {score.verdict}\n")
            if score.breakdown:
                lines.append("| Kategori | Puan | Maksimum | Detay |")
                lines.append("|----------|------|----------|-------|")
                for b in score.breakdown:
                    lines.append(f"| {b.category} | {b.points} | {b.max_points} | {b.details} |")
            lines.append("")

        tags = results.get("tags")
        if tags and tags.matches:
            lines.append("## 🔍 Tehdit Etiketleri\n")
            lines.append("| Etiket | Seviye | Sayı | Açıklama |")
            lines.append("|--------|--------|------|----------|")
            for m in tags.matches:
                lines.append(f"| `{m.tag}` | {m.threat_level.value} | {m.count} | {m.description} |")
            lines.append("")

        mitre = results.get("mitre")
        if mitre:
            lines.append("## 🎯 MITRE ATT&CK Eşlemeleri\n")
            for m in mitre:
                lines.append(f"- **{m.technique_id}** — {m.technique_name} ({m.tactic})")
                for e in m.evidence:
                    lines.append(f"  - {e}")
            lines.append("")

        if score and score.recommendations:
            lines.append("## 💡 Öneriler\n")
            for r in score.recommendations:
                lines.append(f"- {r}")

        return "\n".join(lines)

    def _prepare_template_data(self, results: dict) -> dict:
        fi = results.get("file_info")
        score = results.get("score")
        tags = results.get("tags")
        return {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "file_name": fi.file_name if fi else "N/A",
            "file_size": fi.file_size_human if fi else "N/A",
            "md5": fi.md5 if fi else "N/A",
            "sha1": fi.sha1 if fi else "N/A",
            "sha256": fi.sha256 if fi else "N/A",
            "pdf_version": fi.pdf_version if fi else "N/A",
            "risk_score": score.total_score if score else 0,
            "risk_level": score.risk_level if score else "unknown",
            "risk_color": score.risk_color if score else "#808080",
            "verdict": score.verdict if score else "",
            "breakdown": score.breakdown if score else [],
            "recommendations": score.recommendations if score else [],
            "tag_matches": tags.matches if tags else [],
            "mitre_mappings": results.get("mitre", []),
        }

    def _build_fallback_html(self, results: dict) -> str:
        d = self._prepare_template_data(results)
        return f"""<!DOCTYPE html>
<html><head><title>Sussy PDF Report</title></head>
<body style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:2rem;">
<h1>🔬 Sussy PDF Analiz Raporu</h1>
<p>Dosya: {d['file_name']} | SHA256: {d['sha256']}</p>
<h2>Risk: {d['risk_score']}/100 — {d['verdict']}</h2>
</body></html>"""

    # Serialization helpers
    def _serialize_file_info(self, fi):
        if not fi:
            return {}
        return {"name": fi.file_name, "size": fi.file_size_human,
                "md5": fi.md5, "sha256": fi.sha256, "version": fi.pdf_version}

    def _serialize_score(self, s):
        if not s:
            return {}
        return {"total": s.total_score, "level": s.risk_level, "verdict": s.verdict}

    def _serialize_structure(self, s):
        if not s:
            return {}
        return {"eof_count": s.eof_count, "encrypted": s.is_encrypted}

    def _serialize_tags(self, t):
        if not t:
            return {}
        return {"total": t.total_tags_found, "critical": t.critical_count,
                "verdict": t.verdict}

    def _serialize_incremental(self, i):
        if not i:
            return {}
        return {"eof_count": i.eof_count, "shadow_risk": i.has_shadow_attack_risk}

    def _serialize_metadata(self, m):
        if not m:
            return {}
        return {"title": m.title, "author": m.author, "creator": m.creator}

    def _serialize_emulation(self, e):
        if not e:
            return {}
        return {"risk": e.risk_level, "behaviors": e.behaviors,
                "c2": e.c2_addresses, "commands": e.shell_commands}

    def _serialize_mitre(self, mitre_list):
        if not mitre_list:
            return []
        return [{"id": m.technique_id, "name": m.technique_name,
                 "tactic": m.tactic} for m in mitre_list]
