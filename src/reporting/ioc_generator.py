"""
ioc_generator.py — IOC (Indicator of Compromise) Raporu Üretici

Tespit edilen URL, IP, domain ve hash değerlerini
eyleme geçirilebilir istihbarat raporuna dönüştürür.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests


@dataclass
class IOCEntry:
    ioc_type: str  # url, ip, domain, hash, email
    value: str
    source: str  # Hangi analiz katmanından geldiği
    confidence: str  # high, medium, low
    context: str = ""
    virustotal_result: dict | None = None


@dataclass
class IOCReport:
    report_id: str = ""
    analysis_date: str = ""
    file_name: str = ""
    file_sha256: str = ""
    entries: list[IOCEntry] = field(default_factory=list)
    total_iocs: int = 0
    mitre_techniques: list[str] = field(default_factory=list)


class IOCGenerator:
    """IOC raporu üretme motoru."""

    def __init__(self, vt_api_key: str | None = None):
        self.vt_api_key = vt_api_key or os.environ.get("VIRUSTOTAL_API_KEY")

    def generate(
        self,
        file_info=None,
        emulation_result=None,
        tag_result=None,
        deobfuscation_results=None,
        mitre_mappings=None,
    ) -> IOCReport:
        """Tüm kaynaklardan IOC raporu oluştur."""
        report = IOCReport(
            report_id=hashlib.md5(
                datetime.now(timezone.utc).isoformat().encode()
            ).hexdigest()[:12],
            analysis_date=datetime.now(timezone.utc).isoformat(),
        )

        if file_info:
            report.file_name = file_info.file_name
            report.file_sha256 = file_info.sha256

            # Dosya hash'leri IOC olarak
            for hash_type, hash_val in [
                ("md5", file_info.md5),
                ("sha1", file_info.sha1),
                ("sha256", file_info.sha256),
            ]:
                report.entries.append(IOCEntry(
                    ioc_type="hash",
                    value=hash_val,
                    source="file_ingestion",
                    confidence="high",
                    context=f"Analiz edilen dosyanın {hash_type.upper()} hash değeri",
                ))

        # Emülasyondan IOC'ler
        if emulation_result:
            for url_info in emulation_result.network_calls:
                url = url_info.get("url", "")
                if url and url != "detected_in_code":
                    report.entries.append(IOCEntry(
                        ioc_type="url", value=url, source="js_emulation",
                        confidence="high", context=f"JavaScript ağ çağrısı ({url_info.get('type', '')})",
                    ))

            for addr in emulation_result.c2_addresses:
                ioc_type = "ip" if self._is_ip(addr) else "domain"
                if addr.startswith("http"):
                    ioc_type = "url"
                report.entries.append(IOCEntry(
                    ioc_type=ioc_type, value=addr, source="js_emulation",
                    confidence="high", context="C2 (Komuta-Kontrol) adresi",
                ))

            for cmd in emulation_result.shell_commands:
                report.entries.append(IOCEntry(
                    ioc_type="command", value=cmd, source="js_emulation",
                    confidence="high", context="Shell komutu",
                ))

        # Tag tarama sonuçlarından URI'ler
        if tag_result:
            for match in tag_result.matches:
                if match.tag == "/URI":
                    for ctx in match.contexts:
                        import re
                        urls = re.findall(r"https?://[^\s\"'<>]+", ctx)
                        for url in urls:
                            report.entries.append(IOCEntry(
                                ioc_type="url", value=url, source="tag_scan",
                                confidence="medium", context="/URI etiketinden çıkarıldı",
                            ))

        # MITRE eşlemeleri
        if mitre_mappings:
            report.mitre_techniques = [m.technique_id for m in mitre_mappings]

        # Tekrar edenleri temizle
        seen = set()
        unique = []
        for entry in report.entries:
            key = f"{entry.ioc_type}:{entry.value}"
            if key not in seen:
                seen.add(key)
                unique.append(entry)
        report.entries = unique
        report.total_iocs = len(report.entries)

        return report

    def query_virustotal(self, sha256: str) -> dict | None:
        """VirusTotal API'den hash sorgulama (ücretsiz)."""
        if not self.vt_api_key or self.vt_api_key == "your_api_key_here":
            return None

        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()),
                    "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "message": "Dosya VirusTotal'de bulunamadı"}
            else:
                return {"status": "error", "code": resp.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def to_json(self, report: IOCReport) -> str:
        """IOC raporunu JSON formatına dönüştür."""
        data = {
            "report_id": report.report_id,
            "analysis_date": report.analysis_date,
            "file_name": report.file_name,
            "file_sha256": report.file_sha256,
            "total_iocs": report.total_iocs,
            "mitre_techniques": report.mitre_techniques,
            "indicators": [
                {
                    "type": e.ioc_type,
                    "value": e.value,
                    "source": e.source,
                    "confidence": e.confidence,
                    "context": e.context,
                }
                for e in report.entries
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    @staticmethod
    def _is_ip(value: str) -> bool:
        import re
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))
