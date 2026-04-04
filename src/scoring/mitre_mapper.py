"""
mitre_mapper.py — MITRE ATT&CK Framework Eşlemesi

Tespit edilen davranışları MITRE ATT&CK tekniklerine eşler.
"""

from dataclasses import dataclass, field


@dataclass
class MITREMapping:
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    evidence: list[str] = field(default_factory=list)
    url: str = ""


# MITRE ATT&CK veritabanı (PDF zararlılarına özel)
MITRE_DATABASE = {
    "T1059.007": MITREMapping(
        technique_id="T1059.007",
        technique_name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
        description="JavaScript kodu çalıştırma yoluyla komut yürütme.",
        url="https://attack.mitre.org/techniques/T1059/007/",
    ),
    "T1059.001": MITREMapping(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        description="PowerShell komutları ile sistem üzerinde komut yürütme.",
        url="https://attack.mitre.org/techniques/T1059/001/",
    ),
    "T1204.002": MITREMapping(
        technique_id="T1204.002",
        technique_name="User Execution: Malicious File",
        tactic="Execution",
        description="Kullanıcıyı zararlı dosyayı açmaya yönlendirme.",
        url="https://attack.mitre.org/techniques/T1204/002/",
    ),
    "T1566.001": MITREMapping(
        technique_id="T1566.001",
        technique_name="Phishing: Spearphishing Attachment",
        tactic="Initial Access",
        description="E-posta eklentisi olarak zararlı dosya gönderimi.",
        url="https://attack.mitre.org/techniques/T1566/001/",
    ),
    "T1027": MITREMapping(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        description="Dosya veya bilgi gizleme/karartma teknikleri.",
        url="https://attack.mitre.org/techniques/T1027/",
    ),
    "T1027.006": MITREMapping(
        technique_id="T1027.006",
        technique_name="Obfuscated Files: HTML Smuggling",
        tactic="Defense Evasion",
        description="Dosya içine gömülü zararlı payload.",
        url="https://attack.mitre.org/techniques/T1027/006/",
    ),
    "T1105": MITREMapping(
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic="Command and Control",
        description="Zararlı araçların uzak sunucudan indirilmesi.",
        url="https://attack.mitre.org/techniques/T1105/",
    ),
    "T1203": MITREMapping(
        technique_id="T1203",
        technique_name="Exploitation for Client Execution",
        tactic="Execution",
        description="İstemci uygulamasındaki zafiyet istismarı.",
        url="https://attack.mitre.org/techniques/T1203/",
    ),
    "T1497": MITREMapping(
        technique_id="T1497",
        technique_name="Virtualization/Sandbox Evasion",
        tactic="Defense Evasion",
        description="Sanal makine veya sandbox ortamlarından kaçınma.",
        url="https://attack.mitre.org/techniques/T1497/",
    ),
    "T1071.001": MITREMapping(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="HTTP/HTTPS üzerinden komuta-kontrol iletişimi.",
        url="https://attack.mitre.org/techniques/T1071/001/",
    ),
}


class MITREMapper:
    """MITRE ATT&CK eşleme motoru."""

    def map_findings(
        self,
        tag_result=None,
        emulation_result=None,
        sandbox_result=None,
        yara_result=None,
    ) -> list[MITREMapping]:
        """Analiz bulgularını MITRE tekniklerine eşle."""
        mappings = []
        mapped_ids = set()

        # Tag bazlı eşleme
        if tag_result:
            tags = {m.tag for m in tag_result.matches}

            if "/JS" in tags or "/JavaScript" in tags:
                m = self._get("T1059.007")
                m.evidence.append("PDF içinde JavaScript kodu tespit edildi")
                mappings.append(m)
                mapped_ids.add("T1059.007")

            if "/Launch" in tags:
                m = self._get("T1059.001")
                m.evidence.append("/Launch etiketi ile harici uygulama çalıştırma")
                mappings.append(m)
                mapped_ids.add("T1059.001")

            if "/OpenAction" in tags:
                m = self._get("T1204.002")
                m.evidence.append("/OpenAction ile otomatik tetikleme")
                mappings.append(m)
                mapped_ids.add("T1204.002")

            if "/EmbeddedFiles" in tags:
                if "T1027.006" not in mapped_ids:
                    m = self._get("T1027.006")
                    m.evidence.append("Gömülü dosya tespit edildi")
                    mappings.append(m)
                    mapped_ids.add("T1027.006")

        # Emülasyon bazlı eşleme
        if emulation_result:
            if emulation_result.network_calls and "T1071.001" not in mapped_ids:
                m = self._get("T1071.001")
                m.evidence.extend([c.get("url", "") for c in emulation_result.network_calls[:3]])
                mappings.append(m)

            if emulation_result.c2_addresses and "T1105" not in mapped_ids:
                m = self._get("T1105")
                m.evidence.extend(emulation_result.c2_addresses[:5])
                mappings.append(m)

        # Sandbox bazlı eşleme
        if sandbox_result:
            if sandbox_result.anti_vm_detected or sandbox_result.anti_sandbox_detected:
                m = self._get("T1497")
                m.evidence.extend(sandbox_result.anti_vm_detected[:3])
                mappings.append(m)

        # Phishing (varsayılan — PDF zararlıları genellikle phishing ile gelir)
        if mappings and "T1566.001" not in mapped_ids:
            m = self._get("T1566.001")
            m.evidence.append("Zararlı PDF — olası phishing eklentisi")
            mappings.append(m)

        return mappings

    def _get(self, technique_id: str) -> MITREMapping:
        """Veritabanından teknik kopyası al."""
        template = MITRE_DATABASE.get(technique_id)
        if template:
            return MITREMapping(
                technique_id=template.technique_id,
                technique_name=template.technique_name,
                tactic=template.tactic,
                description=template.description,
                url=template.url,
                evidence=[],
            )
        return MITREMapping(
            technique_id=technique_id,
            technique_name="Unknown",
            tactic="Unknown",
            description="",
        )
