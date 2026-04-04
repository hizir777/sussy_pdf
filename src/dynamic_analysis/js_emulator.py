"""
js_emulator.py — JavaScript Emülasyon Motoru

PDF JavaScript kodlarını izole ortamda emüle ederek
gerçek davranışını analiz eder. C2 adreslerini güvenli şekilde ayıklar.
"""

import re
from dataclasses import dataclass, field


@dataclass
class EmulationResult:
    code: str
    resolved_values: dict = field(default_factory=dict)
    network_calls: list[dict] = field(default_factory=list)
    file_operations: list[dict] = field(default_factory=list)
    shell_commands: list[str] = field(default_factory=list)
    registry_operations: list[str] = field(default_factory=list)
    c2_addresses: list[str] = field(default_factory=list)
    behaviors: list[str] = field(default_factory=list)
    risk_level: str = "unknown"


class PDFJSEnvironment:
    """Sahte Acrobat Reader JavaScript ortamı."""

    def __init__(self):
        self.properties = {
            "app.viewerVersion": "11.0",
            "app.platform": "WIN",
            "app.language": "ENU",
            "this.path": "C:\\Users\\victim\\Desktop\\document.pdf",
            "this.documentFileName": "document.pdf",
            "this.numPages": "3",
            "info.Title": "Resume",
            "info.Author": "John Doe",
            "event.target.name": "Button1",
        }

    def resolve_property(self, prop: str) -> str | None:
        return self.properties.get(prop)


class JSEmulator:
    """
    Basitleştirilmiş JavaScript emülatörü.

    Tam bir JS engine yerine, pattern-based analiz ile
    kodun niyetini belirler ve C2 adreslerini çıkarır.
    """

    def __init__(self):
        self.env = PDFJSEnvironment()

    def emulate(self, code: str) -> EmulationResult:
        """JavaScript kodunu emüle et."""
        result = EmulationResult(code=code)

        # 1. Ağ çağrılarını tespit et
        result.network_calls = self._detect_network_calls(code)

        # 2. Dosya operasyonlarını tespit et
        result.file_operations = self._detect_file_ops(code)

        # 3. Shell komutlarını tespit et
        result.shell_commands = self._detect_shell_commands(code)

        # 4. Registry operasyonlarını tespit et
        result.registry_operations = self._detect_registry_ops(code)

        # 5. C2 adreslerini çıkar
        result.c2_addresses = self._extract_c2(code)

        # 6. Davranış analizi
        result.behaviors = self._analyze_behaviors(code)

        # 7. Risk seviyesi
        result.risk_level = self._determine_risk(result)

        return result

    def _detect_network_calls(self, code: str) -> list[dict]:
        calls = []
        # XMLHttpRequest / XMLHTTP
        for m in re.finditer(
            r'\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']', code
        ):
            calls.append({"method": m.group(1), "url": m.group(2), "type": "XMLHttpRequest"})

        # app.launchURL
        for m in re.finditer(r'(?:app\.)?launchURL\s*\(\s*["\']([^"\']+)["\']', code):
            calls.append({"method": "GET", "url": m.group(1), "type": "launchURL"})

        # ADODB.Stream + SaveToFile pattern (download & execute)
        if re.search(r"(?i)ADODB\.Stream", code) and re.search(r"(?i)SaveToFile", code):
            calls.append({"method": "download", "url": "detected_in_code", "type": "ADODB.Stream"})

        return calls

    def _detect_file_ops(self, code: str) -> list[dict]:
        ops = []
        # SaveToFile
        for m in re.finditer(r'\.SaveToFile\s*\(\s*["\']([^"\']+)["\']', code):
            ops.append({"operation": "write", "path": m.group(1)})

        # FileSystemObject
        for m in re.finditer(
            r'(?:CreateTextFile|OpenTextFile)\s*\(\s*["\']([^"\']+)["\']', code
        ):
            ops.append({"operation": "create", "path": m.group(1)})

        # exportDataObject
        for m in re.finditer(r'exportDataObject\s*\({[^}]*nLaunch\s*:\s*(\d)', code):
            ops.append({"operation": "export_embedded", "auto_launch": m.group(1) != "0"})

        return ops

    def _detect_shell_commands(self, code: str) -> list[str]:
        commands = []
        # WScript.Shell Run
        for m in re.finditer(r'\.Run\s*\(\s*["\']([^"\']+)["\']', code):
            commands.append(m.group(1))

        # Shell.Application ShellExecute
        for m in re.finditer(r'\.ShellExecute\s*\(\s*["\']([^"\']+)["\']', code):
            commands.append(m.group(1))

        # app.launchURL with file: protocol
        for m in re.finditer(r'launchURL\s*\(\s*["\']file:([^"\']+)["\']', code):
            commands.append(f"file:{m.group(1)}")

        return commands

    def _detect_registry_ops(self, code: str) -> list[str]:
        ops = []
        for m in re.finditer(r'\.RegWrite\s*\(\s*["\']([^"\']+)["\']', code):
            ops.append(f"WRITE: {m.group(1)}")
        for m in re.finditer(r'\.RegRead\s*\(\s*["\']([^"\']+)["\']', code):
            ops.append(f"READ: {m.group(1)}")
        return ops

    def _extract_c2(self, code: str) -> list[str]:
        """C2 (Komuta-Kontrol) adreslerini güvenli şekilde çıkar."""
        addresses = set()

        # URL'ler
        for url in re.findall(r"https?://[^\s\"'<>\\)]+", code, re.IGNORECASE):
            addresses.add(url.rstrip(".,;"))

        # IP adresleri
        for ip in re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", code):
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                addresses.add(ip)

        # Domain'ler (basit heuristik)
        for domain in re.findall(r"\b([\w-]+\.(?:com|net|org|ru|cn|tk|xyz|top|info|biz))\b", code):
            addresses.add(domain)

        return list(addresses)

    def _analyze_behaviors(self, code: str) -> list[str]:
        behaviors = []
        checks = [
            (r"(?i)heap|spray|nop|slide", "💉 Heap spray denemesi"),
            (r"(?i)shellcode|payload|exploit", "⚡ Shellcode/exploit referansı"),
            (r"(?i)new\s+ActiveXObject", "🔧 ActiveX nesne oluşturma"),
            (r"(?i)eval\s*\(", "⚠️ Dinamik kod çalıştırma (eval)"),
            (r"(?i)WScript\.Shell", "💀 Windows Shell erişimi"),
            (r"(?i)cmd\.exe|powershell", "💀 Komut satırı erişimi"),
            (r"(?i)ADODB\.Stream", "📥 Dosya indirme mekanizması"),
            (r"(?i)CollectEmailInfo|submitForm", "📧 Veri sızdırma denemesi"),
            (r"(?i)getAnnot|getField", "📋 PDF form veri toplama"),
        ]
        for pattern, desc in checks:
            if re.search(pattern, code):
                behaviors.append(desc)
        return behaviors

    def _determine_risk(self, result: EmulationResult) -> str:
        score = 0
        score += len(result.shell_commands) * 40
        score += len(result.network_calls) * 20
        score += len(result.file_operations) * 25
        score += len(result.registry_operations) * 30
        score += len(result.c2_addresses) * 15

        if score >= 80:
            return "🔴 KRİTİK"
        if score >= 50:
            return "🟡 YÜKSEK"
        if score >= 20:
            return "🟠 ORTA"
        if score > 0:
            return "🟢 DÜŞÜK"
        return "✅ TEMİZ"
