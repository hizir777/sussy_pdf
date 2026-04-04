"""
js_deobfuscator.py — JavaScript Deobfuscation Motoru

eval(), unescape(), String.fromCharCode() gibi
obfuscation fonksiyonlarını çözer.
"""

import re
from dataclasses import dataclass, field


@dataclass
class JSDeobfuscationResult:
    original_code: str
    deobfuscated_code: str
    layers_resolved: int = 0
    dangerous_functions: list[str] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    extracted_ips: list[str] = field(default_factory=list)
    suspicious_patterns: list[str] = field(default_factory=list)


class JSDeobfuscator:
    """JavaScript kod çözme motoru."""

    DANGEROUS_FUNCTIONS = [
        "eval", "unescape", "escape", "exec", "setTimeout", "setInterval",
        "Function", "ActiveXObject", "WScript.Shell", "Scripting.FileSystemObject",
        "ADODB.Stream", "Shell.Application", "XMLHttpRequest",
    ]

    SUSPICIOUS_PATTERNS = [
        (r"(?i)new\s+ActiveXObject\s*\(", "ActiveX nesnesi oluşturuluyor"),
        (r"(?i)WScript\.Shell", "Windows Script Shell erişimi"),
        (r"(?i)\.Run\s*\(", "Harici komut çalıştırma"),
        (r"(?i)\.ShellExecute\s*\(", "Shell komutu çalıştırma"),
        (r"(?i)cmd\.exe|powershell", "Komut satırı referansı"),
        (r"(?i)\.savetofile|\.write\(", "Dosya yazma işlemi"),
        (r"(?i)\.open\s*\(\s*['\"](?:GET|POST)", "HTTP isteği"),
        (r"(?i)\.responseBody|\.responseText", "HTTP yanıt okuma"),
        (r"(?i)\bspray\b|\bnop\b|\bslide\b", "Heap spray göstergesi"),
        (r"%u[0-9a-fA-F]{4}", "Unicode escape (shellcode?)"),
    ]

    def deobfuscate(self, code: str, max_layers: int = 10) -> JSDeobfuscationResult:
        """JavaScript kodunu deobfuscate et."""
        result = JSDeobfuscationResult(
            original_code=code,
            deobfuscated_code=code,
        )

        current = code
        for i in range(max_layers):
            previous = current

            # 1. String.fromCharCode çöz
            current = self._resolve_fromcharcode(current)

            # 2. unescape çöz
            current = self._resolve_unescape(current)

            # 3. String birleştirmeleri basitleştir
            current = self._simplify_concatenation(current)

            # 4. Hex/octal escape'leri çöz
            current = self._resolve_hex_escapes(current)
            current = self._resolve_octal_escapes(current)

            # 5. parseInt tabanlı obfuscation
            current = self._resolve_parseint(current)

            if current == previous:
                break
            result.layers_resolved = i + 1

        result.deobfuscated_code = current

        # Tehlikeli fonksiyonları tespit et
        for func in self.DANGEROUS_FUNCTIONS:
            if func.lower() in current.lower():
                result.dangerous_functions.append(func)

        # URL ve IP çıkar
        result.extracted_urls = re.findall(
            r"https?://[^\s\"'<>]+", current, re.IGNORECASE
        )
        result.extracted_ips = re.findall(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", current
        )

        # Şüpheli kalıpları tara
        for pattern, desc in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, current):
                result.suspicious_patterns.append(desc)

        return result

    def _resolve_fromcharcode(self, code: str) -> str:
        def replace(m):
            try:
                nums = [int(x.strip()) for x in m.group(1).split(",")]
                return '"' + "".join(chr(n) for n in nums if 0 <= n <= 0x10FFFF) + '"'
            except Exception:
                return m.group(0)
        return re.sub(r"String\.fromCharCode\(([^)]+)\)", replace, code, flags=re.IGNORECASE)

    def _resolve_unescape(self, code: str) -> str:
        def replace(m):
            try:
                from urllib.parse import unquote
                return '"' + unquote(m.group(1)) + '"'
            except Exception:
                return m.group(0)
        return re.sub(r'unescape\(["\']([^"\']+)["\']\)', replace, code, flags=re.IGNORECASE)

    def _simplify_concatenation(self, code: str) -> str:
        """'h'+'t'+'t'+'p' → 'http' birleştirme."""
        pattern = r'"([^"]*?)"\s*\+\s*"([^"]*?)"'
        prev = ""
        while code != prev:
            prev = code
            code = re.sub(pattern, r'"\1\2"', code)
        pattern2 = r"'([^']*?)'\s*\+\s*'([^']*?)'"
        prev = ""
        while code != prev:
            prev = code
            code = re.sub(pattern2, r"'\1\2'", code)
        return code

    def _resolve_hex_escapes(self, code: str) -> str:
        def replace(m):
            try:
                return chr(int(m.group(1), 16))
            except Exception:
                return m.group(0)
        return re.sub(r"\\x([0-9a-fA-F]{2})", replace, code)

    def _resolve_octal_escapes(self, code: str) -> str:
        def replace(m):
            try:
                return chr(int(m.group(1), 8))
            except Exception:
                return m.group(0)
        return re.sub(r"\\(\d{1,3})", replace, code)

    def _resolve_parseint(self, code: str) -> str:
        def replace(m):
            try:
                return str(int(m.group(1), int(m.group(2))))
            except Exception:
                return m.group(0)
        return re.sub(r'parseInt\(["\']([^"\']+)["\']\s*,\s*(\d+)\)', replace, code)
