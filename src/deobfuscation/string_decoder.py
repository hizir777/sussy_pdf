"""
string_decoder.py — String/Karakter Kod Çözücü

Hex, octal, unicode ve XOR ile maskelenmiş dizeleri
okunabilir ASCII formatına dönüştürür.
"""

import re
from dataclasses import dataclass


@dataclass
class DecodedString:
    original: str
    decoded: str
    encoding_type: str
    is_url: bool = False
    is_ip: bool = False
    is_suspicious: bool = False


class StringDecoder:
    """PDF string kod çözme motoru."""

    def decode_all(self, text: str) -> list[DecodedString]:
        """Metindeki tüm kodlanmış dizeleri çöz."""
        results = []
        results.extend(self._decode_hex_strings(text))
        results.extend(self._decode_octal_strings(text))
        results.extend(self._decode_unicode_escapes(text))
        results.extend(self._decode_charcode(text))
        results.extend(self._decode_percent_encoding(text))
        return results

    def decode_hex(self, hex_str: str) -> str:
        """Hex dizesini ASCII'ye çevir: 48656C6C6F -> Hello"""
        clean = re.sub(r"[^0-9a-fA-F]", "", hex_str)
        if len(clean) % 2:
            clean += "0"
        try:
            return bytes.fromhex(clean).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def decode_octal(self, text: str) -> str:
        """Octal escape'leri çöz: \\150\\164\\164\\160 -> http"""
        def replace_octal(m):
            try:
                return chr(int(m.group(1), 8))
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r"\\(\d{1,3})", replace_octal, text)

    def decode_unicode(self, text: str) -> str:
        """Unicode escape'leri çöz: \\u0068\\u0074\\u0074\\u0070 -> http"""
        def replace_unicode(m):
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, text)

    def decode_charcode(self, text: str) -> str:
        """String.fromCharCode çözme: String.fromCharCode(104,116,116,112) -> http"""
        def replace_charcode(m):
            try:
                nums = [int(x.strip()) for x in m.group(1).split(",")]
                return "".join(chr(n) for n in nums if 0 <= n <= 0x10FFFF)
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(
            r"String\.fromCharCode\(([^)]+)\)", replace_charcode, text, flags=re.IGNORECASE
        )

    def decode_rot13(self, text: str) -> str:
        """ROT13 çözme."""
        result = []
        for c in text:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    def decode_xor(self, data: bytes, key: int) -> bytes:
        """XOR key ile decode et."""
        return bytes(b ^ key for b in data)

    # --- İç yardımcılar ---
    def _decode_hex_strings(self, text: str) -> list[DecodedString]:
        results = []
        for m in re.finditer(r"<([0-9a-fA-F]{4,})>", text):
            decoded = self.decode_hex(m.group(1))
            if decoded and len(decoded) > 2:
                results.append(DecodedString(
                    original=m.group(0), decoded=decoded,
                    encoding_type="hex",
                    is_url="http" in decoded.lower(),
                    is_ip=bool(re.search(r"\d+\.\d+\.\d+\.\d+", decoded)),
                    is_suspicious=self._is_suspicious(decoded),
                ))
        return results

    def _decode_octal_strings(self, text: str) -> list[DecodedString]:
        results = []
        octal_pattern = r"((?:\\[0-7]{1,3}){3,})"
        for m in re.finditer(octal_pattern, text):
            decoded = self.decode_octal(m.group(1))
            if decoded and len(decoded) > 2:
                results.append(DecodedString(
                    original=m.group(0), decoded=decoded,
                    encoding_type="octal",
                    is_url="http" in decoded.lower(),
                    is_ip=bool(re.search(r"\d+\.\d+\.\d+\.\d+", decoded)),
                    is_suspicious=self._is_suspicious(decoded),
                ))
        return results

    def _decode_unicode_escapes(self, text: str) -> list[DecodedString]:
        results = []
        pattern = r"((?:\\u[0-9a-fA-F]{4}){3,})"
        for m in re.finditer(pattern, text):
            decoded = self.decode_unicode(m.group(1))
            if decoded:
                results.append(DecodedString(
                    original=m.group(0), decoded=decoded,
                    encoding_type="unicode", is_url="http" in decoded.lower(),
                    is_suspicious=self._is_suspicious(decoded),
                ))
        return results

    def _decode_charcode(self, text: str) -> list[DecodedString]:
        results = []
        pattern = r"(String\.fromCharCode\([^)]+\))"
        for m in re.finditer(pattern, text, re.IGNORECASE):
            decoded = self.decode_charcode(m.group(1))
            if decoded:
                results.append(DecodedString(
                    original=m.group(0), decoded=decoded,
                    encoding_type="charcode",
                    is_url="http" in decoded.lower(),
                    is_suspicious=self._is_suspicious(decoded),
                ))
        return results

    def _decode_percent_encoding(self, text: str) -> list[DecodedString]:
        results = []
        pattern = r"((?:%[0-9a-fA-F]{2}){3,})"
        for m in re.finditer(pattern, text):
            try:
                from urllib.parse import unquote
                decoded = unquote(m.group(1))
                results.append(DecodedString(
                    original=m.group(0), decoded=decoded,
                    encoding_type="percent", is_url="http" in decoded.lower(),
                    is_suspicious=self._is_suspicious(decoded),
                ))
            except Exception:
                pass
        return results

    def _is_suspicious(self, text: str) -> bool:
        """Çözümlenen metnin şüpheli olup olmadığını kontrol et."""
        patterns = [
            r"https?://", r"\d+\.\d+\.\d+\.\d+",
            r"(?i)(cmd|powershell|wscript|eval|exec|system)",
            r"(?i)(payload|exploit|shell|dropper|malware)",
        ]
        return any(re.search(p, text) for p in patterns)
