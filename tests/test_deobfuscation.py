"""
Test suite: De-obfuscation modülü
"""

from src.deobfuscation.js_deobfuscator import JSDeobfuscator
from src.deobfuscation.string_decoder import StringDecoder


class TestStringDecoder:
    """StringDecoder test sınıfı."""

    def setup_method(self):
        self.decoder = StringDecoder()

    def test_hex_decode(self):
        """Hex string çözme."""
        assert self.decoder.decode_hex("48656C6C6F") == "Hello"
        assert self.decoder.decode_hex("68747470") == "http"

    def test_octal_decode(self):
        """Octal escape çözme."""
        result = self.decoder.decode_octal("\\150\\164\\164\\160")
        assert result == "http"

    def test_unicode_decode(self):
        """Unicode escape çözme."""
        result = self.decoder.decode_unicode("\\u0068\\u0074\\u0074\\u0070")
        assert result == "http"

    def test_charcode_decode(self):
        """String.fromCharCode çözme."""
        result = self.decoder.decode_charcode("String.fromCharCode(104,116,116,112)")
        assert result == 'http'

    def test_rot13_decode(self):
        """ROT13 çözme."""
        assert self.decoder.decode_rot13("uryyb") == "hello"

    def test_xor_decode(self):
        """XOR decode."""
        data = bytes([0x41 ^ 0x10, 0x42 ^ 0x10])  # 'A'^0x10, 'B'^0x10
        result = self.decoder.decode_xor(data, 0x10)
        assert result == b"AB"

    def test_decode_all_hex(self):
        """decode_all hex string'leri bulabilmeli."""
        text = "some text <48656C6C6F> more text"
        results = self.decoder.decode_all(text)
        assert any(r.decoded == "Hello" for r in results)

    def test_suspicious_url_detection(self):
        """URL içeren çözümlenmiş string'leri şüpheli olarak işaretlemeli."""
        text = "<687474703A2F2F6576696C2E636F6D>"  # http://evil.com
        results = self.decoder.decode_all(text)
        assert any(r.is_url for r in results) or any(r.is_suspicious for r in results)


class TestJSDeobfuscator:
    """JSDeobfuscator test sınıfı."""

    def setup_method(self):
        self.deob = JSDeobfuscator()

    def test_fromcharcode_resolution(self):
        """String.fromCharCode çözümlemesi."""
        code = 'var x = String.fromCharCode(104,101,108,108,111);'
        result = self.deob.deobfuscate(code)
        assert "hello" in result.deobfuscated_code

    def test_string_concatenation(self):
        """String birleştirme basitleştirmesi."""
        code = 'var url = "h" + "t" + "t" + "p" + ":" + "/" + "/";'
        result = self.deob.deobfuscate(code)
        assert "http://" in result.deobfuscated_code

    def test_hex_escape_resolution(self):
        """Hex escape çözümlemesi."""
        code = 'var x = "\\x68\\x74\\x74\\x70";'
        result = self.deob.deobfuscate(code)
        assert "http" in result.deobfuscated_code

    def test_dangerous_functions_detection(self):
        """Tehlikeli fonksiyonları tespit edebilmeli."""
        code = 'eval(unescape("%68%65%6C%6C%6F"));'
        result = self.deob.deobfuscate(code)
        assert "eval" in result.dangerous_functions

    def test_url_extraction(self):
        """URL çıkarabilmeli."""
        code = 'var url = "http://malware.com/payload.exe";'
        result = self.deob.deobfuscate(code)
        assert len(result.extracted_urls) > 0
        assert "malware.com" in result.extracted_urls[0]

    def test_ip_extraction(self):
        """IP adresi çıkarabilmeli."""
        code = 'var host = "192.168.1.100";'
        result = self.deob.deobfuscate(code)
        assert "192.168.1.100" in result.extracted_ips

    def test_suspicious_patterns(self):
        """Şüpheli kalıpları tespit edebilmeli."""
        code = '''
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("cmd.exe /c powershell -e base64payload");
        '''
        result = self.deob.deobfuscate(code)
        assert len(result.suspicious_patterns) > 0

    def test_multilayer_obfuscation(self):
        """Çok katmanlı obfuscation çözebilmeli."""
        code = 'var a = "h"+"t"+"t"+"p"; var b = String.fromCharCode(58,47,47);'
        result = self.deob.deobfuscate(code)
        assert result.layers_resolved >= 1
