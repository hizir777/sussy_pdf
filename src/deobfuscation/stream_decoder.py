"""
stream_decoder.py — PDF Stream Dekompresyon Motoru

/FlateDecode, /ASCIIHexDecode, /ASCII85Decode gibi
filtreleri çözerek sıkıştırılmış veriyi ham hale getirir.
"""

import re
import zlib
from dataclasses import dataclass, field


@dataclass
class DecodedStream:
    object_number: int
    filters: list[str]
    raw_length: int
    decoded_length: int
    decoded_data: bytes
    is_javascript: bool = False
    decode_errors: list[str] = field(default_factory=list)
    decode_chain: list[str] = field(default_factory=list)


class StreamDecoder:
    """PDF Stream dekompresyon motoru."""

    def decode_all_streams(self, content: bytes) -> list[DecodedStream]:
        """Tüm stream'leri bul ve decode et."""
        results = []
        obj_pattern = re.compile(
            rb"(\d+)\s+\d+\s+obj\b(.*?)endobj", re.DOTALL
        )

        for match in obj_pattern.finditer(content):
            obj_num = int(match.group(1))
            obj_content = match.group(2)

            stream_match = re.search(
                rb"stream\r?\n(.*?)\r?\nendstream", obj_content, re.DOTALL
            )
            if not stream_match:
                continue

            filters = self._extract_filters(obj_content)
            if not filters:
                continue

            raw_data = stream_match.group(1)
            decoded = self._decode_chain(raw_data, filters, obj_num)
            results.append(decoded)

        return results

    def decode_stream(self, data: bytes, filters: list[str], obj_num: int = 0) -> DecodedStream:
        """Tek bir stream'i decode et."""
        return self._decode_chain(data, filters, obj_num)

    def _decode_chain(self, data: bytes, filters: list[str], obj_num: int) -> DecodedStream:
        """Filtre zincirini sırayla uygula."""
        result = DecodedStream(
            object_number=obj_num,
            filters=filters,
            raw_length=len(data),
            decoded_length=0,
            decoded_data=b"",
        )

        current_data = data
        for f in filters:
            try:
                current_data = self._apply_filter(current_data, f)
                result.decode_chain.append(f"✅ {f}")
            except Exception as e:
                result.decode_errors.append(f"❌ {f}: {e}")
                break

        result.decoded_data = current_data
        result.decoded_length = len(current_data)

        # JavaScript kontrolü
        js_indicators = [b"eval", b"unescape", b"String.fromCharCode",
                         b"function", b"var ", b"this."]
        result.is_javascript = any(ind in current_data for ind in js_indicators)

        return result

    def _apply_filter(self, data: bytes, filter_name: str) -> bytes:
        """Belirtilen filtreyi uygula."""
        decoders = {
            "/FlateDecode": self._decode_flate,
            "/ASCIIHexDecode": self._decode_ascii_hex,
            "/ASCII85Decode": self._decode_ascii85,
            "/LZWDecode": self._decode_lzw,
            "/RunLengthDecode": self._decode_runlength,
        }
        decoder = decoders.get(filter_name)
        if decoder:
            return decoder(data)
        raise ValueError(f"Bilinmeyen filtre: {filter_name}")

    def _decode_flate(self, data: bytes) -> bytes:
        """zlib (FlateDecode) dekompresyon."""
        try:
            return zlib.decompress(data)
        except zlib.error:
            # Raw deflate dene
            return zlib.decompress(data, -15)

    def _decode_ascii_hex(self, data: bytes) -> bytes:
        """ASCIIHexDecode: hex string'i byte'a dönüştür."""
        hex_str = data.replace(b" ", b"").replace(b"\n", b"").replace(b"\r", b"")
        if hex_str.endswith(b">"):
            hex_str = hex_str[:-1]
        if len(hex_str) % 2:
            hex_str += b"0"
        return bytes.fromhex(hex_str.decode("ascii"))

    def _decode_ascii85(self, data: bytes) -> bytes:
        """ASCII85Decode dekompresyon."""
        import base64
        clean = data.strip()
        if clean.startswith(b"<~"):
            clean = clean[2:]
        if clean.endswith(b"~>"):
            clean = clean[:-2]
        return base64.a85decode(clean)

    def _decode_lzw(self, data: bytes) -> bytes:
        """LZWDecode — basit LZW dekompresyon."""
        # Basitleştirilmiş LZW implementasyonu
        if not data:
            return b""
        result = bytearray()
        dictionary = {i: bytes([i]) for i in range(256)}
        dict_size = 258  # 256 + CLEAR + EOD
        w = bytes([data[0]])
        result.extend(w)
        for i in range(1, len(data)):
            k = data[i]
            if k in dictionary:
                entry = dictionary[k]
            elif k == dict_size:
                entry = w + w[:1]
            else:
                break
            result.extend(entry)
            dictionary[dict_size] = w + entry[:1]
            dict_size += 1
            w = entry
        return bytes(result)

    def _decode_runlength(self, data: bytes) -> bytes:
        """RunLengthDecode dekompresyon."""
        result = bytearray()
        i = 0
        while i < len(data):
            length_byte = data[i]
            if length_byte == 128:  # EOD
                break
            if length_byte < 128:
                count = length_byte + 1
                result.extend(data[i + 1:i + 1 + count])
                i += 1 + count
            else:
                count = 257 - length_byte
                result.extend(data[i + 1:1] * count)
                i += 2
        return bytes(result)

    def _extract_filters(self, obj_content: bytes) -> list[str]:
        """Stream filtrelerini çıkar."""
        filters = []
        single = re.search(rb"/Filter\s*/(\w+)", obj_content)
        if single:
            return [f"/{single.group(1).decode()}"]
        multi = re.search(rb"/Filter\s*\[(.*?)\]", obj_content, re.DOTALL)
        if multi:
            for f in re.findall(rb"/(\w+)", multi.group(1)):
                filters.append(f"/{f.decode()}")
        return filters
