"""
metadata_extractor.py — PDF Metadata Çıkarımı

PDF dosyalarının metadata bilgilerini çıkarır ve bilinen
zararlı kampanya imzalarıyla karşılaştırır.
"""

import re
from dataclasses import dataclass, field


@dataclass
class PDFMetadata:
    """PDF dosyasının metadata bilgileri."""

    title: str | None = None
    author: str | None = None
    subject: str | None = None
    creator: str | None = None  # Oluşturma aracı
    producer: str | None = None  # PDF üretici araç
    creation_date: str | None = None
    modification_date: str | None = None
    keywords: str | None = None
    page_count: int | None = None
    suspicious_indicators: list[str] = field(default_factory=list)


# Bilinen zararlı kampanya imzaları
KNOWN_MALICIOUS_PRODUCERS = [
    "iTextSharp",  # Sık exploit üretiminde kullanılır
    "Scribus",
    "mPDF",
    "FPDF",
    "dompdf",
    "wkhtmltopdf",
    "PhantomJS",
]

KNOWN_MALICIOUS_CREATORS = [
    "Microsoft Word",  # Makro tabanlı saldırılarda sık kullanılır
    "Adobe LiveCycle",
    "OpenOffice",
]

# Şüpheli metadata kalıpları
SUSPICIOUS_PATTERNS = [
    (r"(?i)(cmd|powershell|wscript|cscript|mshta)", "Shell komutu referansı tespit edildi"),
    (r"(?i)(exploit|payload|dropper|shellcode)", "Exploit terminolojisi tespit edildi"),
    (r"(?i)(eval|unescape|fromcharcode)", "JavaScript obfuscation fonksiyonu tespit edildi"),
    (r"[\x00-\x08\x0e-\x1f]", "Kontrol karakterleri tespit edildi (binary enjeksiyon?)"),
]


class MetadataExtractor:
    """PDF metadata çıkarma ve analiz motoru."""

    def extract(self, content: bytes) -> PDFMetadata:
        """
        PDF içeriğinden metadata bilgilerini çıkar.

        Args:
            content: PDF dosyasının ham byte içeriği.

        Returns:
            PDFMetadata: Çıkarılan metadata bilgileri.
        """
        metadata = PDFMetadata()

        # Info dictionary'yi bul
        info_dict = self._find_info_dict(content)

        if info_dict:
            metadata.title = self._extract_field(info_dict, b"/Title")
            metadata.author = self._extract_field(info_dict, b"/Author")
            metadata.subject = self._extract_field(info_dict, b"/Subject")
            metadata.creator = self._extract_field(info_dict, b"/Creator")
            metadata.producer = self._extract_field(info_dict, b"/Producer")
            metadata.creation_date = self._extract_field(info_dict, b"/CreationDate")
            metadata.modification_date = self._extract_field(info_dict, b"/ModDate")
            metadata.keywords = self._extract_field(info_dict, b"/Keywords")

        # Sayfa sayısını tespit et
        metadata.page_count = self._count_pages(content)

        # Şüpheli göstergeleri tara
        metadata.suspicious_indicators = self._scan_suspicious(metadata)

        return metadata

    def _find_info_dict(self, content: bytes) -> bytes | None:
        """PDF Info dictionary'yi bul ve döndür."""
        # /Info referansını trailer'da ara
        info_match = re.search(rb"/Info\s+(\d+)\s+(\d+)\s+R", content)
        if info_match:
            obj_num = info_match.group(1).decode()
            # İlgili nesneyi bul
            obj_pattern = re.compile(
                rf"{obj_num}\\s+\\d+\\s+obj(.*?)endobj".encode(),
                re.DOTALL,
            )
            obj_match = obj_pattern.search(content)
            if obj_match:
                return obj_match.group(1)

        # Alternatif: Doğrudan /Title, /Author vb. içeren dictionary'yi ara
        dict_match = re.search(
            rb"<<[^>]*?/(?:Title|Author|Creator|Producer)[^>]*?>>",
            content,
            re.DOTALL,
        )
        if dict_match:
            return dict_match.group(0)

        return None

    def _extract_field(self, info_dict: bytes, field_name: bytes) -> str | None:
        """Belirli bir metadata alanını çıkar."""
        # String formatı: /FieldName (value) veya /FieldName <hex_value>
        # Parantez içi string
        pattern_paren = re.compile(
            field_name + rb"\s*\(([^)]*)\)",
            re.DOTALL,
        )
        match = pattern_paren.search(info_dict)
        if match:
            return self._decode_pdf_string(match.group(1))

        # Hex string
        pattern_hex = re.compile(
            field_name + rb"\s*<([0-9a-fA-F]+)>",
        )
        match = pattern_hex.search(info_dict)
        if match:
            try:
                return bytes.fromhex(match.group(1).decode()).decode("utf-16-be", errors="ignore")
            except Exception:
                return match.group(1).decode(errors="ignore")

        return None

    def _decode_pdf_string(self, raw: bytes) -> str:
        """PDF string'ini decode et (octal escape'ler dahil)."""
        result = bytearray()
        i = 0
        while i < len(raw):
            if raw[i:i + 1] == b"\\" and i + 1 < len(raw):
                next_char = raw[i + 1:i + 2]
                if next_char in (b"n", b"r", b"t", b"b", b"f"):
                    escape_map = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}
                    result.extend(escape_map[next_char])
                    i += 2
                elif next_char in (b"(", b")", b"\\"):
                    result.extend(next_char)
                    i += 2
                elif next_char.isdigit():
                    # Octal escape: \NNN
                    octal_str = b""
                    j = i + 1
                    while j < len(raw) and j < i + 4 and raw[j:j + 1].isdigit():
                        octal_str += raw[j:j + 1]
                        j += 1
                    result.append(int(octal_str, 8))
                    i = j
                else:
                    result.extend(next_char)
                    i += 2
            else:
                result.append(raw[i])
                i += 1

        return result.decode("latin-1", errors="ignore")

    def _count_pages(self, content: bytes) -> int | None:
        """PDF sayfa sayısını tespit et."""
        # /Type /Pages ... /Count N
        match = re.search(rb"/Type\s*/Pages[^>]*?/Count\s+(\d+)", content, re.DOTALL)
        if match:
            return int(match.group(1))
        # Alternatif: /Type /Page sayısını say
        page_count = len(re.findall(rb"/Type\s*/Page\b", content))
        return page_count if page_count > 0 else None

    def _scan_suspicious(self, metadata: PDFMetadata) -> list[str]:
        """Metadata'da şüpheli kalıpları tara."""
        indicators = []

        # Producer kontrolü
        if metadata.producer:
            for producer in KNOWN_MALICIOUS_PRODUCERS:
                if producer.lower() in metadata.producer.lower():
                    indicators.append(
                        f"Bilinen exploit üreticisi tespit edildi: {metadata.producer}"
                    )

        # Tüm metin alanlarını şüpheli kalıplara karşı tara
        text_fields = [
            metadata.title,
            metadata.author,
            metadata.subject,
            metadata.creator,
            metadata.keywords,
        ]

        for field_value in text_fields:
            if field_value is None:
                continue
            for pattern, description in SUSPICIOUS_PATTERNS:
                if re.search(pattern, field_value):
                    indicators.append(f"{description}: '{field_value[:100]}'")

        # Tarih tutarsızlığı kontrolü
        if metadata.creation_date and metadata.modification_date:
            if metadata.modification_date < metadata.creation_date:
                indicators.append(
                    "Oluşturma tarihi, değişiklik tarihinden sonra — "
                    "zaman damgası manipülasyonu olabilir"
                )

        return indicators
