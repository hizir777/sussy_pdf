"""
pdf_parser.py — PDF Fiziksel Yapı Ayrıştırıcı

PDF belgesinin dört ana bölümünü analiz eder:
  1. Header — Versiyon bilgisi
  2. Body — Nesneler (Objects)
  3. XRef — Çapraz referans tablosu (Cross-Reference)
  4. Trailer — Root nesnesi referansı

Tersine okuma mekanizması: Dosya sonundaki %%EOF'tan geriye doğru okur.
"""

import re
from dataclasses import dataclass, field


@dataclass
class PDFHeader:
    """PDF Header bilgileri."""

    raw: str
    version: str
    major: int
    minor: int
    is_valid: bool
    binary_marker: bool  # 2. satırda binary marker var mı?


@dataclass
class XRefEntry:
    """XRef tablosundaki tek bir giriş."""

    object_number: int
    offset: int
    generation: int
    in_use: bool  # 'n' = kullanımda, 'f' = serbest


@dataclass
class XRefTable:
    """Cross-Reference tablosu."""

    entries: list[XRefEntry] = field(default_factory=list)
    is_stream: bool = False  # XRef stream mi yoksa tablo mu?
    start_offset: int = 0


@dataclass
class PDFTrailer:
    """PDF Trailer bilgileri."""

    raw: bytes = b""
    root_ref: str | None = None  # /Root referansı
    info_ref: str | None = None  # /Info referansı
    size: int | None = None  # Toplam nesne sayısı
    prev: int | None = None  # Önceki XRef offset (artımlı güncelleme)
    encrypt_ref: str | None = None  # /Encrypt referansı (şifreleme)
    startxref: int | None = None


@dataclass
class PDFStructure:
    """PDF'in tam fiziksel yapısı."""

    header: PDFHeader | None = None
    xref_tables: list[XRefTable] = field(default_factory=list)
    trailers: list[PDFTrailer] = field(default_factory=list)
    eof_positions: list[int] = field(default_factory=list)
    eof_count: int = 0
    is_encrypted: bool = False
    is_linearized: bool = False
    has_incremental_updates: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class PDFParser:
    """
    PDF Fiziksel Yapı Ayrıştırıcısı.

    Tersine okuma mekanizması ile dosyayı %%EOF'tan geriye doğru ayrıştırır.
    Bu, saldırganların dosya sonuna eklediği zararlı güncelleme katmanlarını
    tespit etmek için kritik öneme sahiptir.
    """

    def parse(self, content: bytes) -> PDFStructure:
        """
        PDF dosyasının fiziksel yapısını ayrıştır.

        Args:
            content: PDF dosyasının ham byte içeriği.

        Returns:
            PDFStructure: Ayrıştırılmış yapı bilgileri.
        """
        structure = PDFStructure()

        # 1. Header analizi
        structure.header = self._parse_header(content)

        # 2. %%EOF konumlarını bul (tersine okuma başlangıcı)
        structure.eof_positions = self._find_eof_positions(content)
        structure.eof_count = len(structure.eof_positions)

        # 3. Tersine okuma: Son %%EOF'tan trailer'a
        structure.trailers = self._parse_trailers(content)

        # 4. XRef tablosunu ayrıştır
        structure.xref_tables = self._parse_xref_tables(content)

        # 5. Artımlı güncelleme kontrolü
        if structure.eof_count > 1:
            structure.has_incremental_updates = True
            structure.warnings.append(
                f"⚠️ {structure.eof_count} adet %%EOF etiketi tespit edildi. "
                "Artımlı güncelleme veya Shadow Attack olabilir!"
            )

        # 6. Şifreleme kontrolü
        for trailer in structure.trailers:
            if trailer.encrypt_ref:
                structure.is_encrypted = True
                structure.warnings.append("🔒 PDF şifrelenmiş (Encrypted).")

        # 7. Linearizasyon kontrolü
        if b"/Linearized" in content[:1024]:
            structure.is_linearized = True

        return structure

    def _parse_header(self, content: bytes) -> PDFHeader:
        """PDF Header'ı ayrıştır."""
        # İlk satırı al
        first_line = content[:20].split(b"\n")[0].split(b"\r")[0]

        header_match = re.match(rb"%PDF-(\d+)\.(\d+)", first_line)

        if header_match:
            major = int(header_match.group(1))
            minor = int(header_match.group(2))
            version = f"{major}.{minor}"

            # İkinci satırda binary marker kontrolü
            # (%'den sonra 4+ tane high-byte karakter olmalı)
            second_line_start = len(first_line) + 1
            binary_marker = False
            if second_line_start < len(content):
                second_line = content[second_line_start:second_line_start + 10]
                if second_line.startswith(b"%"):
                    high_bytes = sum(1 for b in second_line[1:5] if b > 127)
                    binary_marker = high_bytes >= 4

            return PDFHeader(
                raw=first_line.decode("ascii", errors="ignore"),
                version=version,
                major=major,
                minor=minor,
                is_valid=True,
                binary_marker=binary_marker,
            )

        return PDFHeader(
            raw=first_line.decode("ascii", errors="ignore"),
            version="unknown",
            major=0,
            minor=0,
            is_valid=False,
            binary_marker=False,
        )

    def _find_eof_positions(self, content: bytes) -> list[int]:
        """Tüm %%EOF konumlarını bul."""
        positions = []
        start = 0
        while True:
            pos = content.find(b"%%EOF", start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 5
        return positions

    def _parse_trailers(self, content: bytes) -> list[PDFTrailer]:
        """Tüm trailer'ları ayrıştır (tersine okuma)."""
        trailers = []

        # startxref konumlarını bul
        startxref_pattern = re.compile(rb"startxref\s+(\d+)", re.DOTALL)
        for match in startxref_pattern.finditer(content):
            startxref_value = int(match.group(1))

            # Trailer dictionary'yi bul
            trailer_data = self._find_trailer_dict(content, match.start())

            trailer = PDFTrailer(startxref=startxref_value)

            if trailer_data:
                trailer.raw = trailer_data

                # /Root referansı
                root_match = re.search(rb"/Root\s+(\d+\s+\d+\s+R)", trailer_data)
                if root_match:
                    trailer.root_ref = root_match.group(1).decode()

                # /Info referansı
                info_match = re.search(rb"/Info\s+(\d+\s+\d+\s+R)", trailer_data)
                if info_match:
                    trailer.info_ref = info_match.group(1).decode()

                # /Size
                size_match = re.search(rb"/Size\s+(\d+)", trailer_data)
                if size_match:
                    trailer.size = int(size_match.group(1))

                # /Prev (önceki XRef offset)
                prev_match = re.search(rb"/Prev\s+(\d+)", trailer_data)
                if prev_match:
                    trailer.prev = int(prev_match.group(1))

                # /Encrypt
                encrypt_match = re.search(rb"/Encrypt\s+(\d+\s+\d+\s+R)", trailer_data)
                if encrypt_match:
                    trailer.encrypt_ref = encrypt_match.group(1).decode()

            trailers.append(trailer)

        return trailers

    def _find_trailer_dict(self, content: bytes, before_pos: int) -> bytes | None:
        """Belirtilen konumdan önce gelen trailer dictionary'yi bul."""
        # trailer ... >> bloğunu geriye doğru ara
        search_area = content[max(0, before_pos - 2048):before_pos]

        trailer_match = re.search(rb"trailer\s*<<(.*?)>>", search_area, re.DOTALL)
        if trailer_match:
            return trailer_match.group(0)

        # XRef stream durumunda trailer ayrı olmayabilir
        # Stream nesnesi içinde /Root vb. aranır
        dict_match = re.search(rb"<<(.*?/Root.*?)>>", search_area, re.DOTALL)
        if dict_match:
            return dict_match.group(0)

        return None

    def _parse_xref_tables(self, content: bytes) -> list[XRefTable]:
        """XRef tablolarını ayrıştır."""
        tables = []

        # Klasik xref tablosu
        xref_pattern = re.compile(rb"xref\s*\n", re.MULTILINE)
        for match in xref_pattern.finditer(content):
            table = XRefTable(start_offset=match.start())
            entries = self._parse_xref_section(content, match.end())
            table.entries = entries
            tables.append(table)

        # XRef stream kontrolü
        if not tables:
            if re.search(rb"/Type\s*/XRef", content):
                table = XRefTable(is_stream=True)
                tables.append(table)

        return tables

    def _parse_xref_section(self, content: bytes, start: int) -> list[XRefEntry]:
        """XRef bölümünü satır satır ayrıştır."""
        entries = []
        pos = start
        current_obj_num = 0

        while pos < len(content):
            line_end = content.find(b"\n", pos)
            if line_end == -1:
                break
            line = content[pos:line_end].strip()
            pos = line_end + 1

            if line == b"trailer" or line.startswith(b"<<"):
                break

            # Alt bölüm başlığı: <start_obj> <count>
            subsection_match = re.match(rb"^(\d+)\s+(\d+)$", line)
            if subsection_match:
                current_obj_num = int(subsection_match.group(1))
                continue

            # XRef girişi: <offset> <gen> <n|f>
            entry_match = re.match(rb"^(\d{10})\s+(\d{5})\s+([nf])", line)
            if entry_match:
                entries.append(
                    XRefEntry(
                        object_number=current_obj_num,
                        offset=int(entry_match.group(1)),
                        generation=int(entry_match.group(2)),
                        in_use=entry_match.group(3) == b"n",
                    )
                )
                current_obj_num += 1

        return entries
