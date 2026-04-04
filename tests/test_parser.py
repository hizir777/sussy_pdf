"""
Test suite: PDF Parser modülü
"""

import pytest
from src.static_analysis.pdf_parser import PDFParser


class TestPDFParser:
    """PDFParser test sınıfı."""

    def setup_method(self):
        self.parser = PDFParser()

    def test_parse_header(self):
        """PDF Header'ı doğru parse edebilmeli."""
        content = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        structure = self.parser.parse(content)
        assert structure.header is not None
        assert structure.header.version == "1.7"
        assert structure.header.major == 1
        assert structure.header.minor == 7
        assert structure.header.is_valid is True

    def test_invalid_header(self):
        """Geçersiz header tipini tespit edebilmeli."""
        content = b"NOT A PDF FILE\ncontent"
        structure = self.parser.parse(content)
        assert structure.header.is_valid is False

    def test_eof_detection(self):
        """%%EOF konumlarını bulabilmeli."""
        content = b"%PDF-1.4\ncontent\n%%EOF"
        structure = self.parser.parse(content)
        assert structure.eof_count == 1

    def test_multiple_eof(self):
        """Birden fazla %%EOF tespiti ve uyarı."""
        content = b"%PDF-1.4\ncontent\n%%EOF\nnew content\nxref\n0 0\ntrailer\n<<>>\nstartxref\n0\n%%EOF"
        structure = self.parser.parse(content)
        assert structure.eof_count == 2
        assert structure.has_incremental_updates is True
        assert len(structure.warnings) > 0

    def test_xref_parsing(self):
        """XRef tablosunu ayrıştırabilmeli."""
        content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"xref\n0 2\n"
            b"0000000000 65535 f \n"
            b"0000000010 00000 n \n"
            b"trailer\n<< /Root 1 0 R /Size 2 >>\n"
            b"startxref\n50\n%%EOF"
        )
        structure = self.parser.parse(content)
        assert len(structure.xref_tables) > 0

    def test_trailer_parsing(self):
        """Trailer'ı doğru parse edebilmeli."""
        content = (
            b"%PDF-1.4\n"
            b"trailer\n<< /Root 1 0 R /Info 2 0 R /Size 10 >>\n"
            b"startxref\n100\n%%EOF"
        )
        structure = self.parser.parse(content)
        assert len(structure.trailers) > 0
        assert structure.trailers[0].root_ref is not None

    def test_encryption_detection(self):
        """Şifreli PDF'i tespit edebilmeli."""
        content = (
            b"%PDF-1.4\n"
            b"trailer\n<< /Root 1 0 R /Encrypt 5 0 R >>\n"
            b"startxref\n0\n%%EOF"
        )
        structure = self.parser.parse(content)
        assert structure.is_encrypted is True

    def test_linearization_detection(self):
        """Linearize edilmiş PDF'i tespit edebilmeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /Linearized 1 /L 1234 >>\nendobj\n%%EOF"
        structure = self.parser.parse(content)
        assert structure.is_linearized is True
