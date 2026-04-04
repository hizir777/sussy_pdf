"""
Test suite: Ingestion modülü
"""

import os
import tempfile
import pytest
from src.ingestion.file_handler import FileHandler


class TestFileHandler:
    """FileHandler test sınıfı."""

    def setup_method(self):
        self.handler = FileHandler()

    def _create_temp_pdf(self, content: bytes) -> str:
        """Geçici PDF dosyası oluştur."""
        fd, path = tempfile.mkstemp(suffix=".pdf")
        os.write(fd, content)
        os.close(fd)
        return path

    def test_valid_pdf_ingestion(self):
        """Geçerli PDF dosyasını alabilmeli."""
        content = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R /Size 1 >>\nstartxref\n9\n%%EOF"
        path = self._create_temp_pdf(content)
        try:
            result = self.handler.ingest(path)
            assert result.is_pdf is True
            assert result.pdf_version == "1.7"
            assert len(result.md5) == 32
            assert len(result.sha256) == 64
            assert result.file_size > 0
        finally:
            os.unlink(path)

    def test_invalid_pdf_detection(self):
        """Geçersiz dosyayı tespit edebilmeli."""
        content = b"This is not a PDF file"
        path = self._create_temp_pdf(content)
        try:
            result = self.handler.ingest(path)
            assert result.is_pdf is False
            assert len(result.errors) > 0
        finally:
            os.unlink(path)

    def test_empty_file_rejection(self):
        """Boş dosyayı reddetmeli."""
        path = self._create_temp_pdf(b"")
        try:
            with pytest.raises(ValueError, match="boş"):
                self.handler.ingest(path)
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        """Olmayan dosya için hata vermeli."""
        with pytest.raises(FileNotFoundError):
            self.handler.ingest("/nonexistent/file.pdf")

    def test_hash_consistency(self):
        """Aynı dosya her seferinde aynı hash üretmeli."""
        content = b"%PDF-1.4\ntest content\n%%EOF"
        path = self._create_temp_pdf(content)
        try:
            r1 = self.handler.ingest(path)
            r2 = self.handler.ingest(path)
            assert r1.md5 == r2.md5
            assert r1.sha256 == r2.sha256
        finally:
            os.unlink(path)

    def test_pdf_integrity_check(self):
        """PDF bütünlük kontrolünü yapabilmeli."""
        content = b"%PDF-1.7\nobj content\nxref\n0 0\ntrailer\n<<>>\nstartxref\n0\n%%EOF"
        path = self._create_temp_pdf(content)
        try:
            result = self.handler.validate_pdf_integrity(path)
            assert result["has_header"] is True
            assert result["has_eof"] is True
            assert result["eof_count"] == 1
        finally:
            os.unlink(path)

    def test_multiple_eof_detection(self):
        """Birden fazla %%EOF tespit edebilmeli."""
        content = b"%PDF-1.4\ncontent\n%%EOF\nmore content\n%%EOF"
        path = self._create_temp_pdf(content)
        try:
            result = self.handler.validate_pdf_integrity(path)
            assert result["eof_count"] == 2
            assert "warning" in result
        finally:
            os.unlink(path)

    def test_human_size_formatting(self):
        """Boyut formatlaması doğru olmalı."""
        assert "B" in FileHandler._human_size(500)
        assert "KB" in FileHandler._human_size(2048)
        assert "MB" in FileHandler._human_size(5 * 1024 * 1024)
