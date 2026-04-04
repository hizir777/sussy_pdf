"""
Test suite: Tag Scanner modülü
"""

from src.static_analysis.tag_scanner import TagScanner


class TestTagScanner:
    """TagScanner test sınıfı."""

    def setup_method(self):
        self.scanner = TagScanner()

    def test_clean_pdf(self):
        """Temiz PDF'de etiket bulmamalı."""
        content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        assert result.critical_count == 0
        assert "TEMİZ" in result.verdict

    def test_openaction_detection(self):
        """/OpenAction etiketini tespit edebilmeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        tags = [m.tag for m in result.matches]
        assert "/OpenAction" in tags
        assert result.critical_count > 0

    def test_javascript_detection(self):
        """/JS ve /JavaScript etiketlerini tespit edebilmeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /S /JavaScript /JS (app.alert('test')) >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        tags = [m.tag for m in result.matches]
        assert "/JS" in tags or "/JavaScript" in tags
        assert result.critical_count > 0

    def test_launch_detection(self):
        """/Launch etiketini tespit edebilmeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /S /Launch /Win << /F (cmd.exe) >> >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        tags = [m.tag for m in result.matches]
        assert "/Launch" in tags
        assert result.combined_risk_score > 0

    def test_embedded_files_detection(self):
        """/EmbeddedFiles etiketini tespit edebilmeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /Names << /EmbeddedFiles 2 0 R >> >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        tags = [m.tag for m in result.matches]
        assert "/EmbeddedFiles" in tags

    def test_dangerous_combination(self):
        """/OpenAction + /JS kombinasyonu ekstra skor eklemeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (evil()) >> >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        # Kombinasyon bonus yüzünden skor yüksek olmalı
        assert result.combined_risk_score >= 50

    def test_launch_powershell_combination(self):
        """/Launch + powershell kritik skor vermeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /S /Launch /Win << /F (powershell.exe) >> >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        assert result.combined_risk_score >= 80

    def test_object_number_tracking(self):
        """Etiketlerin hangi nesnede olduğunu takip edebilmeli."""
        content = b"%PDF-1.4\n5 0 obj\n<< /S /JavaScript /JS (code) >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        for m in result.matches:
            if m.tag in ("/JS", "/JavaScript"):
                assert 5 in m.object_numbers or len(m.object_numbers) > 0

    def test_verdict_levels(self):
        """Skor seviyelerine göre doğru verdict vermeli."""
        # Temiz
        clean = self.scanner.scan(b"%PDF-1.4\n%%EOF")
        assert "TEMİZ" in clean.verdict

    def test_context_extraction(self):
        """Etiket bağlamını çıkarabilmeli."""
        content = b"%PDF-1.4\n1 0 obj\n<< /URI (http://evil.com) >>\nendobj\n%%EOF"
        result = self.scanner.scan(content)
        for m in result.matches:
            if m.tag == "/URI":
                assert len(m.contexts) > 0
