"""
Sentetik test PDF'leri oluşturucu.

Bu script unit testlerde kullanılmak üzere
zararsız ve şüpheli PDF örnekleri üretir.
"""

from pathlib import Path

FIXTURES_DIR = Path(__file__).parent


def create_benign_pdf() -> bytes:
    """Zararsız bir test PDF'i oluştur."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer\n"
        b"<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n"
        b"206\n"
        b"%%EOF\n"
    )


def create_suspicious_pdf() -> bytes:
    """Şüpheli etiketler içeren test PDF'i oluştur (zararsız payload)."""
    return (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /S /JavaScript /JS 5 0 R >>\n"
        b"endobj\n"
        b"5 0 obj\n"
        b"<< /Length 89 >>\n"
        b"stream\n"
        b"// THIS IS A TEST - NOT MALICIOUS\n"
        b"var msg = String.fromCharCode(72,101,108,108,111);\n"
        b"endstream\n"
        b"endobj\n"
        b"6 0 obj\n"
        b"<< /S /URI /URI (http://example.com/test) >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 7\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000080 00000 n \n"
        b"0000000137 00000 n \n"
        b"0000000224 00000 n \n"
        b"0000000275 00000 n \n"
        b"0000000414 00000 n \n"
        b"trailer\n"
        b"<< /Size 7 /Root 1 0 R >>\n"
        b"startxref\n"
        b"476\n"
        b"%%EOF\n"
    )


def create_malicious_sample_pdf() -> bytes:
    """Zararlı etiket kombinasyonu simülasyonu (gerçek zararlı KOD İÇERMEZ)."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R\n"
        b"   /AA << /O 5 0 R >> /Names << /EmbeddedFiles 6 0 R >> >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /S /JavaScript /JS (app.alert\\('TEST - NOT REAL MALWARE'\\);) >>\n"
        b"endobj\n"
        b"5 0 obj\n"
        b"<< /S /Launch /Win << /F (cmd.exe) /P (/c echo TEST_ONLY) >> >>\n"
        b"endobj\n"
        b"6 0 obj\n"
        b"<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 7\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000150 00000 n \n"
        b"0000000207 00000 n \n"
        b"0000000294 00000 n \n"
        b"0000000390 00000 n \n"
        b"0000000480 00000 n \n"
        b"trailer\n"
        b"<< /Size 7 /Root 1 0 R >>\n"
        b"startxref\n"
        b"570\n"
        b"%%EOF\n"
    )


def generate_fixtures():
    """Tüm test fixture'larını diske yaz."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "benign_sample.pdf": create_benign_pdf(),
        "suspicious_sample.pdf": create_suspicious_pdf(),
        "malicious_simulation.pdf": create_malicious_sample_pdf(),
    }

    for name, content in fixtures.items():
        path = FIXTURES_DIR / name
        path.write_bytes(content)
        print(f"[OK] Created: {path} ({len(content)} bytes)")


if __name__ == "__main__":
    generate_fixtures()
