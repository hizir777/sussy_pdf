"""
Pytest Configuration & Fixtures (v1.1.0+)

Provides common fixtures for all tests.
"""

import os
import sys
import pytest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


@pytest.fixture
def sample_pdf_content():
    """Load sample normal PDF."""
    fixture_path = Path(__file__).parent / "tests" / "fixtures"
    sample_file = fixture_path / "sample.normal.pdf"
    
    if sample_file.exists():
        return sample_file.read_bytes()
    else:
        # Fallback: minimal PDF structure
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
            b"0000000000 65535 f\n"
            b"0000000009 00000 n\n"
            b"0000000058 00000 n\n"
            b"0000000115 00000 n\n"
            b"trailer\n"
            b"<< /Size 4 /Root 1 0 R >>\n"
            b"startxref\n"
            b"209\n"
            b"%%EOF\n"
        )


@pytest.fixture
def malicious_pdf_content():
    """Load sample malicious PDF."""
    fixture_path = Path(__file__).parent / "tests" / "fixtures"
    sample_file = fixture_path / "sample.malicious.pdf"
    
    if sample_file.exists():
        return sample_file.read_bytes()
    else:
        # Fallback: PDF with /JavaScript
        return (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n"
            b"endobj\n"
            b"4 0 obj\n"
            b"<< /S /JavaScript /JS (alert('malicious')) >>\n"
            b"endobj\n"
            b"2 0 obj\n"
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
            b"endobj\n"
            b"3 0 obj\n"
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
            b"endobj\n"
            b"xref\n"
            b"0 5\n"
            b"0000000000 65535 f\n"
            b"0000000009 00000 n\n"
            b"0000000052 00000 n\n"
            b"0000000135 00000 n\n"
            b"0000000192 00000 n\n"
            b"trailer\n"
            b"<< /Size 5 /Root 1 0 R >>\n"
            b"startxref\n"
            b"249\n"
            b"%%EOF\n"
        )


@pytest.fixture
def invalid_pdf_content():
    """Load invalid PDF."""
    return b"NOT A PDF FILE - just some random binary data"


@pytest.fixture
def temp_pdf_file(tmp_path, sample_pdf_content):
    """Create temporary PDF file."""
    pdf_file = tmp_path / "test_sample.pdf"
    pdf_file.write_bytes(sample_pdf_content)
    return pdf_file


@pytest.fixture(scope="session")
def test_config():
    """Test configuration."""
    return {
        'max_file_size': 500 * 1024 * 1024,  # 500MB
        'timeout': 300,  # 5 minutes
        'sample_count': 10,
    }


# Markers
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow"
    )
