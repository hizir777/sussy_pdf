"""
file_handler.py — Dosya Alımı ve Hash Hesaplama

PDF dosyalarını sisteme alır, doğrular ve kriptografik hash değerlerini hesaplar.
Tedarik zinciri güvenliği için dosya bütünlüğünü garanti altına alır.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class FileInfo:
    """Analiz edilen dosyanın temel bilgileri."""

    file_path: str
    file_name: str
    file_size: int  # bytes
    file_size_human: str
    md5: str
    sha1: str
    sha256: str
    magic_bytes: bytes
    is_pdf: bool
    pdf_version: str | None
    ingestion_time: str
    errors: list[str] = field(default_factory=list)


class FileHandler:
    """
    Dosya alım ve doğrulama motoru.

    Zero Trust prensibi: Hiçbir dosyaya güvenme, her şeyi doğrula.
    """

    # PDF magic bytes: %PDF-
    PDF_MAGIC = b"%PDF-"
    PDF_MAGIC_HEX = "25504446"

    # Maksimum dosya boyutu (varsayılan 50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024

    def __init__(self, max_file_size: int | None = None):
        if max_file_size is not None:
            self.MAX_FILE_SIZE = max_file_size

    def ingest(self, file_path: str) -> FileInfo:
        """
        Dosyayı sisteme al ve analiz için hazırla.

        Args:
            file_path: Analiz edilecek dosyanın yolu.

        Returns:
            FileInfo: Dosya bilgileri ve hash değerleri.

        Raises:
            FileNotFoundError: Dosya bulunamazsa.
            ValueError: Dosya geçerli bir PDF değilse veya boyut sınırını aşarsa.
        """
        path = Path(file_path).resolve()
        errors = []

        # --- Dosya varlık kontrolü ---
        if not path.exists():
            raise FileNotFoundError(f"Dosya bulunamadı: {path}")
        if not path.is_file():
            raise ValueError(f"Belirtilen yol bir dosya değil: {path}")

        # --- Boyut kontrolü ---
        file_size = path.stat().st_size
        if file_size == 0:
            raise ValueError("Dosya boş (0 byte).")
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"Dosya boyutu sınırı aşıldı: {self._human_size(file_size)} > "
                f"{self._human_size(self.MAX_FILE_SIZE)}"
            )

        # --- Dosya okuma ve hash hesaplama ---
        with open(path, "rb") as f:
            content = f.read()

        magic_bytes = content[:8]
        md5, sha1, sha256 = self._compute_hashes(content)

        # --- PDF doğrulama ---
        is_pdf = content[:5] == self.PDF_MAGIC
        pdf_version = None

        if is_pdf:
            pdf_version = self._extract_pdf_version(content)
        else:
            errors.append(
                f"PDF magic bytes bulunamadı. Beklenen: {self.PDF_MAGIC_HEX}, "
                f"Bulunan: {magic_bytes[:5].hex()}"
            )

        return FileInfo(
            file_path=str(path),
            file_name=path.name,
            file_size=file_size,
            file_size_human=self._human_size(file_size),
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            magic_bytes=magic_bytes,
            is_pdf=is_pdf,
            pdf_version=pdf_version,
            ingestion_time=datetime.now(timezone.utc).isoformat(),
            errors=errors,
        )

    def _compute_hashes(self, content: bytes) -> tuple[str, str, str]:
        """MD5, SHA1 ve SHA256 hash'lerini paralel hesapla."""
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        return md5, sha1, sha256

    def _extract_pdf_version(self, content: bytes) -> str | None:
        """PDF versiyon bilgisini header'dan çıkar (örn: '1.7')."""
        try:
            header_line = content[:20].split(b"\n")[0].split(b"\r")[0]
            if header_line.startswith(b"%PDF-"):
                return header_line.decode("ascii", errors="ignore").replace("%PDF-", "").strip()
        except Exception:
            pass
        return None

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Byte değerini okunabilir formata dönüştür."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def validate_pdf_integrity(self, file_path: str) -> dict:
        """
        PDF dosyasının yapısal bütünlüğünü kontrol et.

        Returns:
            dict: Bütünlük kontrol sonuçları.
        """
        with open(file_path, "rb") as f:
            content = f.read()

        results = {
            "has_header": content[:5] == self.PDF_MAGIC,
            "has_eof": b"%%EOF" in content,
            "has_xref": b"xref" in content or b"/XRef" in content,
            "has_trailer": b"trailer" in content,
            "has_startxref": b"startxref" in content,
            "eof_count": content.count(b"%%EOF"),
            "eof_at_end": content.rstrip().endswith(b"%%EOF"),
            "file_size": len(content),
        }

        # Çoklu %%EOF → olası artımlı güncelleme veya shadow attack
        if results["eof_count"] > 1:
            results["warning"] = (
                f"Birden fazla %%EOF etiketi tespit edildi ({results['eof_count']}). "
                "Artımlı güncelleme veya Shadow Attack olabilir!"
            )

        return results
