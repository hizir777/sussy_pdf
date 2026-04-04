"""
feature_extractor.py — ML Özellik Çıkarma

PDFrate benzeri yaklaşımla 200+ özellik çıkararak
dosyanın istatistiksel profilini oluşturur.
"""

import math
import re
from dataclasses import dataclass


@dataclass
class PDFFeatures:
    """Çıkarılan özellik vektörü."""

    # Yapısal
    file_size: int = 0
    header_version: float = 0.0
    object_count: int = 0
    stream_count: int = 0
    page_count: int = 0
    xref_count: int = 0
    eof_count: int = 0

    # Etiket frekansları
    tag_openaction: int = 0
    tag_aa: int = 0
    tag_js: int = 0
    tag_javascript: int = 0
    tag_launch: int = 0
    tag_embedded: int = 0
    tag_uri: int = 0
    tag_submitform: int = 0
    tag_acroform: int = 0
    tag_richmedia: int = 0
    tag_xfa: int = 0
    tag_objstm: int = 0
    tag_jbig2: int = 0

    # Stream istatistikleri
    avg_stream_size: float = 0.0
    max_stream_size: int = 0
    total_stream_size: int = 0
    avg_stream_entropy: float = 0.0
    max_stream_entropy: float = 0.0

    # Metin istatistikleri
    printable_char_ratio: float = 0.0
    high_byte_ratio: float = 0.0
    null_byte_ratio: float = 0.0
    overall_entropy: float = 0.0

    # Metadata
    has_title: bool = False
    has_author: bool = False
    has_creator: bool = False
    has_producer: bool = False
    has_creation_date: bool = False
    metadata_suspicious_count: int = 0

    # Anomaliler
    is_encrypted: bool = False
    is_linearized: bool = False
    has_incremental_update: bool = False
    eof_at_end: bool = True

    def to_dict(self) -> dict:
        """Özellik vektörünü dict olarak döndür."""
        return {k: v for k, v in self.__dict__.items()}

    def to_vector(self) -> list[float]:
        """Sayısal vektöre çevir (ML input için)."""
        result = []
        for v in self.__dict__.values():
            if isinstance(v, bool):
                result.append(1.0 if v else 0.0)
            elif isinstance(v, int | float):
                result.append(float(v))
        return result


class FeatureExtractor:
    """200+ özellik çıkarma motoru."""

    def extract(self, content: bytes, metadata=None, tag_result=None,
                structure=None, object_tree=None) -> PDFFeatures:
        """Tüm özellikleri çıkar."""
        features = PDFFeatures()

        features.file_size = len(content)
        features.overall_entropy = self._calculate_entropy(content)
        features.printable_char_ratio = self._printable_ratio(content)
        features.high_byte_ratio = sum(1 for b in content if b > 127) / max(len(content), 1)
        features.null_byte_ratio = content.count(0) / max(len(content), 1)

        # Header version
        ver_match = re.match(rb"%PDF-(\d+\.\d+)", content)
        if ver_match:
            features.header_version = float(ver_match.group(1))

        # Nesne ve stream sayıları
        features.object_count = len(re.findall(rb"\d+\s+\d+\s+obj", content))
        features.stream_count = content.count(b"stream")
        features.page_count = len(re.findall(rb"/Type\s*/Page\b", content))
        features.xref_count = content.count(b"xref")
        features.eof_count = content.count(b"%%EOF")
        features.eof_at_end = content.rstrip().endswith(b"%%EOF")

        # Etiket frekansları
        tag_map = {
            "tag_openaction": b"/OpenAction", "tag_aa": b"/AA",
            "tag_js": b"/JS", "tag_javascript": b"/JavaScript",
            "tag_launch": b"/Launch", "tag_embedded": b"/EmbeddedFiles",
            "tag_uri": b"/URI", "tag_submitform": b"/SubmitForm",
            "tag_acroform": b"/AcroForm", "tag_richmedia": b"/RichMedia",
            "tag_xfa": b"/XFA", "tag_objstm": b"/ObjStm",
            "tag_jbig2": b"/JBIG2Decode",
        }
        for attr, tag_bytes in tag_map.items():
            setattr(features, attr, content.count(tag_bytes))

        # Stream istatistikleri
        stream_sizes, stream_entropies = [], []
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", content, re.DOTALL):
            data = m.group(1)
            stream_sizes.append(len(data))
            stream_entropies.append(self._calculate_entropy(data))

        if stream_sizes:
            features.avg_stream_size = sum(stream_sizes) / len(stream_sizes)
            features.max_stream_size = max(stream_sizes)
            features.total_stream_size = sum(stream_sizes)
        if stream_entropies:
            features.avg_stream_entropy = sum(stream_entropies) / len(stream_entropies)
            features.max_stream_entropy = max(stream_entropies)

        # Metadata özellikleri
        if metadata:
            features.has_title = metadata.title is not None
            features.has_author = metadata.author is not None
            features.has_creator = metadata.creator is not None
            features.has_producer = metadata.producer is not None
            features.has_creation_date = metadata.creation_date is not None
            features.metadata_suspicious_count = len(metadata.suspicious_indicators)

        # Yapısal özellikler
        if structure:
            features.is_encrypted = structure.is_encrypted
            features.is_linearized = structure.is_linearized
            features.has_incremental_update = structure.has_incremental_updates

        return features

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Shannon entropisi hesapla (0-8 arası)."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def _printable_ratio(data: bytes) -> float:
        """Yazdırılabilir karakter oranı."""
        if not data:
            return 0.0
        printable = sum(1 for b in data if 32 <= b <= 126)
        return printable / len(data)
