"""
object_tree.py — PDF Nesne Ağacı (Object Tree) Çıkarma

PDF belgesindeki tüm nesneleri (objects) ayrıştırır ve
aralarındaki referans ilişkilerini (R) haritalandırır.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class ObjectType(Enum):
    """PDF nesne tipleri."""

    DICTIONARY = "dictionary"
    ARRAY = "array"
    STREAM = "stream"
    STRING = "string"
    NAME = "name"
    NUMBER = "number"
    BOOLEAN = "boolean"
    NULL = "null"
    REFERENCE = "reference"
    UNKNOWN = "unknown"


@dataclass
class PDFObject:
    """Tek bir PDF nesnesi."""

    obj_number: int
    generation: int
    obj_type: ObjectType
    raw_content: bytes
    offset: int  # Dosyadaki byte offseti
    size: int  # Byte cinsinden boyut
    has_stream: bool = False
    stream_data: bytes | None = None
    stream_length: int = 0
    stream_filters: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)  # Bu nesneden referans edilen diğer nesneler
    dictionary: dict[str, str] = field(default_factory=dict)  # Anahtar/değer çiftleri
    suspicious_tags: list[str] = field(default_factory=list)


@dataclass
class ObjectTree:
    """PDF Nesne Ağacı."""

    objects: dict[int, PDFObject] = field(default_factory=dict)
    root_object: int | None = None
    total_objects: int = 0
    total_streams: int = 0
    reference_map: dict[int, list[int]] = field(default_factory=dict)  # obj_num -> [referans edilen obj'ler]
    errors: list[str] = field(default_factory=list)


class ObjectTreeBuilder:
    """PDF Nesne Ağacı oluşturucu."""

    # Şüpheli etiketler
    THREAT_TAGS = {
        b"/OpenAction", b"/AA", b"/JS", b"/JavaScript", b"/Launch",
        b"/EmbeddedFiles", b"/URI", b"/SubmitForm", b"/AcroForm",
        b"/RichMedia", b"/XFA", b"/ObjStm", b"/JBIG2Decode",
    }

    def build(self, content: bytes) -> ObjectTree:
        """
        PDF içeriğinden nesne ağacını oluştur.

        Args:
            content: PDF dosyasının ham byte içeriği.

        Returns:
            ObjectTree: Oluşturulan nesne ağacı.
        """
        tree = ObjectTree()

        # Tüm nesneleri bul: N M obj ... endobj
        obj_pattern = re.compile(
            rb"(\d+)\s+(\d+)\s+obj\b(.*?)endobj",
            re.DOTALL,
        )

        for match in obj_pattern.finditer(content):
            obj_number = int(match.group(1))
            generation = int(match.group(2))
            obj_content = match.group(3)
            offset = match.start()

            pdf_obj = PDFObject(
                obj_number=obj_number,
                generation=generation,
                obj_type=self._determine_type(obj_content),
                raw_content=obj_content,
                offset=offset,
                size=len(match.group(0)),
            )

            # Stream analizi
            stream_match = re.search(rb"stream\r?\n(.*?)\r?\nendstream", obj_content, re.DOTALL)
            if stream_match:
                pdf_obj.has_stream = True
                pdf_obj.stream_data = stream_match.group(1)
                pdf_obj.stream_length = len(pdf_obj.stream_data)
                pdf_obj.stream_filters = self._extract_filters(obj_content)
                tree.total_streams += 1

            # Dictionary alanlarını çıkar
            pdf_obj.dictionary = self._extract_dictionary(obj_content)

            # Referansları bul
            pdf_obj.references = self._find_references(obj_content)

            # Şüpheli etiketleri tara
            pdf_obj.suspicious_tags = self._find_suspicious_tags(obj_content)

            tree.objects[obj_number] = pdf_obj

        tree.total_objects = len(tree.objects)

        # Root nesnesini bul
        tree.root_object = self._find_root(content)

        # Referans haritasını oluştur
        tree.reference_map = self._build_reference_map(tree.objects)

        return tree

    def _determine_type(self, content: bytes) -> ObjectType:
        """Nesne tipini belirle."""
        stripped = content.strip()

        if re.search(rb"stream\r?\n", stripped):
            return ObjectType.STREAM
        if stripped.startswith(b"<<"):
            return ObjectType.DICTIONARY
        if stripped.startswith(b"["):
            return ObjectType.ARRAY
        if stripped.startswith(b"(") or stripped.startswith(b"<"):
            return ObjectType.STRING
        if stripped.startswith(b"/"):
            return ObjectType.NAME
        if re.match(rb"^[+-]?\d+\.?\d*$", stripped):
            return ObjectType.NUMBER
        if stripped in (b"true", b"false"):
            return ObjectType.BOOLEAN
        if stripped == b"null":
            return ObjectType.NULL

        return ObjectType.UNKNOWN

    def _extract_filters(self, content: bytes) -> list[str]:
        """Stream filtrelerini çıkar."""
        filters = []

        # Tek filtre: /Filter /FlateDecode
        single_match = re.search(rb"/Filter\s*/(\w+)", content)
        if single_match:
            filters.append(f"/{single_match.group(1).decode()}")
            return filters

        # Çoklu filtre: /Filter [/FlateDecode /ASCIIHexDecode]
        multi_match = re.search(rb"/Filter\s*\[(.*?)\]", content, re.DOTALL)
        if multi_match:
            for f in re.findall(rb"/(\w+)", multi_match.group(1)):
                filters.append(f"/{f.decode()}")

        return filters

    def _extract_dictionary(self, content: bytes) -> dict[str, str]:
        """Dictionary anahtar/değer çiftlerini çıkar."""
        result = {}

        # << ... >> bloğunu bul
        dict_match = re.search(rb"<<(.*?)>>", content, re.DOTALL)
        if not dict_match:
            return result

        dict_content = dict_match.group(1)

        # /Key Value çiftlerini çıkar
        pairs = re.findall(rb"/(\w+)\s+([^/\n\r]+?)(?=\s*/|\s*>>|\s*$)", dict_content)
        for key, value in pairs:
            result[f"/{key.decode()}"] = value.decode(errors="ignore").strip()

        return result

    def _find_references(self, content: bytes) -> list[str]:
        """Nesne referanslarını bul (N M R formatı)."""
        refs = re.findall(rb"(\d+)\s+(\d+)\s+R", content)
        return [f"{num.decode()} {gen.decode()} R" for num, gen in refs]

    def _find_suspicious_tags(self, content: bytes) -> list[str]:
        """Şüpheli etiketleri tespit et."""
        found = []
        for tag in self.THREAT_TAGS:
            if tag in content:
                found.append(tag.decode())
        return found

    def _find_root(self, content: bytes) -> int | None:
        """Root nesne numarasını bul."""
        match = re.search(rb"/Root\s+(\d+)\s+\d+\s+R", content)
        if match:
            return int(match.group(1))
        return None

    def _build_reference_map(self, objects: dict[int, PDFObject]) -> dict[int, list[int]]:
        """Nesne referans haritasını oluştur."""
        ref_map = {}
        for obj_num, obj in objects.items():
            referenced = []
            for ref_str in obj.references:
                ref_num = int(ref_str.split()[0])
                referenced.append(ref_num)
            if referenced:
                ref_map[obj_num] = referenced
        return ref_map

    def get_object_summary(self, tree: ObjectTree) -> list[dict]:
        """Nesne ağacının özetini döndür."""
        summary = []
        for obj_num in sorted(tree.objects.keys()):
            obj = tree.objects[obj_num]
            entry = {
                "object_number": obj_num,
                "type": obj.obj_type.value,
                "size": obj.size,
                "has_stream": obj.has_stream,
                "stream_length": obj.stream_length,
                "filters": obj.stream_filters,
                "references": obj.references,
                "suspicious_tags": obj.suspicious_tags,
            }
            summary.append(entry)
        return summary
