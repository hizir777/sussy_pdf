"""
ast_analyzer.py — Soyut Sözdizimi Ağacı (AST) Analizi

JavaScript kodunu karakter dizisi yerine mantıksal
yapısıyla analiz ederek polimorfik değişimleri tespit eder.
"""

import re
import ast as python_ast
from dataclasses import dataclass, field


@dataclass
class ASTNode:
    node_type: str
    value: str = ""
    children: list = field(default_factory=list)
    line: int = 0
    suspicious: bool = False
    reason: str = ""


@dataclass
class ASTAnalysisResult:
    total_nodes: int = 0
    function_calls: list[str] = field(default_factory=list)
    variable_assignments: list[dict] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    control_flow: list[str] = field(default_factory=list)
    suspicious_patterns: list[str] = field(default_factory=list)
    obfuscation_score: int = 0  # 0-100
    complexity_score: int = 0


class ASTAnalyzer:
    """
    Basitleştirilmiş JavaScript AST analizi.

    Tam bir JS parser yerine, regex tabanlı pattern matching
    ile kodun mantıksal yapısını analiz eder.
    """

    # Obfuscation göstergeleri ve ağırlıkları
    OBFUSCATION_INDICATORS = {
        "single_char_vars": (r"\b[a-z]\s*=", 10, "Tek karakterli değişken isimleri"),
        "hex_var_names": (r"\b_0x[0-9a-f]+\b", 20, "Hex tabanlı değişken isimleri"),
        "nested_eval": (r"eval\s*\(\s*eval", 30, "İç içe eval çağrıları"),
        "long_strings": (r'["\'][^"\']{500,}["\']', 15, "Çok uzun string literalleri"),
        "array_notation": (r"\[\s*['\"]\\x", 15, "Array tabanlı hex obfuscation"),
        "charcode_chain": (r"fromCharCode.*fromCharCode", 20, "Zincirleme fromCharCode"),
        "split_reverse": (r"\.split\(.*\.reverse\(.*\.join\(", 15, "Split-reverse-join kalıbı"),
        "replace_chain": (r"\.replace\(.*\.replace\(.*\.replace\(", 10, "Zincirleme replace"),
        "base64_decode": (r"(?i)atob\s*\(", 10, "Base64 decode kullanımı"),
        "constructor_call": (r"\[.constructor.\]", 25, "Constructor tabanlı obfuscation"),
    }

    def analyze(self, code: str) -> ASTAnalysisResult:
        """JavaScript kodunun AST analizini yap."""
        result = ASTAnalysisResult()

        # Fonksiyon çağrılarını çıkar
        result.function_calls = self._extract_function_calls(code)
        result.total_nodes += len(result.function_calls)

        # Değişken atamalarını çıkar
        result.variable_assignments = self._extract_assignments(code)
        result.total_nodes += len(result.variable_assignments)

        # String literallerini çıkar
        result.string_literals = self._extract_strings(code)
        result.total_nodes += len(result.string_literals)

        # Kontrol akışını analiz et
        result.control_flow = self._analyze_control_flow(code)

        # Obfuscation skoru
        result.obfuscation_score = self._calculate_obfuscation_score(code)

        # Karmaşıklık skoru
        result.complexity_score = self._calculate_complexity(code)

        # Şüpheli kalıplar
        result.suspicious_patterns = self._find_suspicious_patterns(code)

        return result

    def _extract_function_calls(self, code: str) -> list[str]:
        """Fonksiyon çağrılarını çıkar."""
        calls = re.findall(r"(\w+(?:\.\w+)*)\s*\(", code)
        return list(set(calls))

    def _extract_assignments(self, code: str) -> list[dict]:
        """Değişken atamalarını çıkar."""
        assignments = []
        pattern = r"(?:var|let|const)?\s*(\w+)\s*=\s*([^;]+)"
        for m in re.finditer(pattern, code):
            assignments.append({
                "variable": m.group(1),
                "value_preview": m.group(2)[:100].strip(),
            })
        return assignments

    def _extract_strings(self, code: str) -> list[str]:
        """String literallerini çıkar."""
        strings = []
        for m in re.finditer(r'"([^"]*)"', code):
            if len(m.group(1)) > 3:
                strings.append(m.group(1))
        for m in re.finditer(r"'([^']*)'", code):
            if len(m.group(1)) > 3:
                strings.append(m.group(1))
        return strings

    def _analyze_control_flow(self, code: str) -> list[str]:
        """Kontrol akışı yapılarını tespit et."""
        flows = []
        structures = {
            r"\bif\s*\(": "if",
            r"\belse\s*{": "else",
            r"\bfor\s*\(": "for",
            r"\bwhile\s*\(": "while",
            r"\btry\s*{": "try-catch",
            r"\bswitch\s*\(": "switch",
            r"\bfunction\s+\w+": "function",
        }
        for pattern, name in structures.items():
            count = len(re.findall(pattern, code))
            if count > 0:
                flows.append(f"{name} x{count}")
        return flows

    def _calculate_obfuscation_score(self, code: str) -> int:
        """Obfuscation seviyesini 0-100 arası puanla."""
        score = 0
        for name, (pattern, weight, desc) in self.OBFUSCATION_INDICATORS.items():
            if re.search(pattern, code, re.DOTALL):
                score += weight
        return min(score, 100)

    def _calculate_complexity(self, code: str) -> int:
        """Kod karmaşıklığını hesapla."""
        lines = code.count("\n") + 1
        unique_chars = len(set(code))
        nesting = max(code.count("{") - code.count("}"), 0)
        entropy = unique_chars / max(len(code), 1)

        # Yüksek entropi + az satır = yüksek obfuscation
        if len(code) > 100 and lines < 5:
            return min(int(entropy * 1000), 100)
        return min(lines + nesting * 5, 100)

    def _find_suspicious_patterns(self, code: str) -> list[str]:
        """Şüpheli code kalıplarını tespit et."""
        patterns = []
        checks = [
            (r"(?i)eval\s*\(", "eval() kullanımı — dinamik kod çalıştırma"),
            (r"(?i)document\.write", "document.write — DOM manipülasyonu"),
            (r"(?i)window\.location", "window.location — yönlendirme denemesi"),
            (r"(?i)new\s+Function", "new Function() — dinamik fonksiyon oluşturma"),
            (r"(?i)\.createElement\s*\(\s*['\"]script", "Script elementi oluşturma"),
            (r"(?i)XMLHttpRequest|fetch\s*\(", "Ağ isteği (C2 bağlantısı?)"),
            (r"(?i)\.exec\s*\(|\.spawn\s*\(", "Süreç başlatma denemesi"),
        ]
        for pattern, desc in checks:
            if re.search(pattern, code):
                patterns.append(desc)
        return patterns
