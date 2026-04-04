"""
Test suite: Scoring modülü
"""

import pytest
from src.scoring.heuristic_scorer import HeuristicScorer
from src.static_analysis.tag_scanner import TagScanner
from src.static_analysis.incremental_update import IncrementalUpdateChecker


class TestHeuristicScorer:
    """HeuristicScorer test sınıfı."""

    def setup_method(self):
        self.scorer = HeuristicScorer()

    def test_clean_score(self):
        """Temiz dosya düşük skor almalı."""
        score = self.scorer.score()
        assert score.total_score == 0
        assert score.risk_level == "low"
        assert "TEMİZ" in score.verdict

    def test_critical_score_with_tags(self):
        """Kritik etiketler yüksek skor vermeli."""
        scanner = TagScanner()
        content = b"%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (eval(code)) >> >>\nendobj\n%%EOF"
        tags = scanner.scan(content)
        score = self.scorer.score(tag_scan_result=tags)
        assert score.total_score > 25  # En azından şüpheli

    def test_incremental_update_score(self):
        """Artımlı güncelleme skor eklemeli."""
        checker = IncrementalUpdateChecker()
        content = b"%PDF-1.4\ncontent\n%%EOF\nnew content\nstartxref\n100\n%%EOF"
        inc = checker.check(content)
        score = self.scorer.score(incremental_result=inc)
        assert score.total_score > 0

    def test_score_normalization(self):
        """Skor 0-100 arasında olmalı."""
        score = self.scorer.score()
        assert 0 <= score.total_score <= 100

    def test_recommendations_for_critical(self):
        """Kritik skorla öneriler gelmeli."""
        scanner = TagScanner()
        content = (
            b"%PDF-1.4\n1 0 obj\n<< /S /Launch /Win << /F (powershell.exe) >> "
            b"/OpenAction 2 0 R /JS (eval(code)) >>\nendobj\n%%EOF"
        )
        tags = scanner.scan(content)
        score = self.scorer.score(tag_scan_result=tags)
        assert len(score.recommendations) > 0

    def test_breakdown_details(self):
        """Skor dağılımı detaylı olmalı."""
        scanner = TagScanner()
        content = b"%PDF-1.4\n1 0 obj\n<< /JS (code) >>\nendobj\n%%EOF"
        tags = scanner.scan(content)
        score = self.scorer.score(tag_scan_result=tags)
        assert len(score.breakdown) > 0
        for b in score.breakdown:
            assert b.category
            assert b.max_points > 0
