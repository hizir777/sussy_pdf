"""
main.py — Sussy PDF CLI Giriş Noktası

Tüm analiz pipeline'ını orkestre eden ana modül.

Kullanım:
    python -m src.main analyze <dosya.pdf>
    python -m src.main analyze <dosya.pdf> --output report.json
    python -m src.main serve  # Dashboard API sunucusu
"""

import json
import os
import sys
from pathlib import Path

# Windows konsol encoding fix
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        os.environ["PYTHONIOENCODING"] = "utf-8"

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.ingestion.file_handler import FileHandler
from src.ingestion.metadata_extractor import MetadataExtractor
from src.static_analysis.pdf_parser import PDFParser
from src.static_analysis.object_tree import ObjectTreeBuilder
from src.static_analysis.tag_scanner import TagScanner
from src.static_analysis.incremental_update import IncrementalUpdateChecker
from src.deobfuscation.stream_decoder import StreamDecoder
from src.deobfuscation.string_decoder import StringDecoder
from src.deobfuscation.js_deobfuscator import JSDeobfuscator
from src.deobfuscation.ast_analyzer import ASTAnalyzer
from src.dynamic_analysis.js_emulator import JSEmulator
from src.dynamic_analysis.sandbox_monitor import SandboxMonitor
from src.scoring.yara_engine import YaraEngine
from src.scoring.heuristic_scorer import HeuristicScorer
from src.scoring.feature_extractor import FeatureExtractor
from src.scoring.mitre_mapper import MITREMapper
from src.reporting.ioc_generator import IOCGenerator
from src.reporting.report_builder import ReportBuilder

console = Console()


@click.group()
def cli():
    """🔬 Sussy PDF — Şüpheli PDF Analiz Platformu"""
    pass


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--output", "-o", help="Rapor çıktı dosyası (json/html/md)")
@click.option("--format", "-f", "fmt", default="all", type=click.Choice(["json", "html", "md", "all"]))
@click.option("--verbose", "-v", is_flag=True, help="Detaylı çıktı")
def analyze(file_path: str, output: str | None, fmt: str, verbose: bool):
    """PDF dosyasının tam güvenlik analizini çalıştır."""
    console.print(Panel.fit(
        "[bold cyan]🔬 Sussy PDF Analyzer v1.0.0[/]\n"
        "[dim]Şüpheli PDF Analiz Platformu[/]",
        border_style="cyan",
    ))

    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # --- Sprint 1: Dosya Alımı ---
        task = progress.add_task("📥 Dosya alınıyor...", total=None)
        handler = FileHandler()
        file_info = handler.ingest(file_path)
        results["file_info"] = file_info
        progress.update(task, completed=True, description="✅ Dosya alındı")

        if not file_info.is_pdf:
            console.print("[red]❌ Bu dosya geçerli bir PDF değil![/]")
            sys.exit(1)

        with open(file_path, "rb") as f:
            content = f.read()

        # --- Sprint 2: Statik Analiz ---
        task = progress.add_task("🔍 Statik analiz...", total=None)
        pdf_parser = PDFParser()
        structure = pdf_parser.parse(content)
        results["structure"] = structure

        metadata_extractor = MetadataExtractor()
        metadata = metadata_extractor.extract(content)
        results["metadata"] = metadata

        tree_builder = ObjectTreeBuilder()
        obj_tree = tree_builder.build(content)
        results["object_tree"] = obj_tree

        tag_scanner = TagScanner()
        tag_result = tag_scanner.scan(content)
        results["tags"] = tag_result

        inc_checker = IncrementalUpdateChecker()
        inc_result = inc_checker.check(content)
        results["incremental"] = inc_result
        progress.update(task, completed=True, description="✅ Statik analiz tamamlandı")

        # --- Sprint 3: De-obfuscation ---
        task = progress.add_task("🔓 Gizleme çözme...", total=None)
        stream_decoder = StreamDecoder()
        decoded_streams = stream_decoder.decode_all_streams(content)
        results["decoded_streams"] = decoded_streams

        js_deobfuscator = JSDeobfuscator()
        string_decoder = StringDecoder()
        ast_analyzer = ASTAnalyzer()

        js_results = []
        for ds in decoded_streams:
            if ds.is_javascript:
                js_code = ds.decoded_data.decode("latin-1", errors="ignore")
                deob = js_deobfuscator.deobfuscate(js_code)
                decoded_strings = string_decoder.decode_all(js_code)
                ast_result = ast_analyzer.analyze(deob.deobfuscated_code)
                js_results.append({
                    "deobfuscation": deob,
                    "decoded_strings": decoded_strings,
                    "ast": ast_result,
                })

        results["js_deobfuscation"] = js_results
        progress.update(task, completed=True, description="✅ Gizleme çözme tamamlandı")

        # --- Sprint 4: Dinamik Analiz ---
        task = progress.add_task("⚡ Dinamik analiz...", total=None)
        emulator = JSEmulator()
        sandbox = SandboxMonitor()

        emulation_result = None
        sandbox_result = None
        for js_res in js_results:
            deob = js_res["deobfuscation"]
            emulation_result = emulator.emulate(deob.deobfuscated_code)
            sandbox_result = sandbox.analyze_code_for_evasion(deob.deobfuscated_code)

        results["emulation"] = emulation_result
        results["sandbox"] = sandbox_result
        progress.update(task, completed=True, description="✅ Dinamik analiz tamamlandı")

        # --- Sprint 5: Puanlama ---
        task = progress.add_task("📊 Risk hesaplanıyor...", total=None)
        yara_engine = YaraEngine()
        yara_result = yara_engine.scan(content)
        results["yara"] = yara_result

        scorer = HeuristicScorer()
        score = scorer.score(
            tag_scan_result=tag_result,
            incremental_result=inc_result,
            yara_result=yara_result,
            emulation_result=emulation_result,
            metadata=metadata,
        )
        results["score"] = score

        feature_ext = FeatureExtractor()
        features = feature_ext.extract(content, metadata, tag_result, structure, obj_tree)
        results["features"] = features

        mitre_mapper = MITREMapper()
        mitre = mitre_mapper.map_findings(
            tag_result=tag_result,
            emulation_result=emulation_result,
            sandbox_result=sandbox_result,
            yara_result=yara_result,
        )
        results["mitre"] = mitre

        ioc_gen = IOCGenerator()
        ioc_report = ioc_gen.generate(
            file_info=file_info,
            emulation_result=emulation_result,
            tag_result=tag_result,
            mitre_mappings=mitre,
        )
        results["ioc"] = ioc_report
        results["ioc_json"] = ioc_gen.to_json(ioc_report)
        progress.update(task, completed=True, description="✅ Puanlama tamamlandı")

    # === Konsol Çıktısı ===
    _print_results(file_info, score, tag_result, mitre, ioc_report, verbose)

    # === Rapor Kaydetme ===
    report_builder = ReportBuilder()
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    base_name = Path(file_path).stem

    if fmt in ("json", "all"):
        json_path = output_dir / f"{base_name}_report.json"
        json_path.write_text(report_builder.build_json(results), encoding="utf-8")
        console.print(f"📄 JSON raporu: [cyan]{json_path}[/]")

    if fmt in ("html", "all"):
        html_path = output_dir / f"{base_name}_report.html"
        html_path.write_text(report_builder.build_html(results), encoding="utf-8")
        console.print(f"🌐 HTML raporu: [cyan]{html_path}[/]")

    if fmt in ("md", "all"):
        md_path = output_dir / f"{base_name}_report.md"
        md_path.write_text(report_builder.build_markdown(results), encoding="utf-8")
        console.print(f"📝 Markdown raporu: [cyan]{md_path}[/]")

    if output:
        out_path = Path(output)
        if output.endswith(".json"):
            out_path.write_text(report_builder.build_json(results), encoding="utf-8")
        elif output.endswith(".html"):
            out_path.write_text(report_builder.build_html(results), encoding="utf-8")
        else:
            out_path.write_text(report_builder.build_markdown(results), encoding="utf-8")


@cli.command()
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8443, type=int)
def serve(host: str, port: int):
    """Dashboard API sunucusunu başlat."""
    console.print(f"🚀 Dashboard başlatılıyor: http://{host}:{port}")
    import uvicorn
    from dashboard.api_server import app
    uvicorn.run(app, host=host, port=port)


def _print_results(file_info, score, tags, mitre, ioc, verbose):
    """Konsola sonuçları yazdır."""
    # Dosya bilgileri
    info_table = Table(title="📋 Dosya Bilgileri", show_header=False, border_style="dim")
    info_table.add_column("Alan", style="dim")
    info_table.add_column("Değer")
    info_table.add_row("Dosya", file_info.file_name)
    info_table.add_row("Boyut", file_info.file_size_human)
    info_table.add_row("SHA256", file_info.sha256)
    info_table.add_row("PDF", file_info.pdf_version or "N/A")
    console.print(info_table)

    # Risk skoru
    color_map = {"critical": "red", "high": "yellow", "medium": "bright_yellow", "low": "green"}
    color = color_map.get(score.risk_level, "white")
    console.print(Panel(
        f"[bold {color}]{score.total_score}/100[/]\n{score.verdict}",
        title="📊 Risk Skoru",
        border_style=color,
    ))

    # Etiketler
    if tags.matches:
        tag_table = Table(title="🔍 Tehdit Etiketleri", border_style="dim")
        tag_table.add_column("Etiket")
        tag_table.add_column("Seviye")
        tag_table.add_column("Sayı")
        for m in tags.matches:
            level_colors = {"critical": "red", "high": "yellow", "medium": "bright_yellow", "low": "green"}
            c = level_colors.get(m.threat_level.value, "white")
            tag_table.add_row(f"[{c}]{m.tag}[/]", f"[{c}]{m.threat_level.value}[/]", str(m.count))
        console.print(tag_table)

    # MITRE
    if mitre:
        console.print("\n[bold magenta]🎯 MITRE ATT&CK:[/]")
        for m in mitre:
            console.print(f"  [magenta]{m.technique_id}[/] — {m.technique_name}")

    # IOC
    if ioc.total_iocs > 0:
        console.print(f"\n[bold]🔗 IOC: {ioc.total_iocs} gösterge tespit edildi[/]")


if __name__ == "__main__":
    cli()
