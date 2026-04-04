"""
api_server.py — Dashboard FastAPI Sunucusu

PDF yükleme, analiz ve sonuç görüntüleme API'si.
"""

import os
import sys
import json
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# src modülünü import path'e ekle
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingestion.file_handler import FileHandler
from src.ingestion.metadata_extractor import MetadataExtractor
from src.static_analysis.pdf_parser import PDFParser
from src.static_analysis.object_tree import ObjectTreeBuilder
from src.static_analysis.tag_scanner import TagScanner
from src.static_analysis.incremental_update import IncrementalUpdateChecker
from src.deobfuscation.stream_decoder import StreamDecoder
from src.deobfuscation.js_deobfuscator import JSDeobfuscator
from src.deobfuscation.string_decoder import StringDecoder
from src.dynamic_analysis.js_emulator import JSEmulator
from src.dynamic_analysis.sandbox_monitor import SandboxMonitor
from src.scoring.yara_engine import YaraEngine
from src.scoring.heuristic_scorer import HeuristicScorer
from src.scoring.feature_extractor import FeatureExtractor
from src.scoring.mitre_mapper import MITREMapper
from src.reporting.ioc_generator import IOCGenerator

app = FastAPI(
    title="Sussy PDF API",
    description="Şüpheli PDF Analiz Platformu API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dashboard statik dosyalarını sun
dashboard_dir = Path(__file__).parent
if (dashboard_dir / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(dashboard_dir / "assets")), name="assets")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Dashboard HTML sayfasını sun."""
    index_path = dashboard_dir / "index.html"
    if index_path.exists():
        return index_path.read_text(encoding="utf-8")
    return "<h1>Sussy PDF Dashboard</h1><p>index.html bulunamadı.</p>"


@app.post("/api/analyze")
async def analyze_pdf(file: UploadFile = File(...)):
    """PDF dosyasını analiz et ve sonuçları döndür."""
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "Sadece PDF dosyaları kabul edilir.")

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(413, "Dosya boyutu 50MB sınırını aşıyor.")

    # Geçici dosyaya yaz
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = _run_analysis(tmp_path, content)
        return JSONResponse(content=result)
    finally:
        os.unlink(tmp_path)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


def _run_analysis(file_path: str, content: bytes) -> dict:
    """Tam analiz pipeline'ını çalıştır."""
    # Ingestion
    handler = FileHandler()
    file_info = handler.ingest(file_path)

    # Metadata
    meta_ext = MetadataExtractor()
    metadata = meta_ext.extract(content)

    # Static Analysis
    parser = PDFParser()
    structure = parser.parse(content)

    tree_builder = ObjectTreeBuilder()
    obj_tree = tree_builder.build(content)

    scanner = TagScanner()
    tags = scanner.scan(content)

    inc_checker = IncrementalUpdateChecker()
    inc = inc_checker.check(content)

    # De-obfuscation
    stream_dec = StreamDecoder()
    decoded = stream_dec.decode_all_streams(content)

    js_deob = JSDeobfuscator()
    str_dec = StringDecoder()

    js_data = []
    for ds in decoded:
        if ds.is_javascript:
            code = ds.decoded_data.decode("latin-1", errors="ignore")
            deob = js_deob.deobfuscate(code)
            js_data.append({
                "object": ds.object_number,
                "original_size": len(code),
                "deobfuscated_preview": deob.deobfuscated_code[:500],
                "urls": deob.extracted_urls,
                "ips": deob.extracted_ips,
                "dangerous_functions": deob.dangerous_functions,
            })

    # Dynamic Analysis
    emulator = JSEmulator()
    sandbox = SandboxMonitor()
    emulation = None
    sandbox_res = None

    for ds in decoded:
        if ds.is_javascript:
            code = ds.decoded_data.decode("latin-1", errors="ignore")
            deob = js_deob.deobfuscate(code)
            emulation = emulator.emulate(deob.deobfuscated_code)
            sandbox_res = sandbox.analyze_code_for_evasion(deob.deobfuscated_code)

    # Scoring
    yara = YaraEngine()
    yara_res = yara.scan(content)

    scorer = HeuristicScorer()
    score = scorer.score(
        tag_scan_result=tags, incremental_result=inc,
        yara_result=yara_res, emulation_result=emulation,
        metadata=metadata,
    )

    feat_ext = FeatureExtractor()
    features = feat_ext.extract(content, metadata, tags, structure, obj_tree)

    mapper = MITREMapper()
    mitre = mapper.map_findings(
        tag_result=tags, emulation_result=emulation,
        sandbox_result=sandbox_res, yara_result=yara_res,
    )

    ioc_gen = IOCGenerator()
    ioc = ioc_gen.generate(
        file_info=file_info, emulation_result=emulation,
        tag_result=tags, mitre_mappings=mitre,
    )

    # Build response
    return {
        "file_info": {
            "name": file_info.file_name,
            "size": file_info.file_size_human,
            "md5": file_info.md5,
            "sha1": file_info.sha1,
            "sha256": file_info.sha256,
            "pdf_version": file_info.pdf_version,
            "is_pdf": file_info.is_pdf,
        },
        "risk_score": {
            "total": score.total_score,
            "level": score.risk_level,
            "color": score.risk_color,
            "verdict": score.verdict,
            "breakdown": [
                {"category": b.category, "points": b.points,
                 "max": b.max_points, "details": b.details}
                for b in score.breakdown
            ],
            "recommendations": score.recommendations,
        },
        "structure": {
            "version": structure.header.version if structure.header else "?",
            "eof_count": structure.eof_count,
            "encrypted": structure.is_encrypted,
            "linearized": structure.is_linearized,
            "incremental": structure.has_incremental_updates,
            "object_count": obj_tree.total_objects,
            "stream_count": obj_tree.total_streams,
        },
        "metadata": {
            "title": metadata.title,
            "author": metadata.author,
            "creator": metadata.creator,
            "producer": metadata.producer,
            "suspicious": metadata.suspicious_indicators,
        },
        "tags": {
            "total": tags.total_tags_found,
            "critical": tags.critical_count,
            "high": tags.high_count,
            "medium": tags.medium_count,
            "verdict": tags.verdict,
            "matches": [
                {"tag": m.tag, "level": m.threat_level.value,
                 "count": m.count, "description": m.description,
                 "objects": m.object_numbers}
                for m in tags.matches
            ],
        },
        "javascript": js_data,
        "emulation": {
            "risk": emulation.risk_level if emulation else "N/A",
            "behaviors": emulation.behaviors if emulation else [],
            "c2": emulation.c2_addresses if emulation else [],
            "shell_commands": emulation.shell_commands if emulation else [],
            "network": [
                {"method": c.get("method"), "url": c.get("url"), "type": c.get("type")}
                for c in (emulation.network_calls if emulation else [])
            ],
        } if emulation else None,
        "sandbox": {
            "anti_vm": sandbox_res.anti_vm_detected if sandbox_res else [],
            "anti_sandbox": sandbox_res.anti_sandbox_detected if sandbox_res else [],
            "evasion_score": sandbox_res.evasion_score if sandbox_res else 0,
        } if sandbox_res else None,
        "yara": {
            "matches": [
                {"rule": m.rule_name, "severity": m.severity,
                 "score": m.score, "mitre": m.mitre}
                for m in yara_res.matches
            ],
            "total_score": yara_res.total_score,
        },
        "mitre": [
            {"id": m.technique_id, "name": m.technique_name,
             "tactic": m.tactic, "evidence": m.evidence}
            for m in mitre
        ],
        "ioc": {
            "total": ioc.total_iocs,
            "entries": [
                {"type": e.ioc_type, "value": e.value,
                 "confidence": e.confidence, "context": e.context}
                for e in ioc.entries
            ],
        },
        "features": {
            "entropy": features.overall_entropy,
            "printable_ratio": round(features.printable_char_ratio, 4),
        },
    }
