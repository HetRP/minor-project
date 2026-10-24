"""FastAPI Application & Pipeline Orchestrator for VulnExplain.

Implements the 9-step analysis pipeline:
Ingest -> Parse -> Detect -> Localize -> Flow -> Explain -> Fix -> Validate -> RAG/Chat.
"""

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import (
    create_scan,
    update_scan_progress,
    get_scan,
    list_scans,
    insert_findings,
    get_findings_for_scan,
    get_finding,
    update_finding_fix,
    update_finding_explanation,
)
from ingest import ingest_repository
from parser import parse_file, build_repository_call_graph
from detector import detector
from localizer import localize_function
from flow import generate_flow_mermaid
from explain import initialize_explanation_bundle, explain_single_block
from fix import generate_fix
from validate import validate_remediation
from rag import build_rag_index
from chat import answer_chat_query

app = FastAPI(
    title="VulnExplain API",
    description="Multilingual Repository Vulnerability Analysis and Code Intelligence Engine",
    version="1.0.0",
)

# Enable CORS for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for file contents per scan (to support Code Explorer without re-cloning)
SCAN_FILE_CACHE: dict[str, list[dict[str, Any]]] = {}


# Request Models
class ScanRequest(BaseModel):
    repo_url: str


class ChatRequest(BaseModel):
    message: str


def run_pipeline_worker(scan_id: str, repo_url: str):
    """Background worker executing the complete 9-stage analysis pipeline."""
    try:
        # Step 1: Ingest
        update_scan_progress(scan_id, 10, status="running")
        ingest_res = ingest_repository(repo_url)
        files = ingest_res["files"]
        if not files:
            raise ValueError("No supported source code files detected in repository.")

        # Cache file content for Code Explorer
        SCAN_FILE_CACHE[scan_id] = [
            {
                "path": f["path"],
                "language": f["language"],
                "lines": f.get("lines", 1),
                "content": f.get("content", ""),
            }
            for f in files
        ]

        # Step 2: Parse functions and build call graph
        update_scan_progress(scan_id, 30, status="running")
        all_functions = []
        for f in files:
            funcs = parse_file(f["path"], f["content"], f["language"])
            all_functions.extend(funcs)

        call_graph, callers_map = build_repository_call_graph(all_functions)

        # Step 3: GraphCodeBERT Vulnerability Detection
        update_scan_progress(scan_id, 50, status="running")
        scored_functions = detector.predict_functions(all_functions)

        # Step 4, 5, 6: Localize, Flow, Explain for flagged functions
        update_scan_progress(scan_id, 70, status="running")
        findings_to_store = []
        vuln_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        vuln_by_lang = {}

        flagged_count = 0
        for fn in scored_functions:
            if fn.get("is_vulnerable", False):
                flagged_count += 1
                finding_id = f"find_{uuid.uuid4().hex[:10]}"

                # Step 4: Localize
                loc = localize_function(fn)
                fn_severity = loc["severity"]
                vuln_by_severity[fn_severity] = vuln_by_severity.get(fn_severity, 0) + 1
                vuln_by_lang[fn["language"]] = vuln_by_lang.get(fn["language"], 0) + 1

                # Step 5: Flow (Deterministic AST & Def-Use, NO LLM)
                flow_mermaid = generate_flow_mermaid(
                    func_dict=fn,
                    callers=callers_map.get(fn["id"], []),
                    suspicious_lines=loc["suspicious_lines"],
                )

                # Step 6: Initial explanation bundle
                fn_dict_with_meta = dict(fn)
                fn_dict_with_meta["severity"] = fn_severity
                fn_dict_with_meta["cwe"] = fn["predicted_cwe"]
                explanation = initialize_explanation_bundle(fn_dict_with_meta, flow_mermaid)

                findings_to_store.append({
                    "id": finding_id,
                    "scan_id": scan_id,
                    "file": fn["file"],
                    "func_name": fn["name"],
                    "start_line": fn["start_line"],
                    "end_line": fn["end_line"],
                    "prob": fn["prob"],
                    "cwe": fn["predicted_cwe"],
                    "severity": fn_severity,
                    "code": fn["code"],
                    "language": fn["language"],
                    "prediction_source": fn["prediction_source"],
                    "suspicious_lines": loc["suspicious_lines"],
                    "flow_mermaid": flow_mermaid,
                    "explanation": explanation,
                    "fix_diff": "",
                    "validation": {},
                })

        # Save findings
        insert_findings(findings_to_store)

        # Step 7: Build RAG Index
        update_scan_progress(scan_id, 90, status="running")
        build_rag_index(scan_id, all_functions)

        # Summary computation
        summary = {
            "total_files": len(files),
            "total_functions": len(all_functions),
            "flagged_functions": flagged_count,
            "by_severity": vuln_by_severity,
            "by_language": vuln_by_lang,
            "threshold": detector.threshold,
            "prediction_source": "graphcodebert" if detector.is_loaded else "heuristic",
        }

        # Cleanup temporary clone
        if ingest_res.get("temp_obj"):
            try:
                ingest_res["temp_obj"].cleanup()
            except Exception:
                pass

        # Complete
        update_scan_progress(scan_id, 100, status="done", summary=summary)

    except Exception as e:
        print(f"Pipeline error for scan {scan_id}: {e}")
        update_scan_progress(scan_id, 0, status="failed", error=str(e))


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "detector_loaded": detector.is_loaded,
        "prediction_source": "graphcodebert" if detector.is_loaded else "heuristic",
        "threshold": detector.threshold,
        "device": str(detector.device),
        "groq_configured": bool(os.getenv("GROQ_API_KEY")),
    }


@app.post("/api/scan")
def start_scan(payload: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    create_scan(scan_id, payload.repo_url)
    threading.Thread(target=run_pipeline_worker, args=(scan_id, payload.repo_url), daemon=True).start()
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
def get_scan_status(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans")
def get_recent_scans():
    return list_scans(limit=15)


@app.get("/api/scan/{scan_id}/findings")
def get_scan_findings(scan_id: str):
    return get_findings_for_scan(scan_id)


@app.get("/api/scan/{scan_id}/files")
def get_scan_files(scan_id: str):
    """Returns files with per-file vulnerability counts for Code Explorer."""
    cached_files = SCAN_FILE_CACHE.get(scan_id, [])
    findings = get_findings_for_scan(scan_id)

    # Count vulns per file
    counts_by_file = {}
    for f in findings:
        f_path = f["file"]
        counts_by_file[f_path] = counts_by_file.get(f_path, 0) + 1

    file_list = []
    for cf in cached_files:
        file_list.append({
            "path": cf["path"],
            "language": cf["language"],
            "lines": cf["lines"],
            "vuln_count": counts_by_file.get(cf["path"], 0),
            "content": cf["content"],
        })

    return {"files": file_list}


@app.get("/api/finding/{finding_id}")
def get_finding_detail(finding_id: str):
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@app.get("/api/finding/{finding_id}/explain")
def get_block_explanation(finding_id: str, block: int = Query(0, ge=0)):
    """Progressive disclosure: returns explanation for block i on request."""
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    explanation = finding.get("explanation", {})
    blocks = explanation.get("blocks", [])

    if block >= len(blocks):
        raise HTTPException(status_code=400, detail="Block index out of bounds")

    target_block = blocks[block]
    if not target_block.get("explanation"):
        exp_text = explain_single_block(
            func_name=finding["func_name"],
            block_index=block,
            block_code=target_block["code"],
            full_code=finding["code"],
            cwe=finding["cwe"],
            flow_mermaid=finding.get("flow_mermaid", ""),
        )
        target_block["explanation"] = exp_text
        update_finding_explanation(finding_id, explanation)

    return {
        "block_index": block,
        "block": target_block,
        "total_blocks": len(blocks),
    }


@app.post("/api/finding/{finding_id}/fix")
def remediate_finding(finding_id: str):
    """Generates remediation diff and runs probabilistic validation."""
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Step 7: Fix
    fix_result = generate_fix(finding, flow_mermaid=finding.get("flow_mermaid", ""))

    # Step 8: Validate
    val_result = validate_remediation(finding, fix_result["patched_code"])
    val_result["fix_available"] = fix_result["available"]
    val_result["fix_message"] = fix_result["message"]

    # Persist
    update_finding_fix(finding_id, fix_result["diff"], val_result)

    return {
        "finding_id": finding_id,
        "original_code": fix_result["original_code"],
        "patched_code": fix_result["patched_code"],
        "diff": fix_result["diff"],
        "validation": val_result,
        "available": fix_result["available"],
        "message": fix_result["message"],
    }


@app.post("/api/scan/{scan_id}/chat")
def chat_with_repo(scan_id: str, payload: ChatRequest):
    """Answers user message with intent detection, RAG retrieval, and finding citations."""
    return answer_chat_query(scan_id, payload.message)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
