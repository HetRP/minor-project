"""Real checkpoint/API integration audit; writes only isolated verification artifacts."""
import hashlib
import json
import os
import sys
from pathlib import Path
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "integration"
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("HF_HUB_OFFLINE", "1")

def hashes():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (ROOT / "model/checkpoints/best").iterdir() if p.is_file()}

def run():
    before = hashes()
    import db
    db.DB_PATH = OUT / "verification.db"
    db.init_db()
    import rag
    rag.STORE_BASE_DIR = OUT / "rag"
    import main
    import llm
    from fastapi.testclient import TestClient
    from detector import detector, VulnerabilityDetector
    from model.train import tokenize_code
    report = {"checkpoint_sha256_before": before, "health": main.health(), "checks": {}}
    checks = report["checks"]
    assert detector.is_loaded
    checks["trained_model_loaded"] = True
    calls = []
    for name in ("_call_groq", "_call_hf_inference", "_deterministic_template_fallback"):
        original = getattr(llm, name)
        def wrapper(*args, _fn=original, _name=name, **kwargs):
            try:
                result = _fn(*args, **kwargs)
                calls.append({"provider": _name, "returned_text": bool(result)})
                return result
            except Exception as exc:
                calls.append({"provider": _name, "error_type": type(exc).__name__})
                raise
        setattr(llm, name, wrapper)

    train_projects = set(pd.read_parquet(ROOT / "data/processed/reef_train.parquet", columns=["project"])["project"])
    frame = pd.read_parquet(ROOT / "data/processed/reef_test.parquet")
    selected = []
    for project, group in frame.groupby("project", sort=True):
        group = group[(group.language == "python") & (group.code.str.len() < 5000)]
        if {0, 1}.issubset(set(group.label)) and project not in train_projects:
            selected.extend([group[group.label == label].iloc[0] for label in (1, 0)])
        if len(selected) >= 6:
            break
    assert len(selected) == 6
    fixture = OUT / "unseen_repository_samples"
    fixture.mkdir(exist_ok=True)
    functions = []
    provenance = []
    from parser import parse_file
    for i, row in enumerate(selected):
        name = f"sample_{i}_{'vulnerable' if row.label else 'patched'}.py"
        (fixture / name).write_text(row.code, encoding="utf-8")
        parsed = parse_file(name, row.code, "python")
        assert parsed and parsed[0]["code"] == row.code
        functions.append(parsed[0])
        provenance.append({"file": name, "id": row.id, "project": row.project, "label": int(row.label), "cwe": row.cwe})
    predictions = detector.predict_functions(functions)
    # Independently compute forward probabilities and CWE indices from saved model.
    enc = [tokenize_code(detector.tokenizer, f["code"]) for f in functions]
    ids, mask = [torch.cat([e[k] for e in enc]).to(detector.device) for k in ("input_ids", "attention_mask")]
    with torch.inference_mode(), torch.autocast(device_type=detector.device.type, enabled=detector.device.type == "cuda"):
        vl, cl = detector.model(ids, mask)
        probs = torch.sigmoid(vl.float()).cpu().tolist()
        classes = cl.argmax(-1).cpu().tolist()
    for p, prob, cls in zip(predictions, probs, classes):
        assert p["prediction_source"] == "graphcodebert"
        assert abs(p["prob"] - prob) < 1e-6
        assert p["is_vulnerable"] == (prob >= detector.threshold)
        assert p["predicted_cwe"] == detector.inv_cwe_map[cls]
        assert 0 <= p["cwe_confidence"] <= 1
    report["unseen_predictions"] = [dict(meta, **{k: p[k] for k in ("prob", "is_vulnerable", "predicted_cwe", "cwe_confidence", "prediction_source")}) for meta, p in zip(provenance, predictions)]
    checks["probabilities_threshold_and_cwe_match_direct_forward"] = True
    saved_predictions = pd.read_csv(ROOT / "results/reef_test_predictions.csv").set_index("id")
    report["max_probability_difference_from_saved_evaluation"] = max(abs(p["prob"] - float(saved_predictions.loc[meta["id"], "prob"])) for meta, p in zip(provenance, predictions))
    assert report["max_probability_difference_from_saved_evaluation"] < .001
    checks["backend_matches_saved_held_out_predictions"] = True
    from validate import validate_remediation
    report["real_patched_function_validation"] = []
    for i in range(0, len(functions), 2):
        # Same repository/function name; these are dataset revisions, not generated patches.
        assert functions[i]["name"] == functions[i+1]["name"]
        result = validate_remediation(predictions[i], functions[i+1]["code"])
        assert result["syntax_ok"]
        assert abs(result["prob_after"] - predictions[i+1]["prob"]) < .001
        report["real_patched_function_validation"].append(result)
    checks["real_patched_function_syntax_and_neural_rescoring"] = True
    # Force an inference error: it must propagate rather than fabricate heuristic scores.
    saved_tokenizer = detector.tokenizer
    detector.tokenizer = lambda *a, **k: (_ for _ in ()).throw(ValueError("verification injected failure"))
    try:
        detector.predict_functions(functions[:1])
        raise AssertionError("Inference failure silently swallowed")
    except RuntimeError as exc:
        assert "heuristic substitution disabled" in str(exc)
    finally:
        detector.tokenizer = saved_tokenizer
    checks["inference_errors_do_not_fall_back"] = True
    # Check Unicode byte offsets, which are critical to source/model alignment.
    unicode_code = '# café\ndef unicode_fn(x):\n    return "安全" + x\n'
    assert parse_file("unicode.py", unicode_code, "python")[0]["code"] == unicode_code.split("\n", 1)[1].rstrip()
    checks["unicode_source_extraction"] = True
    client = TestClient(main.app)
    response = client.post("/api/scan", json={"repo_url": str(fixture)})
    response.raise_for_status()
    scan_id = response.json()["scan_id"]
    import time
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scan/{scan_id}").json()
        if scan["status"] in ("done", "failed"):
            break
        time.sleep(.25)
    report["scan"] = scan
    assert scan["status"] == "done", scan
    findings = client.get(f"/api/scan/{scan_id}/findings").json()
    files = client.get(f"/api/scan/{scan_id}/files").json()["files"]
    assert len(files) == 6 and findings
    checks["ingest_parse_detect_localize_flow_explain_api"] = True
    assert all(f["language"] == "python" and f["prediction_source"] == "graphcodebert" for f in findings)
    checks["language_and_prediction_source_persisted"] = True
    detail = client.get(f"/api/finding/{findings[0]['id']}").json()
    assert detail["flow_mermaid"].startswith("flowchart") and detail["explanation"]["summary"]
    block = client.get(f"/api/finding/{detail['id']}/explain?block=0")
    assert block.status_code == 200 and block.json()["block"]["explanation"]
    fixed = client.post(f"/api/finding/{detail['id']}/fix")
    assert fixed.status_code == 200, fixed.text
    report["fix_response"] = fixed.json()
    assert "prob_after" in fixed.json()["validation"]
    if not fixed.json()["available"]:
        assert fixed.json()["patched_code"] == detail["code"]
        assert fixed.json()["diff"] == ""
        assert fixed.json()["validation"]["verdict"] == "unchanged"
    checks["fix_endpoint_and_real_model_rescoring"] = True
    chat = client.post(f"/api/scan/{scan_id}/chat", json={"message": "What vulnerabilities were detected?"})
    assert chat.status_code == 200 and chat.json()["sources"]
    report["chat"] = chat.json()
    checks["chat_retrieval_and_citations"] = True
    index_path = rag.STORE_BASE_DIR / scan_id / "index.faiss"
    report["rag_dense_faiss_available"] = index_path.is_file()
    report["llm_calls"] = calls
    report["findings"] = findings
    report["fixture_directory"] = str(fixture)
    report["checkpoint_sha256_after"] = hashes()
    assert before == report["checkpoint_sha256_after"]
    checks["best_checkpoint_unchanged"] = True
    report["status"] = "completed"
    (OUT / "backend_verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": checks, "scan_id": scan_id, "dense_rag": report["rag_dense_faiss_available"]}, indent=2))

if __name__ == "__main__":
    run()
