"""Regressions for real checkpoint loading and honest unavailable components."""
import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import detector as detector_module
from detector import VulnerabilityDetector
from fix import generate_fix
from flow import generate_flow_mermaid

def test_missing_weights_uses_explicit_heuristic(monkeypatch, tmp_path):
    monkeypatch.setattr(detector_module, "CHECKPOINT_DIR", tmp_path)
    instance = VulnerabilityDetector()
    assert not instance.is_loaded
    assert instance.predict_functions([{"code": "def f(): return 1"}])[0]["prediction_source"] == "heuristic"

def test_incomplete_existing_checkpoint_never_falls_back(monkeypatch, tmp_path):
    (tmp_path / "pytorch_model.bin").write_bytes(b"invalid weights")
    monkeypatch.setattr(detector_module, "CHECKPOINT_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="Incomplete trained checkpoint"):
        VulnerabilityDetector()

def test_offline_fix_preserves_function(monkeypatch):
    monkeypatch.setattr("fix.ask", lambda *a, **k: "// Offline Remediation Template\n// advice")
    original = "def f(x):\n    return x"
    result = generate_fix({"code": original, "language": "python"})
    assert result["patched_code"] == original
    assert result["available"] is False and result["diff"] == ""

def test_no_invented_sink_without_localization():
    graph = generate_flow_mermaid({"name": "f", "file": "f.py"}, [], [])
    assert "No matching dangerous sink localized" in graph
    assert "Vulnerable execution boundary" not in graph

def test_localizer_distinguishes_platform_query_from_execution():
    from localizer import localize_function
    benign = {"language": "python", "code": "def f():\n    return platform.system()", "start_line": 7}
    assert localize_function(benign)["suspicious_lines"] == []
    dangerous = dict(benign, code="def f(x):\n    os.system(x)")
    assert localize_function(dangerous)["suspicious_lines"][0]["line"] == 8
