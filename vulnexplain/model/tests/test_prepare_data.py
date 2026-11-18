"""Verify label cleaning and the CVEfixes/REEF split contract."""
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prepare_data as prep


def row(code, label, project="owner/project"):
    return dict(id=code, code=code, label=label, language="python", cwe="CWE-78",
                project=project, commit_date="")


def test_conflicting_labels_and_normalized_duplicates():
    data = pd.DataFrame([
        row("def same():\r\n    return 12345   ", 1),
        row("def same():\n    return 12345", 0),
        row("def other():\n    return 67890", 0),
        row("def other():\n    return 67890   ", 0),
    ])
    cleaned = prep.clean_and_deduplicate(data)
    assert len(cleaned) == 1
    assert cleaned.iloc[0].code.startswith("def other")


def test_pipeline_uses_cvefixes_only_and_excludes_reef_overlap(tmp_path, monkeypatch):
    for attr, folder in [("CVEFIXES_RAW_DIR", "cve"), ("REEF_RAW_DIR", "reef"),
                         ("PROCESSED_DATA_DIR", "processed"), ("RESULTS_DIR", "results"),
                         ("CHECKPOINTS_DIR", "checkpoints")]:
        directory = tmp_path / folder
        directory.mkdir()
        monkeypatch.setattr(prep, attr, directory)
    cve = [row(f"def train_{i}_{label}():\n    return {i + 1000 + label}", label, f"owner/repo{i}")
           for i in range(20) for label in (0, 1)]
    reef = [row("def external_vuln():\n    return 55555", 1, "external/new"),
            row("def external_fixed():\n    return 77777", 0, "external/new"),
            row("def excluded_project():\n    return 88888", 1, "owner/repo0"),
            {**cve[0], "project": "external/copy"}]
    pd.DataFrame(cve).to_parquet(prep.CVEFIXES_RAW_DIR / "functions.parquet")
    pd.DataFrame(reef).to_parquet(prep.REEF_RAW_DIR / "functions.parquet")
    assert prep.run_pipeline()
    train = pd.read_parquet(prep.PROCESSED_DATA_DIR / "cvefixes_train.parquet")
    val = pd.read_parquet(prep.PROCESSED_DATA_DIR / "cvefixes_val.parquet")
    test = pd.read_parquet(prep.PROCESSED_DATA_DIR / "reef_test.parquet")
    assert set(train.project).isdisjoint(val.project)
    assert set(test.project) == {"external/new"}
    assert len(train) + len(val) == len(cve)
    assert len(test) == 2
    report = json.loads((prep.RESULTS_DIR / "preprocessing_report.json").read_text())
    assert report["reef_overlap_removed"] == 2


def test_missing_data_never_creates_synthetic_training(tmp_path, monkeypatch):
    for attr in ("CVEFIXES_RAW_DIR", "REEF_RAW_DIR", "PROCESSED_DATA_DIR", "RESULTS_DIR"):
        folder = tmp_path / attr
        folder.mkdir()
        monkeypatch.setattr(prep, attr, folder)
    assert not prep.run_pipeline()
    assert not list(prep.PROCESSED_DATA_DIR.glob("*_train.parquet"))
    for path in prep.PROCESSED_DATA_DIR.glob("*_functions_clean.parquet"):
        assert pd.read_parquet(path).empty


def test_jsonl_quarantine_and_pair_labels(tmp_path):
    path = tmp_path / "functions.jsonl"
    pair = dict(project="https://github.com/Owner/Repo.git", language="Python",
                func_before="def vulnerable():\n    return eval(user_input)",
                func_after="def fixed():\n    return int(user_input)", cwes=["CWE-95"])
    path.write_text("invalid json\n" + json.dumps(pair) + "\n[]\n", encoding="utf-8")
    audit = {}
    frame = prep.load_raw_dataset(tmp_path, "cvefixes", audit)
    assert frame.label.tolist() == [1, 0]
    assert set(frame.project) == {"owner/repo"}
    assert set(frame.cwe) == {"CWE-95"}
    assert [item["line"] for item in audit["invalid_jsonl"]] == [1, 3]
