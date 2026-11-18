"""Clean function exports for CVEfixes training/validation and REEF testing.

Stage raw REEF commit files separately; fail closed on missing labeled source data.
Never generate synthetic training or benchmark records.
"""

import argparse
import json
import os
import re
import sys
import hashlib
from urllib.parse import unquote
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from .config import (
    REEF_RAW_DIR,
    CVEFIXES_RAW_DIR,
    PROCESSED_DATA_DIR,
    CHECKPOINTS_DIR,
    RESULTS_DIR,
    SUPPORTED_LANGUAGES,
    LANGUAGE_EXTENSIONS,
    RANDOM_SEED,
)

# Standard schema definition
UNIFIED_COLUMNS = ["id", "code", "label", "language", "cwe", "project", "commit_date"]


def normalize_language(lang_val: str | None, filename: str | None = None) -> str | None:
    """Normalize language names to the 7 supported languages."""
    if filename:
        ext = Path(filename).suffix.lower()
        if ext in LANGUAGE_EXTENSIONS:
            return LANGUAGE_EXTENSIONS[ext]

    if not lang_val or pd.isna(lang_val):
        return None

    raw = str(lang_val).strip().lower()
    mapping = {
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
        "cxx": "cpp",
        "cc": "cpp",
        "c#": "csharp",
        "csharp": "csharp",
        "cs": "csharp",
        "go": "go",
        "golang": "go",
        "java": "java",
        "js": "javascript",
        "javascript": "javascript",
        "py": "python",
        "python": "python",
    }
    return mapping.get(raw, None)


def normalize_cwe(cwe_val: str | None) -> str:
    """Format CWE strings into canonical CWE-XXX or UNKNOWN."""
    if isinstance(cwe_val, (list, tuple)):
        cwe_val = next((v for v in cwe_val if re.search(r"CWE[-_]?\d+", str(v), re.I)), None)
    if not cwe_val or pd.isna(cwe_val):
        return "UNKNOWN"
    s = str(cwe_val).strip().upper()
    match = re.search(r"CWE[-_]?(\d+)", s)
    if match:
        return f"CWE-{match.group(1)}"
    return "UNKNOWN"


def code_key(code: str) -> str:
    """Ignore line endings and trailing spaces, preserving meaningful indentation."""
    canonical = "\n".join(line.rstrip() for line in code.replace("\r\n", "\n").replace("\r", "\n").strip().splitlines())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_raw_dataset(raw_dir: Path, name: str, audit=None) -> pd.DataFrame:
    """Load explicit function-level exports; never guess labels or file-level code."""
    records = []
    def reject(reason):
        if audit is not None:
            reasons = audit.setdefault("rejected", {})
            reasons[reason] = reasons.get(reason, 0) + 1
    for path in sorted(raw_dir.rglob("*")):
        if path.suffix not in {".csv", ".parquet", ".jsonl"}:
            continue
        if path.suffix == ".parquet":
            rows = pd.read_parquet(path).to_dict("records")
        elif path.suffix == ".csv":
            rows = pd.read_csv(path, keep_default_na=False).to_dict("records")
        else:
            rows = read_jsonl(path, audit)
        for i, row in enumerate(rows):
            if "details" in row:
                if audit is not None:
                    audit["commit_records_staged_separately"] = audit.get("commit_records_staged_separately", 0) + 1
                continue  # REEF commit records are staged separately, not mislabeled as functions.
            lang = normalize_language(row.get("language", row.get("lang")))
            project = row.get("project", row.get("repo", row.get("repository")))
            if not isinstance(project, str) or not project.strip():
                reject("missing_project")
                continue
            project = normalize_project(project)
            date = pd.to_datetime(row.get("commit_date"), errors="coerce", utc=True)
            date = "" if pd.isna(date) else date.strftime("%Y-%m-%d")
            cwe = normalize_cwe(row.get("cwe", row.get("cwe_id", row.get("cwes"))))
            if "func_before" in row and "func_after" in row:
                versions = [(row["func_before"], 1), (row["func_after"], 0)]
            else:
                versions = [(row.get("code", row.get("func_src")), row.get("label", row.get("target")))]
            for code, label in versions:
                if not isinstance(code, str) or isinstance(label, bool):
                    reject("invalid_code_or_label")
                    continue
                if str(label) not in {"0", "1", "0.0", "1.0"}:
                    reject("missing_or_nonbinary_label")
                    continue
                records.append(dict(id=f"{name}_{hashlib.sha256(f'{path.relative_to(raw_dir)}:{i}:{label}'.encode()).hexdigest()[:24]}",
                                    code=code, label=int(float(label)), language=lang, cwe=cwe,
                                    project=project, commit_date=date))
    return pd.DataFrame(records, columns=UNIFIED_COLUMNS)


def read_jsonl(path, audit=None):
    """Quarantine malformed lines without dropping the rest of a file."""
    with path.open(encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("Expected an object")
                yield row
            except (ValueError, TypeError) as exc:
                if audit is not None:
                    audit.setdefault("invalid_jsonl", []).append({"file": str(path), "line": line_number, "error": str(exc)})


def normalize_project(value: str) -> str:
    value = value.strip().rstrip("/")
    value = re.sub(r"^https?://(?:www\.)?github\.com/", "", value, flags=re.I)
    return value.removesuffix(".git").lower()


def clean_and_deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.copy()
    df = df[df["code"].map(lambda x: isinstance(x, str))].copy()
    df["code"] = df["code"].str.replace("\r\n", "\n", regex=False).str.replace("\r", "\n", regex=False).str.strip()
    df = df[(df["code"].str.len() > 15) & ~df["code"].str.contains("\x00", regex=False)]
    df = df[df["language"].isin(SUPPORTED_LANGUAGES) & df["label"].isin([0, 1])].copy()
    df["_hash"] = df["code"].map(code_key)
    # Identical source with opposite labels is ambiguous: remove all occurrences.
    conflicts = df.groupby("_hash")["label"].nunique()
    df = df[~df["_hash"].isin(conflicts[conflicts > 1].index)]
    return df.drop_duplicates("_hash")[UNIFIED_COLUMNS].reset_index(drop=True)


def stage_reef(report: dict) -> None:
    """Clean the supplied commit/file format without inventing function labels.

    Preserve patched files and diffs for verified reverse-patch/AST extraction later.
    LLM messages and commit descriptions never become model features.
    """
    output = PROCESSED_DATA_DIR / "reef_files_staged.jsonl"
    seen = set()
    counts = {"commits": 0, "files": 0, "duplicates": 0, "invalid": 0}
    with output.open("w", encoding="utf-8") as dest:
        for path in sorted(REEF_RAW_DIR.glob("*.jsonl")):
            for row in read_jsonl(path, report):
                if "details" not in row:
                    continue
                counts["commits"] += 1
                match = re.search(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]+)", row.get("html_url", ""))
                if not match:
                    counts["invalid"] += 1
                    continue
                if not isinstance(row["details"], list):
                    counts["invalid"] += 1
                    continue
                for detail in row["details"]:
                    if not isinstance(detail, dict):
                        counts["invalid"] += 1
                        continue
                    code, patch = detail.get("raw_code"), detail.get("patch")
                    url = detail.get("raw_url", "")
                    filename = unquote(url.split("/raw/", 1)[-1].partition("/")[2])
                    lang = normalize_language(None, filename)
                    if not lang or not isinstance(code, str) or len(code.strip()) <= 15 or not isinstance(patch, str) or not patch.startswith("@@") or "\x00" in code:
                        counts["invalid"] += 1
                        continue
                    code = code.replace("\r\n", "\n").replace("\r", "\n")
                    key = (match[1].lower(), match[2], filename, code_key(code), patch)
                    if key in seen:
                        counts["duplicates"] += 1
                        continue
                    seen.add(key)
                    dest.write(json.dumps(dict(project=match[1].lower(), commit=match[2], cve_id=row.get("cve_id"),
                                               cwes=row.get("CWEs", []), language=lang, filename=filename,
                                               patched_code=code, patch=patch, raw_url=url), ensure_ascii=False) + "\n")
                    counts["files"] += 1
    report["reef_staging"] = counts
    report["reef_staging"]["path"] = str(output)


def build_cwe_map(train_df: pd.DataFrame, top_k: int = 20) -> dict[str, int]:
    """Builds top-K CWE map from training set + 'OTHER'."""
    # Filter for vulnerable samples with valid CWE
    vuln_cwes = train_df[train_df["label"] == 1]["cwe"].value_counts()
    valid_cwes = [c for c in vuln_cwes.index if c != "UNKNOWN" and c != "OTHER"]

    top_cwes = valid_cwes[:top_k]
    cwe_to_idx = {cwe: i for i, cwe in enumerate(top_cwes)}
    cwe_to_idx["OTHER"] = len(top_cwes)
    return cwe_to_idx


def split_by_project(df: pd.DataFrame):
    """90/10 CVEfixes train/validation by repository; REEF stays external."""
    if df["project"].nunique() < 2:
        raise ValueError("CVEfixes needs at least two repositories for train/validation splitting.")
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.1, random_state=RANDOM_SEED)
    train_idx, val_idx = next(splitter.split(df, groups=df["project"]))
    train, val = df.iloc[train_idx].copy(), df.iloc[val_idx].copy()
    for name, subset in [("train", train), ("validation", val)]:
        if set(subset["label"]) != {0, 1}:
            raise ValueError(f"CVEfixes {name} must contain both labels; supply more repositories.")
    return train, val


def summarize(frame):
    """Describe imbalance and function lengths without changing evaluation data."""
    lengths = frame.code.str.len()
    return {"samples": len(frame), "projects": frame.project.nunique(),
            "labels": {str(k): int(v) for k, v in frame.label.value_counts().items()},
            "languages": {str(k): int(v) for k, v in frame.language.value_counts().items()},
            "language_labels": [{"language": lang, "label": int(label), "count": int(count)}
                                for (lang, label), count in frame.groupby(["language", "label"]).size().items()],
            "unknown_cwe": int((frame.cwe == "UNKNOWN").sum()),
            "code_characters": {str(k): float(v) for k, v in lengths.quantile([0.5, 0.9, 0.99]).dropna().items()}}


def run_pipeline(tokenizer_path=None, max_length=512):
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        from .dataset_transformer import run_all_transformations
    except ImportError:
        from dataset_transformer import run_all_transformations

    print("[PIPELINE] Running full dataset transformation, deduplication, and preprocessing...")
    run_all_transformations()

    report_path = RESULTS_DIR / "preprocessing_report.json"
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if report.get("status") == "ready":
                print(f"[PIPELINE] SUCCESS: Data preparation is ready for model training ({report.get('dataset_total_samples', 0)} samples).")
                return True
        except Exception as e:
            print(f"[PIPELINE] Error reading report: {e}")

    return False

def old_run_pipeline(tokenizer_path=None, max_length=512):
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report = {"training_source": "cvefixes", "validation_source": "cvefixes", "test_source": "reef",
              "status": "incomplete", "blockers": []}
    # Invalidate an older ready report even if this run fails during input parsing.
    (RESULTS_DIR / "preprocessing_report.json").write_text(json.dumps({**report, "blockers": ["Preprocessing has not completed."]}, indent=2), encoding="utf-8")
    nvd = sorted(CVEFIXES_RAW_DIR.glob("nvdcve-*.json"))
    report["nvd_metadata_files"] = len(nvd)
    stage_reef(report)
    report["quality"] = {}
    frames = {}
    for name, directory in [("cvefixes", CVEFIXES_RAW_DIR), ("reef", REEF_RAW_DIR)]:
        audit = {}
        raw = load_raw_dataset(directory, name, audit)
        cleaned = clean_and_deduplicate(raw)
        hashes = raw.code.map(code_key)
        conflicts = raw.assign(code_hash=hashes).groupby("code_hash").label.nunique()
        audit.update(summarize(cleaned))
        audit.update(accepted_before_cleaning=len(raw), removed_by_cleaning=len(raw)-len(cleaned),
                     conflicting_code_hashes=int((conflicts > 1).sum()))
        report["quality"][name] = audit
        # Inspection exports are not a claim that training is ready.
        cleaned.to_csv(PROCESSED_DATA_DIR / f"{name}_functions_clean.csv", index=False)
        cleaned.to_parquet(PROCESSED_DATA_DIR / f"{name}_functions_clean.parquet", index=False)
        frames[name] = cleaned
    cve, reef = frames["cvefixes"], frames["reef"]
    if tokenizer_path:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, local_files_only=True)
        report["token_lengths"] = {}
        for name, frame in frames.items():
            lengths = [len(tokenizer.encode(code, truncation=False)) for code in frame.code]
            report["token_lengths"][name] = {"max_length": max_length,
                "functions_exceeding_limit": sum(n > max_length for n in lengths), "total": len(lengths)}
    report["cvefixes_clean_functions"] = len(cve)
    report["reef_clean_functions"] = len(reef)
    if cve.empty:
        report["blockers"].append("No labeled CVEfixes function records found. NVD JSON feeds contain vulnerability metadata, not source code. Supply a CVEfixes function export (CSV/Parquet/JSONL) with func_before/func_after, language, project, cwe and optional commit_date; or code with an explicit binary label.")
    if reef.empty:
        report["blockers"].append("REEF contains commit-level patched files and diffs. Cleaned files are staged, but are not a function-level benchmark. Verify reverse-patching and extract changed function pairs with AST parsers before assigning labels; unrelated changed functions cannot safely be assumed vulnerable.")
    if not report["blockers"]:
        try:
            train, val = split_by_project(cve)
            # Disallow repositories AND normalized code shared with either development split.
            overlap = reef["project"].isin(set(cve["project"])) | reef["code"].map(code_key).isin(set(cve["code"].map(code_key)))
            report["reef_overlap_removed"] = int(overlap.sum())
            reef = reef[~overlap].copy()
            if reef.empty or set(reef["label"]) != {0, 1}:
                raise ValueError("REEF test must retain both labels after development-set overlap removal.")
            CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
            stats = []
            for name, frame in [("cvefixes_train", train), ("cvefixes_val", val), ("reef_test", reef)]:
                frame.to_parquet(PROCESSED_DATA_DIR / f"{name}.parquet", index=False)
                frame.to_csv(PROCESSED_DATA_DIR / f"{name}.csv", index=False)
                stats.append(dict(split=name, samples=len(frame), vulnerable=int(frame.label.sum()),
                                  patched=int((frame.label == 0).sum()), projects=frame.project.nunique()))
            pd.DataFrame(stats).to_csv(RESULTS_DIR / "data_stats.csv", index=False)
            (CHECKPOINTS_DIR / "cwe_map.json").write_text(json.dumps(build_cwe_map(train), indent=2), encoding="utf-8")
            report["splits"] = stats
            counts = train.label.value_counts()
            report["training_class_weights"] = {str(label): float(len(train) / (2 * count)) for label, count in counts.items()}
            report["split_quality"] = {name: summarize(frame) for name, frame in [("train", train), ("validation", val), ("test", reef)]}
            report["status"] = "ready"
        except ValueError as exc:
            report["blockers"].append(str(exc))
    (RESULTS_DIR / "preprocessing_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return report["status"] == "ready"


def main():
    parser = argparse.ArgumentParser(description="Prepare labeled functions, quality reports and repository-disjoint splits.")
    parser.add_argument("--tokenizer-path", help="Optional local tokenizer directory for exact truncation auditing (no download).")
    parser.add_argument("--max-length", type=int, default=512)
    args = parser.parse_args()
    if args.max_length < 1:
        parser.error("--max-length must be positive")
    return 0 if run_pipeline(args.tokenizer_path, args.max_length) else 1


if __name__ == "__main__":
    sys.exit(main())
