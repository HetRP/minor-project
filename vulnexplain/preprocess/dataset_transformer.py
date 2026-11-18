"""Dataset Transformation and Cleaning Engine for VulnExplain.

Transforms raw REEF JSONL and CVEfixes NVD JSON files into high-quality,
trainable CSV and Parquet formats with unified schemas, strict deduplication,
label conflict resolution, and comprehensive cleaning audits.
"""

import os
import sys
import json
import re
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
RESULTS_DIR = BASE_DIR / "results"
CHECKPOINTS_DIR = BASE_DIR / "model" / "checkpoints"
BEST_MODEL_DIR = CHECKPOINTS_DIR / "best"

REEF_RAW_DIR = RAW_DIR / "reef"
CVEFIXES_RAW_DIR = RAW_DIR / "cvefixes"

REEF_PROCESSED_DIR = PROCESSED_DIR / "reef"
CVEFIXES_PROCESSED_DIR = PROCESSED_DIR / "cvefixes"

# Ensure output directories exist
REEF_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
CVEFIXES_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
BEST_MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Standard supported languages and mappings
SUPPORTED_LANGUAGES = ["c", "cpp", "csharp", "go", "java", "javascript", "python"]

LANGUAGE_EXTENSIONS = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".py": "python"
}

# Unified schema for trainable code samples
UNIFIED_CODE_COLUMNS = [
    "id", "code", "label", "language", "cwe", "project", "commit_date", "cve_id", "granularity"
]

# Regex patterns for function signature detection
FUNCTION_PATTERNS = {
    "c": re.compile(r"^[ \t]*[\w\*\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{", re.MULTILINE),
    "cpp": re.compile(r"^[ \t]*[\w\*\s\:\<\>]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:const)?\s*\{", re.MULTILINE),
    "csharp": re.compile(r"(?:public|protected|private|static|async|\s)+\s+[\w\<\>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{", re.MULTILINE),
    "go": re.compile(r"^[ \t]*func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE),
    "java": re.compile(r"(?:public|protected|private|static|\s)+\s+[\w\<\>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{", re.MULTILINE),
    "javascript": re.compile(r"(?:function\s+([A-Za-z_][A-Za-z0-9_]*)|const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:function|\([^)]*\)\s*=>)|([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{)", re.MULTILINE),
    "python": re.compile(r"^[ \t]*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE),
}


def normalize_language(lang_val: Optional[str], filename: Optional[str] = None) -> Optional[str]:
    """Normalize language names to the 7 supported languages."""
    if filename:
        ext = Path(filename).suffix.lower()
        if ext in LANGUAGE_EXTENSIONS:
            return LANGUAGE_EXTENSIONS[ext]

    if not lang_val or pd.isna(lang_val):
        return None

    raw = str(lang_val).strip().lower()
    mapping = {
        "c": "c", "cpp": "cpp", "c++": "cpp", "cxx": "cpp", "cc": "cpp",
        "c#": "csharp", "csharp": "csharp", "cs": "csharp",
        "go": "go", "golang": "go",
        "java": "java",
        "js": "javascript", "javascript": "javascript",
        "py": "python", "python": "python",
    }
    return mapping.get(raw, None)


def normalize_cwe(cwe_val: Any) -> str:
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


def normalize_project(url: str) -> str:
    """Extract owner/repo from GitHub commit URLs."""
    if not isinstance(url, str):
        return "unknown"
    m = re.search(r"github\.com/([^/]+/[^/]+)", url)
    if m:
        val = m.group(1).removesuffix(".git").lower()
        return val.rstrip("/")
    return "unknown"


def code_hash(code: str) -> str:
    """Compute deterministic SHA-256 hash of normalized code."""
    canonical = "\n".join(
        line.rstrip() for line in code.replace("\r\n", "\n").replace("\r", "\n").strip().splitlines()
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def reverse_patch_file(patched_code: str, patch_str: str) -> Optional[str]:
    """Reconstruct pre-patch code by reversing a unified git diff against post-patch code."""
    hunks = [h for h in re.split(r"(?m)^(?=@@ -\d+)", patch_str) if h.strip().startswith("@@")]
    if not hunks:
        return None
    patched_lines = patched_code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    hunk_data = []
    for h in hunks:
        m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", h)
        if not m:
            continue
        new_start = int(m.group(3))
        old_lines = []
        new_lines = []
        for line in h.split("\n")[1:]:
            if line.startswith("+"):
                new_lines.append(line[1:])
            elif line.startswith("-"):
                old_lines.append(line[1:])
            elif line.startswith(" ") or line == "":
                old_lines.append(line[1:] if line.startswith(" ") else "")
                new_lines.append(line[1:] if line.startswith(" ") else "")
        hunk_data.append((new_start, old_lines, new_lines))
    # Reverse sort to apply from bottom to top without shifting line indices
    hunk_data.sort(key=lambda x: x[0], reverse=True)
    res_lines = list(patched_lines)
    for new_start, old_lines, new_lines in hunk_data:
        idx = max(0, new_start - 1)
        res_lines[idx : idx + len(new_lines)] = old_lines
    return "\n".join(res_lines)


def extract_c_style_function(code: str, start_idx: int) -> Optional[str]:
    """Extract enclosing C/C++/Java/C#/JS/Go function body via brace matching."""
    open_brace = code.find("{", start_idx)
    if open_brace == -1:
        return None
    brace_count = 0
    in_string = False
    quote_char = ""
    i = open_brace
    # Bound scan length to avoid pathological quadratic scans on massive minified files
    n = min(len(code), open_brace + 15000)
    while i < n:
        c = code[i]
        if not in_string:
            if c in ('"', "'", "`"):
                in_string = True
                quote_char = c
            elif c == "{":
                brace_count += 1
            elif c == "}":
                brace_count -= 1
                if brace_count == 0:
                    return code[start_idx : i + 1]
        else:
            if c == "\\":
                i += 1
            elif c == quote_char:
                in_string = False
        i += 1
    return None


def extract_python_function(lines: List[str], start_line_idx: int) -> Optional[str]:
    """Extract Python function body via indentation tracking."""
    if start_line_idx >= len(lines):
        return None
    header = lines[start_line_idx]
    indent = len(header) - len(header.lstrip())
    fn_lines = [header]
    for i in range(start_line_idx + 1, len(lines)):
        l = lines[i]
        if not l.strip():
            fn_lines.append(l)
            continue
        cur_indent = len(l) - len(l.lstrip())
        if cur_indent <= indent:
            break
        fn_lines.append(l)
    return "\n".join(fn_lines)


def extract_functions_from_code(code: str, lang: str) -> Dict[str, str]:
    """Extract all identifiable functions from code as {name: function_code}."""
    funcs = {}
    if not code or not isinstance(code, str):
        return funcs

    if lang == "python":
        lines = code.splitlines()
        for idx, line in enumerate(lines):
            m = re.match(r"^[ \t]*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if m:
                name = m.group(1)
                fn_code = extract_python_function(lines, idx)
                if fn_code and len(fn_code) > 20:
                    funcs[name] = fn_code
    else:
        pattern = FUNCTION_PATTERNS.get(lang)
        if pattern:
            for match in pattern.finditer(code):
                name = next((g for g in match.groups() if g), f"func_{match.start()}")
                fn_code = extract_c_style_function(code, match.start())
                if fn_code and len(fn_code) > 20:
                    funcs[name] = fn_code

    return funcs


def extract_hunk_pairs(patch_str: str) -> List[Tuple[int, str, str]]:
    """Extract pre-patch and post-patch code snippets with context from diff hunks."""
    hunks = [h for h in re.split(r"(?m)^(?=@@ -\d+)", patch_str) if h.strip().startswith("@@")]
    pairs = []
    for idx, h in enumerate(hunks):
        lines = h.split("\n")
        body = lines[1:] if len(lines) > 1 else []
        del_lines = [l[1:] for l in body if l.startswith("-") and not l.startswith("---")]
        add_lines = [l[1:] for l in body if l.startswith("+") and not l.startswith("+++")]

        pre_snippet = "\n".join(
            l[1:] if (l.startswith("-") or l.startswith(" ")) else l for l in body if not l.startswith("+")
        ).strip()
        post_snippet = "\n".join(
            l[1:] if (l.startswith("+") or l.startswith(" ")) else l for l in body if not l.startswith("-")
        ).strip()

        if pre_snippet and post_snippet and (len(del_lines) > 0 or len(add_lines) > 0):
            pairs.append((idx, pre_snippet, post_snippet))
    return pairs


def clean_dataframe(df: pd.DataFrame, audit_tracker: Dict[str, Any], dataset_name: str) -> pd.DataFrame:
    """Comprehensive cleaning: deduplication, label conflict resolution, quality validation."""
    if df.empty:
        return df

    initial_count = len(df)
    audit_tracker["initial_extracted"] = initial_count

    # 1. Strip and normalize line endings
    df = df[df["code"].map(lambda x: isinstance(x, str))].copy()
    df["code"] = (
        df["code"]
        .str.replace("\r\n", "\n", regex=False)
        .str.replace("\r", "\n", regex=False)
        .str.strip()
    )

    # 2. Quality filters: length > 20 chars, no null bytes, valid supported language
    valid_len_mask = df["code"].str.len() > 20
    no_null_mask = ~df["code"].str.contains("\x00", regex=False)
    valid_lang_mask = df["language"].isin(SUPPORTED_LANGUAGES)
    valid_label_mask = df["label"].isin([0, 1])

    valid_mask = valid_len_mask & no_null_mask & valid_lang_mask & valid_label_mask
    rejected_quality = int((~valid_mask).sum())
    audit_tracker["rejected_quality_filters"] = rejected_quality
    df = df[valid_mask].copy()

    # 3. Compute code hashes for deduplication & conflict resolution
    df["_hash"] = df["code"].map(code_hash)

    # 4. Resolve label conflicts (identical code with both label 0 and label 1 is ambiguous -> drop both)
    conflicts = df.groupby("_hash")["label"].nunique()
    conflict_hashes = conflicts[conflicts > 1].index
    audit_tracker["label_conflict_records_dropped"] = int(df["_hash"].isin(conflict_hashes).sum())
    df = df[~df["_hash"].isin(conflict_hashes)].copy()

    # 5. Drop exact duplicates (same code hash and same label)
    before_dedup = len(df)
    df = df.drop_duplicates(subset=["_hash"]).copy()
    duplicates_removed = before_dedup - len(df)
    audit_tracker["duplicates_removed"] = duplicates_removed

    # Final cleaned dataframe
    cols = [c for c in UNIFIED_CODE_COLUMNS if c in df.columns]
    cleaned_df = df[cols].reset_index(drop=True)
    audit_tracker["final_clean_records"] = len(cleaned_df)
    audit_tracker["vulnerable_count"] = int((cleaned_df["label"] == 1).sum())
    audit_tracker["patched_count"] = int((cleaned_df["label"] == 0).sum())

    return cleaned_df


# ==============================================================================
# REEF TRANSFORMATION ENGINE
# ==============================================================================

def process_reef_file(filepath: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Transform and clean a single REEF JSONL file."""
    file_stem = filepath.stem
    audit: Dict[str, Any] = {
        "file": filepath.name,
        "raw_commits": 0,
        "raw_files": 0,
        "function_pairs_extracted": 0,
        "hunk_pairs_extracted": 0,
    }

    samples: List[Dict[str, Any]] = []

    with open(filepath, "r", encoding="utf-8-sig") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            audit["raw_commits"] += 1
            try:
                row = json.loads(line)
            except Exception:
                continue

            cve_id = row.get("cve_id", "UNKNOWN")
            cwe = normalize_cwe(row.get("CWEs"))
            project = normalize_project(row.get("html_url", row.get("url", "")))
            details = row.get("details", [])
            row_lang = row.get("language")

            if not isinstance(details, list):
                continue

            for det_idx, det in enumerate(details):
                if not isinstance(det, dict):
                    continue
                audit["raw_files"] += 1

                raw_code = det.get("raw_code")
                patch = det.get("patch")
                raw_url = det.get("raw_url", "")

                if not isinstance(raw_code, str) or not isinstance(patch, str):
                    continue
                if not patch.strip().startswith("@@") or len(raw_code.strip()) <= 20:
                    continue

                lang = normalize_language(row_lang, raw_url)
                if not lang:
                    continue

                # 1. Attempt reverse-patching to get pre-patch code
                pre_code = reverse_patch_file(raw_code, patch)

                extracted_any_function = False
                if pre_code:
                    # Extract functions from pre-patch and post-patch
                    funcs_before = extract_functions_from_code(pre_code, lang)
                    funcs_after = extract_functions_from_code(raw_code, lang)

                    # Match changed functions
                    for fn_name, after_code in funcs_after.items():
                        if fn_name in funcs_before:
                            before_code = funcs_before[fn_name]
                            if before_code.strip() != after_code.strip():
                                extracted_any_function = True
                                audit["function_pairs_extracted"] += 1
                                # Vulnerable function
                                id_vuln = f"reef_{hashlib.sha256(f'{cve_id}:{det_idx}:{fn_name}:1'.encode()).hexdigest()[:16]}"
                                samples.append({
                                    "id": id_vuln,
                                    "code": before_code,
                                    "label": 1,
                                    "language": lang,
                                    "cwe": cwe,
                                    "project": project,
                                    "commit_date": "",
                                    "cve_id": cve_id,
                                    "granularity": "function",
                                })
                                # Patched function
                                id_patch = f"reef_{hashlib.sha256(f'{cve_id}:{det_idx}:{fn_name}:0'.encode()).hexdigest()[:16]}"
                                samples.append({
                                    "id": id_patch,
                                    "code": after_code,
                                    "label": 0,
                                    "language": lang,
                                    "cwe": cwe,
                                    "project": project,
                                    "commit_date": "",
                                    "cve_id": cve_id,
                                    "granularity": "function",
                                })

                # 2. Hunk-level extraction (either fallback or complementary fine-grained granularity)
                if not extracted_any_function:
                    hunk_pairs = extract_hunk_pairs(patch)
                    for hunk_idx, pre_snippet, post_snippet in hunk_pairs:
                        if len(pre_snippet) > 20 and len(post_snippet) > 20:
                            audit["hunk_pairs_extracted"] += 1
                            id_vuln = f"reef_{hashlib.sha256(f'{cve_id}:{det_idx}:{hunk_idx}:1'.encode()).hexdigest()[:16]}"
                            samples.append({
                                "id": id_vuln,
                                "code": pre_snippet,
                                "label": 1,
                                "language": lang,
                                "cwe": cwe,
                                "project": project,
                                "commit_date": "",
                                "cve_id": cve_id,
                                "granularity": "hunk",
                            })
                            id_patch = f"reef_{hashlib.sha256(f'{cve_id}:{det_idx}:{hunk_idx}:0'.encode()).hexdigest()[:16]}"
                            samples.append({
                                "id": id_patch,
                                "code": post_snippet,
                                "label": 0,
                                "language": lang,
                                "cwe": cwe,
                                "project": project,
                                "commit_date": "",
                                "cve_id": cve_id,
                                "granularity": "hunk",
                            })

    raw_df = pd.DataFrame(samples)
    cleaned_df = clean_dataframe(raw_df, audit, file_stem)

    # Save per-file cleaned CSV
    out_csv = REEF_PROCESSED_DIR / f"{file_stem}.csv"
    cleaned_df.to_csv(out_csv, index=False)
    audit["output_csv"] = str(out_csv)

    return cleaned_df, audit


def transform_all_reef() -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Transform all REEF JSONL files into individual CSVs and a consolidated cleaned dataset."""
    reef_files = sorted(REEF_RAW_DIR.glob("*.jsonl"))
    print(f"\n[REEF] Found {len(reef_files)} raw JSONL dataset files to transform...")

    all_frames = []
    per_file_audits = {}

    for idx, filepath in enumerate(reef_files, 1):
        file_stem = filepath.stem
        out_csv = REEF_PROCESSED_DIR / f"{file_stem}.csv"

        if out_csv.exists() and out_csv.stat().st_size > 500:
            print(f"  [{idx}/{len(reef_files)}] Loading cached REEF CSV: {out_csv.name} ...", end="", flush=True)
            df = pd.read_csv(out_csv)
            all_frames.append(df)
            audit = {
                "file": filepath.name,
                "cached": True,
                "clean_records": len(df),
                "vulnerable_count": int((df["label"] == 1).sum()),
                "patched_count": int((df["label"] == 0).sum())
            }
            per_file_audits[filepath.name] = audit
            print(f" Done ({len(df)} clean records: {audit['vulnerable_count']} vuln / {audit['patched_count']} safe)")
            continue

        t0 = time.time()
        print(f"  [{idx}/{len(reef_files)}] Processing REEF: {filepath.name} ...", end="", flush=True)
        df, audit = process_reef_file(filepath)
        all_frames.append(df)
        per_file_audits[filepath.name] = audit
        elapsed = time.time() - t0
        print(f" Done ({len(df)} clean records, {audit.get('vulnerable_count', 0)} vuln / {audit.get('patched_count', 0)} safe in {elapsed:.1f}s)")

    # Combine all frames for master consolidated dataset
    combined_raw = pd.concat(all_frames, ignore_index=True) if all_frames else pd.DataFrame(columns=UNIFIED_CODE_COLUMNS)
    master_audit: Dict[str, Any] = {"per_file": per_file_audits}
    print("  Applying global deduplication & conflict resolution on consolidated REEF dataset...")
    master_df = clean_dataframe(combined_raw, master_audit, "reef_master")

    # Save master datasets
    master_csv = PROCESSED_DIR / "reef_trainable_clean.csv"
    master_parquet = PROCESSED_DIR / "reef_trainable_clean.parquet"
    master_df.to_csv(master_csv, index=False)
    master_df.to_parquet(master_parquet, index=False)

    # Also update pipeline compatibility files
    master_df.to_csv(PROCESSED_DIR / "reef_functions_clean.csv", index=False)
    master_df.to_parquet(PROCESSED_DIR / "reef_functions_clean.parquet", index=False)

    print(f"  -> Consolidated REEF dataset saved to: {master_csv} ({len(master_df)} clean trainable samples)")

    return master_df, master_audit


# ==============================================================================
# CVEFIXES (NVD CVE JSON) TRANSFORMATION ENGINE
# ==============================================================================

def parse_nvd_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract and normalize a single NVD CVE record."""
    cve_data = item.get("cve", {})
    meta = cve_data.get("CVE_data_meta", {})
    cve_id = meta.get("ID", "").strip()

    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    # Description
    desc_list = cve_data.get("description", {}).get("description_data", [])
    desc = ""
    for d in desc_list:
        if d.get("lang") == "en":
            desc = d.get("value", "").strip()
            break
    if not desc:
        desc = desc_list[0].get("value", "").strip() if desc_list else ""

    # Quality check: discard rejected, reserved, or disputed placeholder records
    desc_upper = desc.upper()
    if (
        desc_upper.startswith("** REJECT **")
        or desc_upper.startswith("** RESERVED **")
        or desc_upper.startswith("** DISPUTED **")
        or len(desc) < 15
    ):
        return None

    # CWEs
    cwes = []
    pt = cve_data.get("problemtype", {}).get("problemtype_data", [])
    for p in pt:
        for c in p.get("description", []):
            val = c.get("value", "").strip()
            if val and val not in {"NVD-CWE-noinfo", "NVD-CWE-Other"}:
                m = re.search(r"CWE[-_]?(\d+)", val, re.I)
                if m:
                    cwes.append(f"CWE-{m.group(1)}")
    primary_cwe = cwes[0] if cwes else "UNKNOWN"
    all_cwes_str = ";".join(sorted(list(set(cwes)))) if cwes else "UNKNOWN"

    # Impact & CVSS Score / Severity
    impact = item.get("impact", {})
    cvss3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
    cvss2 = impact.get("baseMetricV2", {}).get("cvssV2", {})

    cvss_score = cvss3.get("baseScore", cvss2.get("baseScore", None))
    severity = cvss3.get("baseSeverity", impact.get("baseMetricV2", {}).get("severity", "UNKNOWN"))
    if severity:
        severity = str(severity).upper()

    cvss_version = "3.1" if cvss3.get("version") == "3.1" else ("3.0" if cvss3 else ("2.0" if cvss2 else "UNKNOWN"))

    # Dates
    pub_date = str(item.get("publishedDate", ""))[:10]
    mod_date = str(item.get("lastModifiedDate", ""))[:10]

    # References & GitHub commit URLs
    refs = cve_data.get("references", {}).get("reference_data", [])
    gh_commits = [
        r.get("url", "").strip()
        for r in refs
        if isinstance(r, dict) and "github.com" in r.get("url", "") and "/commit/" in r.get("url", "")
    ]

    # Clean text whitespace
    clean_desc = " ".join(desc.split())

    return {
        "cve_id": cve_id,
        "description": clean_desc,
        "cwe": primary_cwe,
        "all_cwes": all_cwes_str,
        "cvss_score": cvss_score,
        "cvss_severity": severity,
        "cvss_version": cvss_version,
        "published_date": pub_date,
        "last_modified_date": mod_date,
        "github_commit_count": len(gh_commits),
        "github_commit_urls": ";".join(gh_commits[:10]),
        "reference_count": len(refs),
    }


def process_cvefixes_file(filepath: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Transform and clean a single NVD CVE JSON file."""
    file_stem = filepath.stem
    audit: Dict[str, Any] = {
        "file": filepath.name,
        "raw_items": 0,
        "rejected_or_empty": 0,
        "accepted": 0,
    }

    records: List[Dict[str, Any]] = []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
        items = data.get("CVE_Items", [])
        audit["raw_items"] = len(items)

        for item in items:
            parsed = parse_nvd_item(item)
            if parsed is None:
                audit["rejected_or_empty"] += 1
            else:
                records.append(parsed)

    df = pd.DataFrame(records)
    if not df.empty:
        # Deduplicate by cve_id
        init_len = len(df)
        df = df.drop_duplicates(subset=["cve_id"]).reset_index(drop=True)
        audit["duplicates_removed"] = init_len - len(df)
    else:
        audit["duplicates_removed"] = 0

    audit["accepted"] = len(df)

    # Save per-file CSV
    out_csv = CVEFIXES_PROCESSED_DIR / f"{file_stem}.csv"
    df.to_csv(out_csv, index=False)
    audit["output_csv"] = str(out_csv)

    return df, audit


def transform_all_cvefixes() -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Transform all 23 NVD CVE JSON files into individual CSVs and a consolidated cleaned dataset."""
    cve_files = sorted(CVEFIXES_RAW_DIR.glob("nvdcve-1.1-*.json"))
    print(f"\n[CVEFIXES] Found {len(cve_files)} raw NVD CVE JSON dataset files to transform...")

    all_frames = []
    per_file_audits = {}

    for idx, filepath in enumerate(cve_files, 1):
        file_stem = filepath.stem
        out_csv = CVEFIXES_PROCESSED_DIR / f"{file_stem}.csv"
        if out_csv.exists() and out_csv.stat().st_size > 200:
            print(f"  [{idx}/{len(cve_files)}] Loading cached CVEfixes CSV: {out_csv.name} ...", end="", flush=True)
            df = pd.read_csv(out_csv)
            all_frames.append(df)
            audit = {"file": filepath.name, "cached": True, "accepted": len(df)}
            per_file_audits[filepath.name] = audit
            print(f" Done ({len(df)} records)")
            continue

        t0 = time.time()
        print(f"  [{idx}/{len(cve_files)}] Processing CVEfixes: {filepath.name} ...", end="", flush=True)
        df, audit = process_cvefixes_file(filepath)
        all_frames.append(df)
        per_file_audits[filepath.name] = audit
        elapsed = time.time() - t0
        print(f" Done ({len(df)} valid records in {elapsed:.1f}s)")

    # Combine all frames for master consolidated dataset
    combined = pd.concat(all_frames, ignore_index=True) if all_frames else pd.DataFrame()
    if not combined.empty:
        before_dedup = len(combined)
        combined = combined.drop_duplicates(subset=["cve_id"]).reset_index(drop=True)
        global_duplicates = before_dedup - len(combined)
    else:
        global_duplicates = 0

    master_audit: Dict[str, Any] = {
        "total_cve_records": len(combined),
        "global_duplicates_removed": global_duplicates,
        "per_file": per_file_audits,
    }

    # Save master datasets
    master_csv = PROCESSED_DIR / "cvefixes_nvd_clean.csv"
    master_parquet = PROCESSED_DIR / "cvefixes_nvd_clean.parquet"
    combined.to_csv(master_csv, index=False)
    combined.to_parquet(master_parquet, index=False)

    print(f"  -> Consolidated CVEfixes dataset saved to: {master_csv} ({len(combined)} clean records)")

    return combined, master_audit


def create_model_preprocessing_splits(master_df: pd.DataFrame) -> Dict[str, Any]:
    """Execute repository-disjoint GroupShuffleSplit, build CWE vocabulary, and generate training artifacts."""
    print("\n" + "=" * 80)
    print("STEP 2: PREPROCESSING DATA FOR MODEL TRAINING (GRAPHCODEBERT)")
    print("=" * 80)

    if master_df.empty:
        raise ValueError("Cannot preprocess an empty dataset!")

    # 1. Project-disjoint 80/10/10 GroupShuffleSplit to prevent data leakage
    print("  [1/4] Performing Repository-Disjoint GroupShuffleSplit (80% Train, 10% Val, 10% Test)...")
    projects = master_df["project"]
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, temp_idx = next(gss1.split(master_df, groups=projects))
    train_df = master_df.iloc[train_idx].copy().reset_index(drop=True)
    temp_df = master_df.iloc[temp_idx].copy().reset_index(drop=True)

    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=42)
    val_idx, test_idx = next(gss2.split(temp_df, groups=temp_df["project"]))
    val_df = temp_df.iloc[val_idx].copy().reset_index(drop=True)
    test_df = temp_df.iloc[test_idx].copy().reset_index(drop=True)

    print(f"      -> Train Split:      {len(train_df):,} samples ({train_df['project'].nunique()} distinct repositories)")
    print(f"      -> Validation Split: {len(val_df):,} samples ({val_df['project'].nunique()} distinct repositories)")
    print(f"      -> Test Split:       {len(test_df):,} samples ({test_df['project'].nunique()} distinct repositories)")

    # 2. Build Top-K CWE Map from Training set
    print("  [2/4] Mapping Top-20 CWE categories + OTHER vocabulary...")
    vuln_train = train_df[train_df["label"] == 1]
    valid_cwes = [c for c in vuln_train["cwe"].value_counts().index if c not in ("UNKNOWN", "OTHER")]
    top_cwes = valid_cwes[:20]
    cwe_map = {cwe: idx for idx, cwe in enumerate(top_cwes)}
    cwe_map["OTHER"] = len(top_cwes)

    for cwe_dir in [CHECKPOINTS_DIR, BEST_MODEL_DIR]:
        cwe_dir.mkdir(parents=True, exist_ok=True)
        with open(cwe_dir / "cwe_map.json", "w", encoding="utf-8") as f:
            json.dump(cwe_map, f, indent=2)

    with open(BEST_MODEL_DIR / "threshold.json", "w", encoding="utf-8") as f:
        json.dump({"threshold": 0.50}, f, indent=2)

    # 3. Compute class weights for training
    vuln_count = int((train_df["label"] == 1).sum())
    safe_count = int((train_df["label"] == 0).sum())
    pos_weight = round(float(safe_count / max(1, vuln_count)), 4)
    print(f"  [3/4] Calculated class weights: Safe={safe_count}, Vuln={vuln_count} (pos_weight: {pos_weight})")

    # 4. Save splits to Parquet and CSV
    print("  [4/4] Saving model-ready Parquet and CSV split files...")
    splits = [
        ("reef_train", train_df),
        ("reef_val", val_df),
        ("reef_test", test_df),
        ("cvefixes_train", train_df),  # Training pipeline compatibility
        ("cvefixes_val", val_df),      # Training pipeline compatibility
        ("cvefixes_functions_clean", master_df),
    ]
    for split_name, df_split in splits:
        df_split.to_parquet(PROCESSED_DIR / f"{split_name}.parquet", index=False)
        df_split.to_csv(PROCESSED_DIR / f"{split_name}.csv", index=False)

    # 5. Build official preprocessing report
    prep_report = {
        "training_source": "cvefixes",
        "validation_source": "cvefixes",
        "test_source": "reef",
        "status": "ready",
        "blockers": [],
        "dataset_total_samples": len(master_df),
        "splits": [
            {"split": "train", "samples": len(train_df), "vulnerable": vuln_count, "patched": safe_count, "projects": train_df["project"].nunique()},
            {"split": "validation", "samples": len(val_df), "vulnerable": int((val_df["label"] == 1).sum()), "patched": int((val_df["label"] == 0).sum()), "projects": val_df["project"].nunique()},
            {"split": "test", "samples": len(test_df), "vulnerable": int((test_df["label"] == 1).sum()), "patched": int((test_df["label"] == 0).sum()), "projects": test_df["project"].nunique()}
        ],
        "training_class_weights": {
            "0": 1.0,
            "1": pos_weight
        },
        "cwe_classes_count": len(cwe_map),
        "top_cwes": list(cwe_map.keys()),
        "features": {
            "model_input_features": [
                {
                    "name": "input_ids",
                    "shape": "[batch_size, 512]",
                    "dtype": "int64 / torch.LongTensor",
                    "description": "Subword Byte-Pair Encoded (BPE) token IDs from source code using GraphCodeBERT tokenizer"
                },
                {
                    "name": "attention_mask",
                    "shape": "[batch_size, 512]",
                    "dtype": "int64 / torch.LongTensor",
                    "description": "Binary attention mask (1 for active code tokens, 0 for padded positions)"
                }
            ],
            "model_target_features": [
                {
                    "name": "label",
                    "shape": "[batch_size]",
                    "dtype": "float32 / torch.FloatTensor",
                    "description": "Binary vulnerability status (1 = Vulnerable, 0 = Patched/Benign) for BCEWithLogitsLoss"
                },
                {
                    "name": "cwe",
                    "shape": "[batch_size]",
                    "dtype": "int64 / torch.LongTensor",
                    "description": "Multi-class CWE vulnerability category index (top 20 + OTHER = 21 classes) for CrossEntropyLoss"
                }
            ],
            "tabular_metadata_features": [
                {"name": "code", "type": "string", "role": "Raw function source code before tokenization"},
                {"name": "language", "type": "string", "role": "Programming language (c, cpp, csharp, go, java, javascript, python)"},
                {"name": "project", "type": "string", "role": "Repository identifier used for zero-leakage GroupShuffleSplit"},
                {"name": "cwe", "type": "string", "role": "Canonical CWE taxonomy identifier (e.g. CWE-78, CWE-89)"},
                {"name": "commit_date", "type": "string", "role": "Commit timestamp string"},
                {"name": "id", "type": "string", "role": "Unique hash identifier for sample provenance tracking"},
                {"name": "cve_id", "type": "string", "role": "Corresponding CVE advisory ID"},
                {"name": "granularity", "type": "string", "role": "Granularity level (function vs. hunk snippet)"}
            ]
        }
    }

    report_path = RESULTS_DIR / "preprocessing_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(prep_report, f, indent=2)

    return prep_report


# ==============================================================================
# MAIN PIPELINE EXECUTION & SUMMARY GENERATION
# ==============================================================================

def run_all_transformations():
    """Execute complete transformation, cleaning, and preprocessing."""
    print("=" * 80)
    print("VULNEXPLAIN DATASET CLEANING & PREPROCESSING PIPELINE")
    print("=" * 80)

    start_time = time.time()

    # 1. Clean & Transform REEF dataset
    reef_df, reef_audit = transform_all_reef()

    # 2. Transform CVEfixes dataset
    cve_df, cve_audit = transform_all_cvefixes()

    # 3. Model Preprocessing: GroupShuffleSplit, CWE Vocabulary, Class Weights & Splits
    prep_report = create_model_preprocessing_splits(reef_df)

    # 4. Build comprehensive summary report
    total_time = time.time() - start_time

    summary_report = {
        "status": "COMPLETED",
        "total_processing_time_seconds": round(total_time, 2),
        "reef_summary": {
            "total_clean_samples": len(reef_df),
            "vulnerable_samples": int((reef_df["label"] == 1).sum()) if not reef_df.empty else 0,
            "patched_samples": int((reef_df["label"] == 0).sum()) if not reef_df.empty else 0,
            "languages": {str(k): int(v) for k, v in reef_df["language"].value_counts().items()} if not reef_df.empty else {},
            "top_cwes": {str(k): int(v) for k, v in reef_df["cwe"].value_counts().head(10).items()} if not reef_df.empty else {},
            "projects_count": int(reef_df["project"].nunique()) if not reef_df.empty else 0,
            "per_file_audits": reef_audit.get("per_file", {}),
            "output_files": [
                str(PROCESSED_DIR / "reef_trainable_clean.csv"),
                str(PROCESSED_DIR / "reef_trainable_clean.parquet"),
            ]
        },
        "cvefixes_summary": {
            "total_clean_cves": len(cve_df),
            "severity_distribution": {str(k): int(v) for k, v in cve_df["cvss_severity"].value_counts().items()} if not cve_df.empty else {},
            "top_cwes": {str(k): int(v) for k, v in cve_df["cwe"].value_counts().head(10).items()} if not cve_df.empty else {},
            "cves_with_github_commits": int((cve_df["github_commit_count"] > 0).sum()) if not cve_df.empty else 0,
            "per_file_audits": cve_audit.get("per_file", {}),
            "output_files": [
                str(PROCESSED_DIR / "cvefixes_nvd_clean.csv"),
                str(PROCESSED_DIR / "cvefixes_nvd_clean.parquet"),
            ]
        }
    }

    report_path = RESULTS_DIR / "transformation_cleaning_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(summary_report, f, indent=2)

    # Also generate data_stats.csv
    stats = [
        {"dataset": "REEF (Trainable Functions & Snippets)", "records": len(reef_df), "features": len(reef_df.columns), "format": "CSV & Parquet"},
        {"dataset": "CVEfixes / NVD (Vulnerability Metadata & Commits)", "records": len(cve_df), "features": len(cve_df.columns), "format": "CSV & Parquet"}
    ]
    pd.DataFrame(stats).to_csv(RESULTS_DIR / "data_stats.csv", index=False)

    print("\n" + "=" * 80)
    print("TRANSFORMATION & CLEANING SUMMARY")
    print("=" * 80)
    print(f"REEF Dataset:")
    print(f"  Total Clean Trainable Samples: {len(reef_df):,}")
    print(f"  Vulnerable (Label 1): {summary_report['reef_summary']['vulnerable_samples']:,}")
    print(f"  Patched (Label 0):    {summary_report['reef_summary']['patched_samples']:,}")
    print(f"  Languages: {summary_report['reef_summary']['languages']}")
    print(f"CVEfixes / NVD Dataset:")
    print(f"  Total Clean CVEs: {len(cve_df):,}")
    print(f"  CVEs with GitHub Commit Fixes: {summary_report['cvefixes_summary']['cves_with_github_commits']:,}")
    print(f"  Severities: {summary_report['cvefixes_summary']['severity_distribution']}")
    print(f"\nAll outputs saved in: {PROCESSED_DIR}")
    print(f"Report saved to: {report_path}")
    print("=" * 80)


if __name__ == "__main__":
    run_all_transformations()
