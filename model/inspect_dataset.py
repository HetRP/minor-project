"""Inspect raw REEF and CVEfixes datasets.

Walks data/raw/reef/ and data/raw/cvefixes/, prints:
- Folder tree (2 levels deep)
- File types & sizes
- Row counts & schema columns / table keys
- 3 sample records
- Identified candidate fields for: code, label, cwe, language, project, commit_date
Saves inspection report to results/dataset_inspection.txt.
"""

import os
import sys
if hasattr(sys.stdout,'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8',errors='replace')
from pathlib import Path
import json
import sqlite3
import gzip
import tarfile
import xml.etree.ElementTree as ET
import pandas as pd

from config import REEF_RAW_DIR, CVEFIXES_RAW_DIR, RESULTS_DIR


def inspect_directory(dir_path: Path, max_depth: int = 100) -> list[str]:
    """Generates tree structure up to max_depth."""
    lines = [f"Tree of {dir_path}:"]
    if not dir_path.exists():
        lines.append(f"  [Directory does not exist: {dir_path}]")
        return lines

    base_depth = len(dir_path.parts)
    entries = []
    for root, dirs, files in os.walk(dir_path):
        current_depth = len(Path(root).parts) - base_depth
        if current_depth >= max_depth:
            dirs.clear()
            continue
        indent = "  " * (current_depth + 1)
        rel_root = Path(root).relative_to(dir_path)
        if str(rel_root) != ".":
            entries.append(f"{indent}DIR: {rel_root}")
        for f in files:
            p = Path(root) / f
            size_mb = p.stat().st_size / (1024 * 1024)
            entries.append(f"{indent}  FILE: {f} ({size_mb:.2f} MB)")

    if not entries:
        lines.append("  (Directory is empty)")
    else:
        lines.extend(entries)
    return lines


def identify_fields(columns: list[str]) -> dict[str, str | None]:
    """Identify column candidates based on standard naming conventions."""
    cols_lower = {c.lower(): c for c in columns}

    def find_match(candidates: list[str]) -> str | None:
        for cand in candidates:
            for col_l, original in cols_lower.items():
                if cand in col_l:
                    return original
        return None

    return {
        "code": find_match(["func_before", "code", "function", "func_src", "source_code", "func"]),
        "label": find_match(["is_vulnerable", "vul", "target", "label", "vulnerable"]),
        "cwe": find_match(["cwe", "cwe_id", "cwe_name", "vulnerability_type"]),
        "language": find_match(["lang", "language", "file_ext", "extension"]),
        "project": find_match(["repo", "project", "repository", "owner"]),
        "commit_date": find_match(["date", "commit_date", "author_date", "time", "created_at"]),
    }


def inspect_file(file_path: Path) -> list[str]:
    """Inspects a single tabular or database file."""
    lines = [f"\n--- Inspecting File: {file_path.name} ({file_path.stat().st_size / 1024:.1f} KB) ---"]
    suffix = file_path.suffix.lower()

    try:
        if file_path.name.endswith('.log.gz'):
            with gzip.open(file_path,'rt',encoding='utf-8',errors='replace') as f:
                lines.append('Gzip collection log (not model examples): '+f.read(1000))
        elif suffix in ('.tgz','.tar'):
            with tarfile.open(file_path,'r:*') as archive:
                lines.append('Archive members (not extracted): '+str([(m.name,m.size) for m in archive]))
        elif suffix=='.xml':
            count=0
            for event,node in ET.iterparse(file_path,events=('end',)):
                if node.tag.rsplit('}',1)[-1]=='Weakness': count+=1
                node.clear()
            lines.append(f'CWE XML catalog: {count} Weakness records; auxiliary taxonomy, not function examples')
        elif file_path.name.endswith('.sql.gz') or suffix == '.sql':
            opener=gzip.open if suffix=='.gz' else open
            with opener(file_path,'rt',encoding='utf-8') as f:
                lines.append('SQLite SQL dump header: '+f.read(180))
            schema=RESULTS_DIR/'cvefixes_schema.json'
            if schema.exists(): lines.append('Complete extracted schemas: '+schema.read_text())
            else: lines.append('Run prepare_data.py --restore-only to stream and inspect every table.')
        elif suffix in [".csv", ".tsv"]:
            sep = "\t" if suffix == ".tsv" else ","
            df = pd.read_csv(file_path, nrows=5, sep=sep)
            total_rows = sum(1 for _ in open(file_path, "r", encoding="utf-8", errors="ignore")) - 1
            lines.append(f"Type: Tabular ({suffix}) | Est. Row Count: {total_rows}")
            lines.append(f"Columns ({len(df.columns)}): {list(df.columns)}")
            fields = identify_fields(list(df.columns))
            lines.append(f"Identified Fields: {json.dumps(fields, indent=2)}")
            lines.append("Sample Records (up to 3):")
            for idx, row in df.head(3).iterrows():
                row_dict = {k: (str(v)[:120] + "..." if len(str(v)) > 120 else v) for k, v in row.items()}
                lines.append(f"  Sample #{idx+1}: {row_dict}")

        elif suffix == ".parquet":
            df = pd.read_parquet(file_path)
            lines.append(f"Type: Parquet | Row Count: {len(df)}")
            lines.append(f"Columns ({len(df.columns)}): {list(df.columns)}")
            fields = identify_fields(list(df.columns))
            lines.append(f"Identified Fields: {json.dumps(fields, indent=2)}")
            lines.append("Sample Records (up to 3):")
            for idx, row in df.head(3).iterrows():
                row_dict = {k: (str(v)[:120] + "..." if len(str(v)) > 120 else v) for k, v in row.items()}
                lines.append(f"  Sample #{idx+1}: {row_dict}")

        elif suffix in [".json", ".jsonl"]:
            records = []
            if suffix == ".jsonl":
                with open(file_path, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f):
                        if i < 5:
                            records.append(json.loads(line.strip()))
                    lines.append(f'Exact JSONL row count: {i+1 if records else 0}')
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    records = data[:5] if isinstance(data, list) else [data]

            lines.append(f"Type: JSON/JSONL | Sampled Records: {len(records)}")
            if records and isinstance(records[0], dict):
                cols = list(records[0].keys())
                lines.append(f"Keys ({len(cols)}): {cols}")
                fields = identify_fields(cols)
                lines.append(f"Identified Fields: {json.dumps(fields, indent=2)}")
                if 'details' in records[0]:
                    lines.append('Nested file keys: '+str(list((records[0]['details'] or [{}])[0])))
                    lines.append('Labels require verified raw_code/unified patch reconstruction, not flat-column guessing.')
                lines.append("Sample Records (up to 3):")
                for idx, r in enumerate(records[:3]):
                    r_summary = {k: (str(v)[:120] + "..." if len(str(v)) > 120 else v) for k, v in r.items()}
                    lines.append(f"  Sample #{idx+1}: {r_summary}")

        elif suffix in [".db", ".sqlite", ".sqlite3"]:
            conn = sqlite3.connect(f'file:{file_path.as_posix()}?mode=ro',uri=True)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cur.fetchall()]
            lines.append(f"Type: SQLite Database | Tables ({len(tables)}): {tables}")
            for t in tables:
                cur.execute(f"PRAGMA table_info({t});")
                cols = [c[1] for c in cur.fetchall()]
                cur.execute(f"SELECT COUNT(*) FROM {t};")
                cnt = cur.fetchone()[0]
                lines.append(f"  Table `{t}` ({cnt} rows): cols={cols}")
                fields = identify_fields(cols)
                lines.append(f"    Mapped fields: {fields}")
            conn.close()
        else:
            lines.append(f"Type: Other/Text ({suffix})")
    except Exception as e:
        lines.append(f"Error inspecting {file_path.name}: {e}")

    return lines


def run_inspection():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report_lines = [
        "=" * 80,
        "VULNEXPLAIN DATASET INSPECTION REPORT",
        "=" * 80,
    ]

    report_lines.append("\n[1] REEF DIRECTORY (data/raw/reef/)")
    report_lines.extend(inspect_directory(REEF_RAW_DIR))
    reef_files = list(REEF_RAW_DIR.rglob("*.*"))
    if not reef_files:
        report_lines.append("NOTICE: No raw REEF files found in data/raw/reef/.")
        report_lines.append("See docs/DATASETS.md for download instructions.")
    else:
        for f in reef_files:
            if f.suffix in [".csv", ".tsv", ".parquet", ".json", ".jsonl", ".db", ".sqlite"]:
                report_lines.extend(inspect_file(f))

    report_lines.append("\n" + "=" * 80)
    report_lines.append("\n[2] CVEFIXES DIRECTORY (data/raw/cvefixes/)")
    report_lines.extend(inspect_directory(CVEFIXES_RAW_DIR))
    cvefixes_files = list(CVEFIXES_RAW_DIR.rglob("*.*"))
    if not cvefixes_files:
        report_lines.append("NOTICE: No raw CVEfixes files found in data/raw/cvefixes/.")
        report_lines.append("See docs/DATASETS.md for download instructions.")
    else:
        for f in cvefixes_files:
            if f.suffix in [".csv", ".tsv", ".parquet", ".json", ".jsonl", ".db", ".sqlite", ".gz", ".sql", ".xml", ".tgz"]:
                report_lines.extend(inspect_file(f))

    report_path = RESULTS_DIR / "dataset_inspection.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")

    print("\n".join(report_lines))
    print(f"\nInspection complete. Report saved to: {report_path}")


if __name__ == "__main__":
    run_inspection()
