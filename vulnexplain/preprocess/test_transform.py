import json
import re
import hashlib
from pathlib import Path
import pandas as pd

LANGUAGE_EXTENSIONS = {
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".cxx": "cpp", ".hpp": "cpp", ".cs": "csharp", ".go": "go",
    ".java": "java", ".js": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".py": "python"
}

def normalize_language(lang_val, filename=None):
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
        "go": "go", "golang": "go", "java": "java",
        "js": "javascript", "javascript": "javascript",
        "py": "python", "python": "python",
    }
    return mapping.get(raw, None)

def normalize_cwe(cwe_val):
    if isinstance(cwe_val, (list, tuple)):
        cwe_val = next((v for v in cwe_val if re.search(r"CWE[-_]?\d+", str(v), re.I)), None)
    if not cwe_val or pd.isna(cwe_val):
        return "UNKNOWN"
    s = str(cwe_val).strip().upper()
    match = re.search(r"CWE[-_]?(\d+)", s)
    if match:
        return f"CWE-{match.group(1)}"
    return "UNKNOWN"

def normalize_project(url):
    m = re.search(r"github\.com/([^/]+/[^/]+)", str(url))
    if m:
        return m.group(1).removesuffix(".git").lower()
    return "unknown"

def reverse_patch_file(patched_code, patch_str):
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
    hunk_data.sort(key=lambda x: x[0], reverse=True)
    res_lines = list(patched_lines)
    for new_start, old_lines, new_lines in hunk_data:
        idx = new_start - 1
        res_lines[idx : idx + len(new_lines)] = old_lines
    return "\n".join(res_lines)

def extract_hunks_with_context(patch_str):
    hunks = [h for h in re.split(r"(?m)^(?=@@ -\d+)", patch_str) if h.strip().startswith("@@")]
    pairs = []
    for idx, h in enumerate(hunks):
        lines = h.split("\n")
        body = lines[1:] if len(lines) > 1 else []
        del_lines = [l[1:] for l in body if l.startswith("-") and not l.startswith("---")]
        add_lines = [l[1:] for l in body if l.startswith("+") and not l.startswith("+++")]
        
        pre_snippet = "\n".join(l[1:] if (l.startswith("-") or l.startswith(" ")) else l for l in body if not l.startswith("+")).strip()
        post_snippet = "\n".join(l[1:] if (l.startswith("+") or l.startswith(" ")) else l for l in body if not l.startswith("-")).strip()
        
        if pre_snippet and post_snippet and (len(del_lines) > 0 or len(add_lines) > 0):
            pairs.append((idx, pre_snippet, post_snippet))
    return pairs

def test_on_file(filepath):
    print("Testing on:", filepath)
    count = 0
    samples = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            count += 1
            row = json.loads(line)
            cve_id = row.get("cve_id", "UNKNOWN")
            cwe = normalize_cwe(row.get("CWEs"))
            proj = normalize_project(row.get("html_url", row.get("url", "")))
            details = row.get("details", [])
            for det_idx, det in enumerate(details):
                raw_code = det.get("raw_code", "")
                patch = det.get("patch", "")
                raw_url = det.get("raw_url", "")
                lang = normalize_language(row.get("language"), raw_url)
                if not lang or not raw_code or not patch or not patch.startswith("@@"):
                    continue
                pairs = extract_hunks_with_context(patch)
                for hunk_idx, pre_code, post_code in pairs:
                    if len(pre_code) > 20:
                        h_pre = hashlib.sha256(f"{cve_id}:{det_idx}:{hunk_idx}:1".encode()).hexdigest()[:16]
                        samples.append({
                            "id": f"reef_{h_pre}",
                            "code": pre_code,
                            "label": 1,
                            "language": lang,
                            "cwe": cwe,
                            "project": proj,
                            "cve_id": cve_id,
                            "commit_date": ""
                        })
                    if len(post_code) > 20:
                        h_post = hashlib.sha256(f"{cve_id}:{det_idx}:{hunk_idx}:0".encode()).hexdigest()[:16]
                        samples.append({
                            "id": f"reef_{h_post}",
                            "code": post_code,
                            "label": 0,
                            "language": lang,
                            "cwe": cwe,
                            "project": proj,
                            "cve_id": cve_id,
                            "commit_date": ""
                        })
    df = pd.DataFrame(samples)
    print(f"Processed {count} commits -> Extracted {len(df)} samples")
    print("Label distribution:\n", df["label"].value_counts().to_dict())
    print("Sample:\n", df.head(2).to_dict("records"))

if __name__ == "__main__":
    test_on_file("data/raw/reef/query_C#.jsonl")
