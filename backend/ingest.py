"""Ingest module for VulnExplain.

Performs shallow clone (depth=1) of GitHub repositories into a temporary workspace,
filters files by language and size, skips vendor/build artifacts, and returns
ingested source file records.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
import git

# Language mapping
EXTENSION_TO_LANG = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".py": "python",
}

IGNORE_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "bin",
    "obj",
    "out",
    "target",
    "venv",
    ".venv",
    "__pycache__",
    ".idea",
    ".vscode",
    ".github",
}

MAX_FILE_SIZE_BYTES = 200 * 1024  # 200 KB
DEFAULT_MAX_FILES = 500


def is_binary_file(file_path: Path) -> bool:
    """Checks if a file appears to contain binary content."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\0" in chunk
    except Exception:
        return True


def ingest_repository(repo_url: str, max_files: int = DEFAULT_MAX_FILES) -> dict[str, Any]:
    """Clones or accesses repository and extracts source files."""
    repo_url = repo_url.strip()
    is_local = os.path.exists(repo_url)

    if is_local:
        clone_dir = Path(repo_url).resolve()
        temp_dir_obj = None
    else:
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="vulnexplain_repo_")
        clone_dir = Path(temp_dir_obj.name)

        try:
            print(f"Cloning {repo_url} (depth=1) to {clone_dir}...")
            git.Repo.clone_from(repo_url, str(clone_dir), depth=1)
        except Exception as e:
            if temp_dir_obj:
                temp_dir_obj.cleanup()
            raise ValueError(f"Failed to clone repository '{repo_url}': {str(e)}")

    ingested_files = []
    lang_counts = {}

    for root, dirs, files in os.walk(clone_dir):
        # In-place filter ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]

        for fname in sorted(files):
            if len(ingested_files) >= max_files:
                break

            file_path = Path(root) / fname
            ext = file_path.suffix.lower()

            if ext not in EXTENSION_TO_LANG:
                continue

            # Check file size
            try:
                size = file_path.stat().st_size
                if size > MAX_FILE_SIZE_BYTES or size == 0:
                    continue
                if is_binary_file(file_path):
                    continue

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                rel_path = str(file_path.relative_to(clone_dir))
                lang = EXTENSION_TO_LANG[ext]

                ingested_files.append({
                    "path": rel_path,
                    "abs_path": str(file_path),
                    "language": lang,
                    "content": content,
                    "size": size,
                    "lines": content.count("\n") + 1,
                })
                lang_counts[lang] = lang_counts.get(lang, 0) + 1

            except Exception as read_err:
                print(f"Skipping file {file_path}: {read_err}")

        if len(ingested_files) >= max_files:
            print(f"Reached maximum file threshold ({max_files}). Stopping ingestion.")
            break

    return {
        "repo_dir": str(clone_dir),
        "temp_obj": temp_dir_obj,  # Retained so caller can cleanup when done
        "files": ingested_files,
        "total_files": len(ingested_files),
        "languages": lang_counts,
    }
