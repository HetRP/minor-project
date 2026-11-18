"""Data settings independent of model training and torch."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REEF_RAW_DIR = BASE_DIR / "data/raw/reef"
CVEFIXES_RAW_DIR = BASE_DIR / "data/raw/cvefixes"
PROCESSED_DATA_DIR = BASE_DIR / "data/processed"
RESULTS_DIR = BASE_DIR / "results"
CHECKPOINTS_DIR = BASE_DIR / "model/checkpoints"
RANDOM_SEED = 42
SUPPORTED_LANGUAGES = ["c", "cpp", "csharp", "go", "java", "javascript", "python"]
LANGUAGE_EXTENSIONS = {".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".cxx": "cpp", ".hpp": "cpp", ".cs": "csharp", ".go": "go",
    ".java": "java", ".js": "javascript", ".jsx": "javascript", ".py": "python"}
