"""Configuration constants and paths for VulnExplain model training and inference.
"""

from pathlib import Path
import hashlib
import torch

def file_sha256(path):
    digest=hashlib.sha256()
    with open(path,'rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''): digest.update(block)
    return digest.hexdigest()

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
REEF_RAW_DIR = RAW_DATA_DIR / "reef"
CVEFIXES_RAW_DIR = RAW_DATA_DIR / "cvefixes"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

CHECKPOINTS_DIR = BASE_DIR / "model" / "checkpoints"
BEST_MODEL_DIR = CHECKPOINTS_DIR / "best"
RESULTS_DIR = BASE_DIR / "results"

# Supported programming languages (normalized)
SUPPORTED_LANGUAGES = [
    "c",
    "cpp",
    "csharp",
    "go",
    "java",
    "javascript",
    "python",
]

# File extensions mapping to normalized language names
LANGUAGE_EXTENSIONS = {
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

# Model architecture & training hyperparameters
MODEL_NAME = "microsoft/graphcodebert-base"
MAX_SEQ_LENGTH = 512
BATCH_SIZE = 8
LEARNING_RATE = 2e-5
NUM_EPOCHS = 3
WEIGHT_DECAY = 0.01
RANDOM_SEED = 42
CWE_LOSS_WEIGHT = 0.3

# Default decision threshold (refined during validation in train.py)
DEFAULT_THRESHOLD = 0.50

# Severity mapping for common CWE categories
CWE_SEVERITY_MAP = {
    "CWE-78": "Critical",   # OS Command Injection
    "CWE-89": "Critical",   # SQL Injection
    "CWE-94": "Critical",   # Code Injection
    "CWE-120": "Critical",  # Classic Buffer Overflow
    "CWE-119": "High",      # Memory Buffer Restriction
    "CWE-125": "High",      # Out-of-bounds Read
    "CWE-787": "High",      # Out-of-bounds Write
    "CWE-416": "High",      # Use After Free
    "CWE-476": "Medium",    # NULL Pointer Dereference
    "CWE-79": "Medium",     # Cross-site Scripting (XSS)
    "CWE-22": "High",       # Path Traversal
    "CWE-352": "Medium",    # CSRF
    "CWE-20": "Medium",     # Improper Input Validation
    "CWE-200": "Medium",    # Information Exposure
    "CWE-269": "High",      # Privilege Management
    "CWE-287": "High",      # Improper Authentication
    "CWE-310": "Medium",    # Cryptographic Issues
    "CWE-400": "Medium",    # Uncontrolled Resource Consumption (DoS)
    "CWE-862": "High",      # Missing Authorization
    "CWE-190": "Medium",    # Integer Overflow
    "OTHER": "Medium",
    "UNKNOWN": "Medium",
}


def get_device() -> torch.device:
    """Returns CUDA if available, MPS for Apple Silicon if functional, otherwise CPU."""
    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")
