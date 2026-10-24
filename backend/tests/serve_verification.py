"""Serve the real application with isolated verification persistence."""
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("HF_HUB_OFFLINE", "1")
import db
db.DB_PATH = ROOT / "results/integration/browser_verification.db"
db.init_db()
import rag
rag.STORE_BASE_DIR = ROOT / "results/integration/browser_rag"
import main
import uvicorn
uvicorn.run(main.app, host="127.0.0.1", port=8765)
