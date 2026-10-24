"""GraphCodeBERT Vulnerability Detector module for VulnExplain.

Loads model weights once at startup, performs batch inference at the function level,
evaluates probabilities against threshold.json, and predicts CWE classifications.
Gracefully operates in heuristic mode if trained weights are not yet present.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Any
import torch

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "model"
CHECKPOINT_DIR = MODEL_DIR / "checkpoints" / "best"

# Ensure both vulnexplain root and model dir are in sys.path for runtime imports
for path_entry in (str(BASE_DIR), str(MODEL_DIR)):
    if path_entry not in sys.path:
        sys.path.insert(0, path_entry)

try:
    from model.config import MODEL_NAME, MAX_SEQ_LENGTH, get_device
    from model.train import VulnGraphCodeBERT, tokenize_code
    from transformers import AutoTokenizer
except ImportError:
    try:
        from config import MODEL_NAME, MAX_SEQ_LENGTH, get_device
        from train import VulnGraphCodeBERT, tokenize_code
        from transformers import AutoTokenizer
    except ImportError:
        MODEL_NAME = "microsoft/graphcodebert-base"
        MAX_SEQ_LENGTH = 512
        get_device = lambda: torch.device("cpu")
        VulnGraphCodeBERT = None


class VulnerabilityDetector:
    """Manages GraphCodeBERT model loading and function-level inference."""

    def __init__(self):
        self.device = get_device()
        self.model = None
        self.tokenizer = None
        self.threshold = 0.50
        self.cwe_map: dict[str, int] = {}
        self.inv_cwe_map: dict[int, str] = {}
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        """Loads model checkpoint, tokenizer, cwe_map, and threshold."""
        weights_file = CHECKPOINT_DIR / "pytorch_model.bin"
        if weights_file.exists():
            # A broken trained installation must never masquerade as neural inference.
            if VulnGraphCodeBERT is None:
                raise RuntimeError("Trained weights exist but model dependencies cannot be imported")
            for name in ("threshold.json", "cwe_map.json", "tokenizer.json", "config.json", "training_config.json"):
                if not (CHECKPOINT_DIR / name).is_file():
                    raise RuntimeError(f"Incomplete trained checkpoint: missing {name}")
            config = json.loads((CHECKPOINT_DIR / "training_config.json").read_text(encoding="utf-8"))
            if config.get("status") != "completed" or config.get("smoke_test"):
                raise RuntimeError("Detector requires a completed, non-smoke training checkpoint")
            self.threshold = float(json.loads((CHECKPOINT_DIR / "threshold.json").read_text())["threshold"])
            if not 0 < self.threshold < 1 or self.threshold != config["threshold"]:
                raise RuntimeError("Invalid or inconsistent classification threshold")
            self.cwe_map = json.loads((CHECKPOINT_DIR / "cwe_map.json").read_text())
            if sorted(self.cwe_map.values()) != list(range(len(self.cwe_map))):
                raise RuntimeError("CWE mapping must contain contiguous unique class indices")
            self.inv_cwe_map = {v: k for k, v in self.cwe_map.items()}
            self.tokenizer = AutoTokenizer.from_pretrained(CHECKPOINT_DIR, local_files_only=True)
            self.model = VulnGraphCodeBERT(str(CHECKPOINT_DIR), len(self.cwe_map), from_local_config=True)
            self.model.load_state_dict(torch.load(weights_file, map_location="cpu", weights_only=True), strict=True)
            self.model.to(self.device).eval()
            self.is_loaded = True
            print(f"Trained GraphCodeBERT loaded on {self.device}; threshold={self.threshold}")
            return
        print("NOTICE: Detector weights not found at model/checkpoints/best/pytorch_model.bin.")
        print("Running in AST heuristic detector mode (backend will not crash).")
        self.is_loaded = False

    def _heuristic_score(self, func: dict[str, Any]) -> tuple[float, str, float]:
        """Static pattern heuristic used when PyTorch checkpoint has not yet been trained."""
        code = func.get("code", "")
        lang = func.get("language", "python")

        patterns = [
            # OS Command Injection
            (r"(?:system|exec|popen|subprocess\.Popen|subprocess\.call|Runtime\.getRuntime\(\)\.exec)\s*\(", "CWE-78", 0.88),
            # SQL Injection
            (r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|%|\.format|\$|\$\{).*FROM", "CWE-89", 0.85),
            (r"(?:execute|executeQuery|rawQuery)\s*\(\s*[\"'].*\%|\+", "CWE-89", 0.82),
            # Buffer Overflow
            (r"(?:strcpy|strcat|sprintf|gets)\s*\(", "CWE-120", 0.86),
            # XSS
            (r"(?:innerHTML|outerHTML|document\.write)\s*=", "CWE-79", 0.80),
            # Code Execution
            (r"(?:eval|exec)\s*\(", "CWE-94", 0.87),
            # Path Traversal
            (r"(?:\.\./|\.\.\\|readFile\(.*(?:\+|param))", "CWE-22", 0.79),
            # Insecure Deserialization
            (r"(?:pickle\.loads|yaml\.load\([^,)]+\))", "CWE-20", 0.84),
        ]

        for pat, cwe, prob in patterns:
            if re.search(pat, code, re.IGNORECASE):
                return prob, cwe, 0.90

        # Base non-vulnerable score
        return 0.12, "OTHER", 0.20

    def predict_functions(self, functions: list[dict[str, Any]], batch_size: int = 8) -> list[dict[str, Any]]:
        """Scores all functions and annotates them with vulnerability probabilities."""
        if not functions:
            return []

        # If model is not loaded, use heuristic scoring
        if not self.is_loaded or self.model is None or self.tokenizer is None:
            results = []
            for f in functions:
                prob, cwe, conf = self._heuristic_score(f)
                res = dict(f)
                res["prob"] = prob
                res["prediction_source"] = "heuristic"
                res["is_vulnerable"] = prob >= self.threshold
                res["predicted_cwe"] = cwe
                res["cwe_confidence"] = round(conf, 4)
                results.append(res)
            return results

        # Run batch model inference
        results = []
        for i in range(0, len(functions), batch_size):
            batch_funcs = functions[i:i + batch_size]
            codes = [f.get("code", "") for f in batch_funcs]

            try:
                encoded = [tokenize_code(self.tokenizer, code, MAX_SEQ_LENGTH) for code in codes]
                encoding = {key: torch.cat([row[key] for row in encoded]) for key in ("input_ids", "attention_mask")}
                input_ids = encoding["input_ids"].to(self.device)
                attention_mask = encoding["attention_mask"].to(self.device)

                with torch.inference_mode(), torch.autocast(device_type=self.device.type, enabled=self.device.type == "cuda"):
                    vuln_logits, cwe_logits = self.model(input_ids, attention_mask)
                    probs = torch.sigmoid(vuln_logits.float()).cpu().numpy().tolist()
                    cwe_softmax = torch.softmax(cwe_logits.float(), dim=-1)
                    cwe_confs, cwe_indices = torch.max(cwe_softmax, dim=-1)
                    cwe_confs = cwe_confs.cpu().numpy().tolist()
                    cwe_indices = cwe_indices.cpu().numpy().tolist()

                for j, f in enumerate(batch_funcs):
                    prob = float(probs[j]) if isinstance(probs, list) else float(probs)
                    cwe_idx = int(cwe_indices[j]) if isinstance(cwe_indices, list) else int(cwe_indices)
                    conf = float(cwe_confs[j]) if isinstance(cwe_confs, list) else float(cwe_confs)
                    cwe_name = self.inv_cwe_map.get(cwe_idx, "OTHER")

                    res = dict(f)
                    res["prob"] = prob
                    res["prediction_source"] = "graphcodebert"
                    res["is_vulnerable"] = prob >= self.threshold
                    res["predicted_cwe"] = cwe_name
                    res["cwe_confidence"] = round(conf, 4)
                    results.append(res)
            except Exception as e:
                raise RuntimeError("Trained GraphCodeBERT inference failed; heuristic substitution disabled") from e

        return results


# Global singleton instance
detector = VulnerabilityDetector()
