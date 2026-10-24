"""Probabilistic validation module for VulnExplain.

Re-scores patched functions through the detector, runs AST syntax verification,
and assigns an empirical verdict (improved / unchanged / worse).
"""

import ast
from typing import Any
from detector import detector
from parser import _try_get_ts_parser


def verify_syntax(code: str, lang: str) -> tuple[bool, str]:
    """Checks whether the code parses cleanly without syntax errors."""
    # Try Tree-Sitter first
    ts_parser = _try_get_ts_parser(lang)
    if ts_parser:
        try:
            tree = ts_parser.parse(bytes(code, "utf-8"))
            if hasattr(tree.root_node, "has_error") and tree.root_node.has_error:
                return False, "Tree-sitter detected syntax ERROR node in patched code"
            return True, "AST syntax check passed cleanly"
        except Exception as e:
            return False, f"Tree-sitter parse exception: {e}"

    # Fallback syntax checks
    if lang == "python":
        try:
            ast.parse(code)
            return True, "Python AST syntax verified"
        except SyntaxError as se:
            return False, f"Python SyntaxError: {se.msg} (line {se.lineno})"

    # Universal brace & balance check for C, C++, Java, JS, C#, Go
    open_braces = code.count("{")
    close_braces = code.count("}")
    if open_braces != close_braces:
        return False, f"Unbalanced braces: {open_braces} open vs {close_braces} close"

    return True, "Basic structural checks passed"


def validate_remediation(
    original_func: dict[str, Any],
    patched_code: str,
) -> dict[str, Any]:
    """Evaluates patched code security posture and syntax integrity."""
    prob_before = float(original_func.get("prob", 0.50))
    lang = original_func.get("language", "python")
    func_name = original_func.get("func_name", original_func.get("name", "function"))

    # 1. Syntax Verification
    syntax_ok, syntax_msg = verify_syntax(patched_code, lang)

    # 2. Re-run Detector on Patched Code
    mock_func_entry = {
        "id": "patched_eval",
        "name": func_name,
        "code": patched_code,
        "language": lang,
        "file": original_func.get("file", "patched"),
        "start_line": 1,
    }
    pred_results = detector.predict_functions([mock_func_entry])
    if not pred_results:
        raise RuntimeError("Detector returned no prediction for remediation validation")
    prob_after = float(pred_results[0]["prob"])
    cwe_after = pred_results[0]["predicted_cwe"]

    # If syntax failed, don't reward
    if not syntax_ok:
        verdict = "worse"
    elif prob_after < prob_before - 0.05:
        verdict = "improved"
    elif abs(prob_after - prob_before) <= 0.05:
        verdict = "unchanged"
    else:
        verdict = "worse"

    return {
        "prob_before": round(prob_before, 4),
        "prob_after": round(prob_after, 4),
        "delta": round(prob_after - prob_before, 4),
        "syntax_ok": syntax_ok,
        "syntax_message": syntax_msg,
        "cwe_after": cwe_after,
        "verdict": verdict,
        "disclaimer": (
            "Probabilistic AI validation based on GraphCodeBERT neural embeddings and AST syntax checks. "
            "This provides empirical risk reduction scoring rather than mathematical formal proof."
        ),
    }
