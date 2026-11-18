"""Smoke tests for VulnExplain core pipeline components.

Runs fast validation using pytest:
1. Parser function extraction across all 7 supported languages.
2. Detector probability scoring in [0, 1].
3. Flow generator producing Mermaid flowchart strings.
4. Chat intent classifier mapping 5 question types correctly.
"""

import sys
from pathlib import Path
import pytest

# Ensure backend package can be imported
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from parser import parse_file
from detector import detector
from flow import generate_flow_mermaid
from chat import detect_intent


def test_parser_extracts_all_seven_languages():
    """Verify that parser extracts functions from 3-line samples across all 7 languages."""
    samples = {
        "python": ("test.py", "def compute_sum(a, b):\n    total = a + b\n    return total"),
        "javascript": ("test.js", "function calculate(x) {\n    let val = x * 2;\n    return val;\n}"),
        "java": ("Test.java", "public class Test {\n    public int doWork(int n) {\n        return n + 1;\n    }\n}"),
        "csharp": ("Test.cs", "class App {\n    public void Run() {\n        Console.WriteLine(\"test\");\n    }\n}"),
        "c": ("test.c", "int add(int a, int b) {\n    int res = a + b;\n    return res;\n}"),
        "cpp": ("test.cpp", "int multiply(int x, int y) {\n    return x * y;\n}"),
        "go": ("test.go", "package main\nfunc Ping(h string) error {\n    return nil\n}"),
    }

    for lang, (fname, code) in samples.items():
        extracted = parse_file(fname, code, lang)
        assert len(extracted) >= 1, f"Failed to extract function for language: {lang}"
        fn = extracted[0]
        assert "name" in fn and len(fn["name"]) > 0
        assert fn["start_line"] >= 1
        assert fn["end_line"] >= fn["start_line"]
        assert len(fn["code"]) > 0


def test_detector_returns_probability_in_bounds():
    """Verify detector returns probability score between 0.0 and 1.0."""
    func_sample = {
        "id": "sample_1",
        "name": "login",
        "file": "auth.py",
        "code": "def login(user):\n    query = 'SELECT * FROM users WHERE u=' + user\n    db.execute(query)",
        "language": "python",
        "start_line": 1,
    }
    preds = detector.predict_functions([func_sample])
    assert len(preds) == 1
    score = preds[0]["prob"]
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0
    assert "is_vulnerable" in preds[0]
    assert "predicted_cwe" in preds[0]


def test_flow_mermaid_syntax():
    """Verify flow generator returns string starting with flowchart."""
    func_dict = {
        "id": "file.py:test_fn:10",
        "name": "test_fn",
        "file": "file.py",
        "start_line": 10,
        "code": "def test_fn(x):\n    cmd = 'echo ' + x\n    os.system(cmd)",
        "def_use": [{"var": "cmd", "def_line": 11, "uses": [12]}],
    }
    callers = ["main_handler:api.py:5"]
    suspicious = [{"line": 12, "reason": "os.system command execution", "snippet": "os.system(cmd)"}]

    mermaid_str = generate_flow_mermaid(func_dict, callers, suspicious)
    assert isinstance(mermaid_str, str)
    assert mermaid_str.strip().startswith("flowchart")
    assert "test_fn" in mermaid_str


def test_chat_intent_detection_five_categories():
    """Verify intent detector correctly maps 5 sample questions."""
    test_cases = [
        ("How do I fix this SQL injection vulnerability?", "fix_query"),
        ("Can you show me the execution flow and call graph for this method?", "flow_query"),
        ("What vulnerabilities and security risks were detected in this repo?", "vulnerability_query"),
        ("What is the high-level architecture and structure of this codebase?", "architecture_query"),
        ("Explain what the compute_hash function does in auth.py", "code_explanation"),
    ]

    for question, expected_intent in test_cases:
        detected = detect_intent(question)
        assert detected == expected_intent, f"Expected {expected_intent} for '{question}', got {detected}"
