"""Vulnerability Localizer module for VulnExplain.

Calculates severity from CWE classification and pinpoints suspicious sink lines
using concise, language-specific dangerous pattern rules.
"""

import re
from typing import Any

# Static mapping: CWE -> Severity
CWE_SEVERITY_DICT = {
    "CWE-78": "Critical",   # OS Command Injection
    "CWE-89": "Critical",   # SQL Injection
    "CWE-94": "Critical",   # Code Injection
    "CWE-120": "Critical",  # Classic Buffer Overflow
    "CWE-119": "High",      # Memory Buffer Restriction
    "CWE-125": "High",      # Out-of-bounds Read
    "CWE-787": "High",      # Out-of-bounds Write
    "CWE-416": "High",      # Use After Free
    "CWE-22": "High",       # Path Traversal
    "CWE-269": "High",      # Privilege Management
    "CWE-287": "High",      # Improper Authentication
    "CWE-862": "High",      # Missing Authorization
    "CWE-79": "Medium",     # Cross-Site Scripting (XSS)
    "CWE-352": "Medium",    # CSRF
    "CWE-20": "Medium",     # Improper Input Validation
    "CWE-200": "Medium",    # Information Exposure
    "CWE-476": "Medium",    # NULL Pointer Dereference
    "CWE-400": "Medium",    # Uncontrolled Resource Consumption
    "CWE-190": "Medium",    # Integer Overflow
    "CWE-310": "Medium",    # Cryptographic Issues
    "OTHER": "Medium",
    "UNKNOWN": "Medium",
}

# Concise per-language dangerous sink regex patterns
DANGEROUS_SINKS = {
    "c": [
        (r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(", "Unbounded buffer copy / format sink"),
        (r"\b(system|popen)\s*\(", "Command execution sink"),
    ],
    "cpp": [
        (r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(", "Unbounded memory buffer copy"),
        (r"\b(system|popen)\s*\(", "Process execution sink"),
    ],
    "csharp": [
        (r"(?:SqlCommand|OleDbCommand)\s*\([^)]*[\+\$]", "Concatenated SQL query sink"),
        (r"Process\.Start\s*\(", "Process creation sink"),
    ],
    "go": [
        (r"exec\.Command\s*\(", "Command execution sink"),
        (r"db\.(?:Query|Exec)\s*\([^,)]*\+", "Concatenated database query"),
        (r"os\.Open(?:File)?\s*\([^,)]*\+", "Unsanitized path access sink"),
    ],
    "java": [
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "Process execution sink"),
        (r"ProcessBuilder\s*\(", "Process creation sink"),
        (r"(?:executeQuery|executeUpdate|rawQuery)\s*\([^)]*[\+\%]", "SQL string concatenation sink"),
    ],
    "javascript": [
        (r"\b(eval|Function)\s*\(", "Arbitrary code execution sink"),
        (r"\.(?:innerHTML|outerHTML|write)\s*=", "Unsafe DOM insertion sink (XSS)"),
        (r"child_process\.(?:exec|spawn)\s*\(", "Process execution sink"),
    ],
    "python": [
        (r"\b(eval|exec)\s*\(", "Arbitrary code evaluation sink"),
        (r"os\.(?:system|popen)\s*\(", "Command execution sink"),
        (r"subprocess\.(?:Popen|call|run)\s*\([^,)]*shell\s*=\s*True", "Shell command execution sink"),
        (r"pickle\.loads?\s*\(", "Insecure deserialization sink"),
        (r"\.(?:execute|raw)\s*\(\s*f?[\"'].*(?:\+|%|\.format|\{)", "Dynamic SQL string formatting sink"),
    ],
}


def get_severity(cwe: str) -> str:
    """Returns severity string for a given CWE identifier."""
    return CWE_SEVERITY_DICT.get(cwe.upper(), "Medium")


def localize_function(func_dict: dict[str, Any]) -> dict[str, Any]:
    """Identifies exact lines within the function matching dangerous sinks.

    Returns:
        dict with `severity`, `suspicious_lines` (absolute file line numbers and pattern notes).
    """
    cwe = func_dict.get("predicted_cwe", "UNKNOWN")
    severity = get_severity(cwe)
    lang = func_dict.get("language", "python")
    code = func_dict.get("code", "")
    start_line = func_dict.get("start_line", 1)

    sinks = DANGEROUS_SINKS.get(lang, [])
    # Also check universal patterns
    universal_sinks = [
        (r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|%|\.format|\$|\$\{).*FROM", "Inline dynamic SQL sink"),
        (r"(?<![\w.])(?:eval|exec|system)\s*\(", "Generic command/code evaluation sink"),
    ]

    suspicious_lines = []
    lines = code.splitlines()

    for idx, line_text in enumerate(lines):
        abs_line = start_line + idx
        matched_notes = []

        for pattern, note in sinks + universal_sinks:
            if re.search(pattern, line_text, re.IGNORECASE):
                matched_notes.append(note)

        if matched_notes:
            suspicious_lines.append({
                "line": abs_line,
                "relative_line": idx + 1,
                "snippet": line_text.strip(),
                "reason": "; ".join(sorted(set(matched_notes))),
            })

    return {
        "severity": severity,
        "suspicious_lines": suspicious_lines,
    }
