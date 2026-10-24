"""Automated code remediation and diff generation module for VulnExplain.

Uses LLM with prompt-injection boundaries to remediate vulnerabilities and
generates clean unified diffs using Python's standard difflib.
"""

import difflib
import re
from typing import Any
from llm import ask, sanitize_untrusted_code


def extract_code_from_markdown(text: str) -> str:
    """Extracts code block from markdown fences if present."""
    match = re.search(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def generate_fix(func_dict: dict[str, Any], flow_mermaid: str = "") -> dict[str, str]:
    """Requests remediated function from LLM and generates unified diff."""
    func_name = func_dict.get("func_name", func_dict.get("name", "function"))
    original_code = func_dict.get("code", "")
    cwe = func_dict.get("cwe", func_dict.get("predicted_cwe", "UNKNOWN"))
    lang = func_dict.get("language", "python")
    file_path = func_dict.get("file", "source_file")

    system_prompt = (
        "You are an expert secure coding software engineer. You will receive a vulnerable function.\n"
        "Your task: Return ONLY the complete, corrected, secure version of the function.\n"
        "Requirements:\n"
        "1. Fix the vulnerability completely (parameterize queries, sanitize inputs, enforce bounds, or use safe APIs).\n"
        "2. Preserve the exact function name, arguments, and return types where possible.\n"
        "3. Do NOT add conversational preamble or conversational sign-off. Output ONLY the code inside standard markdown fences (```)."
    )

    untrusted_code = sanitize_untrusted_code(original_code)
    user_prompt = (
        f"Language: {lang}\n"
        f"Function Name: {func_name}\n"
        f"Target Vulnerability: {cwe}\n"
        f"Flow Context:\n{flow_mermaid}\n\n"
        f"Vulnerable Implementation:\n{untrusted_code}\n\n"
        "Generate the secure patched implementation:"
    )

    raw_response = ask(system_prompt, user_prompt, max_tokens=1000)
    patched_code = extract_code_from_markdown(raw_response)

    # Offline guidance is not executable remediation. Preserve the real function.
    available = bool(patched_code and patched_code != original_code and not patched_code.startswith("// Offline Remediation Template"))
    if not available:
        patched_code = original_code

    # Generate unified diff
    orig_lines = original_code.splitlines(keepends=True)
    patch_lines = patched_code.splitlines(keepends=True)

    diff_lines = list(difflib.unified_diff(
        orig_lines,
        patch_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    ))
    diff_text = "\n".join(diff_lines)

    return {
        "original_code": original_code,
        "patched_code": patched_code,
        "diff": diff_text if diff_text else "",
        "available": available,
        "message": "" if available else "No executable patch was generated. Configure a working LLM provider and review changes manually.",
    }
