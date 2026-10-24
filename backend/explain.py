"""Step-by-step grounded vulnerability explanation generator for VulnExplain.

Splits vulnerable functions into logical blocks and produces:
1. Overall summary (what it does, why vulnerable, security impact)
2. Block-by-block targeted explanations for progressive disclosure in the UI.
"""

import json
import re
from typing import Any
from llm import ask, sanitize_untrusted_code


def split_into_blocks(code: str, base_line: int = 1, max_blocks: int = 6) -> list[dict[str, Any]]:
    """Splits function code into 2 to 6 logical statement blocks."""
    lines = code.splitlines()
    if not lines:
        return []

    # Identify break candidates (blank lines or major control statements)
    break_indices = []
    for idx, l in enumerate(lines):
        if not l.strip() or re.match(r"^\s*(?:if|for|while|try|switch|return)\b", l):
            break_indices.append(idx)

    # If too few breaks, split evenly
    if len(break_indices) < 2:
        step = max(1, len(lines) // max_blocks)
        break_indices = list(range(step, len(lines), step))

    # Cluster breaks into up to max_blocks
    total_lines = len(lines)
    chunk_size = max(1, total_lines // max_blocks)
    cutoffs = sorted(list(set([0] + [i for i in break_indices if i < total_lines] + [total_lines])))

    # Merge small chunks
    merged = [0]
    for c in cutoffs[1:]:
        if (c - merged[-1]) >= max(2, total_lines // (max_blocks * 2)):
            merged.append(c)
    if merged[-1] != total_lines:
        merged.append(total_lines)

    # Enforce max_blocks limit
    if len(merged) - 1 > max_blocks:
        step = len(lines) / max_blocks
        merged = [int(i * step) for i in range(max_blocks)] + [total_lines]

    blocks = []
    for i in range(len(merged) - 1):
        start_idx = merged[i]
        end_idx = merged[i + 1]
        b_lines = lines[start_idx:end_idx]
        b_code = "\n".join(b_lines)
        if not b_code.strip():
            continue

        blocks.append({
            "index": len(blocks),
            "start_line": base_line + start_idx,
            "end_line": base_line + end_idx - 1,
            "code": b_code,
            "explanation": None,
        })

    # If empty, return entire code as single block
    if not blocks:
        blocks.append({
            "index": 0,
            "start_line": base_line,
            "end_line": base_line + len(lines) - 1,
            "code": code,
            "explanation": None,
        })

    return blocks


def generate_overall_summary(func_name: str, code: str, cwe: str, severity: str, flow_mermaid: str) -> dict[str, str]:
    """Generates overall summary (what it does, why vulnerable, impact) using LLM."""
    system_prompt = (
        "You are an expert vulnerability analyst. Analyze the provided code, predicted CWE, and flow graph.\n"
        "Return a JSON object with EXACTLY three string keys:\n"
        '{"what_it_does": "...", "why_vulnerable": "...", "impact": "..."}\n'
        "Do not include any other markdown or wrapper text outside the JSON object."
    )

    untrusted_code = sanitize_untrusted_code(code)
    user_prompt = (
        f"Function Name: {func_name}\n"
        f"Predicted CWE: {cwe}\n"
        f"Severity: {severity}\n"
        f"Program Flow Graph:\n{flow_mermaid}\n\n"
        f"Untrusted Function Implementation:\n{untrusted_code}\n\n"
        "Provide your analysis JSON."
    )

    raw = ask(system_prompt, user_prompt, max_tokens=600)
    # Parse JSON output
    try:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            parsed = json.loads(match.group(0))
            return {
                "what_it_does": parsed.get("what_it_does", f"Implements {func_name} logic."),
                "why_vulnerable": parsed.get("why_vulnerable", f"Susceptible to {cwe} due to missing input validation."),
                "impact": parsed.get("impact", f"Security impact rated as {severity}."),
            }
    except Exception:
        pass

    return {
        "what_it_does": f"Source-specific explanation unavailable for '{func_name}'; review the displayed code and static flow.",
        "why_vulnerable": f"The detector predicted {cwe}. This prediction does not establish an exploitable vulnerability.",
        "impact": f"Assigned severity: {severity}. Actual security impact has not been verified.",
    }


def explain_single_block(
    func_name: str,
    block_index: int,
    block_code: str,
    full_code: str,
    cwe: str,
    flow_mermaid: str,
) -> str:
    """Produces a targeted explanation for one code block in the context of the vulnerability flow."""
    system_prompt = (
        "You are a code security reviewer explaining a vulnerability step-by-step.\n"
        "Explain specifically what THIS CODE BLOCK does and its role in the overall vulnerability path.\n"
        "Keep the explanation concise (2-3 sentences), factual, and directly tied to the code."
    )

    untrusted_block = sanitize_untrusted_code(block_code)
    user_prompt = (
        f"Function: {func_name}\n"
        f"Vulnerability Type: {cwe}\n"
        f"Flow Graph:\n{flow_mermaid}\n\n"
        f"Code Block #{block_index + 1}:\n{untrusted_block}\n\n"
        "Explain this specific block's role in the execution flow:"
    )

    return ask(system_prompt, user_prompt, max_tokens=250)


def initialize_explanation_bundle(func_dict: dict[str, Any], flow_mermaid: str) -> dict[str, Any]:
    """Prepares the initial explanation structure with blocks and overall summary."""
    func_name = func_dict.get("func_name", func_dict.get("name", "function"))
    code = func_dict.get("code", "")
    cwe = func_dict.get("cwe", func_dict.get("predicted_cwe", "UNKNOWN"))
    severity = func_dict.get("severity", "Medium")
    start_line = func_dict.get("start_line", 1)

    blocks = split_into_blocks(code, base_line=start_line, max_blocks=6)
    summary = generate_overall_summary(func_name, code, cwe, severity, flow_mermaid)

    # Pre-generate explanation for block 0 so UI has immediate content
    if blocks:
        blocks[0]["explanation"] = explain_single_block(
            func_name, 0, blocks[0]["code"], code, cwe, flow_mermaid
        )

    return {
        "summary": summary,
        "blocks": blocks,
        "total_blocks": len(blocks),
    }
