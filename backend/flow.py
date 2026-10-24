"""Program analysis vulnerability flow generator for VulnExplain.

Constructs Mermaid flowchart TD diagrams purely from static AST call graphs
and intra-function def-use chains. NEVER uses LLM hallucinations.
"""

import re
from typing import Any


def sanitize_label(text: str) -> str:
    """Sanitizes text for safe inclusion inside Mermaid node labels."""
    cleaned = text.replace('"', "'").replace("\n", " ").replace("`", "").strip()
    cleaned = re.sub(r"[\{\}\[\]\<\>]", "", cleaned)
    return cleaned[:65]


def generate_flow_mermaid(
    func_dict: dict[str, Any],
    callers: list[str],
    suspicious_lines: list[dict[str, Any]],
    max_nodes: int = 15,
) -> str:
    """Builds a deterministic Mermaid flowchart TD representation of the vulnerability path."""
    func_name = func_dict.get("func_name", func_dict.get("name", "function"))
    file_name = func_dict.get("file", "unknown")
    start_line = func_dict.get("start_line", 1)
    def_use_list = func_dict.get("def_use", [])

    lines = ["flowchart TD"]
    node_counter = 0

    def next_id():
        nonlocal node_counter
        node_counter += 1
        return f"N{node_counter}"

    # 1. Flagged Function Entry Node
    entry_id = next_id()
    entry_label = sanitize_label(f"Function: {func_name} ({file_name}:{start_line})")
    lines.append(f'    {entry_id}["{entry_label}"]')

    # 2. Callers / Inbound Paths
    if callers:
        for c in callers[:2]:
            c_id = next_id()
            c_label = sanitize_label(f"Caller: {c.split(':')[-2] if ':' in c else c}")
            lines.append(f'    {c_id}["{c_label}"] --> {entry_id}')
    else:
        ext_id = next_id()
        lines.append(f'    {ext_id}["No callers resolved - entry point unknown"] --> {entry_id}')

    # 3. Intra-Function Data Flow (Def-Use Chains)
    last_node = entry_id
    tracked_nodes = 3

    if def_use_list:
        for item in def_use_list[:3]:
            if tracked_nodes >= max_nodes - 3:
                break
            var = sanitize_label(str(item.get("var", "var")))
            d_line = item.get("def_line", start_line)
            u_lines = item.get("uses", [])

            # Def Node
            def_node_id = next_id()
            def_label = sanitize_label(f"Def: '{var}' (line {d_line})")
            lines.append(f'    {def_node_id}["{def_label}"]')
            lines.append(f"    {last_node} --> {def_node_id}")
            last_node = def_node_id
            tracked_nodes += 1

            # Use Node
            if u_lines:
                use_node_id = next_id()
                u_line = u_lines[0]
                use_label = sanitize_label(f"Use: '{var}' referenced (line {u_line})")
                lines.append(f'    {use_node_id}["{use_label}"]')
                lines.append(f"    {def_node_id} --> {use_node_id}")
                last_node = use_node_id
                tracked_nodes += 1

    # 4. Dangerous Sink Node(s)
    sink_ids = []
    if suspicious_lines:
        for sink in suspicious_lines[:2]:
            if tracked_nodes >= max_nodes:
                break
            s_id = next_id()
            s_line = sink.get("line", start_line)
            reason = sanitize_label(sink.get("reason", "Vulnerable Sink"))
            snip = sanitize_label(sink.get("snippet", ""))[:30]
            s_label = sanitize_label(f"⚠️ SINK (line {s_line}): {snip} [{reason}]")

            lines.append(f'    {s_id}["{s_label}"]')
            lines.append(f"    {last_node} ==> {s_id}")
            sink_ids.append(s_id)
            tracked_nodes += 1
    else:
        s_id = next_id()
        lines.append(f'    {s_id}["No matching dangerous sink localized"]')
        lines.append(f"    {last_node} --> {s_id}")

    # Apply styling classes
    lines.append("    classDef sinkStyle fill:#ffe6e6,stroke:#cc0000,stroke-width:2px,color:#990000;")
    lines.append("    classDef entryStyle fill:#e6f3ff,stroke:#0066cc,stroke-width:2px,color:#003366;")
    lines.append(f"    class {entry_id} entryStyle;")
    for s_id in sink_ids:
        lines.append(f"    class {s_id} sinkStyle;")

    return "\n".join(lines)
