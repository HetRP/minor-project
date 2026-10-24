"""Tree-sitter and AST-based multilingual code parser for VulnExplain.

Extracts functions/methods across C, C++, C#, Go, Java, JavaScript, and Python.
Constructs repo-level call graphs and intra-function data-flow (def-use) edges.
Includes a regex-based fallback parser for high-reliability execution.
"""

import re
from typing import Any

# Language name mapping for tree-sitter-languages
TS_LANG_MAP = {
    "c": "c",
    "cpp": "cpp",
    "csharp": "c_sharp",
    "go": "go",
    "java": "java",
    "javascript": "javascript",
    "python": "python",
}

# Tree-sitter node types identifying function/method definitions
FUNC_NODE_TYPES = {
    "c": {"function_definition"},
    "cpp": {"function_definition", "template_declaration"},
    "csharp": {"method_declaration", "local_function_statement", "constructor_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
    "javascript": {"function_declaration", "function", "method_definition", "arrow_function"},
    "python": {"function_definition"},
}


def _try_get_ts_parser(lang: str):
    """Attempts to load tree-sitter parser safely."""
    try:
        from tree_sitter_languages import get_parser
        ts_name = TS_LANG_MAP.get(lang, lang)
        return get_parser(ts_name)
    except Exception:
        return None


def extract_functions_treesitter(file_path: str, code: str, lang: str) -> list[dict[str, Any]]:
    """Extracts functions using tree-sitter AST."""
    parser = _try_get_ts_parser(lang)
    if not parser:
        return []

    lines = code.splitlines()
    code_bytes = code.encode("utf-8")
    def node_text(node):
        return code_bytes[node.start_byte:node.end_byte].decode("utf-8")
    tree = parser.parse(code_bytes)
    root_node = tree.root_node

    target_types = FUNC_NODE_TYPES.get(lang, set())
    extracted = []

    def traverse(node):
        if node.type in target_types:
            # Extract function name
            name = None
            for child in node.children:
                if child.type in {"identifier", "name", "property_identifier"}:
                    name = node_text(child)
                    break
                # Special case for C/C++ declarator
                if child.type in {"function_declarator", "declarator"}:
                    for sub in child.children:
                        if sub.type == "identifier":
                            name = node_text(sub)
                            break
                    if not name:
                        name = node_text(child).split("(")[0].strip()

            if not name:
                name = f"anonymous_{node.start_point[0] + 1}"

            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            func_code = node_text(node)

            # Collect function calls and def-use inside this function AST
            calls = set()
            def_nodes = []
            use_nodes = []

            def walk_func(fn_node):
                if fn_node.type in {"call_expression", "call", "invocation_expression"}:
                    # Call target
                    for c in fn_node.children:
                        if c.type in {"identifier", "field_expression", "member_expression"}:
                            callee = node_text(c).split(".")[-1].strip()
                            if callee and callee != name:
                                calls.add(callee)
                            break
                elif fn_node.type in {"assignment_expression", "variable_declarator", "assignment"}:
                    # Left side is variable def
                    if fn_node.children:
                        left = fn_node.children[0]
                        var_name = node_text(left).strip()
                        if var_name.isidentifier():
                            def_nodes.append((var_name, fn_node.start_point[0] + 1))
                elif fn_node.type == "identifier":
                    ident = node_text(fn_node).strip()
                    if ident.isidentifier():
                        use_nodes.append((ident, fn_node.start_point[0] + 1))

                for ch in fn_node.children:
                    walk_func(ch)

            walk_func(node)

            # Build def-use chains
            def_use = []
            for var_name, def_line in def_nodes[:15]:
                uses = [u_line for u_name, u_line in use_nodes if u_name == var_name and u_line > def_line]
                if uses:
                    def_use.append({"var": var_name, "def_line": def_line, "uses": sorted(list(set(uses)))[:5]})

            extracted.append({
                "id": f"{file_path}:{name}:{start_line}",
                "name": name,
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "code": func_code,
                "language": lang,
                "calls": sorted(list(calls)),
                "def_use": def_use,
            })

        for child in node.children:
            traverse(child)

    traverse(root_node)
    return extracted


def extract_functions_fallback(file_path: str, code: str, lang: str) -> list[dict[str, Any]]:
    """Robust regex-based fallback extractor for the 7 languages."""
    lines = code.splitlines()
    extracted = []

    # Patterns matching function signatures
    patterns = {
        "python": r"^[ \t]*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        "javascript": r"(?:function\s+([A-Za-z_][A-Za-z0-9_]*)|const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:function|\([^)]*\)\s*=>))",
        "java": r"(?:public|protected|private|static|\s)+\s+[\w\<\>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{",
        "csharp": r"(?:public|protected|private|static|async|\s)+\s+[\w\<\>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{",
        "c": r"^[ \t]*[\w\*\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{",
        "cpp": r"^[ \t]*[\w\*\s\:\<\>]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:const)?\s*\{",
        "go": r"^[ \t]*func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    }

    regex = re.compile(patterns.get(lang, patterns["python"]))

    for i, line in enumerate(lines):
        match = regex.search(line)
        if match:
            # Extract non-None matched group
            name = next((g for g in match.groups() if g), f"func_{i+1}")
            start_line = i + 1

            # Estimate end line
            if lang == "python":
                base_indent = len(line) - len(line.lstrip())
                end_line = len(lines)
                for j in range(i + 1, len(lines)):
                    cur_line = lines[j]
                    if cur_line.strip() and (len(cur_line) - len(cur_line.lstrip())) <= base_indent:
                        end_line = j
                        break
            else:
                # Brace-matching heuristic
                brace_count = 0
                started = False
                end_line = min(len(lines), i + 40)
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    if "{" in lines[j]:
                        started = True
                    if started and brace_count <= 0:
                        end_line = j + 1
                        break

            func_lines = lines[start_line - 1:end_line]
            func_code = "\n".join(func_lines)

            # Find simple calls
            call_candidates = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", func_code)
            calls = [c for c in set(call_candidates) if c != name and not c.startswith("__")][:10]

            # Def-use heuristic
            assigns = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=", func_code)
            def_use = []
            for var in set(assigns[:5]):
                if var.isidentifier():
                    def_use.append({"var": var, "def_line": start_line, "uses": [start_line + 1]})

            extracted.append({
                "id": f"{file_path}:{name}:{start_line}",
                "name": name,
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "code": func_code,
                "language": lang,
                "calls": calls,
                "def_use": def_use,
            })

    return extracted


def parse_file(file_path: str, code: str, lang: str) -> list[dict[str, Any]]:
    """Parses a single file, attempting tree-sitter with regex fallback."""
    try:
        funcs = extract_functions_treesitter(file_path, code, lang)
        if funcs:
            return funcs
    except Exception as e:
        print(f"Tree-sitter parse notice for {file_path}: {e}")

    return extract_functions_fallback(file_path, code, lang)


def build_repository_call_graph(functions: list[dict[str, Any]]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Constructs forward and reverse call graphs across all parsed functions in repo.

    Returns:
        call_graph: { caller_id: [callee_id, ...] }
        callers_map: { callee_id: [caller_id, ...] }
    """
    func_name_to_ids: dict[str, list[str]] = {}
    for f in functions:
        func_name_to_ids.setdefault(f["name"], []).append(f["id"])

    call_graph: dict[str, list[str]] = {}
    callers_map: dict[str, list[str]] = {}

    for f in functions:
        f_id = f["id"]
        call_graph[f_id] = []
        callers_map.setdefault(f_id, [])

        for called_name in f.get("calls", []):
            if called_name in func_name_to_ids:
                for target_id in func_name_to_ids[called_name]:
                    if target_id != f_id:
                        call_graph[f_id].append(target_id)
                        callers_map.setdefault(target_id, []).append(f_id)

    return call_graph, callers_map
