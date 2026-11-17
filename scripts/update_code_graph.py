#!/usr/bin/env python3
"""Deterministic AST & Graphify Context Knowledge Graph Builder for OmniSINT.

Parses all Python modules in the repository using Python's built-in `ast` module,
extracts classes, functions, imports, inheritance edges, and intra-package call relationships,
computes architectural communities and high-centrality internal 'god nodes', and writes:
  - graphify-out/graph.json
  - graphify-out/GRAPH_REPORT.md
"""

from __future__ import annotations

import ast
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT_DIR / "graphify-out"
SCAN_DIRS = ["omnisint", "scripts", "tests"]


def _resolve_call_target(call_node: ast.Call, imported_symbols: dict[str, str], local_prefix: str) -> str | None:
    """Resolve simple function or imported symbol calls into candidate qualified IDs."""
    func = call_node.func
    if isinstance(func, ast.Name):
        if func.id in imported_symbols:
            return imported_symbols[func.id]
        return f"{local_prefix}.{func.id}"
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = func.value.id
        if base in imported_symbols:
            return f"{imported_symbols[base]}.{func.attr}"
    return None


def extract_module_info(py_file: Path, rel_path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse a Python file into AST nodes (module, classes, functions) and structural edges."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    module_name = rel_path.removesuffix(".py").replace("/", ".")
    if module_name.endswith(".__init__"):
        module_name = module_name.removesuffix(".__init__")

    source = py_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=rel_path)
    module_doc = (ast.get_docstring(tree) or "").strip().splitlines()[0] if ast.get_docstring(tree) else ""

    top_package = (
        module_name.split(".")[1]
        if module_name.startswith("omnisint.") and "." in module_name
        else module_name.split(".")[0]
    )

    nodes.append(
        {
            "id": module_name,
            "type": "module",
            "file": rel_path,
            "community": top_package,
            "docstring": module_doc,
        }
    )

    imported_symbols: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                edges.append({"source": module_name, "target": alias.name, "relation": "imports"})
                local_name = alias.asname or alias.name.split(".")[0]
                imported_symbols[local_name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            edges.append({"source": module_name, "target": node.module, "relation": "imports"})
            for alias in node.names:
                if alias.name != "*":
                    local_name = alias.asname or alias.name
                    imported_symbols[local_name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.ClassDef):
            cls_id = f"{module_name}.{node.name}"
            cls_doc = (ast.get_docstring(node) or "").strip().splitlines()[0] if ast.get_docstring(node) else ""
            methods = [
                item.name
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            nodes.append(
                {
                    "id": cls_id,
                    "type": "class",
                    "file": rel_path,
                    "line": node.lineno,
                    "community": top_package,
                    "methods": methods,
                    "docstring": cls_doc,
                }
            )
            edges.append({"source": module_name, "target": cls_id, "relation": "defines"})
            for base in node.bases:
                base_name = ast.unparse(base)
                edges.append({"source": cls_id, "target": base_name, "relation": "inherits"})

            seen_calls: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    target = _resolve_call_target(sub, imported_symbols, module_name)
                    if target and target not in seen_calls:
                        seen_calls.add(target)
                        edges.append({"source": cls_id, "target": target, "relation": "calls"})
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_id = f"{module_name}.{node.name}"
            fn_doc = (ast.get_docstring(node) or "").strip().splitlines()[0] if ast.get_docstring(node) else ""
            nodes.append(
                {
                    "id": fn_id,
                    "type": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                    "file": rel_path,
                    "line": node.lineno,
                    "community": top_package,
                    "docstring": fn_doc,
                }
            )
            edges.append({"source": module_name, "target": fn_id, "relation": "defines"})

            seen_calls = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    target = _resolve_call_target(sub, imported_symbols, module_name)
                    if target and target not in seen_calls:
                        seen_calls.add(target)
                        edges.append({"source": fn_id, "target": target, "relation": "calls"})

    return nodes, edges


def build_graph() -> dict[str, Any]:
    """Scan workspace and build the structured codebase knowledge graph."""
    all_nodes: list[dict[str, Any]] = []
    all_edges: list[dict[str, Any]] = []

    for folder in SCAN_DIRS:
        target = ROOT_DIR / folder
        if not target.exists():
            continue
        for py_file in sorted(target.rglob("*.py")):
            rel_path = py_file.relative_to(ROOT_DIR).as_posix()
            nodes, edges = extract_module_info(py_file, rel_path)
            all_nodes.extend(nodes)
            all_edges.extend(edges)

    internal_ids = {n["id"] for n in all_nodes}
    # Keep only edges whose targets are internal symbols for call edges, plus all imports/defines/inherits
    filtered_edges = [
        edge
        for edge in all_edges
        if edge["relation"] != "calls" or edge["target"] in internal_ids
    ]

    # Rank high-centrality internal nodes (exclude stdlib/third-party symbols like __future__, typing, BaseModel)
    degree_counter: Counter[str] = Counter()
    for edge in filtered_edges:
        if edge["source"] in internal_ids:
            degree_counter[edge["source"]] += 1
        if edge["target"] in internal_ids:
            degree_counter[edge["target"]] += 1

    communities: dict[str, list[str]] = defaultdict(list)
    for node in all_nodes:
        communities[node["community"]].append(node["id"])

    god_nodes = [
        {"id": node_id, "degree": degree}
        for node_id, degree in degree_counter.most_common(12)
    ]

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_nodes": len(all_nodes),
            "total_edges": len(filtered_edges),
            "communities_count": len(communities),
        },
        "god_nodes": god_nodes,
        "communities": dict(communities),
        "nodes": all_nodes,
        "edges": filtered_edges,
    }


def write_outputs(graph: dict[str, Any]) -> bool:
    """Write graph.json and GRAPH_REPORT.md only when structural graph contents change."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    graph_json_path = OUTPUT_DIR / "graph.json"
    report_md_path = OUTPUT_DIR / "GRAPH_REPORT.md"

    if graph_json_path.exists():
        try:
            existing = json.loads(graph_json_path.read_text(encoding="utf-8"))
            keys_to_compare = ("stats", "god_nodes", "communities", "nodes", "edges")
            if all(existing.get(k) == graph.get(k) for k in keys_to_compare):
                return False
        except Exception:
            pass

    graph_json_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")

    lines = [
        "# OmniSINT — Graphify Codebase Knowledge Report",
        "",
        f"- **Generated (UTC):** `{graph['generated_at_utc']}`",
        f"- **Total AST Nodes:** `{graph['stats']['total_nodes']}`",
        f"- **Total Structural Edges:** `{graph['stats']['total_edges']}`",
        f"- **Architectural Communities:** `{graph['stats']['communities_count']}`",
        "",
        "## 1. High-Centrality 'God Nodes' (Core Abstractions)",
        "| Node ID | Degree (Connections) |",
        "| :--- | :--- |",
    ]
    for gn in graph["god_nodes"]:
        lines.append(f"| `{gn['id']}` | {gn['degree']} |")

    lines.extend(["", "## 2. Architectural Communities & Symbols"])
    for comm, members in sorted(graph["communities"].items()):
        lines.append(f"### Community: `{comm}` ({len(members)} nodes)")
        for node in graph["nodes"]:
            if node["community"] == comm:
                doc_suffix = f" — {node['docstring']}" if node.get("docstring") else ""
                lines.append(f"- **`{node['id']}`** (`{node['type']}` in `{node['file']}`){doc_suffix}")
        lines.append("")

    report_md_path.write_text("\n".join(lines), encoding="utf-8")
    return True


if __name__ == "__main__":
    graph_data = build_graph()
    changed = write_outputs(graph_data)
    status = "Updated" if changed else "Up-to-date"
    print(
        f"[Graphify] {status} graphify-out/ ({graph_data['stats']['total_nodes']} nodes, "
        f"{graph_data['stats']['total_edges']} edges)"
    )
