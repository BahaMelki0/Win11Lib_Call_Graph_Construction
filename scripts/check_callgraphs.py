#!/usr/bin/env python3
"""Scan `data/interim/call_graphs` for empty call graphs and write diagnostics.

Usage:
  python scripts/check_callgraphs.py [path]
"""
from pathlib import Path
import json
import sys

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/interim/call_graphs")
root = root.expanduser().resolve()

if not root.exists():
    print(f"Directory not found: {root}")
    raise SystemExit(1)

empty = []
checked = 0
for p in sorted(root.rglob("*.callgraph.json")):
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Skipping (invalid JSON): {p} ({exc})")
        continue
    checked += 1
    funcs = payload.get("functions") or []
    edges = payload.get("edges") or []
    if not funcs and not edges:
        empty.append(p)
        try:
            note = [f"Empty call graph: {p}", f"program: {payload.get('program')}", f"functions: {len(funcs)}", f"edges: {len(edges)}"]
            ghidra_log = p.with_suffix(p.suffix + ".ghidra.log")
            if ghidra_log.exists():
                note.append("ghidra_log: " + str(ghidra_log))
            note_text = "\n".join(note)
            out = p.with_suffix(p.suffix + ".empty.log")
            out.write_text(note_text, encoding="utf-8")
        except Exception:
            pass

print(f"Checked: {checked} call graph files")
print(f"Empty graphs: {len(empty)}")
if empty:
    print("Empty files:")
    for p in empty:
        print(" -", p)

sys.exit(0 if not empty else 2)
