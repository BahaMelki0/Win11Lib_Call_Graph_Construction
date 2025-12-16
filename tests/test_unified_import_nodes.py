from __future__ import annotations

import json
from pathlib import Path

import networkx as nx

from call_graph_win11.analysis.unified_graph import UnifiedGraphBuilder


def _write_metadata(root: Path, module: str, *, exports: list[str], imports: list[tuple[str, list[str]]] | None = None) -> None:
    payload = {
        "path": str(root / f"{module}.dll"),
        "exports": [{"name": name, "ordinal": 1, "address": 1} for name in exports],
        "imports": [
            {"module": mod, "functions": [{"name": fn, "ordinal": None, "hint": None} for fn in fns]}
            for (mod, fns) in (imports or [])
        ],
        "debug": [],
    }
    (root / f"{module}.dll.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_callgraph_v11(path: Path, program: str, functions: list[dict], edges: list[dict]) -> None:
    payload = {
        "schema_version": "1.1",
        "program": program,
        "functions": functions,
        "edges": edges,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_unified_import_id_connects_to_syscall(tmp_path: Path) -> None:
    metadata_root = tmp_path / "inventory"
    metadata_root.mkdir()

    _write_metadata(metadata_root, "PROGA", exports=["Foo"], imports=[("NTDLL.DLL", ["NtCreateFile"])])
    _write_metadata(metadata_root, "NTDLL", exports=["NtCreateFile"], imports=[])

    callgraphs = tmp_path / "callgraphs"
    callgraphs.mkdir()

    # NTDLL export node (internal) used to create syscall stub edges in unify.
    _write_callgraph_v11(
        callgraphs / "ntdll.callgraph.json",
        "ntdll.dll",
        functions=[
            {"node_id": "0x1000", "entry_point": "0x1000", "name": "NtCreateFile", "source": "DEFAULT"},
        ],
        edges=[],
    )

    # PROGA exported function calls an imported symbol (stable IMPORT:* node id).
    _write_callgraph_v11(
        callgraphs / "proga.callgraph.json",
        "proga.dll",
        functions=[
            {"node_id": "0x2000", "entry_point": "0x2000", "name": "Foo", "source": "DEFAULT"},
            {"node_id": "IMPORT:NTDLL.DLL!NtCreateFile", "entry_point": None, "name": "NtCreateFile", "namespace": "NTDLL.DLL", "source": "IMPORTED"},
        ],
        edges=[
            {"caller": "0x2000", "callee": "IMPORT:NTDLL.DLL!NtCreateFile", "site": "0x2005", "kind": "import"},
        ],
    )

    builder = UnifiedGraphBuilder(metadata_root, include_internal=False)
    builder.build([callgraphs / "proga.callgraph.json", callgraphs / "ntdll.callgraph.json"])
    g: nx.DiGraph = builder.graph

    assert "PROGA.DLL!FOO" in g
    assert "NTDLL.DLL!NTCREATEFILE" in g

    # Stage 3 (syscall augmentation) – add stub and syscall node and verify reachability.
    g.add_node("SYSCALL:NtCreateFile", program="SYSCALL", name="NtCreateFile", layer="syscall", is_external=True)
    g.add_edge("NTDLL.DLL!NTCREATEFILE", "SYSCALL:NtCreateFile", kind="syscall")
    assert nx.has_path(g, "PROGA.DLL!FOO", "SYSCALL:NtCreateFile")
