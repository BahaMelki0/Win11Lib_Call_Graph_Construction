"""Utilities for loading and merging call graph artefacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Sequence

import networkx as nx

try:
    import igraph as ig
except ImportError:  # pragma: no cover - igraph optional
    ig = None

FUNCTION_FIELDS = [
    "node_id",
    "entry_point",
    "address_space",
    "name",
    "qualified_name",
    "namespace",
    "signature",
    "is_external",
    "calling_convention",
    "source",
    "is_thunk",
]


def _node_id(program: str, address: str) -> str:
    return f"{program}:{address}"

def _stable_node_key(program: str, raw_id: str) -> str:
    if isinstance(raw_id, str) and raw_id.startswith("IMPORT:"):
        return raw_id
    return _node_id(program, raw_id)


def load_call_graph(path: Path) -> nx.DiGraph:
    """Load a call graph JSON emitted by the Ghidra exporter into a directed graph."""

    with Path(path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    program = payload.get("program", Path(path).stem)
    functions = payload.get("functions", [])
    edges = payload.get("edges", [])
    arch = payload.get("arch")
    machine = payload.get("machine")

    graph = nx.DiGraph(program=program, source=str(Path(path).resolve()), arch=arch, machine=machine)

    raw_to_node: dict[str, str] = {}
    for function in functions:
        raw_id = function.get("node_id") or function.get("entry_point")
        if raw_id is None:
            continue
        raw_id = str(raw_id)
        node = _stable_node_key(program, raw_id)
        raw_to_node[raw_id] = node
        # Backward compatible: 'address' remains the intra-binary identifier (node_id/entry_point).
        attributes = {"program": program, "address": function.get("entry_point") or raw_id}
        for field in FUNCTION_FIELDS:
            if field == "entry_point":
                continue
            if field in function:
                attributes[field] = function[field]

        graph.add_node(node, **attributes)

    for edge in edges:
        caller = edge.get("caller")
        callee = edge.get("callee")
        if caller is None or callee is None:
            continue

        caller_raw = str(caller)
        callee_raw = str(callee)
        caller_node = raw_to_node.get(caller_raw) or _stable_node_key(program, caller_raw)
        callee_node = raw_to_node.get(callee_raw) or _stable_node_key(program, callee_raw)

        if caller_node not in graph:
            graph.add_node(caller_node, program=program, address=caller_raw, name=None, is_external=True)
        if callee_node not in graph:
            graph.add_node(callee_node, program=program, address=callee_raw, name=None, is_external=True)

        edge_attrs: dict[str, object] = {}
        if "site" in edge:
            edge_attrs["site"] = edge.get("site")
        if "kind" in edge:
            edge_attrs["kind"] = edge.get("kind")
        graph.add_edge(caller_node, callee_node, **edge_attrs)

    graph.graph["node_count"] = graph.number_of_nodes()
    graph.graph["edge_count"] = graph.number_of_edges()
    return graph


def merge_call_graphs(paths: Iterable[Path]) -> nx.DiGraph:
    """Compose multiple graphs into a single directed graph."""

    merged = nx.DiGraph(name="merged_call_graph")
    sources: list[str] = []
    programs: set[str] = set()

    for path in paths:
        graph = load_call_graph(path)
        merged = nx.compose(merged, graph)
        sources.append(graph.graph.get("source", str(path)))
        program = graph.graph.get("program")
        if program:
            programs.add(program)

    merged.graph["sources"] = sources
    merged.graph["programs"] = sorted(programs)
    merged.graph["node_count"] = merged.number_of_nodes()
    merged.graph["edge_count"] = merged.number_of_edges()
    return merged


def export_generic_graph(graph: nx.DiGraph, destination: Path) -> None:
    """Persist an aggregated networkx graph to JSON."""

    destination = Path(destination)
    payload = {
        "graph": graph.graph.get("name", destination.stem),
        "mode": graph.graph.get("mode"),
        "programs": list(sorted({data.get("program", "unknown") for _, data in graph.nodes(data=True)})),
        "sources": graph.graph.get("sources", []),
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "nodes": [],
        "edges": [],
    }

    for node, data in graph.nodes(data=True):
        attributes = {k: (str(v) if v is not None else None) for k, v in data.items()}
        payload["nodes"].append({"id": node, **attributes})

    for source, target, data in graph.edges(data=True):
        edge_payload = {"source": source, "target": target}
        if data:
            edge_payload.update({k: (str(v) if v is not None else None) for k, v in data.items()})
        payload["edges"].append(edge_payload)

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def load_generic_graph(path: Path) -> nx.DiGraph:
    """
    Load a generic graph JSON that contains `nodes` and `edges` entries (e.g., unified graph output).
    """

    with Path(path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    graph = nx.DiGraph(name=payload.get("graph", Path(path).stem))

    for entry in payload.get("nodes", []):
        node_id = entry.get("id") or entry.get("node_id")
        if not node_id:
            continue
        attrs = {k: v for k, v in entry.items() if k not in {"id", "node_id"}}
        graph.add_node(node_id, **attrs)

    for edge in payload.get("edges", []):
        source = edge.get("source")
        target = edge.get("target")
        if not source or not target:
            continue
        attrs = {k: v for k, v in edge.items() if k not in {"source", "target"}}
        graph.add_edge(source, target, **attrs)

    graph.graph["node_count"] = graph.number_of_nodes()
    graph.graph["edge_count"] = graph.number_of_edges()
    return graph


def to_igraph(graph: nx.DiGraph) -> "ig.Graph":
    """Convert a networkx graph into an igraph.Graph."""

    if ig is None:  # pragma: no cover - import guard
        raise ImportError("igraph is not installed. Install optional dependency `pip install igraph`.")

    directed = graph.is_directed()
    vertices = list(graph.nodes())
    ig_graph = ig.Graph(directed=directed)
    ig_graph.add_vertices(len(vertices))
    ig_graph.vs["name"] = vertices
    ig_graph.vs["node_id"] = vertices
    index_map = {node: idx for idx, node in enumerate(vertices)}

    # Transfer node attributes
    attr_names: set[str] = set()
    for _, data in graph.nodes(data=True):
        attr_names.update(data.keys())

    for attr in attr_names:
        ig_graph.vs[attr] = [graph.nodes[v].get(attr) for v in vertices]

    # Add edges
    edges_data = list(graph.edges(data=True))
    edge_indices = [(index_map[source], index_map[target]) for source, target, _ in edges_data]
    if edge_indices:
        ig_graph.add_edges(edge_indices)

    # Transfer edge attributes
    edge_attr_names: set[str] = set()
    for _, _, data in edges_data:
        edge_attr_names.update(data.keys())

    for attr in edge_attr_names:
        ig_graph.es[attr] = [data.get(attr) for _, _, data in edges_data]

    # Transfer graph-level metadata
    for key, value in graph.graph.items():
        ig_graph[key] = value

    return ig_graph


__all__ = ["load_call_graph", "merge_call_graphs", "export_generic_graph", "load_generic_graph", "to_igraph"]
