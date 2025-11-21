"""Tests for call graph loading and merging utilities."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

import networkx as nx

from call_graph_win11.analysis.graph_loader import export_generic_graph, load_call_graph, merge_call_graphs, to_igraph


def _write_sample(tmp_path: Path, name: str) -> Path:
    data = {
        "program": name,
        "functions": [
            {"entry_point": "0x1", "name": f"{name}_func_a", "qualified_name": f"{name}!func_a"},
            {"entry_point": "0x2", "name": f"{name}_func_b", "qualified_name": f"{name}!func_b"},
        ],
        "edges": [
            {"caller": "0x1", "callee": "0x2"},
        ],
    }
    target = tmp_path / f"{name}.json"
    with target.open("w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return target


def test_load_call_graph(tmp_path: Path) -> None:
    path = _write_sample(tmp_path, "demo")
    graph = load_call_graph(path)

    assert graph.graph["program"] == "demo"
    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1

    node = "demo:0x1"
    assert node in graph
    assert graph.nodes[node]["name"] == "demo_func_a"


def test_merge_call_graphs(tmp_path: Path) -> None:
    a = _write_sample(tmp_path, "alpha")
    b = _write_sample(tmp_path, "beta")

    merged = merge_call_graphs([a, b])
    assert merged.number_of_nodes() == 4
    assert merged.number_of_edges() == 2
    assert set(merged.graph["programs"]) == {"alpha", "beta"}


def test_export_generic_graph(tmp_path: Path) -> None:
    path = _write_sample(tmp_path, "gamma")
    graph = load_call_graph(path)

    destination = tmp_path / "combined.json"
    export_generic_graph(graph, destination)

    with destination.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    assert payload["node_count"] == graph.number_of_nodes()
    assert payload["edge_count"] == graph.number_of_edges()
    assert len(payload["nodes"]) == graph.number_of_nodes()


def test_to_igraph(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("igraph")

    path = _write_sample(tmp_path, "delta")
    graph = load_call_graph(path)
    ig_graph = to_igraph(graph)

    assert ig_graph.vcount() == graph.number_of_nodes()
    assert ig_graph.ecount() == graph.number_of_edges()
    assert set(ig_graph.vs["program"]) == {"delta"}
