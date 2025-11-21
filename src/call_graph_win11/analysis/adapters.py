"""Adapters that make graph libraries conform to :class:`GraphBackend`."""

from __future__ import annotations

from collections.abc import Iterable

import networkx as nx


class NetworkXAdapter:
    """Adapter exposing a `GraphBackend`-compatible API for NetworkX DiGraphs."""

    def __init__(self, graph: nx.DiGraph) -> None:
        self._graph = graph

    def neighbors(self, node: str, mode: str = "out") -> Iterable[str]:
        if mode.lower() == "out":
            return self._graph.successors(node)
        if mode.lower() == "in":
            return self._graph.predecessors(node)
        raise ValueError(f"Unsupported mode: {mode}")

    def shortest_paths(self, source: str, target: str) -> list[list[str]]:
        path = nx.shortest_path(self._graph, source=source, target=target, method="dijkstra")
        return [path]

    def in_degree_single(self, node: str) -> int:
        return int(self._graph.in_degree(node))

    def nodes(self) -> Iterable[str]:
        return self._graph.nodes
