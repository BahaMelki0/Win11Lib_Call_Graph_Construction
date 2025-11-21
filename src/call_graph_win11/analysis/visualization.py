"""Visualization helpers for call graphs."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

import matplotlib.pyplot as plt
import networkx as nx


def _subset_graph(graph: nx.DiGraph, max_nodes: int | None) -> nx.DiGraph:
    if max_nodes is None or graph.number_of_nodes() <= max_nodes:
        return graph

    degrees = sorted(graph.degree, key=lambda item: item[1], reverse=True)
    keep = {node for node, _ in degrees[:max_nodes]}
    subgraph = graph.subgraph(keep).copy()

    # Ensure the subgraph is weakly connected for nicer layouts by keeping the largest component
    if subgraph.number_of_nodes() == 0:
        return subgraph

    components = list(nx.weakly_connected_components(subgraph))
    if len(components) <= 1:
        return subgraph

    largest = max(components, key=len)
    return subgraph.subgraph(largest).copy()


def _program_colors(graph: nx.DiGraph) -> dict[str, str]:
    programs = sorted({data.get("program", "unknown") for _, data in graph.nodes(data=True)})
    palette = plt.get_cmap("tab20")
    colors = {}
    for idx, program in enumerate(programs):
        colors[program] = palette(idx % palette.N)
    return colors


def plot_call_graph(
    graph: nx.DiGraph,
    output_path: Path,
    *,
    max_nodes: int | None = 200,
    layout: str = "spring",
    show_labels: bool = False,
    title: str | None = None,
) -> Path:
    """
    Render a call graph to ``output_path`` using matplotlib.

    Large graphs can be limited via ``max_nodes``. When labels are disabled the plot emphasises
    topology and colour-codes distinct programs.
    """

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    graph = _subset_graph(graph, max_nodes)
    if graph.number_of_nodes() == 0:
        raise ValueError("Graph contains no nodes to visualize.")

    colors = _program_colors(graph)
    node_colours = [colors.get(data.get("program", "unknown")) for _, data in graph.nodes(data=True)]
    node_sizes = []
    for node in graph.nodes():
        degree = graph.out_degree(node) + graph.in_degree(node)
        node_sizes.append(50 + degree * 5)

    if layout == "kamada-kawai":
        positions = nx.kamada_kawai_layout(graph)
    else:
        positions = nx.spring_layout(graph, seed=42, k=None, iterations=100)

    plt.figure(figsize=(12, 12))
    nx.draw_networkx_edges(graph, positions, alpha=0.2, width=0.5, arrows=False)
    nx.draw_networkx_nodes(graph, positions, node_color=node_colours, node_size=node_sizes, alpha=0.9)

    if show_labels and graph.number_of_nodes() <= 150:
        labels = {}
        for node, data in graph.nodes(data=True):
            label = data.get("name") or data.get("qualified_name") or data.get("address")
            labels[node] = label
        nx.draw_networkx_labels(graph, positions, labels=labels, font_size=7)

    if title is None:
        summary = Counter(data.get("program", "unknown") for _, data in graph.nodes(data=True))
        title = ", ".join(f"{program}: {count} nodes" for program, count in summary.items())

    plt.title(title)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    return output_path


__all__ = ["plot_call_graph"]
