"""High-level orchestration for building the unified call graph."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from call_graph_win11.config import ExtractionConfig


class GraphMerger(Protocol):
    """Protocol expected from components that merge per-library graphs."""

    def merge(self, graph_paths: list[Path]) -> Path:
        ...


def build_unified_graph(
    config: ExtractionConfig,
    collector,
    merger: GraphMerger,
    *,
    output_dir: Path,
) -> Path:
    """
    Entry point for building the full system call graph.

    The collector is expected to expose a ``collect`` method returning the exported artefacts,
    while the merger condenses them into a single igraph-compatible representation.
    """

    output_dir.mkdir(parents=True, exist_ok=True)
    artefacts = collector.collect(config)
    return merger.merge(artefacts)
