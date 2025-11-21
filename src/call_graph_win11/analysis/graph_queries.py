"""Helpers for analysing the unified call graph."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence

import networkx as nx

NodeId = str


def _node_label(node: NodeId, data: dict[str, object]) -> str:
    """Best-effort user-facing label for a graph node."""

    label = data.get("name") or data.get("qualified_name") or data.get("address")
    if isinstance(label, str) and label:
        return label
    if label is None:
        return node
    return str(label)


def _normalise_prefixes(prefixes: Sequence[str] | str) -> tuple[str, ...]:
    if isinstance(prefixes, str):
        return (prefixes,)
    return tuple(prefixes)


def _is_syscall(data: dict[str, object], *, program_hint: Optional[str], prefixes: tuple[str, ...]) -> bool:
    label = _node_label("", data)
    if prefixes and not label.startswith(prefixes):
        return False
    if program_hint is None:
        return True
    program = data.get("program")
    if not isinstance(program, str):
        return False
    return program.lower().endswith(program_hint.lower())


def detect_unconnected_syscalls(
    graph: nx.DiGraph,
    *,
    syscall_prefix: Sequence[str] | str = ("Nt", "Zw"),
    name_attr: str = "name",
    program_hint: str = "ntdll.dll",
) -> set[NodeId]:
    """Return syscalls that no other node references (in-degree == 0)."""

    prefixes = _normalise_prefixes(syscall_prefix)
    unconnected: set[NodeId] = set()

    for node, data in graph.nodes(data=True):
        label = data.get(name_attr) or data.get("qualified_name") or ""
        if not isinstance(label, str):
            label = str(label)
        if not label.startswith(prefixes):
            continue
        if program_hint and not _is_syscall(data, program_hint=program_hint, prefixes=prefixes):
            continue
        if graph.in_degree(node) == 0:
            unconnected.add(node)
    return unconnected


def _default_candidate_filter(node: NodeId, data: dict[str, object], *, candidate_programs: Optional[set[str]]) -> bool:
    program = data.get("program")
    if candidate_programs and program not in candidate_programs:
        return False

    program_lower = str(program or "").lower()
    if program_lower.endswith("ntdll.dll") and (not candidate_programs or program not in candidate_programs):
        return False

    source = data.get("source")
    # Functions defined in the DLL typically have source=="DEFAULT".
    return source == "DEFAULT"


def _syscall_nodes(
    graph: nx.DiGraph,
    target_syscalls: Optional[Iterable[str]],
    *,
    prefixes: tuple[str, ...],
    syscall_program_hint: Optional[str],
) -> tuple[set[NodeId], set[str]]:
    """
    Resolve the collection of syscall nodes to analyse and report unresolved targets.
    """

    syscall_nodes: set[NodeId] = set()
    missing: set[str] = set()

    name_to_nodes: dict[str, list[NodeId]] = defaultdict(list)
    for node, data in graph.nodes(data=True):
        name_to_nodes[_node_label(node, data)].append(node)

    if target_syscalls:
        for target in target_syscalls:
            if target in graph:
                syscall_nodes.add(target)
                continue
            matches = name_to_nodes.get(target, [])
            if matches:
                syscall_nodes.update(matches)
            else:
                missing.add(target)
    else:
        for node, data in graph.nodes(data=True):
            if _is_syscall(data, program_hint=syscall_program_hint, prefixes=prefixes):
                syscall_nodes.add(node)

    return syscall_nodes, missing


@dataclass
class HookCandidateCoverage:
    node: NodeId
    label: str
    program: str
    coverage: set[NodeId]


@dataclass
class HookRecommendation:
    hooks: list[HookCandidateCoverage]
    uncovered_syscalls: set[NodeId]
    missing_targets: set[str]


def find_minimal_hook_set(
    graph: nx.DiGraph,
    target_syscalls: Optional[Iterable[str]] = None,
    *,
    syscall_prefix: Sequence[str] | str = ("Nt", "Zw"),
    syscall_program_hint: str = "ntdll.dll",
    candidate_programs: Optional[Iterable[str]] = None,
    candidate_filter: Optional[Callable[[NodeId, dict[str, object]], bool]] = None,
) -> HookRecommendation:
    """
    Greedy hitting-set approximation for covering target syscalls with exported APIs.

    Returns a HookRecommendation describing the selected hooks and any uncovered syscalls.
    """

    prefixes = _normalise_prefixes(syscall_prefix)
    candidate_programs_set = set(candidate_programs) if candidate_programs else None
    filter_fn = candidate_filter or (lambda node, data: _default_candidate_filter(node, data, candidate_programs=candidate_programs_set))

    syscall_nodes, missing = _syscall_nodes(
        graph,
        target_syscalls,
        prefixes=prefixes,
        syscall_program_hint=syscall_program_hint,
    )

    coverage_map: dict[NodeId, set[NodeId]] = defaultdict(set)
    for syscall in syscall_nodes:
        ancestors = nx.ancestors(graph, syscall)
        for candidate in ancestors:
            data = graph.nodes[candidate]
            if filter_fn(candidate, data):
                coverage_map[candidate].add(syscall)

    selected: list[HookCandidateCoverage] = []
    uncovered = set(syscall_nodes)

    while uncovered:
        best_node: Optional[NodeId] = None
        best_coverage: set[NodeId] = set()

        for candidate, coverage in coverage_map.items():
            remaining = coverage & uncovered
            if len(remaining) > len(best_coverage):
                best_node = candidate
                best_coverage = remaining

        if not best_node or not best_coverage:
            break

        data = graph.nodes[best_node]
        selected.append(
            HookCandidateCoverage(
                node=best_node,
                label=_node_label(best_node, data),
                program=str(data.get("program") or ""),
                coverage=set(best_coverage),
            )
        )
        uncovered -= best_coverage
        coverage_map.pop(best_node, None)

    return HookRecommendation(hooks=selected, uncovered_syscalls=uncovered, missing_targets=missing)


def functions_without_syscalls(
    graph: nx.DiGraph,
    *,
    syscall_prefix: Sequence[str] | str = ("Nt", "Zw"),
    syscall_program_hint: str = "ntdll.dll",
    candidate_programs: Optional[Iterable[str]] = None,
) -> list[HookCandidateCoverage]:
    """Return API functions whose outbound graph never reaches a syscall."""

    prefixes = _normalise_prefixes(syscall_prefix)
    candidate_programs_set = set(candidate_programs) if candidate_programs else None

    syscall_nodes, _ = _syscall_nodes(
        graph,
        target_syscalls=None,
        prefixes=prefixes,
        syscall_program_hint=syscall_program_hint,
    )

    syscall_descendants_cache: dict[NodeId, bool] = {}
    results: list[HookCandidateCoverage] = []

    for node, data in graph.nodes(data=True):
        if not _default_candidate_filter(node, data, candidate_programs=candidate_programs_set):
            continue

        descendants = nx.descendants(graph, node)
        has_syscall = any(descendant in syscall_nodes for descendant in descendants)
        syscall_descendants_cache[node] = has_syscall
        if not has_syscall:
            results.append(
                HookCandidateCoverage(
                    node=node,
                    label=_node_label(node, data),
                    program=str(data.get("program") or ""),
                    coverage=set(),
                )
            )

    return results


def build_syscall_reachability_report(
    graph: nx.DiGraph,
    *,
    syscall_prefix: Sequence[str] | str = ("Nt", "Zw"),
    syscall_program_hint: str = "ntdll.dll",
    candidate_programs: Optional[Iterable[str]] = None,
) -> list[HookCandidateCoverage]:
    """
    Compute reachable syscall coverage for each API candidate.

    Returns a list of HookCandidateCoverage entries sorted by descending coverage size.
    """

    prefixes = _normalise_prefixes(syscall_prefix)
    candidate_programs_set = set(candidate_programs) if candidate_programs else None

    syscall_nodes, _ = _syscall_nodes(
        graph,
        target_syscalls=None,
        prefixes=prefixes,
        syscall_program_hint=syscall_program_hint,
    )

    coverage_map: list[HookCandidateCoverage] = []
    for node, data in graph.nodes(data=True):
        if not _default_candidate_filter(node, data, candidate_programs=candidate_programs_set):
            continue
        descendants = nx.descendants(graph, node)
        covered = {desc for desc in descendants if desc in syscall_nodes}
        coverage_map.append(
            HookCandidateCoverage(
                node=node,
                label=_node_label(node, data),
                program=str(data.get("program") or ""),
                coverage=covered,
            )
        )

    coverage_map.sort(key=lambda entry: len(entry.coverage), reverse=True)
    return coverage_map


__all__ = [
    "HookCandidateCoverage",
    "HookRecommendation",
    "build_syscall_reachability_report",
    "detect_unconnected_syscalls",
    "find_minimal_hook_set",
    "functions_without_syscalls",
]
