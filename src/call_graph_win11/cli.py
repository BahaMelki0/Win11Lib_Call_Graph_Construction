"""Command line entry points for the project."""

from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

import json
import networkx as nx
import typer

from call_graph_win11 import __version__
from call_graph_win11.analysis.graph_audit import (
    load_excluded_paths,
    scan_call_graphs,
    write_summary_report,
)
from call_graph_win11.analysis.graph_loader import (
    export_generic_graph,
    load_call_graph,
    load_generic_graph,
    merge_call_graphs,
    to_igraph,
)
from call_graph_win11.analysis.graph_queries import (
    detect_unconnected_syscalls,
)
from call_graph_win11.analysis.visualization import plot_call_graph
from call_graph_win11.analysis.unified_graph import MetadataIndex, SCHEMA_VERSION, UnifiedGraphBuilder
from call_graph_win11.analysis.graph_queries import (
    HookCandidateCoverage,
    HookRecommendation,
    build_syscall_reachability_report,
    detect_unconnected_syscalls,
    find_minimal_hook_set,
    functions_without_syscalls,
)
from call_graph_win11.data.pdb_fetcher import fetch_pdbs
from call_graph_win11.data.windows_inventory import build_inventory, export_inventory_csv
from call_graph_win11.io.ghidra_interface import DEFAULT_HEADLESS
from call_graph_win11.pipelines.ghidra_callgraph import export_call_graphs
from call_graph_win11.ui import create_app


def _sanitize_for_graphml(graph: nx.DiGraph) -> nx.DiGraph:
    """Return a copy of the graph with GraphML-friendly attributes."""

    def sanitize(mapping):
        for key in list(mapping.keys()):
            value = mapping[key]
            if value is None:
                # remove nulls for GraphML compatibility
                del mapping[key]
                continue
            if isinstance(value, (list, tuple, set)):
                mapping[key] = ",".join(str(item) for item in value)
            elif isinstance(value, dict):
                mapping[key] = json.dumps(value)

    copy = graph.copy()
    sanitize(copy.graph)
    for _, data in copy.nodes(data=True):
        sanitize(data)
    for _, _, data in copy.edges(data=True):
        sanitize(data)
    return copy


def _resolve_inputs(inputs: List[Path]) -> List[Path]:
    resolved: List[Path] = []
    for item in inputs:
        candidate = item.expanduser().resolve()
        if not candidate.exists():
            raise typer.BadParameter(f"Input not found: {candidate}")
        resolved.append(candidate)
    return resolved


def _normalize_syscall_prefixes(prefixes: Sequence[str] | str) -> tuple[str, ...]:
    if isinstance(prefixes, str):
        values = [prefixes]
    else:
        values = list(prefixes)
    cleaned: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value:
            cleaned.append(value.upper())
    return tuple(cleaned)


def _resolve_symbol_store(
    symbol_path: Optional[str],
    *,
    use_symbol_server: bool,
    symbol_cache: Path,
    symbol_server_url: str,
) -> str | Path | None:
    symbol_store: str | Path | None = None
    cache_root = symbol_cache.expanduser().resolve()
    if symbol_path is not None:
        try:
            sp = Path(symbol_path)
            if sp.drive or sp.root:
                sp = sp.expanduser().resolve()
            if sp.exists():
                symbol_store = sp
            else:
                symbol_store = symbol_path
        except Exception:
            symbol_store = symbol_path
    elif use_symbol_server:
        cache_root.mkdir(parents=True, exist_ok=True)
        symbol_store = f"srv*{cache_root}*{symbol_server_url}"
    return symbol_store


def _run_exports(
    binaries: list[Path],
    *,
    ghidra_headless: Path,
    project_root: Path,
    project_name: str,
    script_path: Path,
    output_dir: Path,
    metadata_root: Path,
    pdb_root: Optional[Path],
    windows_root: Path,
    symbol_store: str | Path | None,
    verbose: bool,
    flatten_names: bool,
    workers: int,
) -> None:
    if not binaries:
        return
    ghidra_headless = ghidra_headless.expanduser().resolve()
    project_root = project_root.expanduser().resolve()
    script_path = script_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    metadata_root = metadata_root.expanduser().resolve()
    windows_root = windows_root.expanduser().resolve()

    if not script_path.exists():
        raise typer.BadParameter(f"Ghidra script not found: {script_path}")
    if not ghidra_headless.exists():
        raise typer.BadParameter(f"Ghidra headless launcher not found: {ghidra_headless}")

    if pdb_root:
        pdb_root = pdb_root.expanduser().resolve()
        if not pdb_root.exists():
            typer.secho(
                f"Warning: PDB root {pdb_root} does not exist; proceeding without local PDBs.",
                fg=typer.colors.YELLOW,
            )
            pdb_root = None

    if workers <= 1 or len(binaries) == 1:
        export_call_graphs(
            binaries,
            ghidra_headless=ghidra_headless,
            project_root=project_root,
            project_name=project_name,
            script_path=script_path,
            output_dir=output_dir,
            overwrite=False,
            metadata_root=metadata_root,
            pdb_root=pdb_root,
            windows_root=windows_root,
            symbol_store=symbol_store,
            verbose=verbose,
            flatten_names=flatten_names,
        )
        return

    worker_count = min(workers, len(binaries))
    buckets: list[list[Path]] = [[] for _ in range(worker_count)]
    for idx, binary in enumerate(binaries):
        buckets[idx % worker_count].append(binary)

    def _run_bucket(worker_idx: int, chunk: list[Path]) -> list[CallGraphRunResult]:
        if not chunk:
            return []
        return export_call_graphs(
            chunk,
            ghidra_headless=ghidra_headless,
            project_root=project_root / f"worker_{worker_idx}",
            project_name=f"{project_name}_w{worker_idx}",
            script_path=script_path,
            output_dir=output_dir,
            overwrite=False,
            metadata_root=metadata_root,
            pdb_root=pdb_root,
            windows_root=windows_root,
            symbol_store=symbol_store,
            verbose=verbose,
            flatten_names=flatten_names,
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(_run_bucket, worker_idx + 1, bucket)
            for worker_idx, bucket in enumerate(buckets)
            if bucket
        ]
        for fut in as_completed(futures):
            fut.result()


def _load_graph_from_inputs(inputs: List[Path]) -> nx.DiGraph:
    resolved = _resolve_inputs(inputs)
    if not resolved:
        raise typer.BadParameter("At least one --input call graph is required.")
    if len(resolved) == 1:
        return load_call_graph(resolved[0])
    return merge_call_graphs(resolved)


def _format_node_label(graph: nx.DiGraph, node: str) -> str:
    data = graph.nodes[node]
    for key in ("name", "qualified_name", "address"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return node


def _load_graph_any(path: Path) -> tuple[nx.DiGraph, str]:
    """Load either exporter (functions/edges) or unified (nodes/edges) graph."""

    path = path.expanduser().resolve()
    if not path.exists():
        raise typer.BadParameter(f"Input not found: {path}")
    head = path.read_text(encoding="utf-8")[:2048]
    if "\"functions\"" in head:
        return load_call_graph(path), "callgraph"
    if "\"nodes\"" in head and "\"edges\"" in head:
        return load_generic_graph(path), "unified"
    raise typer.BadParameter(f"Unrecognised graph format: {path}")


def _prune_to_syscalls(
    graph: nx.DiGraph,
    *,
    syscall_prefix: tuple[str, ...] = ("Nt", "Zw"),
    syscall_program_hint: str = "ntdll.dll",
) -> nx.DiGraph:
    """Return a subgraph containing paths that reach syscalls."""

    prefixes = _normalize_syscall_prefixes(syscall_prefix)
    syscall_nodes: set[str] = set()
    for node, data in graph.nodes(data=True):
        name = data.get("name") or data.get("qualified_name") or ""
        name_upper = str(name).upper()
        if prefixes and name_upper.startswith(prefixes):
            program = str(data.get("program") or graph.graph.get("program") or "")
            if program.lower().endswith(syscall_program_hint.lower()):
                syscall_nodes.add(node)

    keep: set[str] = set(syscall_nodes)
    for node in syscall_nodes:
        keep |= nx.ancestors(graph, node)

    pruned = graph.subgraph(keep).copy()
    pruned.graph["mode"] = "syscall"
    pruned.graph["sources"] = [graph.graph.get("source", "")] if graph.graph.get("source") else []
    return pruned


def _prune_unified_to_syscalls(
    graph: nx.DiGraph,
    *,
    syscall_prefix: tuple[str, ...] = ("Nt", "Zw"),
    syscall_program_hint: str = "ntdll.dll",
) -> nx.DiGraph:
    """Return a subgraph (from a unified nodes/edges graph) containing paths that reach syscalls."""

    prefixes = _normalize_syscall_prefixes(syscall_prefix)
    syscall_nodes: set[str] = set()
    for node, data in graph.nodes(data=True):
        layer = str(data.get("layer") or "").lower()
        name = data.get("name") or data.get("qualified_name") or ""
        program = str(data.get("program") or "")
        if layer == "syscall":
            syscall_nodes.add(node)
            continue
        name_upper = str(name).upper()
        if prefixes and name_upper.startswith(prefixes) and program.lower().endswith(syscall_program_hint.lower()):
            syscall_nodes.add(node)

    if not syscall_nodes:
        pruned = graph.subgraph([]).copy()
        pruned.graph["mode"] = "syscall"
        return pruned

    keep: set[str] = set(syscall_nodes)
    for node in syscall_nodes:
        keep |= nx.ancestors(graph, node)

    pruned = graph.subgraph(keep).copy()
    pruned.graph["mode"] = "syscall"
    return pruned


def _normalize_program_name(name: str) -> str:
    """Uppercase and append .DLL when the caller passes a bare module stem."""

    cleaned = (name or "").strip()
    if not cleaned:
        return ""
    if not cleaned.lower().endswith((".dll", ".exe")):
        cleaned = f"{cleaned}.dll"
    return cleaned.upper()


def _project_syscalls(
    graph: nx.DiGraph,
    target_program: str,
    *,
    syscall_prefix: tuple[str, ...] = ("Nt", "Zw"),
    syscall_program_hint: str = "ntdll.dll",
    max_hops: Optional[int] = None,
    allow_kinds: Optional[set[str]] = None,
    max_syscalls_per_function: Optional[int] = None,
) -> tuple[nx.DiGraph, list[dict], dict]:
    """Project a unified graph to syscall reachability for a target program."""

    target_program_upper = _normalize_program_name(target_program)
    syscall_program_upper = _normalize_program_name(syscall_program_hint)
    prefixes = _normalize_syscall_prefixes(syscall_prefix)

    # Filter edges by kind if requested
    if allow_kinds:
        kinds = {k.lower() for k in allow_kinds}
        edges_to_keep = [
            (u, v)
            for u, v, data in graph.edges(data=True)
            if str(data.get("kind", "")).lower() in kinds
        ]
        graph = graph.edge_subgraph(edges_to_keep).copy()

    # Identify target nodes and syscall nodes
    func_nodes: list[str] = []
    syscall_nodes: list[str] = []
    for node, data in graph.nodes(data=True):
        program = str(data.get("program") or "").upper()
        layer = str(data.get("layer") or "").lower()
        name = data.get("name") or data.get("qualified_name") or ""
        if program == target_program_upper:
            func_nodes.append(node)
        if layer == "syscall":
            syscall_nodes.append(node)
        else:
            name_upper = str(name).upper()
            if prefixes and name_upper.startswith(prefixes) and program.endswith(syscall_program_upper):
                syscall_nodes.append(node)

    if not syscall_nodes:
        raise typer.BadParameter("No syscall nodes found in the unified graph.")
    if not func_nodes:
        raise typer.BadParameter(f"No functions found for program '{target_program}'. Did you mean '{target_program_upper}'?")

    # Reverse graph for reachability; unweighted BFS
    reversed_graph = graph.reverse(copy=True)
    # Multi-source shortest path lengths
    dist: dict[str, float] = nx.multi_source_dijkstra_path_length(reversed_graph, syscall_nodes, weight=None)

    results: list[dict] = []
    projection_edges: list[tuple[str, str, int, str | None]] = []
    via_counter: Counter[str] = Counter()
    hops_counter: Counter[int] = Counter()
    syscalls_reached: set[str] = set()
    funcs_reaching: set[str] = set()

    for fn in func_nodes:
        if fn not in dist:
            continue
        # compute distances to each syscall from fn (forward)
        lengths = nx.single_source_shortest_path_length(graph, source=fn)
        pairs = [(sc, d) for sc, d in lengths.items() if sc in syscall_nodes and d is not None]
        if max_hops is not None:
            pairs = [(sc, d) for sc, d in pairs if d <= max_hops]
        pairs.sort(key=lambda t: t[1])
        if max_syscalls_per_function:
            pairs = pairs[:max_syscalls_per_function]
        for sc, hops in pairs:
            path = nx.shortest_path(graph, source=fn, target=sc)
            via_program = None
            if len(path) > 1:
                via_program = str(graph.nodes[path[1]].get("program") or "")
            preview = []
            for node in path[:8]:
                data = graph.nodes[node]
                label = data.get("name") or data.get("qualified_name") or data.get("address") or node
                preview.append(str(label))
            syscall_name = graph.nodes[sc].get("name") or graph.nodes[sc].get("qualified_name") or sc
            func_name = graph.nodes[fn].get("name") or graph.nodes[fn].get("qualified_name") or fn
            results.append(
                {
                    "function_id": fn,
                    "function_name": func_name,
                    "syscall_id": sc,
                    "syscall_name": syscall_name,
                    "hops": hops,
                    "via_program": via_program,
                    "path_preview": preview,
                }
            )
            projection_edges.append((fn, sc, hops, via_program))
            via_counter[via_program or ""] += 1
            hops_counter[hops] += 1
            syscalls_reached.add(syscall_name)
            funcs_reaching.add(fn)

    # Build projection graph
    projection = nx.DiGraph(name=f"{target_program_upper}_syscall_projection", mode="syscall_projection")
    projection.graph["target_program"] = target_program_upper
    for node, data in graph.nodes(data=True):
        if node in funcs_reaching or node in {edge[1] for edge in projection_edges}:
            projection.add_node(node, **data)
    for src, dst, hops, via_program in projection_edges:
        projection.add_edge(src, dst, kind="projection", hops=hops, via_program=via_program)

    metrics = {
        "target_program": target_program_upper,
        "num_funcs_in_target": len(func_nodes),
        "num_funcs_reaching_syscalls": len(funcs_reaching),
        "num_syscalls_reached": len(syscalls_reached),
        "syscalls_reached_by_at_least_one": sorted(syscalls_reached),
        "hops_histogram": {str(k): v for k, v in sorted(hops_counter.items())},
        "top_via_programs": [{"program": k, "count": v} for k, v in via_counter.most_common(10)],
    }
    return projection, results, metrics

app = typer.Typer(help="Utilities for the Call Graph Reconstruction project.")


@app.callback()
def version(display_version: bool = typer.Option(False, "--version", "-V", help="Show version and exit.")) -> None:
    """Print the package version when requested."""

    if display_version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("hello")
def hello(name: str = "Analyst") -> None:
    """Sample command to verify the CLI wiring."""

    typer.echo(f"Hello, {name}! Ready to build some call graphs.")


@app.command("inventory")
def inventory(
    root: Path = typer.Option(Path(r"C:\Windows"), help="Root directory to scan for PE files."),
    output: Path = typer.Option(Path("data/raw/windows_inventory"), help="Directory where metadata JSON files are written."),
    limit: Optional[int] = typer.Option(None, help="Process at most this many PE files (useful for dry runs)."),
    sample: bool = typer.Option(True, help="Validate well-known system DLLs after the scan."),
    sample_names: List[str] = typer.Option(
        ["System32\\ntdll.dll", "System32\\kernel32.dll", "System32\\user32.dll"],
        help="Relative paths (from root) of DLLs to validate.",
    ),
) -> None:
    """Recursively scan a Windows directory, extract PE metadata, and persist per-file JSON."""

    root = root.expanduser()
    output = output.expanduser()
    if not root.exists():
        raise typer.BadParameter(f"Root path {root} does not exist.")

    sample_paths: Optional[List[Path]] = None
    if sample:
        sample_paths = []
        for name in sample_names:
            candidate = (root / Path(name)).resolve()
            sample_paths.append(candidate)

    typer.echo(f"Scanning {root} for PE files...")
    result = build_inventory(root, output, limit=limit, samples=sample_paths)

    typer.echo(f"Visited files: {result.total_files}")
    typer.echo(f"Detected PE files: {result.pe_files}")
    typer.echo(f"Metadata written: {result.metadata_written}")

    if result.errors:
        typer.secho("Errors:", fg=typer.colors.YELLOW)
        for err in result.errors[:10]:
            typer.echo(f"  - {err}")
        if len(result.errors) > 10:
            typer.echo(f"  ... ({len(result.errors) - 10} more)")

    if result.sample_reports:
        typer.secho("Sample validation:", fg=typer.colors.GREEN)
        for path_str, report in result.sample_reports.items():
            typer.echo(f"  {path_str}")
            if "error" in report:
                typer.secho(f"    error: {report['error']}", fg=typer.colors.RED)
                continue
            typer.echo(f"    machine: {report['machine']}")
            typer.echo(f"    RSDS present: {report['has_rsds']}")
            for rsds in report.get("rsds_entries", []):
                typer.echo(f"      pdb: {rsds.get('pdb_path')}")
                typer.echo(f"      guid: {rsds.get('guid')}")
                typer.echo(f"      age: {rsds.get('age')}")
                typer.echo(f"      symbol folder: {rsds.get('symbol_server_path')}")


@app.command("inventory-csv")
def inventory_csv(
    metadata_root: Path = typer.Option(
        Path("data/raw/windows_inventory"), help="Directory containing inventory JSON files."
    ),
    output_csv: Path = typer.Option(
        Path("data/raw/windows_inventory.csv"), help="Destination CSV summarising the collected metadata."
    ),
    relative_to: Optional[Path] = typer.Option(
        None, help="Optional root used to relativize paths in the CSV (defaults to absolute paths)."
    ),
) -> None:
    """Aggregate per-library metadata JSON files into a single CSV summary."""

    metadata_root = metadata_root.expanduser()
    output_csv = output_csv.expanduser()
    relative_root = relative_to.expanduser() if relative_to is not None else None

    typer.echo(f"Exporting inventory metadata from {metadata_root} to {output_csv}...")
    try:
        rows = export_inventory_csv(metadata_root, output_csv, relative_to=relative_root)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(f"Rows written: {rows}")


@app.command("fetch-pdbs")
def fetch_pdbs_command(
    metadata_root: Path = typer.Option(Path("data/raw/windows_inventory"), help="Directory containing inventory JSON files."),
    output_root: Path = typer.Option(Path("data/external/pdbs"), help="Directory where downloaded PDBs are stored."),
    cache_root: Optional[Path] = typer.Option(None, help="Optional shared symbol cache root (defaults to output directory)."),
    limit: Optional[int] = typer.Option(None, help="Limit the number of unique PDBs to download."),
    force: bool = typer.Option(False, help="Re-download existing PDBs and overwrite them."),
    pdb_name: List[str] = typer.Option([], help="Only download PDBs matching these filenames."),
    max_metadata: Optional[int] = typer.Option(None, help="Process at most this many metadata JSON files."),
) -> None:
    """Retrieve PDB files referenced by the collected inventory metadata."""

    metadata_root = metadata_root.expanduser()
    output_root = output_root.expanduser()
    cache_root = cache_root.expanduser() if cache_root is not None else None

    if not metadata_root.exists():
        raise typer.BadParameter(f"Metadata root {metadata_root} does not exist.")

    typer.echo(f"Collecting RSDS signatures from {metadata_root}...")
    pdb_filters = pdb_name or None
    summary = fetch_pdbs(
        metadata_root,
        output_root,
        cache_root=cache_root,
        limit=limit,
        force=force,
        pdb_names=pdb_filters,
        max_metadata_files=max_metadata,
    )

    typer.echo(f"PDB requests attempted: {summary.attempted}")
    typer.echo(f"Downloaded: {summary.downloaded}")
    typer.echo(f"Skipped (existing): {summary.skipped_existing}")
    typer.echo(f"Reused from cache: {summary.reused_cache}")
    typer.echo(f"Failures: {summary.failure_count}")

    if summary.failed:
        typer.secho("Failed downloads:", fg=typer.colors.RED)
        for signature, error in summary.failed[:10]:
            typer.echo(
                f"  {signature.pdb_name}/{signature.identifier}: {error}"
            )
        if summary.failure_count > 10:
            typer.echo(f"  ... ({summary.failure_count - 10} additional failures)")


@app.command("callgraph-empty-report")
def callgraph_empty_report(
    data_dir: Path = typer.Option(Path("data/interim/call_graphs"), help="Directory containing *.callgraph.json files."),
    output: Path = typer.Option(Path("docs/analytics/empty_call_graphs.json"), help="Destination file for the empty-graph report."),
    format: str = typer.Option("json", "--format", "-f", help="Report format: json or md."),
) -> None:
    """Scan call graph artefacts and record empty/malformed entries."""

    data_dir = data_dir.expanduser()
    summaries = scan_call_graphs(data_dir)
    flagged = [summary for summary in summaries if summary.status != "ok"]

    if not flagged:
        typer.secho("No empty or malformed graphs were detected.", fg=typer.colors.GREEN)
        return

    fmt = format.lower()
    try:
        write_summary_report(flagged, output, format=fmt)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(f"Recorded {len(flagged)} entries in {output.resolve()}")


@dataclass(frozen=True)
class _InventoryRecord:
    module: str
    arch: str
    path: Optional[Path]
    imports: list[str]


def _normalize_module_name(name: str) -> str:
    if not name:
        return ""
    cleaned = name.strip()
    if not cleaned:
        return ""
    if not cleaned.lower().endswith((".dll", ".exe")):
        cleaned = f"{cleaned}.dll"
    return cleaned.upper()


def _machine_to_arch(machine: str | None) -> str:
    if not machine:
        return "unknown"
    lowered = machine.lower()
    if lowered.startswith("image_file_machine_amd64") or lowered in {"amd64", "x86_64", "x64"}:
        return "x64"
    if lowered.startswith("image_file_machine_i386") or lowered in {"i386", "x86"}:
        return "x86"
    if lowered.startswith("image_file_machine_arm64") or "arm64" in lowered:
        return "arm64"
    return machine.upper()


def _record_from_metadata(metadata: dict, metadata_path: Path) -> _InventoryRecord | None:
    module_name = ""
    path_value = metadata.get("path")
    if isinstance(path_value, str) and path_value:
        module_name = _normalize_module_name(Path(path_value).name)
    if not module_name:
        module_name = _normalize_module_name(metadata_path.stem)
    if not module_name:
        return None

    machine = metadata.get("machine")
    arch = _machine_to_arch(machine if isinstance(machine, str) else None)
    binary_path = Path(path_value) if isinstance(path_value, str) else None

    imports: list[str] = []
    for entry in metadata.get("imports", []):
        module = _normalize_module_name(entry.get("module", "") if isinstance(entry, dict) else "")
        if module:
            imports.append(module)

    return _InventoryRecord(module=module_name, arch=arch, path=binary_path, imports=imports)


def _choose_inventory_record(
    records: list[_InventoryRecord],
    *,
    arch: str,
) -> _InventoryRecord:
    if len(records) == 1:
        return records[0]

    def score(record: _InventoryRecord) -> tuple[int, int]:
        path_str = str(record.path).lower() if record.path else ""
        preferred = 1
        if arch == "x64" and "\\system32\\" in path_str:
            preferred = 0
        elif arch == "x86" and "\\syswow64\\" in path_str:
            preferred = 0
        return (preferred, len(path_str) if path_str else len(record.module))

    return min(records, key=score)


def _load_inventory_candidates(metadata_root: Path) -> dict[str, list[_InventoryRecord]]:
    candidates: dict[str, list[_InventoryRecord]] = defaultdict(list)
    for metadata_file in metadata_root.rglob("*.json"):
        if metadata_file.is_dir():
            continue
        try:
            metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        record = _record_from_metadata(metadata, metadata_file)
        if record:
            candidates[record.module].append(record)
    return candidates


def _select_target_arch(
    modules: list[str],
    candidates: dict[str, list[_InventoryRecord]],
) -> str:
    if not modules:
        raise typer.BadParameter("At least one module is required to select an architecture.")
    arch_sets = []
    for module in modules:
        arches = {rec.arch for rec in candidates.get(module, [])}
        if not arches:
            raise typer.BadParameter(f"Module not found in inventory: {module}")
        arch_sets.append(arches)
    common = set.intersection(*arch_sets)
    if not common:
        raise typer.BadParameter(f"No shared architecture across requested modules: {sorted(modules)}.")
    for preferred in ("x64", "x86", "arm64", "unknown"):
        if preferred in common:
            return preferred
    return sorted(common)[0]


def _select_inventory_records(
    candidates: dict[str, list[_InventoryRecord]],
    *,
    arch: str,
) -> dict[str, _InventoryRecord]:
    records: dict[str, _InventoryRecord] = {}
    for module, records_list in candidates.items():
        filtered = [rec for rec in records_list if rec.arch == arch]
        if not filtered:
            continue
        records[module] = _choose_inventory_record(filtered, arch=arch)
    return records


def _resolve_api_set_alias(
    module: str,
    records: dict[str, _InventoryRecord],
    cache: dict[str, str],
) -> str:
    module = _normalize_module_name(module)
    if not module:
        return ""
    if module in cache:
        return cache[module]
    if module.startswith(("API-MS-", "EXT-MS-")):
        host = None
        record = records.get(module)
        if record:
            for imported in record.imports:
                if not imported.startswith(("API-MS-", "EXT-MS-")):
                    host = imported
                    if host == "KERNELBASE.DLL":
                        break
        if not host:
            host = "KERNELBASE.DLL"
        cache[module] = host
        return host
    cache[module] = module
    return module


def _build_module_adjacency(
    records: dict[str, _InventoryRecord],
) -> dict[str, set[str]]:
    alias_cache: dict[str, str] = {}
    adjacency: dict[str, set[str]] = {module: set() for module in records}
    for module, record in records.items():
        for imported in record.imports:
            resolved = _resolve_api_set_alias(imported, records, alias_cache)
            if resolved and resolved in records:
                adjacency[module].add(resolved)
    return adjacency


def _reachable_nodes(adjacency: dict[str, set[str]], start: str) -> set[str]:
    if start not in adjacency:
        return set()
    visited = {start}
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in adjacency.get(node, ()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited


def _invert_adjacency(adjacency: dict[str, set[str]]) -> dict[str, set[str]]:
    reversed_adj = {node: set() for node in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reversed_adj.setdefault(target, set()).add(source)
    return reversed_adj


def _detect_flatten_names(callgraph_dir: Path, arch: str) -> bool:
    arch_dir = callgraph_dir / arch
    if not arch_dir.exists():
        return True
    for path in arch_dir.rglob("*.callgraph.json"):
        try:
            rel = path.relative_to(arch_dir)
        except ValueError:
            continue
        if len(rel.parts) > 1:
            return False
    return True


def _callgraph_output_path(
    binary: Path,
    *,
    output_dir: Path,
    windows_root: Path,
    flatten_names: bool,
    arch: str,
) -> Path:
    output_dir_arch = (output_dir / arch).resolve()
    try:
        relative = binary.resolve().relative_to(windows_root.resolve())
        rel_str = str(relative)
    except ValueError:
        rel_str = binary.name

    if flatten_names:
        flattened = rel_str.replace(":", "_").replace("\\", "_").replace("/", "_")
        return output_dir_arch / f"{flattened}.callgraph.json"

    if "\\" in rel_str or "/" in rel_str:
        return output_dir_arch / Path(rel_str).parent / f"{Path(rel_str).name}.callgraph.json"
    return output_dir_arch / f"{rel_str}.callgraph.json"


@app.command("callgraph-unify")
def callgraph_unify(
    callgraph_dir: Path = typer.Option(Path("data/interim/call_graphs"), help="Directory containing *.callgraph.json files."),
    metadata_root: Path = typer.Option(Path("data/raw/windows_inventory"), help="Inventory metadata root (JSON files)."),
    output: Path = typer.Option(Path("data/interim/unified/unified.callgraph.json"), help="Destination JSON for the unified graph."),
    limit: Optional[int] = typer.Option(None, help="Optional limit on the number of call graphs to process."),
    module: List[str] = typer.Option([], "--module", "-m", help="Restrict to these module names (e.g., kernel32.dll)."),
    auto_generate_missing: bool = typer.Option(
        False,
        "--auto-generate-missing",
        help="Auto-generate missing call graphs needed to connect the requested modules (requires at least two --module values).",
    ),
    workers: int = typer.Option(1, help="Number of concurrent Ghidra instances when auto-generating missing graphs."),
    ghidra_headless: Path = typer.Option(DEFAULT_HEADLESS, help="Path to analyzeHeadless launcher."),
    project_root: Path = typer.Option(Path("ghidra-projects"), help="Directory where the Ghidra project will be stored."),
    project_name: str = typer.Option("call_graph_auto", help="Name of the Ghidra project to use."),
    script_path: Path = typer.Option(Path("scripts/ghidra/export_call_graph.py"), help="Ghidra script that exports call graphs."),
    pdb_root: Path = typer.Option(Path("data/external/pdbs"), help="Root of downloaded PDB symbol store."),
    symbol_path: Optional[str] = typer.Option(None, help="Explicit symbol search path passed to Ghidra (-symbolPath)."),
    symbol_cache: Path = typer.Option(Path("data/external/pdbs"), help="Local cache used when building a symbol server chain."),
    use_symbol_server: bool = typer.Option(
        True, help="Use the Microsoft public symbol server with the provided cache."
    ),
    symbol_server_url: str = typer.Option("https://msdl.microsoft.com/download/symbols", help="Symbol server URL."),
    windows_root: Path = typer.Option(Path(r"C:\Windows"), help="Windows directory used when building the inventory."),
    flatten_names: Optional[bool] = typer.Option(
        None, help="Flatten output filenames for auto-generated graphs; default auto-detects from callgraph_dir."
    ),
    fail_if_disconnected: bool = typer.Option(
        True,
        "--fail-if-disconnected/--allow-disconnected",
        help="Fail if no full module path exists after auto-generation.",
    ),
    verbose: bool = typer.Option(False, help="Print per-binary progress during auto-generation."),
    api_set_forwarders: bool = typer.Option(
        True,
        "--api-set-forwarders/--no-api-set-forwarders",
        help="Include API-set forwarder nodes (synthetic placeholders).",
    ),
    include_internal: bool = typer.Option(
        False,
        "--include-internal",
        help="Include internal (non-import, non-export) functions. Default focuses on imports/exports only.",
    ),
    prompt_missing: bool = typer.Option(
        False,
        "--prompt-missing",
        help="Prompt to generate missing call graphs for requested modules before unification.",
    ),
) -> None:
    """Build the unified cross-DLL call graph and emit igraph-compatible JSON."""

    callgraph_dir = callgraph_dir.expanduser().resolve()
    metadata_root = metadata_root.expanduser().resolve()
    output = output.expanduser().resolve()

    if not callgraph_dir.exists():
        raise typer.BadParameter(f"Call graph directory not found: {callgraph_dir}")
    if not metadata_root.exists():
        raise typer.BadParameter(f"Metadata root not found: {metadata_root}")

    if workers < 1:
        raise typer.BadParameter("--workers must be >= 1")

    paths: list[Path] = []
    module_filter: Optional[set[str]] = None
    requested_modules: list[str] = []
    if module:
        requested_modules = [_normalize_module_name(entry) for entry in module if entry.strip()]
        if any(not entry for entry in requested_modules):
            raise typer.BadParameter("Module names must be non-empty.")

    if prompt_missing and requested_modules and not auto_generate_missing:
        candidates = _load_inventory_candidates(metadata_root)
        target_arch = _select_target_arch(requested_modules, candidates)
        records = _select_inventory_records(candidates, arch=target_arch)

        missing_requested = [entry for entry in requested_modules if entry not in records]
        if missing_requested:
            raise typer.BadParameter(
                f"Requested modules were not found in inventory for the selected architecture: {missing_requested}"
            )

        detected_flatten = _detect_flatten_names(callgraph_dir, target_arch) if flatten_names is None else flatten_names
        callgraph_dir.mkdir(parents=True, exist_ok=True)
        missing_records: list[_InventoryRecord] = []
        for module_name in requested_modules:
            record = records.get(module_name)
            if not record or not record.path:
                missing_records.append(record) if record else None
                continue
            output_path = _callgraph_output_path(
                record.path,
                output_dir=callgraph_dir,
                windows_root=windows_root,
                flatten_names=detected_flatten,
                arch=target_arch,
            )
            if not output_path.exists():
                missing_records.append(record)

        if missing_records:
            missing_names = sorted({rec.module for rec in missing_records if rec})
            if missing_names and typer.confirm(
                f"Missing call graphs for requested modules: {', '.join(missing_names)}. Generate now?"
            ):
                symbol_store = _resolve_symbol_store(
                    symbol_path,
                    use_symbol_server=use_symbol_server,
                    symbol_cache=symbol_cache,
                    symbol_server_url=symbol_server_url,
                )
                binaries = [rec.path for rec in missing_records if rec and rec.path and rec.path.is_file()]
                _run_exports(
                    binaries,
                    ghidra_headless=ghidra_headless,
                    project_root=project_root,
                    project_name=project_name,
                    script_path=script_path,
                    output_dir=callgraph_dir,
                    metadata_root=metadata_root,
                    pdb_root=pdb_root,
                    windows_root=windows_root,
                    symbol_store=symbol_store,
                    verbose=verbose,
                    flatten_names=detected_flatten,
                    workers=workers,
                )

    if auto_generate_missing:
        if len(module) < 2:
            raise typer.BadParameter("--auto-generate-missing requires at least two --module values.")

        if not requested_modules:
            requested_modules = [_normalize_module_name(entry) for entry in module if entry.strip()]
            if any(not entry for entry in requested_modules):
                raise typer.BadParameter("Module names must be non-empty.")

        candidates = _load_inventory_candidates(metadata_root)
        target_arch = _select_target_arch(requested_modules, candidates)
        records = _select_inventory_records(candidates, arch=target_arch)

        missing_requested = [entry for entry in requested_modules if entry not in records]
        if missing_requested:
            raise typer.BadParameter(
                f"Requested modules were not found in inventory for the selected architecture: {missing_requested}"
            )

        module_graph = _build_module_adjacency(records)
        reversed_graph = _invert_adjacency(module_graph)

        if len(requested_modules) == 2:
            start_module, end_module = requested_modules
            reachable_from_start = _reachable_nodes(module_graph, start_module)
            reachable_to_end = _reachable_nodes(reversed_graph, end_module)
            candidate_modules = reachable_from_start & reachable_to_end
            if not candidate_modules:
                raise typer.BadParameter("No module-level path exists between the requested modules.")
        else:
            reachable_map = {mod: _reachable_nodes(module_graph, mod) for mod in requested_modules}
            reverse_map = {mod: _reachable_nodes(reversed_graph, mod) for mod in requested_modules}
            candidate_modules = set(requested_modules)
            has_any_path = False
            for src in requested_modules:
                for dst in requested_modules:
                    if src == dst:
                        continue
                    if dst in reachable_map[src]:
                        has_any_path = True
                    candidate_modules |= reachable_map[src] & reverse_map[dst]
            if not has_any_path:
                raise typer.BadParameter("No module-level paths exist between the requested modules.")

        detected_flatten = _detect_flatten_names(callgraph_dir, target_arch) if flatten_names is None else flatten_names
        callgraph_dir.mkdir(parents=True, exist_ok=True)

        missing_records: list[_InventoryRecord] = []
        callgraph_paths: dict[str, Path] = {}
        for module_name in sorted(candidate_modules):
            record = records.get(module_name)
            if not record or not record.path:
                missing_records.append(record) if record else None
                continue
            output_path = _callgraph_output_path(
                record.path,
                output_dir=callgraph_dir,
                windows_root=windows_root,
                flatten_names=detected_flatten,
                arch=target_arch,
            )
            if output_path.exists():
                callgraph_paths[module_name] = output_path
            else:
                missing_records.append(record)

        if missing_records:
            binaries = [rec.path for rec in missing_records if rec and rec.path and rec.path.is_file()]
            if binaries:
                symbol_store = _resolve_symbol_store(
                    symbol_path,
                    use_symbol_server=use_symbol_server,
                    symbol_cache=symbol_cache,
                    symbol_server_url=symbol_server_url,
                )
                _run_exports(
                    binaries,
                    ghidra_headless=ghidra_headless,
                    project_root=project_root,
                    project_name=project_name,
                    script_path=script_path,
                    output_dir=callgraph_dir,
                    metadata_root=metadata_root,
                    pdb_root=pdb_root,
                    windows_root=windows_root,
                    symbol_store=symbol_store,
                    verbose=verbose,
                    flatten_names=detected_flatten,
                    workers=workers,
                )

        available_modules: set[str] = set()
        for module_name in sorted(candidate_modules):
            record = records.get(module_name)
            if not record or not record.path:
                continue
            output_path = _callgraph_output_path(
                record.path,
                output_dir=callgraph_dir,
                windows_root=windows_root,
                flatten_names=detected_flatten,
                arch=target_arch,
            )
            if output_path.exists():
                callgraph_paths[module_name] = output_path
                available_modules.add(module_name)

        available_adj = {
            node: targets & available_modules
            for node, targets in module_graph.items()
            if node in available_modules
        }
        reverse_available = _invert_adjacency(available_adj)

        if len(requested_modules) == 2:
            start_module, end_module = requested_modules
            reachable_from_start = _reachable_nodes(available_adj, start_module)
            reachable_to_end = _reachable_nodes(reverse_available, end_module)
            available_modules = reachable_from_start & reachable_to_end
            if fail_if_disconnected and end_module not in reachable_from_start:
                raise typer.BadParameter(
                    "No full module path exists between the requested modules after auto-generation."
                )
        else:
            reachable_map = {mod: _reachable_nodes(available_adj, mod) for mod in requested_modules}
            missing_pairs: list[tuple[str, str]] = []
            for idx, src in enumerate(requested_modules):
                for dst in requested_modules[idx + 1 :]:
                    if dst not in reachable_map[src] and src not in reachable_map[dst]:
                        missing_pairs.append((src, dst))
            if fail_if_disconnected and missing_pairs:
                sample = ", ".join(f"{a}->{b}" for a, b in missing_pairs[:5])
                raise typer.BadParameter(
                    f"No full module path exists between requested modules after auto-generation (e.g. {sample})."
                )

        paths = [callgraph_paths[name] for name in sorted(available_modules) if name in callgraph_paths]
        if not paths:
            raise typer.BadParameter("No call graph artefacts were found after auto-generation.")
    else:
        paths = sorted(callgraph_dir.rglob("*.callgraph.json"))
        if module:
            module_filter = {entry.strip().upper() for entry in module if entry.strip()}
            filtered: list[Path] = []

            def _candidate_module(candidate: Path) -> str:
                stem = candidate.name
                if stem.endswith(".callgraph.json"):
                    stem = stem[: -len(".callgraph.json")]
                if not stem.lower().endswith((".dll", ".exe")):
                    stem = f"{stem}.dll"
                return stem.upper()

            for candidate in paths:
                if _candidate_module(candidate) in module_filter:
                    filtered.append(candidate)
            paths = filtered

        if not paths:
            raise typer.BadParameter(f"No call graph artefacts found under {callgraph_dir}")
        if limit is not None:
            paths = paths[:limit]

    builder = UnifiedGraphBuilder(
        metadata_root,
        include_internal=include_internal,
        include_api_set_forwarders=api_set_forwarders,
    )
    typer.echo(f"Building unified graph from {len(paths)} artefacts...")
    builder.build(paths)
    builder.export(output)
    typer.secho(f"Unified graph written to {output}", fg=typer.colors.GREEN)


@app.command("callgraph-syscall-prune")
def callgraph_syscall_prune(
    input: List[Path] = typer.Option(..., "--input", "-i", help="Call graph JSON(s) to prune to syscall paths."),
    output_dir: Path = typer.Option(Path("data/interim/syscall_graphs"), help="Output directory for pruned graphs."),
    syscall_program: str = typer.Option("ntdll.dll", help="DLL hosting syscalls (default: ntdll.dll)."),
    syscall_prefix: List[str] = typer.Option(["Nt", "Zw"], help="Syscall name prefixes to consider."),
) -> None:
    """
    Keep only nodes/edges that can reach syscalls in the provided call graphs.
    """

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    prefixes: tuple[str, ...] = tuple(syscall_prefix)

    for item in input:
        graph = load_call_graph(item)
        pruned = _prune_to_syscalls(graph, syscall_prefix=prefixes, syscall_program_hint=syscall_program)

        try:
            relative = item.resolve().relative_to(Path("data/interim/call_graphs").resolve())
            destination = output_dir / relative
        except Exception:
            destination = output_dir / item.name
        destination.parent.mkdir(parents=True, exist_ok=True)

        export_generic_graph(pruned, destination)
        typer.echo(f"{item} -> {destination} (nodes={pruned.number_of_nodes()}, edges={pruned.number_of_edges()})")


@app.command("callgraph-unified-syscall-prune")
def callgraph_unified_syscall_prune(
    input: Path = typer.Option(..., "--input", "-i", help="Unified nodes/edges graph JSON to prune to syscall paths."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Destination path for pruned graph."),
    output_dir: Path = typer.Option(
        Path("data/interim/syscall_graphs"), help="Directory where syscall-pruned unified graphs are written."
    ),
    syscall_program: str = typer.Option("ntdll.dll", help="DLL hosting syscalls (default: ntdll.dll)."),
    syscall_prefix: List[str] = typer.Option(["Nt", "Zw"], help="Syscall name prefixes to consider."),
) -> None:
    """
    Keep only paths that can reach syscalls in a unified graph (nodes/edges JSON).
    """

    input_path = input.expanduser().resolve()
    if not input_path.exists():
        raise typer.BadParameter(f"Input not found: {input_path}")
    prefixes: tuple[str, ...] = tuple(syscall_prefix)

    graph = load_generic_graph(input_path)
    pruned = _prune_unified_to_syscalls(graph, syscall_prefix=prefixes, syscall_program_hint=syscall_program)

    if output:
        destination = output.expanduser().resolve()
    else:
        output_dir = output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            rel = input_path.relative_to(input_path.parents[1])
            destination = (output_dir / rel).with_suffix(".syscall.json")
        except Exception:
            destination = output_dir / f"{input_path.stem}.syscall.json"
    export_generic_graph(pruned, destination)
    typer.echo(f"{input_path} -> {destination} (nodes={pruned.number_of_nodes()}, edges={pruned.number_of_edges()})")


@app.command("callgraph-project-syscalls")
def callgraph_project_syscalls(
    graph: Path = typer.Option(..., "--graph", "-g", help="Unified nodes/edges graph JSON."),
    program: str = typer.Option(..., "--program", "-p", help="Target program (DLL) to project, e.g., KERNEL32.DLL."),
    output_graph: Optional[Path] = typer.Option(None, "--out-graph", help="Projection graph JSON output."),
    output_table: Optional[Path] = typer.Option(None, "--out-table", help="Projection table CSV output."),
    output_metrics: Optional[Path] = typer.Option(None, "--out-metrics", help="Projection metrics JSON output."),
    max_hops: Optional[int] = typer.Option(None, help="Optional max hops to syscalls."),
    allow_kinds: List[str] = typer.Option([], help="Restrict to these edge kinds (direct, import, forwarder, syscall)."),
    max_syscalls_per_function: Optional[int] = typer.Option(None, help="Limit syscalls recorded per function."),
    syscall_program: str = typer.Option("ntdll.dll", help="DLL hosting syscalls (default: ntdll.dll)."),
    syscall_prefix: List[str] = typer.Option(["Nt", "Zw"], help="Syscall prefixes."),
) -> None:
    """
    Project a unified graph to show which syscalls a target DLL can reach (via cross-DLL paths).
    """

    graph_path = graph.expanduser().resolve()
    if not graph_path.exists():
        raise typer.BadParameter(f"Graph not found: {graph_path}")

    g = load_generic_graph(graph_path)
    projection, rows, metrics = _project_syscalls(
        g,
        program,
        syscall_prefix=tuple(syscall_prefix),
        syscall_program_hint=syscall_program,
        max_hops=max_hops,
        allow_kinds=set(allow_kinds) if allow_kinds else None,
        max_syscalls_per_function=max_syscalls_per_function,
    )

    base_dir = Path("data/interim/syscall_graphs")
    base_dir.mkdir(parents=True, exist_ok=True)
    stem_safe = program.upper().replace(".", "_")

    if output_graph is None:
        output_graph = base_dir / f"{stem_safe}.syscall_projection.json"
    output_graph = output_graph.expanduser().resolve()
    projection.graph["mode"] = "syscall"
    projection.graph["source_graph"] = str(graph_path)
    export_generic_graph(projection, output_graph)
    typer.echo(f"Projection graph written to {output_graph} (nodes={projection.number_of_nodes()}, edges={projection.number_of_edges()})")

    if output_table is None:
        output_table = base_dir / f"{stem_safe}.syscall_projection.csv"
    output_table = output_table.expanduser().resolve()
    output_table.parent.mkdir(parents=True, exist_ok=True)
    with output_table.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["function_id", "function_name", "syscall_id", "syscall_name", "hops", "via_program", "path_preview"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    typer.echo(f"Projection table written to {output_table}")

    if output_metrics is None:
        output_metrics = base_dir / f"{stem_safe}.syscall_projection.metrics.json"
    output_metrics = output_metrics.expanduser().resolve()
    output_metrics.parent.mkdir(parents=True, exist_ok=True)
    output_metrics.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    typer.echo(f"Projection metrics written to {output_metrics}")


@app.command("callgraph-syscall-report")
def callgraph_syscall_report(
    input: List[Path] = typer.Option(..., "--input", "-i", help="Call graph JSON(s) to analyse."),
    program: Optional[str] = typer.Option(None, help="Limit API candidates to this program (e.g. advapi32.dll)."),
    syscall_program: str = typer.Option("ntdll.dll", help="DLL hosting syscalls (default: ntdll.dll)."),
    syscall_prefix: List[str] = typer.Option(["Nt", "Zw"], help="Syscall name prefixes to consider."),
    top: int = typer.Option(15, help="Number of sample entries to print for each category."),
) -> None:
    """Summarise syscall reachability, highlighting gaps in coverage."""

    graph = _load_graph_from_inputs(input)
    candidate_programs = {program} if program else None
    prefixes: tuple[str, ...] = tuple(syscall_prefix)

    unconnected = detect_unconnected_syscalls(
        graph,
        syscall_prefix=prefixes,
        program_hint=syscall_program,
    )
    typer.echo(f"Syscalls with no inbound edges: {len(unconnected)}")
    for syscall in list(unconnected)[:top]:
        typer.echo(f"  - {_format_node_label(graph, syscall)} ({syscall})")

    orphan_apis = functions_without_syscalls(
        graph,
        syscall_prefix=prefixes,
        syscall_program_hint=syscall_program,
        candidate_programs=candidate_programs,
    )
    typer.echo(f"API functions without syscall reachability: {len(orphan_apis)}")
    for entry in orphan_apis[:top]:
        typer.echo(f"  - {entry.label} ({entry.program})")

    coverage = build_syscall_reachability_report(
        graph,
        syscall_prefix=prefixes,
        syscall_program_hint=syscall_program,
        candidate_programs=candidate_programs,
    )
    typer.echo("Top API candidates by syscall coverage:")
    for entry in coverage[:top]:
        typer.echo(f"  - {entry.label} ({entry.program}) -> {len(entry.coverage)} syscalls")


@app.command("callgraph-hook-plan")
def callgraph_hook_plan(
    input: List[Path] = typer.Option(..., "--input", "-i", help="Call graph JSON(s) to analyse."),
    program: Optional[str] = typer.Option(None, help="Limit hook candidates to this program (e.g. advapi32.dll)."),
    syscall_program: str = typer.Option("ntdll.dll", help="DLL hosting syscalls (default: ntdll.dll)."),
    syscall_prefix: List[str] = typer.Option(["Nt", "Zw"], help="Syscall name prefixes to consider."),
    max_uncovered: int = typer.Option(25, help="Maximum number of uncovered syscalls to list."),
) -> None:
    """Compute a greedy minimal hook set covering the reachable syscalls."""

    graph = _load_graph_from_inputs(input)
    candidate_programs = {program} if program else None
    prefixes: tuple[str, ...] = tuple(syscall_prefix)

    recommendation: HookRecommendation = find_minimal_hook_set(
        graph,
        target_syscalls=None,
        syscall_prefix=prefixes,
        syscall_program_hint=syscall_program,
        candidate_programs=candidate_programs,
    )

    if recommendation.missing_targets:
        typer.secho("Warning: unresolved syscall identifiers:", fg=typer.colors.YELLOW)
        for missing in sorted(recommendation.missing_targets):
            typer.echo(f"  - {missing}")

    typer.echo(f"Selected hooks: {len(recommendation.hooks)}")
    for idx, hook in enumerate(recommendation.hooks, start=1):
        coverage_names = sorted(_format_node_label(graph, node) for node in hook.coverage)
        display_coverage = ", ".join(coverage_names[:5])
        if len(coverage_names) > 5:
            display_coverage += f", ... (+{len(coverage_names) - 5})"
        typer.echo(f"{idx:2d}. {hook.label} ({hook.program}) -> {len(hook.coverage)} syscalls")
        if coverage_names:
            typer.echo(f"      covers: {display_coverage}")

    if recommendation.uncovered_syscalls:
        typer.secho("Uncovered syscalls:", fg=typer.colors.YELLOW)
        for node in sorted(list(recommendation.uncovered_syscalls))[:max_uncovered]:
            typer.echo(f"  - {_format_node_label(graph, node)} ({node})")
        remaining = len(recommendation.uncovered_syscalls) - max_uncovered
        if remaining > 0:
            typer.echo(f"    ... (+{remaining} more)")
    else:
        typer.secho("All targeted syscalls are covered by the hook set.", fg=typer.colors.GREEN)


@app.command("callgraph-validate")
def callgraph_validate(
    input: List[Path] = typer.Option(..., "--input", "-i", help="Call graph or unified graph JSON to validate."),
    metadata_root: Optional[Path] = typer.Option(
        None, help="Inventory root used to sanity-check syscall coverage for unified graphs."
    ),
    syscall_ratio: float = typer.Option(
        0.8, help="Minimum ratio of syscall nodes vs ntdll Nt* exports when metadata_root is provided."
    ),
) -> None:
    """Validate graph structure and basic syscall coverage."""

    meta_index: MetadataIndex | None = None
    if metadata_root:
        metadata_root = metadata_root.expanduser().resolve()
        if not metadata_root.exists():
            raise typer.BadParameter(f"Metadata root not found: {metadata_root}")
        meta_index = MetadataIndex(metadata_root)

    any_errors = False
    for path in input:
        graph, kind = _load_graph_any(path)
        nodes = set(graph.nodes)
        errors: list[str] = []

        if len(nodes) != graph.number_of_nodes():
            errors.append("Duplicate node ids detected.")
        for source, target in graph.edges():
            if source not in nodes or target not in nodes:
                errors.append(f"Dangling edge: {source} -> {target}")

        is_unified = kind == "unified" or any(str(node).startswith("SYSCALL:") for node in nodes)
        if is_unified and meta_index:
            meta_nt = meta_index.get_module_record("NTDLL.DLL")
            expected_nt = 0
            if meta_nt:
                expected_nt = sum(1 for name in meta_nt.exports if name.startswith("NT"))
            actual_syscalls = sum(
                1
                for node, data in graph.nodes(data=True)
                if str(node).startswith("SYSCALL:") or data.get("layer") == "syscall"
            )
            if expected_nt and actual_syscalls < expected_nt * syscall_ratio:
                errors.append(
                    f"Syscall node count too low: expected >= {int(expected_nt * syscall_ratio)}, found {actual_syscalls}"
                )

        if errors:
            any_errors = True
            typer.secho(f"{path} failed validation:", fg=typer.colors.RED)
            for err in errors:
                typer.echo(f"  - {err}")
        else:
            typer.secho(f"{path} passed validation.", fg=typer.colors.GREEN)

    if any_errors:
        raise typer.Exit(code=1)


@app.command("ghidra-callgraph")
def ghidra_callgraph(
    binary: List[Path] = typer.Option(..., "--binary", "-b", help="PE files to analyse with Ghidra."),
    ghidra_headless: Path = typer.Option(DEFAULT_HEADLESS, help="Path to analyzeHeadless launcher."),
    project_root: Path = typer.Option(Path("ghidra-projects"), help="Directory where the Ghidra project will be stored."),
    project_name: str = typer.Option("call_graph_samples", help="Name of the Ghidra project to use."),
    script_path: Path = typer.Option(Path("scripts/ghidra/export_call_graph.py"), help="Ghidra script that exports call graphs."),
    output_dir: Path = typer.Option(Path("data/interim/call_graphs"), help="Directory for call graph JSON outputs."),
    overwrite: bool = typer.Option(False, help="Overwrite existing call graph exports."),
    metadata_root: Path = typer.Option(Path("data/raw/windows_inventory"), help="Inventory metadata root (JSON files)."),
    pdb_root: Path = typer.Option(Path("data/external/pdbs"), help="Root of downloaded PDB symbol store."),
    windows_root: Path = typer.Option(Path(r"C:\Windows"), help="Windows directory used when building the inventory."),
    symbol_path: Optional[str] = typer.Option(None, help="Explicit symbol search path passed to Ghidra (-symbolPath)."),
    symbol_cache: Path = typer.Option(Path("data/external/pdbs"), help="Local cache used when building a symbol server chain."),
    use_symbol_server: bool = typer.Option(
        True, help="Use the Microsoft public symbol server with the provided cache."
    ),
    symbol_server_url: str = typer.Option("https://msdl.microsoft.com/download/symbols", help="Symbol server URL."),
    verbose: bool = typer.Option(False, help="Print per-binary progress."),
    flatten_names: bool = typer.Option(
        False, help="Flatten output filenames instead of mirroring the Windows directory hierarchy."
    ),
) -> None:
    """Run the Ghidra call graph exporter for the provided binaries."""

    script_path = script_path.expanduser().resolve()
    ghidra_headless = ghidra_headless.expanduser().resolve()
    project_root = project_root.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    metadata_root = metadata_root.expanduser().resolve()
    pdb_root = pdb_root.expanduser().resolve()
    windows_root = windows_root.expanduser().resolve()
    symbol_store: str | Path | None = None
    cache_root = symbol_cache.expanduser().resolve()
    if symbol_path is not None:
        # allow srv* chains as raw strings
        try:
            sp = Path(symbol_path)
            if sp.drive or sp.root:
                sp = sp.expanduser().resolve()
            if sp.exists():
                symbol_store = sp
            else:
                # accept non-existent path if caller passed srv* chain
                symbol_store = symbol_path
        except Exception:
            symbol_store = symbol_path
    elif use_symbol_server:
        cache_root.mkdir(parents=True, exist_ok=True)
        symbol_store = f"srv*{cache_root}*{symbol_server_url}"

    if not script_path.exists():
        raise typer.BadParameter(f"Ghidra script not found: {script_path}")
    if not metadata_root.exists():
        raise typer.BadParameter(f"Metadata root not found: {metadata_root}")
    if not pdb_root.exists():
        typer.secho(f"Warning: PDB root {pdb_root} does not exist, continuing without symbol enrichment.", fg=typer.colors.YELLOW)
        pdb_root = None
    # symbol_store remains None unless explicitly provided via --symbol-path

    binaries: List[Path] = []
    for item in binary:
        candidate = item.expanduser().resolve()
        if not candidate.exists():
            raise typer.BadParameter(f"Binary not found: {candidate}")
        binaries.append(candidate)

    typer.echo(f"Running Ghidra headless on {len(binaries)} binaries...")
    results = export_call_graphs(
        binaries,
        ghidra_headless=ghidra_headless,
        project_root=project_root,
        project_name=project_name,
        script_path=script_path,
        output_dir=output_dir,
        overwrite=overwrite,
        metadata_root=metadata_root if pdb_root else None,
        pdb_root=pdb_root,
        windows_root=windows_root,
        symbol_store=symbol_store,
        verbose=verbose,
        flatten_names=flatten_names,
    )

    failed = 0
    for result in results:
        status = "success" if result.succeeded else ("skipped" if result.skipped else f"error ({result.returncode})")
        typer.echo(f"{result.binary} -> {result.output} [{status}]")
        if result.metadata:
            typer.echo(f"  metadata: {result.metadata}")
        if result.pdb_path:
            typer.echo(f"  pdb     : {result.pdb_path}")
        elif not result.skipped:
            typer.secho("  pdb     : not resolved", fg=typer.colors.YELLOW)
        if result.stderr:
            typer.echo(result.stderr.strip())
        if not result.succeeded and not result.skipped:
            failed += 1

    if failed:
        raise typer.Exit(code=1)


@app.command("callgraph-batch")
def callgraph_batch(
    include: List[str] = typer.Option(["System32", "SysWOW64"], "--include", "-I", help="Relative subdirectories of the Windows root to process."),
    metadata_root: Path = typer.Option(Path("data/raw/windows_inventory"), help="Inventory metadata root (JSON files)."),
    windows_root: Path = typer.Option(Path(r"C:\Windows"), help="Windows directory used when building the inventory."),
    limit: Optional[int] = typer.Option(None, help="Process at most this many binaries."),
    workers: int = typer.Option(1, help="Number of concurrent Ghidra instances to run."),
    skip_existing: bool = typer.Option(True, help="Skip binaries whose call graph already exists unless --overwrite is set."),
    ghidra_headless: Path = typer.Option(DEFAULT_HEADLESS, help="Path to analyzeHeadless launcher."),
    project_root: Path = typer.Option(Path("ghidra-projects"), help="Directory where the Ghidra project will be stored."),
    project_name: str = typer.Option("call_graph_batch", help="Name of the Ghidra project to use."),
    script_path: Path = typer.Option(Path("scripts/ghidra/export_call_graph.py"), help="Ghidra script that exports call graphs."),
    output_dir: Path = typer.Option(Path("data/interim/call_graphs"), help="Directory for call graph JSON outputs."),
    overwrite: bool = typer.Option(False, help="Overwrite existing call graph exports."),
    pdb_root: Path = typer.Option(Path("data/external/pdbs"), help="Root of downloaded PDB symbol store."),
    symbol_path: Optional[str] = typer.Option(None, help="Explicit symbol search path passed to Ghidra (-symbolPath)."),
    symbol_cache: Path = typer.Option(Path("data/external/pdbs"), help="Local cache used when building a symbol server chain."),
    use_symbol_server: bool = typer.Option(
        True, help="Use the Microsoft public symbol server with the provided cache."
    ),
    symbol_server_url: str = typer.Option("https://msdl.microsoft.com/download/symbols", help="Symbol server URL."),
    verbose: bool = typer.Option(False, help="Print per-binary progress."),
    flatten_names: bool = typer.Option(
        False, help="Flatten output filenames instead of mirroring the Windows directory hierarchy."
    ),
) -> None:
    """Run the call graph exporter for all binaries under the selected Windows subdirectories."""

    metadata_root = metadata_root.expanduser().resolve()
    windows_root = windows_root.expanduser().resolve()
    ghidra_headless = ghidra_headless.expanduser().resolve()
    project_root = project_root.expanduser().resolve()
    script_path = script_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    pdb_root = pdb_root.expanduser().resolve()

    if not metadata_root.exists():
        raise typer.BadParameter(f"Metadata root not found: {metadata_root}")
    if not script_path.exists():
        raise typer.BadParameter(f"Ghidra script not found: {script_path}")
    symbol_store: str | Path | None = None
    cache_root = symbol_cache.expanduser().resolve()
    if symbol_path is not None:
        try:
            sp = Path(symbol_path)
            if sp.drive or sp.root:
                sp = sp.expanduser().resolve()
            if sp.exists():
                symbol_store = sp
            else:
                symbol_store = symbol_path
        except Exception:
            symbol_store = symbol_path
    elif use_symbol_server:
        cache_root.mkdir(parents=True, exist_ok=True)
        symbol_store = f"srv*{cache_root}*{symbol_server_url}"

    include_prefixes: list[Path] = []
    for entry in include:
        prefix = (windows_root / Path(entry)).resolve()
        include_prefixes.append(prefix)

    binaries: list[Path] = []
    for metadata_file in sorted(metadata_root.rglob("*.json")):
        if metadata_file.is_dir():
            continue
        try:
            metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        binary_path = metadata.get("path")
        if not binary_path:
            continue
        candidate = Path(binary_path).resolve()
        if not candidate.is_file():
            if verbose:
                typer.secho(f"Skipping missing file: {candidate}", fg=typer.colors.YELLOW)
            continue
        if not any(candidate.is_relative_to(prefix) for prefix in include_prefixes):
            continue

        machine = metadata.get("machine")
        arch = (machine or "").lower() if isinstance(machine, str) else ""
        if arch.startswith("image_file_machine_amd64") or arch in {"amd64", "x86_64", "x64"}:
            arch = "x64"
        elif arch.startswith("image_file_machine_i386") or arch in {"i386", "x86"}:
            arch = "x86"
        elif arch.startswith("image_file_machine_arm64") or ("arm64" in arch):
            arch = "arm64"
        else:
            arch = arch.upper() if arch else "unknown"

        if skip_existing and not overwrite:
            try:
                relative = candidate.relative_to(windows_root)
                rel_str = str(relative)
            except ValueError:
                rel_str = candidate.name
            out_root = output_dir / arch
            if flatten_names:
                flattened = rel_str.replace(":", "_").replace("\\", "_").replace("/", "_")
                output_path = out_root / f"{flattened}.callgraph.json"
            else:
                if "\\" in rel_str or "/" in rel_str:
                    output_path = out_root / Path(rel_str).parent / f"{Path(rel_str).name}.callgraph.json"
                else:
                    output_path = out_root / f"{rel_str}.callgraph.json"
            if output_path.exists():
                continue

        binaries.append(candidate)
        if limit is not None and len(binaries) >= limit:
            break

    if not binaries:
        typer.echo("No binaries matched the provided filters.")
        return

    if workers < 1:
        raise typer.BadParameter("--workers must be >= 1")

    output_dir.mkdir(parents=True, exist_ok=True)
    project_root.mkdir(parents=True, exist_ok=True)

    if not pdb_root.exists():
        typer.secho(f"Warning: PDB root {pdb_root} does not exist; proceeding without local PDBs.", fg=typer.colors.YELLOW)
        pdb_root = None

    typer.echo(f"Processing {len(binaries)} binaries with project '{project_name}'...")
    if workers == 1 or len(binaries) == 1:
        results = export_call_graphs(
            binaries,
            ghidra_headless=ghidra_headless,
            project_root=project_root,
            project_name=project_name,
            script_path=script_path,
            output_dir=output_dir,
            overwrite=overwrite,
            metadata_root=metadata_root,
            pdb_root=pdb_root,
            windows_root=windows_root,
            symbol_store=symbol_store,
            verbose=verbose,
            flatten_names=flatten_names,
        )
    else:
        worker_count = min(workers, len(binaries))
        buckets: list[list[Path]] = [[] for _ in range(worker_count)]
        for idx, binary in enumerate(binaries):
            buckets[idx % worker_count].append(binary)

        def _run_bucket(worker_idx: int, chunk: list[Path]) -> list[CallGraphRunResult]:
            if not chunk:
                return []
            return export_call_graphs(
                chunk,
                ghidra_headless=ghidra_headless,
                project_root=project_root / f"worker_{worker_idx}",
                project_name=f"{project_name}_w{worker_idx}",
                script_path=script_path,
                output_dir=output_dir,
                overwrite=overwrite,
                metadata_root=metadata_root,
                pdb_root=pdb_root,
                windows_root=windows_root,
                symbol_store=symbol_store,
                verbose=verbose,
                flatten_names=flatten_names,
            )

        results: list[CallGraphRunResult] = []
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(_run_bucket, worker_idx + 1, bucket)
                for worker_idx, bucket in enumerate(buckets)
                if bucket
            ]
            for fut in as_completed(futures):
                results.extend(fut.result())

    succeeded = sum(1 for r in results if r.succeeded)
    skipped = sum(1 for r in results if r.skipped)
    failed = len(results) - succeeded - skipped

    typer.echo(f"Completed. Success: {succeeded}, Skipped: {skipped}, Failed: {failed}")
    if failed:
        typer.secho("Failures:", fg=typer.colors.RED)
        for result in results:
            if not result.succeeded and not result.skipped:
                typer.echo(f"  {result.binary} -> rc={result.returncode}")
                if result.stderr:
                    typer.echo(result.stderr.strip())


@app.command("callgraph-visualize")
def callgraph_visualize(
    input: Path = typer.Option(..., "--input", "-i", help="Call graph JSON emitted by the exporter."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Destination PNG (defaults to data/interim/figures/<name>.png)."),
    max_nodes: Optional[int] = typer.Option(200, help="Limit the number of nodes drawn for readability."),
    layout: str = typer.Option("spring", help="Layout algorithm: spring or kamada-kawai."),
    show_labels: bool = typer.Option(False, help="Render node labels (best for <=150 nodes)."),
    show_legend: bool = typer.Option(True, help="Show a legend mapping colors to DLLs."),
) -> None:
    """Render a call graph JSON into a static image."""

    input_path = input.expanduser().resolve()
    if not input_path.exists():
        raise typer.BadParameter(f"Call graph file not found: {input_path}")

    # Detect format: per-DLL exporter vs generic/unified (nodes/edges).
    with input_path.open("r", encoding="utf-8") as handle:
        payload_preview = json.load(handle)
    if "functions" in payload_preview:
        graph = load_call_graph(input_path)
    elif "nodes" in payload_preview and "edges" in payload_preview:
        graph = load_generic_graph(input_path)
    else:
        raise typer.BadParameter("Unsupported graph format: expected exporter JSON or unified graph with nodes/edges.")

    default_output = Path("data/interim/figures") / f"{input_path.stem}.png"
    output_path = (output or default_output).expanduser().resolve()

    png_path = plot_call_graph(
        graph,
        output_path,
        max_nodes=max_nodes,
        layout=layout,
        show_labels=show_labels,
        show_legend=show_legend,
        title=f"{graph.graph.get('program', input_path.stem)} ({graph.number_of_nodes()} nodes)",
    )

    typer.echo(f"Nodes: {graph.number_of_nodes()}  Edges: {graph.number_of_edges()}")
    typer.echo(f"Visualization saved to {png_path}")


@app.command("callgraph-aggregate")
def callgraph_aggregate(
    input: List[Path] = typer.Option(..., "--input", "-i", help="Call graph JSON artefacts to merge.", rich_help_panel="Inputs"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Combined graph output path (JSON or GraphML)."),
    export_format: str = typer.Option("json", "--format", help="Output format when writing combined graph (json or graphml)."),
    visualize: Optional[Path] = typer.Option(None, "--visualize", "-v", help="Optional PNG path for visualization."),
    max_nodes: Optional[int] = typer.Option(200, help="Limit the number of nodes drawn in the visualization."),
    layout: str = typer.Option("spring", help="Layout algorithm for visualization."),
    show_labels: bool = typer.Option(False, help="Show node labels in visualization."),
    show_legend: bool = typer.Option(True, help="Show a legend mapping colors to DLLs."),
) -> None:
    """Merge multiple call graph JSON files and optionally visualise the combined graph."""

    if not input:
        raise typer.BadParameter("At least one --input call graph is required.")

    resolved_inputs: List[Path] = []
    for item in input:
        candidate = item.expanduser().resolve()
        if not candidate.exists():
            raise typer.BadParameter(f"Call graph not found: {candidate}")
        resolved_inputs.append(candidate)

    merged = merge_call_graphs(resolved_inputs)
    typer.echo(f"Merged {len(resolved_inputs)} graphs -> {merged.number_of_nodes()} nodes / {merged.number_of_edges()} edges")
    programs = merged.graph.get("programs", [])
    if programs:
        typer.echo("Programs: " + ", ".join(programs))

    if output:
        destination = output.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        fmt = export_format.lower()
        if fmt == "json":
            export_generic_graph(merged, destination)
        elif fmt == "graphml":
            nx.write_graphml(_sanitize_for_graphml(merged), destination)
        else:
            raise typer.BadParameter(f"Unsupported format: {export_format}")
        typer.echo(f"Combined graph written to {destination}")

    if visualize:
        visualize_path = visualize.expanduser().resolve()
        png_path = plot_call_graph(
            merged,
            visualize_path,
            max_nodes=max_nodes,
            layout=layout,
            show_labels=show_labels,
            show_legend=show_legend,
        )
        typer.echo(f"Visualization saved to {png_path}")


@app.command("callgraph-igraph-summary")
def callgraph_igraph_summary(
    input: List[Path] = typer.Option(..., "--input", "-i", help="Call graph JSONs to analyse with igraph.", rich_help_panel="Inputs"),
    metric: str = typer.Option("degree", help="Centrality metric: degree, betweenness, pagerank."),
    top: int = typer.Option(10, help="Show the top-N vertices for the selected metric."),
) -> None:
    """Summarise call graphs using igraph centrality metrics."""

    if not input:
        raise typer.BadParameter("At least one --input call graph is required.")

    resolved = []
    for item in input:
        candidate = item.expanduser().resolve()
        if not candidate.exists():
            raise typer.BadParameter(f"Call graph not found: {candidate}")
        resolved.append(candidate)

    if len(resolved) == 1:
        graph = load_call_graph(resolved[0])
    else:
        graph = merge_call_graphs(resolved)

    try:
        ig_graph = to_igraph(graph)
    except ImportError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(f"Vertices: {ig_graph.vcount()}  Edges: {ig_graph.ecount()}")

    metric = metric.lower()
    if metric == "degree":
        scores = ig_graph.degree()
    elif metric == "betweenness":
        scores = ig_graph.betweenness()
    elif metric == "pagerank":
        scores = ig_graph.pagerank()
    else:
        raise typer.BadParameter(f"Unsupported metric: {metric}")

    vs = ig_graph.vs
    ranked = sorted(range(len(scores)), key=lambda idx: scores[idx], reverse=True)[:top]
    typer.echo(f"Top {len(ranked)} vertices by {metric}:")
    for idx in ranked:
        attrs = vs[idx].attributes()
        program = attrs.get("program", "unknown")
        name = attrs.get("name") or attrs.get("qualified_name") or attrs.get("address") or vs[idx]["name"]
        value = scores[idx]
        typer.echo(f"{idx:5d} | {program:12s} | {name!s:<50.50} | {metric}={value:.4f}")


@app.command("callgraph-ui")
def callgraph_ui(
    data_dir: Path = typer.Option(Path("data/interim/call_graphs"), help="Directory containing *.callgraph.json files."),
    host: str = typer.Option("127.0.0.1", help="Host interface for the Dash server."),
    port: int = typer.Option(8050, help="Port for the Dash server."),
    debug: bool = typer.Option(False, help="Enable Dash debug mode."),
    mode: str = typer.Option(
        "auto",
        help="Graph mode to load: raw (per-DLL), unified (nodes/edges), syscall (pruned), or auto to accept any.",
        case_sensitive=False,
    ),
    exclude_report: Optional[Path] = typer.Option(
        None,
        help="Optional JSON report (from callgraph-empty-report) listing graphs to ignore.",
    ),
) -> None:
    """Launch the interactive Dash application for exploring call graphs."""

    candidate = data_dir.expanduser()
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate).resolve()
    if not candidate.exists():
        project_root = Path(__file__).resolve().parents[2]
        alt = (project_root / data_dir).resolve()
        if alt.exists():
            candidate = alt
    excluded_paths: Optional[set[Path]] = None
    if exclude_report is not None:
        excluded_paths = load_excluded_paths(exclude_report, candidate)
        if excluded_paths:
            typer.echo(f"Skipping {len(excluded_paths)} graphs based on {exclude_report}.")
    app_instance = create_app(candidate, excluded_paths=excluded_paths, mode=mode)
    app_instance.run(host=host, port=port, debug=debug)


def run() -> None:
    """Entry point used by ``python -m call_graph_win11.cli``."""

    app()


if __name__ == "__main__":
    run()
