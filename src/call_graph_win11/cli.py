"""Command line entry points for the project."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

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
    merge_call_graphs,
    to_igraph,
)
from call_graph_win11.analysis.visualization import plot_call_graph
from call_graph_win11.analysis.unified_graph import UnifiedGraphBuilder
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


@app.command("callgraph-unify")
def callgraph_unify(
    callgraph_dir: Path = typer.Option(Path("data/interim/call_graphs"), help="Directory containing *.callgraph.json files."),
    metadata_root: Path = typer.Option(Path("data/raw/windows_inventory"), help="Inventory metadata root (JSON files)."),
    output: Path = typer.Option(Path("data/interim/unified/unified.callgraph.json"), help="Destination JSON for the unified graph."),
    limit: Optional[int] = typer.Option(None, help="Optional limit on the number of call graphs to process."),
    module: List[str] = typer.Option([], "--module", "-m", help="Restrict to these module names (e.g., kernel32.dll)."),
) -> None:
    """Build the unified cross-DLL call graph and emit igraph-compatible JSON."""

    callgraph_dir = callgraph_dir.expanduser().resolve()
    metadata_root = metadata_root.expanduser().resolve()
    output = output.expanduser().resolve()

    if not callgraph_dir.exists():
        raise typer.BadParameter(f"Call graph directory not found: {callgraph_dir}")
    if not metadata_root.exists():
        raise typer.BadParameter(f"Metadata root not found: {metadata_root}")

    paths = sorted(callgraph_dir.rglob("*.callgraph.json"))
    module_filter: Optional[set[str]] = None
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

    builder = UnifiedGraphBuilder(metadata_root)
    typer.echo(f"Building unified graph from {len(paths)} artefacts...")
    builder.build(paths)
    builder.export(output)
    typer.secho(f"Unified graph written to {output}", fg=typer.colors.GREEN)


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
    symbol_path: Optional[Path] = typer.Option(None, help="Explicit symbol search path passed to Ghidra (-symbolPath)."),
) -> None:
    """Run the Ghidra call graph exporter for the provided binaries."""

    script_path = script_path.expanduser().resolve()
    ghidra_headless = ghidra_headless.expanduser().resolve()
    project_root = project_root.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    metadata_root = metadata_root.expanduser().resolve()
    pdb_root = pdb_root.expanduser().resolve()
    windows_root = windows_root.expanduser().resolve()
    symbol_store = None
    if symbol_path is not None:
        symbol_path = symbol_path.expanduser().resolve()
        if not symbol_path.exists():
            raise typer.BadParameter(f"Symbol path not found: {symbol_path}")
        symbol_store = symbol_path

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
    skip_existing: bool = typer.Option(True, help="Skip binaries whose call graph already exists unless --overwrite is set."),
    ghidra_headless: Path = typer.Option(DEFAULT_HEADLESS, help="Path to analyzeHeadless launcher."),
    project_root: Path = typer.Option(Path("ghidra-projects"), help="Directory where the Ghidra project will be stored."),
    project_name: str = typer.Option("call_graph_batch", help="Name of the Ghidra project to use."),
    script_path: Path = typer.Option(Path("scripts/ghidra/export_call_graph.py"), help="Ghidra script that exports call graphs."),
    output_dir: Path = typer.Option(Path("data/interim/call_graphs"), help="Directory for call graph JSON outputs."),
    overwrite: bool = typer.Option(False, help="Overwrite existing call graph exports."),
    pdb_root: Path = typer.Option(Path("data/external/pdbs"), help="Root of downloaded PDB symbol store."),
    symbol_path: Optional[Path] = typer.Option(None, help="Explicit symbol search path passed to Ghidra (-symbolPath)."),
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
    if symbol_path is not None:
        symbol_path = symbol_path.expanduser().resolve()
        if not symbol_path.exists():
            raise typer.BadParameter(f"Symbol path not found: {symbol_path}")

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
        if not any(candidate.is_relative_to(prefix) for prefix in include_prefixes):
            continue

        if skip_existing and not overwrite:
            try:
                relative = candidate.relative_to(windows_root)
                output_path = output_dir / relative.parent / f"{relative.name}.callgraph.json"
            except ValueError:
                output_path = output_dir / f"{candidate.name}.callgraph.json"
            if output_path.exists():
                continue

        binaries.append(candidate)
        if limit is not None and len(binaries) >= limit:
            break

    if not binaries:
        typer.echo("No binaries matched the provided filters.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    project_root.mkdir(parents=True, exist_ok=True)

    symbol_store = None
    if symbol_path is not None:
        symbol_store = symbol_path
    elif not pdb_root.exists():
        typer.secho(f"Warning: PDB root {pdb_root} does not exist; proceeding without symbol path.", fg=typer.colors.YELLOW)
        pdb_root = None

    typer.echo(f"Processing {len(binaries)} binaries with project '{project_name}'...")
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
    )

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
) -> None:
    """Render a call graph JSON into a static image."""

    input_path = input.expanduser().resolve()
    if not input_path.exists():
        raise typer.BadParameter(f"Call graph file not found: {input_path}")

    graph = load_call_graph(input_path)
    default_output = Path("data/interim/figures") / f"{input_path.stem}.png"
    output_path = (output or default_output).expanduser().resolve()

    png_path = plot_call_graph(
        graph,
        output_path,
        max_nodes=max_nodes,
        layout=layout,
        show_labels=show_labels,
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
        png_path = plot_call_graph(merged, visualize_path, max_nodes=max_nodes, layout=layout, show_labels=show_labels)
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
    app_instance = create_app(candidate, excluded_paths=excluded_paths)
    app_instance.run(host=host, port=port, debug=debug)


def run() -> None:
    """Entry point used by ``python -m call_graph_win11.cli``."""

    app()


if __name__ == "__main__":
    run()
