# Call Graph Reconstruction for Windows System Libraries

[![CI](https://github.com/BahaMelki0/Win11Lib_Call_Graph_Construction/actions/workflows/ci.yml/badge.svg)](https://github.com/BahaMelki0/Win11Lib_Call_Graph_Construction/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Toolkit to reconstruct and analyse call graphs that link Windows 11 system
library exports to the NTDLL syscalls they trigger. It ships a Typer CLI,
Ghidra automation scripts, a Dash UI, and notebooks so you can inventory
binaries, fetch symbols, export per-DLL graphs, unify them, and explore syscall
reachability. Data directories are included as empty placeholders (`.gitkeep`)
so the repo can be shared safely without binaries or PDBs.

## Windows Library Call Stack

Windows splits user-mode services across multiple layers. High-level DLLs in
System32 (e.g., `kernel32`, `advapi32`, `user32`) present ergonomic APIs, but
most of those functions ultimately delegate to `ntdll.dll`, which contains the
syscall stubs that transition into kernel mode. Hooking only the syscalls
produces too much noise (every process shares the same syscall surface), while
hooking an entire user-mode DLL is expensive.

Building a graph that connects each exported API down to the syscall(s) it
triggers gives analysts two advantages:

- **Precision** -- focus on the handful of exports that actually reach the
  syscalls needed to monitor a behaviour of interest.
- **Coverage reasoning** -- reachability analysis shows which syscalls remain
  uncovered, guiding additional reverse engineering or dynamic tracing.

The tooling in this repository automates that mapping so a minimal, high-signal
hook set can be derived programmatically, with the Dash explorer backed by
`igraph` for high-performance traversals and layout generation.

## Getting Started

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate

# 2. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -e .[dev]

# 3. Run the default checks
pytest
```

## CLI Usage

The project exposes its tooling through a Typer-based CLI. If you installed the
package with `pip install -e .`, the `call-graph` entrypoint is available on
your PATH; otherwise invoke the module directly with `python -m
call_graph_win11.cli`. Use `--help` on any command to inspect its options.

```powershell
call-graph --help
call-graph inventory --help
```

Quick demo without Windows data: run the UI against the tiny sample graphs:

```powershell
call-graph callgraph-ui --data-dir docs/analytics/sample_graphs --port 8060
```

### Typical workflow

1. **Inventory the Windows installation**

   ```powershell
   call-graph inventory `
       --root C:\Windows `
       --output data/raw/windows_inventory `
       --limit 250             # optional: restrict for dry runs
   ```

2. **Fetch matching PDBs for the collected RSDS signatures (optional)**

   ```powershell
   call-graph fetch-pdbs `
       --metadata-root data/raw/windows_inventory `
       --output-root data/external/pdbs `
       --cache-root D:\symbol-cache   # optional shared cache
   ```

3. **Export call graphs with Ghidra (single run)**

   ```powershell
   call-graph ghidra-callgraph `
       --binary C:\Windows\System32\kernel32.dll `
       --binary C:\Windows\System32\advapi32.dll `
       --project-root ghidra-projects `
       --metadata-root data/raw/windows_inventory `
       --pdb-root data/external/pdbs `   # optional
       --symbol-cache data/external/pdbs `
       --output-dir data/interim/call_graphs `
       --overwrite
   ```

   To sweep whole directories, switch to the batch command:

   ```powershell
   call-graph callgraph-batch `
       --include System32 --include SysWOW64 `
       --workers 4 `
       --metadata-root data/raw/windows_inventory `
       --windows-root C:\Windows `
       --output-dir data/interim/call_graphs `
       --pdb-root data/external/pdbs `
       --symbol-cache data/external/pdbs
   ```

   Note: by default the CLI builds a symbol path of the form
   `srv*<symbol-cache>*https://msdl.microsoft.com/download/symbols` for on-demand
   PDB downloads. Use `--symbol-path` to override, `--symbol-server-url` to point
   at a different server, or `--no-use-symbol-server` to rely solely on a local
   cache. You can also omit `--pdb-root` entirely to run without PDBs.

4. **Generate analytics and reports**

   ```powershell
   call-graph callgraph-syscall-report `
       --input data/interim/call_graphs/<arch>/System32/kernel32.dll.callgraph.json `
       --top 20

   call-graph callgraph-hook-plan `
       --input data/interim/call_graphs/<arch>/System32/kernel32.dll.callgraph.json `
       --program kernel32.dll `
       --max-uncovered 25
   ```

5. **Visualise or aggregate**

   ```powershell
   call-graph callgraph-aggregate `
       --input data/interim/call_graphs/<arch>/System32/*.callgraph.json `
       --output docs/analytics/kernel32_kernelbase.json `
       --visualize docs/analytics/kernel32_kernelbase.png `
       --show-legend

   call-graph callgraph-visualize `
       --input data/interim/call_graphs/<arch>/System32/kernel32.dll.callgraph.json `
       --show-labels `
       --show-legend
   ```

6. **Audit for empty graphs (recommended before UI usage)**

   ```powershell
   call-graph callgraph-empty-report `
       --data-dir data/interim/call_graphs `
       --output docs/analytics/empty_call_graphs.json
   ```

   Feed the resulting JSON to the UI so resource-only DLLs are hidden:

   ```powershell
   call-graph callgraph-ui `
       --data-dir data/interim/call_graphs `
       --exclude-report docs/analytics/empty_call_graphs.json
   ```

7. **Build a unified cross-DLL graph (sample run)**

   ```powershell
   call-graph callgraph-unify `
       --callgraph-dir data/interim/call_graphs `
       --metadata-root data/raw/windows_inventory `
       --output data/interim/unified/unified_sample.callgraph.json `
       --module kernel32.dll `
       --module api-ms-win-core-file-l1-2-0.dll `
       --module ntdll.dll
   ```

   To auto-generate missing call graphs during unification (requires Ghidra):

   ```powershell
   call-graph callgraph-unify `
       --callgraph-dir data/interim/call_graphs `
       --metadata-root data/raw/windows_inventory `
       --output data/interim/unified/unified_sample.callgraph.json `
       --module kernel32.dll `
       --module kernelbase.dll `
       --auto-generate-missing `
       --workers 4 `
       --windows-root C:\Windows `
       --ghidra-headless "C:\Path\To\Ghidra\support\analyzeHeadless.bat" `
       --project-root ghidra-projects `
       --project-name unify_autogen `
       --no-use-symbol-server
   ```

   The resulting JSON encodes nodes as `PROGRAM!Symbol`, edge kinds
   (`reaches`, `forwarder`, `apiset`), and per-DLL reproducibility metadata
   (SHA-256, PDB GUID/age, Windows build).
   Start with a few modules as shown above; once you are satisfied with the
   output, drop the `--module` flags to process the full data set. If some
   imports cannot be resolved yet (e.g., CRT helpers or DLLs that have not been
   extracted), the command logs warnings but still writes the unified graph so
   the outstanding gaps are captured. With `--auto-generate-missing`, any
   missing per-DLL graphs are generated on the fly and written under
   `--callgraph-dir/<arch>`. If no complete module path can be found between
   the requested modules, the command fails; pass `--allow-disconnected` to
   keep whatever subgraphs are available. The unified graph only contains
   exported APIs (stable names across DLLs) and never includes internal
   functions. API-set DLLs (`api-ms-win-*`, `ext-ms-*`) are resolved to their
   host (usually
   `KERNELBASE.DLL`) during unification, and forwarder edges are retained unless
   you pass `--no-api-set-forwarders`.

### Three-stage pipeline (concise)

**Stage 1: Raw per-DLL graphs**  
`ghidra-callgraph` / `callgraph-batch` generate `*.callgraph.json` with:
- internal nodes keyed by address (`0x...`)
- import nodes keyed as `IMPORT:<lib>!<symbol>`
- edges carry `caller`, `callee`, `site`, `kind`

**Stage 2: Unified user-mode graph**  
`callgraph-unify` walks `--callgraph-dir` recursively, compresses export->import
reachability via internals, resolves imports to real exports, and emits only
API nodes (`DLL!Export`) with edges of kind `reaches`/`apiset`/`forwarder`.
Use `--module` to restrict to specific DLLs or omit to unify everything.
Use `--auto-generate-missing` to build missing per-DLL graphs on demand
(requires Ghidra options and the inventory metadata). Pass
`--no-api-set-forwarders` to drop API-set forwarder edges.

**Stage 3: Syscall augmentation and projection**  
Augment a unified graph with syscall stubs (`NTDLL!NtX -> SYSCALL:NtX`), then
either prune to syscall-connected subgraphs or project per-DLL syscall
reachability: `callgraph-unified-syscall-prune`, `callgraph-project-syscalls`.

8. **Launch the Dash explorer (pick a mode)**

   ```powershell
   call-graph callgraph-ui `
       --data-dir data/interim/call_graphs `
       --mode raw `
       --port 8051 `
       --exclude-report docs/analytics/empty_call_graphs.json
   ```

Modes:
- `raw` (per-DLL raw graphs)
- `unified` (nodes/edges unified graphs)
- `syscall` (syscall-pruned views or projections)
- `auto` (accept any)

The UI enforces the mode based on graph metadata and file contents. Set "Custom nodes" to `0` to remove the node cap.

### Syscall-focused graphs

Note: unified syscall pruning and projection require syscall stubs to be present
in the unified graph (Stage 3). Syscall stubs are modeled as
`NTDLL!NtX -> SYSCALL:NtX` edges.

Per-DLL prune (paths to syscalls inside a single DLL, e.g., `ntdll.dll`):
```powershell
call-graph callgraph-syscall-prune `
    --input data/interim/call_graphs/<arch>/System32/ntdll.dll.callgraph.json `
    --output-dir data/interim/syscall_graphs
```

Unified syscall prune (keep only paths that reach syscalls in a unified graph):
```powershell
call-graph callgraph-unified-syscall-prune `
    --input data/interim/unified/full.callgraph.json `
    --output-dir data/interim/syscall_graphs
```

Syscall projection for a target DLL (cross-DLL paths from a unified graph):
```powershell
call-graph callgraph-project-syscalls `
    --graph data/interim/unified/full.callgraph.json `
    --program KERNEL32.DLL `
    --out-graph data/interim/syscall_graphs/KERNEL32.syscall_projection.json `
    --out-table data/interim/syscall_graphs/KERNEL32.syscall_projection.csv `
    --out-metrics data/interim/syscall_graphs/KERNEL32.syscall_projection.metrics.json
```

Syscall prefix matching is case-insensitive (Nt/Zw and NT/ZW are treated the same).

If you want to unify a small set of DLLs without auto-generation, but still
generate missing call graphs on demand, use `--prompt-missing` with
`callgraph-unify`.

All of these steps are orchestrated end-to-end by
`scripts/run_full_pipeline.ps1`, which chains inventory, PDB mirroring, batch
exports, CSV generation, and analytics reports for reproducible runs.

## Reporting Artefacts

- `docs/report/main.tex` -- long-form document covering methodology, tooling,
  and results.
- `docs/report/progress_summary_1.tex` -- short summary highlighting the current
  unified graph status and pending work.
- `docs/analytics/` -- CSV/JSON/PNG outputs from sample runs (kept light-weight
  so the repo remains shareable).
- `docs/analytics/sample_graphs/` -- tiny sample call graphs and a unified graph
  to demo the UI without Windows binaries.
- `docs/schema.md` -- JSON schema reference for exporter and unified outputs.

### Tooling Requirements

- Python 3.12+
- One or more reverse engineering frameworks (Ghidra, IDA Pro)
- Access to a reference Windows 11 installation (x64) whose system libraries
  can be inspected
- Optional: Graph tooling (Graphviz) for visualisation
- Compatibility: tested with Ghidra 11.4.2 and Java 21; PDB analyzers must be
  enabled in headless mode (default).

## Repository Layout

```
.
"" configs/                 # YAML/JSON config files for runs
"" data/                    # empty placeholders; populated by pipelines
"  "" external/             # symbol/PDB cache
"  "" interim/              # exported graphs, figures, unified artefacts
"  "" processed/            # final analytics
"  "" raw/                  # direct dumps from inventory tools
"" docs/
"  "" analytics/            # CLI and notebook outputs (CSV/JSON/PNG)
"  "" ghidra-scripts/       # helper scripts for headless exports
"  "" meeting-notes/        # templates and dated notes
"  "" references/           # curated reading material and links
"  "" report/               # LaTeX report sources
"  "" research/             # experiments, methodologies, design drafts
"" notebooks/               # Jupyter notebooks for exploratory analysis
"" scripts/                 # CLI scripts and automation helpers
"" src/call_graph_win11/    # Python package with project code
"  "" analysis/             # graph queries and metrics
"  "" data/                 # parsers and collectors
"  "" io/                   # IO integration (Ghidra, IDA, exports)
"  "" pipelines/            # workflows for building graphs
"" tests/                   # pytest-based regression and unit tests
```

## Roadmap

1. **Inventory Windows libraries**: catalogue DLLs and capture metadata
   (exports, PE headers, signatures).
2. **Automate call graph extraction**: use repeatable scripts (Ghidra/IDA) to
   dump per-library call graphs.
3. **Unify graphs**: normalise, merge, and deduplicate per-library data into a
   global graph compatible with `igraph` and `networkx`.
4. **Analysis layer**: implement graph queries to surface interesting syscall
   paths and minimal hooking sets.
5. **Reporting**: document findings in `docs/research/` and track open decisions
   via `docs/meeting-notes/`.

## Discovery Scripts

Run the Windows library inventory pass (writes per-file JSON metadata under
`data/raw/windows_inventory`), pull matching PDBs, and keep data scoped with
`--limit` while iterating:

```powershell
python -m call_graph_win11.cli inventory
python -m call_graph_win11.cli fetch-pdbs --pdb-name ntdll.pdb --pdb-name kernel32.pdb --pdb-name user32.pdb --limit 3
```

Use `--limit <n>` for a quick dry run and `--output <path>` to redirect the
inventory elsewhere. Sample validation for `ntdll.dll`, `kernel32.dll`, and
`user32.dll` is performed automatically. Symbol downloads are stored under
`data/external/pdbs/` using the standard symbol-server directory layout. Add
`--cache-root <path>` to point at a larger, shared symbol cache; downloads are
stored once under that root and hard-linked/copied into the requested `--output`
location so repeated runs avoid re-fetching identical GUIDs.

- Consolidate the collected metadata into a single CSV overview:

  ```powershell
  python -m call_graph_win11.cli inventory-csv `
      --metadata-root data/raw/windows_inventory `
      --output-csv docs/windows_inventory_summary.csv `
      --relative-to C:\Windows
  ```

  The CSV captures core PE attributes (machine, subsystem, entry point, section
  count), export/import counts, and the primary RSDS/PDB linkage when present.

### Automated Pipeline

Run the full acquisition and analysis loop with a single command:

```powershell
.\scripts\run_full_pipeline.ps1 `
    -WindowsRoot C:\Windows `
    -MetadataDir data/raw/windows_inventory `
    -PdbDir data/external/pdbs `
    -CallGraphDir data/interim/call_graphs `
    -CsvOutput docs/windows_inventory_summary.csv `
    -ReportsDir docs/analytics `
    -Limit 50
```

The script orchestrates `inventory -> fetch-pdbs -> callgraph-batch ->
inventory-csv` and drops the latest CLI reports under `docs/analytics/`
(syscall reachability, greedy hook plan, and any notebook-exported CSVs).

## Ghidra Call Graph Export

Once the metadata and PDBs are in place, you can exercise the headless Ghidra
workflow (requires a local Ghidra installation):

```powershell
python -m call_graph_win11.cli ghidra-callgraph `
    --binary C:\Windows\System32\ntdll.dll `
    --binary C:\Windows\System32\kernel32.dll `
    --binary C:\Windows\System32\user32.dll `
    --project-root ghidra-projects `
    --project-name call_graph_samples
```

The command invokes `scripts/ghidra/export_call_graph.py`, which writes graph
JSON under `data/interim/call_graphs/<arch>/...` (mirroring the Windows-relative
path unless `--flatten-names` is set). Pass `--overwrite` to regenerate
existing outputs or `--script-path` to point at custom exporters.
When PDBs are available in `data/external/pdbs/`, the CLI wires them into
Ghidra via a pre-script before exporting the call graph, so recovered symbol
names are preserved in the JSON output.

## Graph Exploration

- Visualise an individual call graph (PNG output in `data/interim/figures/`):

  ```powershell
  python -m call_graph_win11.cli callgraph-visualize `
      --input data/interim/call_graphs/<arch>/System32/ntdll.dll.callgraph.json `
      --max-nodes 250 `
      --show-legend
  ```

- Merge multiple call graphs, emit a combined artefact (JSON/GraphML), and
  render a summary view:

  ```powershell
  python -m call_graph_win11.cli callgraph-aggregate `
      --input data/interim/call_graphs/<arch>/System32/ntdll.dll.callgraph.json `
      --input data/interim/call_graphs/<arch>/System32/kernel32.dll.callgraph.json `
      --input data/interim/call_graphs/<arch>/System32/user32.dll.callgraph.json `
      --output data/interim/call_graphs/samples_combined.json `
      --format graphml `
      --visualize data/interim/figures/samples_combined.png `
      --max-nodes 300 `
      --show-legend
  ```

- Inspect `igraph` centrality metrics (degree, betweenness, PageRank) from the
  command line:

  ```powershell
  python -m call_graph_win11.cli callgraph-igraph-summary `
      --input data/interim/call_graphs/<arch>/System32/ntdll.dll.callgraph.json `
      --input data/interim/call_graphs/<arch>/System32/kernel32.dll.callgraph.json `
      --input data/interim/call_graphs/<arch>/System32/user32.dll.callgraph.json `
      --metric betweenness `
      --top 15
  ```

  The aggregated GraphML output opens smoothly in GUI tools such as Gephi,
  Cytoscape, or yEd for deeper interactive exploration.

- Audit syscall reachability or derive greedy hook recommendations:

  ```powershell
  python -m call_graph_win11.cli callgraph-syscall-report `
      --input data/interim/call_graphs/<arch>/System32/ntdll.dll.callgraph.json `
      --top 10

  python -m call_graph_win11.cli callgraph-hook-plan `
      --input data/interim/call_graphs/<arch>/System32/advapi32.dll.callgraph.json `
      --input data/interim/call_graphs/<arch>/System32/ntdll.dll.callgraph.json `
      --program advapi32.dll
  ```

  The first command lists orphaned syscalls and APIs that never reach them,
  while the second approximates a minimal set of API hooks that covers the
  reachable syscalls.

- Validate graph structure (dangling edges, syscall coverage when metadata is
  available):

  ```powershell
  call-graph callgraph-validate `
      --input data/interim/unified/unified_smoke.callgraph.json `
      --metadata-root data/raw/windows_inventory
  ```

- Launch the interactive Dash UI to browse binaries and inspect subgraphs:

  ```powershell
  python -m call_graph_win11.cli callgraph-ui `
      --data-dir data/interim/call_graphs `
      --host 127.0.0.1 `
      --port 8050
  ```

  Use the dropdown to pick a library, adjust the node limit slider to focus on
  the busiest region, and hover nodes for attributes. Key UI controls:

  - `Highlight`: free-text search that soft-highlights matching nodes and their
    incident edges.
  - `Filters`: quickly scope the graph to syscalls (`Nt*/Zw*`) or exported APIs
    only.
  - `Preset highlight`: choose between hook candidates, syscall-free APIs, or
    the greedy hook set computed for the current library.
  - `Graph layout`: toggle between force-directed, concentric, and breadth-first
    layouts (powered by `igraph`).
  - `Node size`: switch between fixed nodes or degree-scaled sizing to surface
    potential hubs instantly.
  - `Performance`: auto-simplify labels/edges for large graphs (toggle
    auto/on/off).
  - `Inbound depth`: choose how many hops of inbound callers to include when
    focusing on a target function.
  - `Path inspector`: select a `Start` and `Focus` function to render the
    shortest path preview and a compact Cytoscape subgraph with start/end
    colour accents.
  - Sidebar panels (`Stats`, `Program Legend`, `Top degree functions`, `Syscall
    coverage`) summarise graph composition, colour assignments, and hook
    recommendations. Coverage badges call out top 5% and bottom 10% candidates,
    while zero-coverage APIs receive a neutral chip for quick triage.

## Batch Extraction (System32 & SysWOW64)

Automate call-graph generation for the core Windows directories. The command
below walks the inventory, filters binaries that live under
`C:\Windows\System32` or `C:\Windows\SysWOW64`, fetches the required PDBs, and
writes the results to `data/interim/call_graphs/<arch>/<relative_path>.callgraph.json`
(or flattened names if `--flatten-names` is set).

```powershell
python -m call_graph_win11.cli callgraph-batch `
    --ghidra-headless "C:\Path\To\Ghidra\support\analyzeHeadless.bat" `
    --project-root ghidra-projects `
    --project-name win_batch `
    --workers 4 `
    --overwrite
```

Useful flags:

- `--include` to add more subdirectories (defaults to `System32` and
  `SysWOW64`).
- `--limit` for dry-run testing.
- `--workers` to run multiple Ghidra headless jobs in parallel (each worker
  uses its own sub-project under `--project-root`).
- `--symbol-path` to supply an explicit PDB search path (otherwise the pipeline
  falls back to `data/external/pdbs`).

The notebooks `notebooks/sample_call_graph_analysis.ipynb` and
`notebooks/call_graph_analysis_demo.ipynb` demonstrate how to load and analyse
these artefacts interactively (degree statistics, syscall coverage, inspection
of top callers, etc.). Executing them now normalises cell IDs, captures
outputs, and writes summary CSVs in `docs/analytics/`. The corresponding Ghidra
scripts are mirrored under `docs/ghidra-scripts/` for inspection or manual use.

## Contributing

1. Create a feature branch.
2. Ensure linting and tests pass: `pytest`.
3. Submit your changes for review or merge when ready.

> Tip: use `scripts/bootstrap_env.ps1` to recreate the local environment
> quickly.

Happy reversing!




