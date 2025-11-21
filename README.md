# Call Graph Reconstruction for Windows System Libraries

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

- **Precision** — focus on the handful of exports that actually reach the
  syscalls needed to monitor a behaviour of interest.
- **Coverage reasoning** — reachability analysis shows which syscalls remain
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

### Typical workflow

1. **Inventory the Windows installation**

   ```powershell
   call-graph inventory `
       --root C:\Windows `
       --output data/raw/windows_inventory `
       --limit 250             # optional: restrict for dry runs
   ```

2. **Fetch matching PDBs for the collected RSDS signatures**

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
       --pdb-root data/external/pdbs `
       --symbol-cache data/external/pdbs `
       --output-dir data/interim/call_graphs `
       --overwrite
   ```

   To sweep whole directories, switch to the batch command:

   ```powershell
   call-graph callgraph-batch `
       --include System32 --include SysWOW64 `
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
   cache.

4. **Generate analytics and reports**

   ```powershell
   call-graph callgraph-syscall-report `
       --input data/interim/call_graphs/System32/kernel32.dll.callgraph.json `
       --top 20

   call-graph callgraph-hook-plan `
       --input data/interim/call_graphs/System32/kernel32.dll.callgraph.json `
       --program kernel32.dll `
       --max-uncovered 25
   ```

5. **Visualise or aggregate**

   ```powershell
   call-graph callgraph-aggregate `
       --input data/interim/call_graphs/System32/*.callgraph.json `
       --output docs/analytics/kernel32_kernelbase.json `
       --visualize docs/analytics/kernel32_kernelbase.png

   call-graph callgraph-visualize `
       --input data/interim/call_graphs/System32/kernel32.dll.callgraph.json `
       --show-labels
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

   The resulting JSON encodes nodes (`PROGRAM!Symbol`, syscall stubs under
   `SYSCALL:*`), edge kinds (`direct`, `import`, `forwarder`, `syscall`), and
   per-DLL reproducibility metadata (SHA-256, PDB GUID/age, Windows build).
   Start with a few modules as shown above; once you are satisfied with the
   output, drop the `--module` flags to process the full data set. If some
   imports cannot be resolved yet (e.g., CRT helpers or DLLs that have not been
   extracted), the command logs warnings but still writes the unified graph so
   the outstanding gaps are captured. By default the unified graph keeps only
   imported and exported functions (stable names across DLLs); add
   `--include-internal` if you want the full function set instead.

8. **Launch the Dash explorer**

   ```powershell
   call-graph callgraph-ui `
       --data-dir data/interim/call_graphs `
       --port 8051 `
       --exclude-report docs/analytics/empty_call_graphs.json
   ```

All of these steps are orchestrated end-to-end by
`scripts/run_full_pipeline.ps1`, which chains inventory, PDB mirroring, batch
exports, CSV generation, and analytics reports for reproducible runs.

## Reporting Artefacts

- `docs/report/main.tex` — long-form document covering methodology, tooling,
  and results.
- `docs/report/progress_summary_1.tex` — short summary highlighting the current
  unified graph status and pending work.
- `docs/analytics/` — CSV/JSON/PNG outputs from sample runs (kept light-weight
  so the repo remains shareable).

### Tooling Requirements

- Python 3.12+
- One or more reverse engineering frameworks (Ghidra, IDA Pro)
- Access to a reference Windows 11 installation (x64) whose system libraries
  can be inspected
- Optional: Graph tooling (Graphviz) for visualisation

## Repository Layout

```
.
├─ configs/                 # YAML/JSON config files for runs
├─ data/                    # empty placeholders; populated by pipelines
│  ├─ external/             # symbol/PDB cache
│  ├─ interim/              # exported graphs, figures, unified artefacts
│  ├─ processed/            # final analytics
│  └─ raw/                  # direct dumps from inventory tools
├─ docs/
│  ├─ analytics/            # CLI and notebook outputs (CSV/JSON/PNG)
│  ├─ ghidra-scripts/       # helper scripts for headless exports
│  ├─ meeting-notes/        # templates and dated notes
│  ├─ references/           # curated reading material and links
│  ├─ report/               # LaTeX report sources
│  └─ research/             # experiments, methodologies, design drafts
├─ ghidra-projects/         # sample Ghidra projects/metadata
├─ notebooks/               # Jupyter notebooks for exploratory analysis
├─ scripts/                 # CLI scripts and automation helpers
├─ src/call_graph_win11/    # Python package with project code
│  ├─ analysis/             # graph queries and metrics
│  ├─ data/                 # parsers and collectors
│  ├─ io/                   # IO integration (Ghidra, IDA, exports)
│  └─ pipelines/            # workflows for building graphs
└─ tests/                   # pytest-based regression and unit tests
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
JSON to `data/interim/call_graphs/<binary>.callgraph.json`. Pass `--overwrite`
to regenerate existing outputs or `--script-path` to point at custom exporters.
When PDBs are available in `data/external/pdbs/`, the CLI wires them into
Ghidra via a pre-script before exporting the call graph, so recovered symbol
names are preserved in the JSON output.

## Graph Exploration

- Visualise an individual call graph (PNG output in `data/interim/figures/`):

  ```powershell
  python -m call_graph_win11.cli callgraph-visualize `
      --input data/interim/call_graphs/ntdll.dll.callgraph.json `
      --max-nodes 250
  ```

- Merge multiple call graphs, emit a combined artefact (JSON/GraphML), and
  render a summary view:

  ```powershell
  python -m call_graph_win11.cli callgraph-aggregate `
      --input data/interim/call_graphs/ntdll.dll.callgraph.json `
      --input data/interim/call_graphs/kernel32.dll.callgraph.json `
      --input data/interim/call_graphs/user32.dll.callgraph.json `
      --output data/interim/call_graphs/samples_combined.json `
      --format graphml `
      --visualize data/interim/figures/samples_combined.png `
      --max-nodes 300
  ```

- Inspect `igraph` centrality metrics (degree, betweenness, PageRank) from the
  command line:

  ```powershell
  python -m call_graph_win11.cli callgraph-igraph-summary `
      --input data/interim/call_graphs/ntdll.dll.callgraph.json `
      --input data/interim/call_graphs/kernel32.dll.callgraph.json `
      --input data/interim/call_graphs/user32.dll.callgraph.json `
      --metric betweenness `
      --top 15
  ```

  The aggregated GraphML output opens smoothly in GUI tools such as Gephi,
  Cytoscape, or yEd for deeper interactive exploration.

- Audit syscall reachability or derive greedy hook recommendations:

  ```powershell
  python -m call_graph_win11.cli callgraph-syscall-report `
      --input data/interim/call_graphs/System32/ntdll.dll.callgraph.json `
      --top 10

  python -m call_graph_win11.cli callgraph-hook-plan `
      --input data/interim/call_graphs/System32/advapi32.dll.callgraph.json `
      --input data/interim/call_graphs/System32/ntdll.dll.callgraph.json `
      --program advapi32.dll
  ```

  The first command lists orphaned syscalls and APIs that never reach them,
  while the second approximates a minimal set of API hooks that covers the
  reachable syscalls.

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
writes the results to `data/interim/call_graphs/<relative_path>.callgraph.json`.

```powershell
python -m call_graph_win11.cli callgraph-batch `
    --ghidra-headless "C:\Path\To\Ghidra\support\analyzeHeadless.bat" `
    --project-root ghidra-projects `
    --project-name win_batch `
    --overwrite
```

Useful flags:

- `--include` to add more subdirectories (defaults to `System32` and
  `SysWOW64`).
- `--limit` for dry-run testing.
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
