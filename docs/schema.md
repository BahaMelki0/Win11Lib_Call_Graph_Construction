# Graph schema

This document captures the JSON structures produced by the exporter and the unified graph builder.
All JSON payloads carry a `"schema_version": "1.0"` field to make downstream validation deterministic.

## Per-DLL call graph (`*.callgraph.json`)

Top-level keys:

- `schema_version`: string (`"1.0"`).
- `program`: DLL/EXE name.
- `functions`: array of function records:
  - `entry_point`: string address (e.g., `"0x180012340"`).
  - `name` / `qualified_name`: function label (export name or recovered symbol).
  - `calling_convention`: optional string.
  - `is_external`: bool (true for imports).
  - `source`: string tag (`IMPORTED`, `DEFAULT`, `ANALYSIS`, etc.).
- `edges`: array of call edges:
  - `caller`: string address (must match a function `entry_point`).
  - `callee`: string address.

Node identity inside the UI/loader is `PROGRAM:entry_point`.

## Unified graph (`unified*.callgraph.json`)

Top-level keys:

- `schema_version`: string (`"1.0"`).
- `graph`: name of the graph.
- `windows`: host OS info.
- `dlls`: list of DLL metadata (path, sha256, file_version, pdb GUID/age).
- `layers`: counts per layer (e.g., `library`, `syscall`).
- `node_count` / `edge_count`.
- `nodes`: array of node records:
  - `id`: `PROGRAM!Symbol` for library nodes, `SYSCALL:NtX` for syscalls.
  - `program`: DLL name or `SYSCALL`.
  - `name`: symbol name.
  - `address`: optional address (library nodes only).
  - `is_external`: bool (true for imports/forwarders/syscalls).
  - `layer`: `library` or `syscall`.
  - `calling_convention`, `source`: optional strings (e.g., `IMPORTED`, `SYNTHETIC`, `SYSCALL`).
- `edges`: array of edges:
  - `source` / `target`: node ids.
  - `kind`: one of `direct`, `import`, `forwarder`, `syscall`.

Node identity is stable across DLLs because only imported/exported functions are kept by default
(`--include-internal` restores all functions). API-set DLLs (`api-ms-win-*`, `ext-ms-*`) are
resolved to their host (typically `KERNELBASE.DLL`) during unification; forwarder edges connect
the alias to the host.

## Validation rules

The `callgraph-validate` CLI command enforces:

- No dangling edges (all edge endpoints exist).
- Unique node ids.
- For unified graphs: syscall node count should roughly match the number of `Nt*` exports from
  `ntdll.dll` in the provided inventory (80% threshold by default).

Use `callgraph-validate --input ... --metadata-root data/raw/windows_inventory` to run the checks.
