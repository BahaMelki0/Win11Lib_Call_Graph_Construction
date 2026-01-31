# Graph schema

This document captures the JSON structures produced by the exporter and the unified graph builder.
All JSON payloads carry a `"schema_version"` field to make downstream validation deterministic.

## Stage 1 -- Per-DLL raw call graph (`*.callgraph.json`)

Top-level keys:

- `schema_version`: string (current: `"1.1"`).
- `mode`: optional string (`"raw"` for exporter output; `"syscall"` for pruned views).
- `program`: DLL/EXE name.
- `functions`: array of function records:
  - `node_id`: stable node id.
    - internal functions: entrypoint address (e.g., `"0x180012340"`).
    - imports: `"IMPORT:<LIB>!<Symbol>"`.
  - `entry_point`: string address (or null for imports).
  - `name` / `qualified_name`: function label.
  - `namespace`: namespace or library name.
  - `calling_convention`: optional string.
  - `is_external`: bool (true for imports).
  - `source`: string tag (`IMPORTED`, `DEFAULT`, `ANALYSIS`, etc.).
  - `is_thunk`: bool.
- `edges`: array of call edges:
  - `caller`: node id.
  - `callee`: node id.
  - `site`: callsite address (string).
  - `kind`: `direct` | `import` | `ref` | `unknown` (or `direct_ref`).

Stage-1 output is **local and noisy**: internal nodes exist and are used to prove reachability.

## Stage 2 -- Unified user-mode graph (`unified*.callgraph.json`)

Top-level keys:

- `schema_version`: string (current: `"1.0"`).
- `mode`: optional string (`"unified"`).
- `graph`: name of the graph.
- `windows`: host OS info.
- `dlls`: list of DLL metadata (path, sha256, file_version, pdb GUID/age).
- `layers`: counts per layer (e.g., `library`, `syscall`).
- `node_count` / `edge_count`.
- `nodes`: array of node records:
  - `id`: `PROGRAM!Symbol` for library nodes.
  - `program`: DLL name.
  - `name`: symbol name.
  - `address`: optional address (usually null for unified nodes).
  - `is_external`: bool (true for imports/forwarders).
  - `layer`: `library`.
  - `calling_convention`, `source`: optional strings (e.g., `EXPORTED`, `SYNTHETIC`).
- `edges`: array of edges:
  - `source` / `target`: node ids.
  - `kind`: `reaches`, `forwarder`, `apiset`.
  - `min_hops`: optional integer capturing the shortest collapsed path length for `reaches` edges.

**Invariants:**
- No internal nodes.
- No `IMPORT:*` nodes.
- No syscall nodes.

## Stage 3 -- Syscall augmentation

### A) Syscall-augmented unified graph

Adds syscall stubs (does not remove any nodes):

- Nodes: `SYSCALL:NtX`.
- Edges: `NTDLL!NtX -> SYSCALL:NtX` with kind `syscall`.

### B) Syscall-pruned unified subgraph (`*.syscall.json`)

Induced subgraph of all nodes that can reach any `SYSCALL:*` node.
Keeps intermediary DLL nodes (e.g., `KERNEL32 -> KERNELBASE -> NTDLL -> SYSCALL`).

### C) Syscall projection graph (`*_syscall_projection.json`)

Derived from a unified graph; captures which syscalls a target DLL can reach.

Top-level keys:

- `schema_version`: string (`"1.0"`).
- `mode`: `"syscall_projection"`.
- `graph`: name of the projection (e.g., `KERNEL32.DLL_syscall_projection`).
- `source_graph`: path to the unified graph used.
- `target_program`: program being projected.
- `node_count` / `edge_count`.
- `nodes`: functions from the target DLL that reach a syscall, plus the syscall nodes they reach.
- `edges`: projection edges from function -> syscall:
  - `source` / `target`: node ids.
  - `kind`: `"projection"`.
  - `hops`: shortest path length.
  - `via_program`: first DLL on the shortest path that is not the target DLL.

## Validation rules

The `callgraph-validate` CLI command enforces:

- No dangling edges (all edge endpoints exist).
- Unique node ids.
- For unified graphs: syscall node count should roughly match the number of `Nt*` exports from
  `ntdll.dll` in the provided inventory (80% threshold by default).

Use:

```powershell
call-graph callgraph-validate --input <graph.json> --metadata-root data/raw/windows_inventory
```

