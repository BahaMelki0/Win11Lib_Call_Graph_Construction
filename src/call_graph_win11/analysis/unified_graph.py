"""Builder for the unified, cross-DLL Windows call graph."""

from __future__ import annotations

import hashlib
import json
import logging
import platform
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

import networkx as nx
import pefile
from call_graph_win11.analysis.graph_loader import load_call_graph
LOGGER = logging.getLogger(__name__)

LIBRARY_LAYER = "library"
SYSCALL_LAYER = "syscall"
SCHEMA_VERSION = "1.0"


def _normalize_module(name: str) -> str:
    if not name:
        return ""
    name = name.strip()
    if not name:
        return ""
    if not name.lower().endswith((".dll", ".exe")):
        name = f"{name}.dll"
    return name.upper()


def _symbol_name(entry: dict) -> str:
    for key in ("name", "qualified_name"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    entry_point = entry.get("entry_point")
    if isinstance(entry_point, str) and entry_point:
        return entry_point
    node_id = entry.get("node_id")
    if isinstance(node_id, str) and node_id:
        return node_id
    return f"sub_{abs(hash(json.dumps(entry, sort_keys=True))) & 0xFFFF}"


def _node_id(program: str, symbol: str) -> str:
    return f"{program}!{symbol}"

def _parse_import_node_id(raw_id: str) -> tuple[str, str] | None:
    """
    Parse importer node ids emitted by the Ghidra exporter, e.g.:
      IMPORT:KERNEL32.DLL!CreateFileW
      IMPORT:!SomeSymbol
    Returns (library, symbol) if possible.
    """
    if not isinstance(raw_id, str) or not raw_id.startswith("IMPORT:"):
        return None
    rest = raw_id[len("IMPORT:") :]
    if "!" not in rest:
        return None
    lib, sym = rest.split("!", 1)
    lib = lib.strip()
    sym = sym.strip()
    if not sym:
        return None
    return lib, sym


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_version(path: Path) -> str | None:
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except FileNotFoundError:
        return None
    except Exception:  # pragma: no cover - malformed PE
        return None
    try:
        vs = pe.VS_FIXEDFILEINFO[0]
    except Exception:  # pragma: no cover - resource missing
        return None
    ms = vs.FileVersionMS
    ls = vs.FileVersionLS
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


@dataclass
class NodeRecord:
    node_id: str
    program: str
    name: str
    address: Optional[str]
    is_external: bool
    layer: str = LIBRARY_LAYER
    calling_convention: Optional[str] = None
    source: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "id": self.node_id,
            "name": self.name,
            "program": self.program,
            "address": self.address,
            "is_external": self.is_external,
            "layer": self.layer,
            "calling_convention": self.calling_convention,
            "source": self.source,
        }


@dataclass
class ModuleMetadata:
    path: Path
    data: dict
    hash_sha256: Optional[str] = None
    file_version: Optional[str] = None
    pdb_guid: Optional[str] = None
    pdb_age: Optional[int] = None
    import_map: Dict[str, List[str]] = field(default_factory=dict)
    exports: Dict[str, dict] = field(default_factory=dict)


class MetadataIndex:
    """Index PE metadata JSON files and expose helpers for lookup."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Metadata root {self.root} not found.")
        self._index: dict[str, Path] = {}
        self._cache: dict[str, ModuleMetadata] = {}
        self._alias_cache: dict[str, str] = {}
        self._build_index()

    def _build_index(self) -> None:
        for path in self.root.rglob("*.json"):
            module = _normalize_module(path.stem)
            if module and module not in self._index:
                self._index[module] = path

    def _load_metadata(self, module: str) -> ModuleMetadata | None:
        module = _normalize_module(module)
        if not module:
            return None
        cached = self._cache.get(module)
        if cached:
            return cached
        path = self._index.get(module)
        if not path:
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:  # pragma: no cover - unexpected
            LOGGER.warning("Failed to parse metadata for %s: %s", module, exc)
            return None
        meta = ModuleMetadata(path=path, data=data)
        binary_path_str = data.get("path")
        binary_path = Path(binary_path_str) if isinstance(binary_path_str, str) else None
        if binary_path and binary_path.exists():
            try:
                meta.hash_sha256 = _sha256(binary_path)
                meta.file_version = _file_version(binary_path)
            except OSError:
                meta.hash_sha256 = None
                meta.file_version = None
        else:
            meta.hash_sha256 = None
            meta.file_version = None
        for debug_entry in data.get("debug", []):
            codeview = debug_entry.get("codeview")
            if isinstance(codeview, dict) and codeview.get("signature") == "RSDS":
                meta.pdb_guid = codeview.get("guid")
                meta.pdb_age = codeview.get("age")
                break
        import_map: dict[str, list[str]] = defaultdict(list)
        for entry in data.get("imports", []):
            module_name = _normalize_module(entry.get("module", ""))
            for fn in entry.get("functions", []):
                name = fn.get("name")
                if not name:
                    continue
                import_map[name.upper()].append(module_name)
        meta.import_map = import_map
        exports = {}
        for entry in data.get("exports", []):
            name = entry.get("name")
            if name:
                exports[name.upper()] = entry
        meta.exports = exports
        self._cache[module] = meta
        return meta

    def get_import_targets(self, module: str, symbol: str) -> list[str]:
        meta = self._load_metadata(module)
        if not meta:
            return []
        return [self.resolve_alias(name) for name in meta.import_map.get(symbol.upper(), [])]

    def get_exports(self, module: str) -> list[str]:
        meta = self._load_metadata(module)
        if not meta:
            return []
        return list(meta.exports.keys())

    def resolve_alias(self, module: str) -> str:
        module = _normalize_module(module)
        if not module:
            return ""
        if module in self._alias_cache:
            return self._alias_cache[module]
        if module.startswith(("API-MS-", "EXT-MS-")):
            meta = self._load_metadata(module)
            host: str | None = None
            if meta:
                for entry in meta.data.get("imports", []):
                    host_candidate = _normalize_module(entry.get("module", ""))
                    if host_candidate and not host_candidate.startswith(("API-MS-", "EXT-MS-")):
                        host = host_candidate
                        if host == "KERNELBASE.DLL":
                            break
            if not host:
                host = "KERNELBASE.DLL"
            self._alias_cache[module] = host
            return host
        self._alias_cache[module] = module
        return module

    def iter_alias_modules(self) -> Iterator[str]:
        for module in self._index.keys():
            if module.startswith(("API-MS-", "EXT-MS-")):
                yield module

    def get_module_record(self, module: str) -> ModuleMetadata | None:
        return self._load_metadata(module)


class UnifiedGraphBuilder:
    """Compose individual call graphs into a single cross-DLL graph."""

    def __init__(self, metadata_root: Path, *, include_internal: bool = False) -> None:
        self.metadata_index = MetadataIndex(metadata_root)
        self.graph = nx.DiGraph(name="Unified Windows Call Graph")
        self.edge_set: set[Tuple[str, str, str]] = set()
        self.dll_records: dict[str, dict] = {}
        self.unresolved_imports: list[tuple[str, str]] = []
        self.include_internal = include_internal
        self.windows_info = {
            "platform": platform.platform(),
            "version": platform.version(),
            "release": platform.release(),
        }
        # program -> name_lower -> node_id
        self.name_index: dict[str, dict[str, str]] = {}

    @staticmethod
    def _is_import_node(node_id: str, data: dict[str, object]) -> bool:
        if isinstance(node_id, str) and node_id.startswith("IMPORT:"):
            return True
        if str(data.get("source") or "").upper() == "IMPORTED":
            return True
        if bool(data.get("is_external")):
            return True
        return False

    def _add_or_update_node(self, record: NodeRecord) -> str:
        """Insert or update a node, reusing placeholders when a matching name already exists."""

        attrs = record.as_dict()
        name = attrs.get("name")
        program = attrs.get("program")
        program_str = str(program) if program is not None else ""
        program_map = self.name_index.setdefault(program_str, {})
        existing_id = None
        if isinstance(name, str) and name:
            existing_id = program_map.get(name.lower())
        node_id = existing_id or record.node_id

        if node_id in self.graph.nodes:
            existing = self.graph.nodes[node_id]
            for key, value in attrs.items():
                if value is not None:
                    existing[key] = value
        else:
            self.graph.add_node(node_id, **attrs)

        if isinstance(name, str) and name:
            program_map[name.lower()] = node_id

        return node_id

    def _ensure_placeholder_node(self, program: str, symbol: str) -> str:
        name_map = self.name_index.get(program, {})
        existing = name_map.get(symbol.lower())
        if existing:
            return existing
        symbol_norm = symbol.upper()
        node_id = _node_id(program, symbol_norm)
        record = NodeRecord(
            node_id=node_id,
            program=program,
            name=symbol_norm,
            address=None,
            is_external=True,
            calling_convention=None,
            source="SYNTHETIC",
        )
        return self._add_or_update_node(record)

    def _add_edge(self, source: str, target: str, kind: str, *, min_hops: int | None = None) -> None:
        key = (source, target, kind)
        if key in self.edge_set:
            return
        if source not in self.graph.nodes or target not in self.graph.nodes:
            return
        attrs = {"kind": kind}
        if min_hops is not None:
            attrs["min_hops"] = min_hops
        self.graph.add_edge(source, target, **attrs)
        self.edge_set.add(key)

    def _export_nodes_for_module(self, module: str) -> list[dict]:
        meta = self.metadata_index.get_module_record(module)
        if not meta:
            return []
        exports: list[dict] = []
        for entry in meta.data.get("exports", []):
            name = entry.get("name")
            if not name:
                continue
            exports.append(entry)
        return exports

    def _imports_for_module(self, module: str) -> list[dict]:
        meta = self.metadata_index.get_module_record(module)
        if not meta:
            return []
        imports: list[dict] = []
        for entry in meta.data.get("imports", []):
            mod = _normalize_module(entry.get("module", ""))
            for fn in entry.get("functions", []):
                name = fn.get("name")
                if not name:
                    continue
                imports.append({"module": mod, "name": name})
        return imports

    def _resolve_import_targets(self, importing_module: str, symbol: str, lib_hint: str | None = None) -> list[str]:
        targets: list[str] = []
        if lib_hint:
            tgt = self.metadata_index.resolve_alias(_normalize_module(lib_hint))
            if tgt:
                targets.append(tgt)
        targets.extend(self.metadata_index.get_import_targets(importing_module, symbol))
        seen: set[str] = set()
        unique: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    def _add_api_set_forwarders(self) -> None:
        for module in self.metadata_index.iter_alias_modules():
            host = self.metadata_index.resolve_alias(module)
            exports = self.metadata_index.get_exports(module)
            for export_name in exports:
                alias_node = self._ensure_placeholder_node(module, export_name)
                host_node = self._ensure_placeholder_node(host, export_name)
                self._add_edge(alias_node, host_node, "apiset")

    def _map_exports_to_raw(self, raw_graph: nx.DiGraph, exports: list[dict], image_base: int | None) -> dict[str, list[str]]:
        name_index: dict[str, list[str]] = defaultdict(list)
        addr_index: dict[str, list[str]] = defaultdict(list)
        for node, data in raw_graph.nodes(data=True):
            name_val = str(data.get("name") or data.get("qualified_name") or data.get("address") or node).upper()
            name_index[name_val].append(node)
            addr_val = data.get("address")
            if isinstance(addr_val, str):
                addr_index[addr_val.lower()].append(node)

        mapping: dict[str, list[str]] = {}
        for entry in exports:
            name = entry.get("name")
            if not name:
                continue
            name_upper = name.upper()
            nodes: list[str] = []
            # Prefer address-based match when image_base is available
            if image_base is not None:
                rva = entry.get("address")
                if isinstance(rva, int):
                    va = image_base + rva
                    key = f"0x{va:X}".lower()
                    nodes.extend(addr_index.get(key, []))
            if not nodes:
                nodes.extend(name_index.get(name_upper, []))
            mapping[name_upper] = nodes
        return mapping

    def _is_import_raw_node(self, node: str, data: dict) -> bool:
        if str(node).startswith("IMPORT:"):
            return True
        if self._is_import_node(node, data):
            return True
        return False

    def _compress_module(self, raw_graph: nx.DiGraph) -> None:
        program = _normalize_module(raw_graph.graph.get("program", ""))
        if not program:
            return

        meta = self.metadata_index.get_module_record(program)
        image_base = None
        if meta:
            try:
                image_base = int(meta.data.get("image_base"))
            except Exception:
                image_base = None
            self.dll_records[program] = {
                "program": program,
                "path": str(meta.data.get("path", meta.path)),
                "sha256": meta.hash_sha256,
                "file_version": meta.file_version,
                "pdb_guid": meta.pdb_guid,
                "pdb_age": meta.pdb_age,
            }

        exports = self._export_nodes_for_module(program)
        imports = self._imports_for_module(program)
        import_set = {f"IMPORT:{entry['module']}!{entry['name']}".upper() for entry in imports}

        exp_to_raw = self._map_exports_to_raw(raw_graph, exports, image_base)

        compressed_edges: dict[tuple[str, str], int] = {}

        import_nodes: set[str] = set()
        for node, data in raw_graph.nodes(data=True):
            if self._is_import_raw_node(node, data):
                import_nodes.add(node)

        for exp_entry in exports:
            exp_name = exp_entry.get("name")
            if not exp_name:
                continue
            exp_upper = exp_name.upper()
            src_id = _node_id(program, exp_upper)
            seeds = exp_to_raw.get(exp_upper, [])
            self._add_or_update_node(
                NodeRecord(
                    node_id=src_id,
                    program=program,
                    name=exp_upper,
                    address=None,
                    is_external=False,
                    source="EXPORTED",
                )
            )
            if not seeds:
                continue

            for seed in seeds:
                queue: list[tuple[str, int]] = [(seed, 0)]
                visited: set[str] = set()
                while queue:
                    current, dist = queue.pop(0)
                    if current in visited:
                        continue
                    visited.add(current)
                    for succ in raw_graph.successors(current):
                        succ_data = raw_graph.nodes[succ]
                        if succ in import_nodes:
                            # import hit
                            imp_id = str(succ)
                            lib_hint = ""
                            sym = ""
                            parsed = _parse_import_node_id(imp_id)
                            if parsed:
                                lib_hint, sym = parsed
                            else:
                                sym = str(succ_data.get("name") or "").split("!")[-1]
                                lib_hint = succ_data.get("namespace") or ""
                            sym_upper = sym.upper() if sym else (str(succ).split("!")[-1].upper())
                            key = (exp_upper, f"{lib_hint}|{sym_upper}")
                            hops = dist + 1
                            if key not in compressed_edges or compressed_edges[key] > hops:
                                compressed_edges[key] = hops
                            continue
                        if self._is_import_raw_node(succ, succ_data):
                            continue
                        queue.append((succ, dist + 1))

        for (exp_upper, imp_key), hops in compressed_edges.items():
            lib_hint, imp_sym = imp_key.split("|", 1)
            targets = self._resolve_import_targets(program, imp_sym, lib_hint if lib_hint else None)
            if not targets:
                self.unresolved_imports.append((program, imp_sym))
                continue
            src_id = _node_id(program, exp_upper)
            for tgt_prog in targets:
                tgt_prog_norm = _normalize_module(tgt_prog)
                tgt_id = _node_id(tgt_prog_norm, imp_sym.upper())
                self._add_or_update_node(
                    NodeRecord(
                        node_id=tgt_id,
                        program=tgt_prog_norm,
                        name=imp_sym.upper(),
                        address=None,
                        is_external=True,
                        source="EXPORTED",
                    )
                )
                self._add_edge(src_id, tgt_id, "reaches", min_hops=hops)

    def integrity_checks(self) -> None:
        for source, target in self.graph.edges():
            if source not in self.graph.nodes or target not in self.graph.nodes:
                raise RuntimeError(f"Dangling edge detected: {source} -> {target}")
        if len(self.graph.nodes) != len(set(self.graph.nodes)):
            raise RuntimeError("Duplicate node identifiers detected.")
        if self.unresolved_imports:
            sample = ", ".join(f"{mod}!{name}" for mod, name in self.unresolved_imports[:5])
            LOGGER.warning("Unresolved imports detected (sample: %s)", sample)

    def build(self, callgraph_paths: Iterable[Path]) -> None:
        for path in callgraph_paths:
            raw_graph = load_call_graph(path)
            self._compress_module(raw_graph)
        self._add_api_set_forwarders()
        self.integrity_checks()

    def export(self, destination: Path) -> None:
        destination = destination.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        nodes = [self.graph.nodes[node] | {"id": node} for node in self.graph.nodes]
        edges = [{"source": s, "target": t, "kind": data.get("kind"), "min_hops": data.get("min_hops")} for s, t, data in self.graph.edges(data=True)]
        layers: dict[str, int] = defaultdict(int)
        for node in nodes:
            layers[node.get("layer", LIBRARY_LAYER)] += 1
        payload = {
            "schema_version": SCHEMA_VERSION,
            "graph": self.graph.graph.get("name", destination.stem),
            "windows": self.windows_info,
            "dlls": list(self.dll_records.values()),
            "layers": layers,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }
        destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")


__all__ = ["UnifiedGraphBuilder"]
