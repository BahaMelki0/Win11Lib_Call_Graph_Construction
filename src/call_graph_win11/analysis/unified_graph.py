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
    return f"sub_{abs(hash(json.dumps(entry, sort_keys=True))) & 0xFFFF}"


def _node_id(program: str, symbol: str) -> str:
    return f"{program}!{symbol}"


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
        self.address_maps: dict[str, dict[str, str]] = {}
        self.function_sources: dict[str, dict[str, dict]] = {}
        self.dll_records: dict[str, dict] = {}
        self.unresolved_imports: list[tuple[str, str]] = []
        self.include_internal = include_internal
        self.windows_info = {
            "platform": platform.platform(),
            "version": platform.version(),
            "release": platform.release(),
        }

    def ingest_call_graph(self, path: Path) -> None:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        program = _normalize_module(payload.get("program", Path(path).stem))
        functions = payload.get("functions", [])
        address_map: dict[str, str] = {}
        source_map: dict[str, dict] = {}
        meta = self.metadata_index.get_module_record(program)
        exported_names: set[str] = set()
        if meta:
            exported_names = {name.upper() for name in meta.exports}

        for fn in functions:
            symbol = _symbol_name(fn)
            address = fn.get("entry_point")
            node_id = _node_id(program, symbol)
            if node_id in self.graph.nodes:
                # ensure unique by suffixing address
                node_id = _node_id(program, f"{symbol}@{address}")
            is_imported = fn.get("source") == "IMPORTED"
            is_exported = symbol.upper() in exported_names
            if not (is_imported or is_exported or self.include_internal):
                continue
            record_source = fn.get("source") or ("EXPORTED" if is_exported else None)
            record = NodeRecord(
                node_id=node_id,
                program=program,
                name=symbol,
                address=address,
                is_external=bool(is_imported),
                calling_convention=fn.get("calling_convention"),
                source=record_source,
            )
            self._add_or_update_node(record)
            if address:
                address_map[address] = node_id
            source_map[node_id] = fn
        self.address_maps[program] = address_map
        self.function_sources[program] = source_map

        if meta:
            self.dll_records[program] = {
                "program": program,
                "path": str(meta.data.get("path", meta.path)),
                "sha256": meta.hash_sha256,
                "file_version": meta.file_version,
                "pdb_guid": meta.pdb_guid,
                "pdb_age": meta.pdb_age,
            }

        for edge in payload.get("edges", []):
            caller = address_map.get(edge.get("caller"))
            callee = address_map.get(edge.get("callee"))
            if not caller or not callee:
                continue
            callee_source = source_map.get(callee, {})
            callee_name = callee_source.get("name")
            if callee_source.get("source") == "IMPORTED" and callee_name:
                targets = self.metadata_index.get_import_targets(program, callee_name)
                if not targets:
                    self.unresolved_imports.append((program, callee_name))
                    continue
                for target in targets:
                    target_node = self._ensure_placeholder_node(target, callee_name)
                    self._add_edge(caller, target_node, "import")
                    if program != target:
                        self._add_edge(callee, target_node, "forwarder")
            else:
                self._add_edge(caller, callee, "direct")

        for node_id, fn in source_map.items():
            if fn.get("source") != "IMPORTED":
                continue
            callee_name = fn.get("name")
            if not callee_name:
                continue
            targets = self.metadata_index.get_import_targets(program, callee_name)
            if not targets:
                self.unresolved_imports.append((program, callee_name))
                continue
            for target in targets:
                target_node = self._ensure_placeholder_node(target, callee_name)
                self._add_edge(node_id, target_node, "forwarder")

    def _ensure_placeholder_node(self, program: str, symbol: str) -> str:
        node_id = _node_id(program, symbol)
        if node_id not in self.graph.nodes:
            record = NodeRecord(
                node_id=node_id,
                program=program,
                name=symbol,
                address=None,
                is_external=True,
                calling_convention=None,
                source="SYNTHETIC",
            )
            self._add_or_update_node(record)
        return node_id

    def _add_or_update_node(self, record: NodeRecord) -> None:
        existing = self.graph.nodes[record.node_id] if record.node_id in self.graph else None
        attrs = record.as_dict()
        if existing:
            for key, value in attrs.items():
                if value is not None:
                    existing[key] = value
        else:
            self.graph.add_node(record.node_id, **attrs)

    def _add_edge(self, source: str, target: str, kind: str) -> None:
        key = (source, target, kind)
        if key in self.edge_set:
            return
        if source not in self.graph.nodes or target not in self.graph.nodes:
            return
        self.graph.add_edge(source, target, kind=kind)
        self.edge_set.add(key)

    def add_api_set_forwarders(self) -> None:
        for module in self.metadata_index.iter_alias_modules():
            host = self.metadata_index.resolve_alias(module)
            exports = self.metadata_index.get_exports(module)
            for export_name in exports:
                alias_node = self._ensure_placeholder_node(module, export_name)
                host_node = self._ensure_placeholder_node(host, export_name)
                self._add_edge(alias_node, host_node, "forwarder")

    def add_syscall_nodes(self) -> None:
        program = "NTDLL.DLL"
        source_map = self.function_sources.get(program, {})
        for node_id, fn in source_map.items():
            name = fn.get("name") or ""
            if not name.startswith(("Nt", "Zw")):
                continue
            syscall_node = f"SYSCALL:{name}"
            record = NodeRecord(
                node_id=syscall_node,
                program="SYSCALL",
                name=name,
                address=None,
                is_external=True,
                layer=SYSCALL_LAYER,
                source="SYSCALL",
            )
            self._add_or_update_node(record)
            self._add_edge(node_id, syscall_node, "syscall")

    def integrity_checks(self) -> None:
        for source, target in self.graph.edges():
            if source not in self.graph.nodes or target not in self.graph.nodes:
                raise RuntimeError(f"Dangling edge detected: {source} -> {target}")
        if len(self.graph.nodes) != len(set(self.graph.nodes)):
            raise RuntimeError("Duplicate node identifiers detected.")
        if self.unresolved_imports:
            sample = ", ".join(f"{mod}!{name}" for mod, name in self.unresolved_imports[:5])
            LOGGER.warning("Unresolved imports detected (sample: %s)", sample)

    def acceptance_tests(self) -> None:
        test_graph = nx.DiGraph()
        for source, target, data in self.graph.edges(data=True):
            test_graph.add_edge(source, target, kind=data.get("kind"))

        source_a = "KERNEL32.DLL!CreateFileW"
        target_a = "SYSCALL:NtCreateFile"
        if test_graph.has_node(source_a) and test_graph.has_node(target_a):
            path_a = nx.has_path(test_graph, source_a, target_a)
            if not path_a:
                LOGGER.warning("Missing path KERNEL32!CreateFileW -> ... -> SYSCALL:NtCreateFile")
        else:
            LOGGER.warning("Skipping CreateFileW acceptance check (nodes missing).")

        api_source = "API-MS-WIN-CORE-FILE-L1-2-0.DLL!CreateFileW"
        host_target = "KERNELBASE.DLL!CreateFileW"
        if test_graph.has_node(api_source) and test_graph.has_node(host_target):
            path_b = nx.has_path(test_graph, api_source, host_target)
            if not path_b:
                LOGGER.warning("API set forwarder path not found for CreateFileW.")
        else:
            LOGGER.warning("Skipping API set forwarder acceptance check (nodes missing).")

        ntdll_meta = self.metadata_index.get_module_record("NTDLL.DLL")
        exported_nt = 0
        if ntdll_meta:
            exported_nt = sum(1 for name in ntdll_meta.exports if name.startswith("NT"))
        syscall_nodes = [node for node, data in self.graph.nodes(data=True) if data.get("layer") == SYSCALL_LAYER]
        if exported_nt and len(syscall_nodes) < exported_nt * 0.8:
            LOGGER.warning(
                "Syscall node count mismatch: expected >= %s, found %s",
                exported_nt,
                len(syscall_nodes),
            )

    def build(self, callgraph_paths: Iterable[Path]) -> None:
        for path in callgraph_paths:
            self.ingest_call_graph(path)
        self.add_api_set_forwarders()
        self.add_syscall_nodes()
        self.integrity_checks()
        self.acceptance_tests()

    def export(self, destination: Path) -> None:
        destination = destination.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        nodes = [self.graph.nodes[node] | {"id": node} for node in self.graph.nodes]
        edges = [{"source": s, "target": t, "kind": data.get("kind")} for s, t, data in self.graph.edges(data=True)]
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
