"""Logic responsible for pulling function metadata from reverse engineering tools."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class DecompilerAdapter(Protocol):
    """Adapter API for reverse engineering tools (Ghidra, IDA)."""

    def list_functions(self, binary_path: Path) -> list[str]:
        ...

    def export_call_graph(self, binary_path: Path, output_path: Path) -> Path:
        ...


@dataclass(slots=True)
class LibraryDescriptor:
    """Metadata that uniquely identifies a Windows system library."""

    path: Path
    architecture: str = "x86_64"
    min_os_build: str | None = None
    symbols_file: Path | None = None


def collect_library_call_graphs(
    libs: list[LibraryDescriptor],
    decompiler: DecompilerAdapter,
    output_dir: Path,
) -> list[Path]:
    """
    Drive the configured decompiler to export call graphs for each requested library.

    Returns the list of generated artefacts for further processing. This function is a template,
    the concrete implementation should add caching, error handling, and logging.
    """

    output_dir.mkdir(parents=True, exist_ok=True)
    exports: list[Path] = []
    for library in libs:
        export_path = output_dir / f"{library.path.stem}_call_graph.json"
        exports.append(decompiler.export_call_graph(library.path, export_path))
    return exports
