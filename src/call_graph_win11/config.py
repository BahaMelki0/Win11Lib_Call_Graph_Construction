"""Configuration primitives for the project."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List


@dataclass(slots=True)
class ProjectPaths:
    """Paths to key project directories relative to the repository root."""

    root: Path = Path(__file__).resolve().parents[2]
    data_raw: Path = field(init=False)
    data_processed: Path = field(init=False)
    data_interim: Path = field(init=False)
    data_external: Path = field(init=False)
    docs: Path = field(init=False)
    notebooks: Path = field(init=False)

    def __post_init__(self) -> None:
        self.data_raw = self.root / "data" / "raw"
        self.data_processed = self.root / "data" / "processed"
        self.data_interim = self.root / "data" / "interim"
        self.data_external = self.root / "data" / "external"
        self.docs = self.root / "docs"
        self.notebooks = self.root / "notebooks"


@dataclass(slots=True)
class ExtractionConfig:
    """Settings guiding the reverse engineering extraction phase."""

    target_root: Path
    libraries: List[str]
    ghidra_project_dir: Path
    ida_project_dir: Path | None = None
    include_private_symbols: bool = False

    @classmethod
    def from_windows_root(
        cls,
        windows_root: Path,
        library_paths: Iterable[str],
        *,
        include_private_symbols: bool = False,
    ) -> "ExtractionConfig":
        """Factory helper that expands common system library locations."""

        resolved_libs = [str((windows_root / lib).resolve()) for lib in library_paths]
        return cls(
            target_root=windows_root,
            libraries=resolved_libs,
            ghidra_project_dir=windows_root.parent / "ghidra-projects",
            include_private_symbols=include_private_symbols,
        )
