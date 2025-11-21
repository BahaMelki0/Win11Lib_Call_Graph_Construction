"""Helper routines to export call graphs via Ghidra headless scripts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import json
import requests

from call_graph_win11.data.pdb_fetcher import (
    CodeViewSignature,
    download_pdb,
    iter_metadata_files,
)
from call_graph_win11.io.ghidra_interface import DEFAULT_HEADLESS, run_headless


@dataclass(slots=True)
class CallGraphRunResult:
    binary: Path
    output: Path
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False
    pdb_path: Path | None = None
    metadata: Path | None = None

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.skipped


def _metadata_path_for_binary(binary: Path, metadata_root: Path, windows_root: Path) -> Path | None:
    try:
        relative = binary.resolve().relative_to(windows_root.resolve())
    except ValueError:
        relative = None

    if relative:
        candidate = metadata_root / relative.parent / f"{relative.name}.json"
        if candidate.exists():
            return candidate

    binary_resolved = str(binary.resolve()).lower()
    for metadata_file in iter_metadata_files(metadata_root):
        try:
            with metadata_file.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
        except json.JSONDecodeError:
            continue
        path_value = metadata.get("path")
        if path_value and str(path_value).lower() == binary_resolved:
            return metadata_file
    return None


def _ensure_pdb(metadata: dict, metadata_file: Path, pdb_root: Path, session: Optional[requests.Session] = None) -> Optional[Path]:
    if pdb_root is None:
        return None

    debug_entries = metadata.get("debug", [])
    if not debug_entries:
        return None

    sess = session or requests.Session()
    for entry in debug_entries:
        codeview = entry.get("codeview")
        if not isinstance(codeview, dict):
            continue
        if codeview.get("signature") != "RSDS":
            continue
        pdb_name = Path(codeview.get("pdb_path", "")).name
        identifier = codeview.get("symbol_server_path")
        if not pdb_name or not identifier:
            continue

        signature = CodeViewSignature(pdb_name=pdb_name, identifier=identifier)
        signature.sources.add(metadata_file)
        destination = signature.destination_path(pdb_root)
        if destination.exists():
            return destination

        success, _ = download_pdb(sess, signature, pdb_root)
        if success and destination.exists():
            return destination

    return None


def _pdb_path_from_metadata(
    metadata_file: Path,
    pdb_root: Path,
    *,
    session: Optional[requests.Session] = None,
) -> tuple[Optional[Path], dict]:
    with metadata_file.open("r", encoding="utf-8") as handle:
        metadata = json.load(handle)

    pdb_path = _ensure_pdb(metadata, metadata_file, pdb_root, session=session) if pdb_root else None
    debug_entries = metadata.get("debug", [])
    return pdb_path, metadata


def export_call_graphs(
    binaries: Iterable[Path],
    *,
    ghidra_headless: Path = DEFAULT_HEADLESS,
    project_root: Path,
    project_name: str = "call_graph_win11",
    script_path: Path = Path("scripts/ghidra/export_call_graph.py"),
    output_dir: Path = Path("data/interim/call_graphs"),
    overwrite: bool = False,
    metadata_root: Path | None = None,
    pdb_root: Path | None = None,
    pdb_script: Path = Path("scripts/ghidra/set_pdb_path.py"),
    windows_root: Path = Path(r"C:\Windows"),
    symbol_store: str | Path | None = None,
) -> List[CallGraphRunResult]:
    """
    Invoke the Ghidra headless exporter for the provided binaries.

    Returns a list of run results capturing stdout/stderr per binary.
    """

    results: List[CallGraphRunResult] = []
    script_path = script_path.resolve()
    pdb_script = pdb_script.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()

    for binary in binaries:
        binary = binary.resolve()
        try:
            relative = binary.resolve().relative_to(windows_root.resolve())
            output_path = output_dir / relative.parent / f"{relative.name}.callgraph.json"
        except ValueError:
            output_path = output_dir / f"{binary.name}.callgraph.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output_path.exists() and not overwrite:
            results.append(
                CallGraphRunResult(
                    binary=binary,
                    output=output_path,
                    returncode=0,
                    stdout="skipped (existing output)",
                    stderr="",
                    skipped=True,
                )
            )
            continue

        args = [str(binary), str(output_path)]

        pre_scripts: list[tuple[Path, Sequence[str]]] = []
        metadata_file: Path | None = None
        pdb_path: Path | None = None

        if metadata_root and pdb_root:
            metadata_file = _metadata_path_for_binary(binary, metadata_root.resolve(), windows_root.resolve())
            if metadata_file and metadata_file.exists():
                resolved, _metadata = _pdb_path_from_metadata(metadata_file, pdb_root.resolve(), session=session)
                if resolved:
                    pdb_path = resolved.resolve()
                    pre_scripts.append((pdb_script, [str(pdb_path)]))

        completed = run_headless(
            ghidra_headless,
            project_root,
            script_path,
            args,
            project_name=project_name,
            overwrite=overwrite,
            pre_scripts=pre_scripts,
            symbol_path=symbol_store,
        )

        results.append(
            CallGraphRunResult(
                binary=binary,
                output=output_path,
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                metadata=metadata_file,
                pdb_path=pdb_path,
            )
        )

    return results
