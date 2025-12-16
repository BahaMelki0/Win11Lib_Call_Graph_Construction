"""Download PDB symbol files from Microsoft's public symbol server."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import requests

LOGGER = logging.getLogger(__name__)

SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols"
DEFAULT_TIMEOUT = 120


@dataclass(slots=True)
class CodeViewSignature:
    """Representation of a CodeView RSDS record."""

    pdb_name: str
    identifier: str
    sources: set[Path] = field(default_factory=set)

    def destination_dir(self, root: Path) -> Path:
        return root / self.pdb_name / self.identifier

    def destination_path(self, root: Path) -> Path:
        return self.destination_dir(root) / self.pdb_name


@dataclass(slots=True)
class DownloadSummary:
    attempted: int = 0
    downloaded: int = 0
    skipped_existing: int = 0
    reused_cache: int = 0
    failed: list[tuple[CodeViewSignature, str]] = field(default_factory=list)

    @property
    def failure_count(self) -> int:
        return len(self.failed)


def iter_metadata_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.json"):
        if path.is_file():
            yield path


def _extract_rsds_entries(metadata: dict, source_path: Path) -> list[CodeViewSignature]:
    results: dict[tuple[str, str], CodeViewSignature] = {}

    for entry in metadata.get("debug", []):
        codeview = entry.get("codeview")
        if not isinstance(codeview, dict):
            continue
        if codeview.get("signature") != "RSDS":
            continue

        pdb_path = codeview.get("pdb_path")
        identifier = codeview.get("symbol_server_path")
        if not pdb_path or not identifier:
            continue

        pdb_name = Path(pdb_path).name
        key = (pdb_name, identifier)

        signature = results.get(key)
        if signature is None:
            signature = CodeViewSignature(pdb_name=pdb_name, identifier=identifier)
            results[key] = signature
        signature.sources.add(source_path)

    return list(results.values())


def gather_codeview_signatures(
    metadata_root: Path,
    *,
    max_metadata_files: Optional[int] = None,
    max_unique: Optional[int] = None,
    pdb_filter: Optional[set[str]] = None,
) -> list[CodeViewSignature]:
    """
    Scan metadata directory and collect unique RSDS signatures.

    ``max_metadata_files`` restricts the number of metadata JSON files processed.
    ``max_unique`` restricts how many distinct signatures are collected.
    """

    signatures: Dict[Tuple[str, str], CodeViewSignature] = {}
    processed = 0
    filter_lower: Optional[set[str]] = None
    if pdb_filter:
        filter_lower = {name.lower() for name in pdb_filter}

    for metadata_file in iter_metadata_files(metadata_root):
        if max_metadata_files is not None and processed >= max_metadata_files:
            break

        processed += 1
        try:
            with metadata_file.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
        except json.JSONDecodeError as exc:
            LOGGER.warning("Failed to parse %s: %s", metadata_file, exc)
            continue

        source_field = metadata.get("path")
        source_path = Path(source_field) if source_field else metadata_file

        for signature in _extract_rsds_entries(metadata, source_path):
            if filter_lower and signature.pdb_name.lower() not in filter_lower:
                continue
            key = (signature.pdb_name, signature.identifier)
            existing = signatures.get(key)
            if existing is None:
                signatures[key] = signature
                if max_unique is not None and len(signatures) >= max_unique:
                    return list(signatures.values())
            else:
                existing.sources.update(signature.sources)

    return list(signatures.values())


def _compressed_name(pdb_name: str) -> str:
    if pdb_name.lower().endswith(".pdb") and len(pdb_name) >= 4:
        return pdb_name[:-1] + "_"
    return pdb_name + "_"


def _is_cabinet(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
    except OSError:
        return False
    return header == b"MSCF"


def _expand_cabinet(cab_path: Path, dest_path: Path) -> None:
    expand_exe = shutil.which("expand")
    if expand_exe is None:
        raise RuntimeError("expand.exe not found; unable to extract CAB-compressed PDB.")

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [expand_exe, str(cab_path), str(dest_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"expand failed: {result.stderr.strip()}")


def _finalize_download(temp_path: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)

    if _is_cabinet(temp_path):
        _expand_cabinet(temp_path, destination)
        try:
            temp_path.unlink()
        except OSError:
            LOGGER.debug("Unable to delete temporary CAB %s", temp_path)
        return

    try:
        temp_path.replace(destination)
    except OSError:
        shutil.copy2(temp_path, destination)
        temp_path.unlink(missing_ok=True)


def _materialize_from_cache(cache_source: Path, destination: Path) -> None:
    """
    Create/refresh ``destination`` using the already-downloaded ``cache_source``.

    Attempts a hard link when possible for efficiency and falls back to copy.
    """

    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists():
        try:
            if destination.samefile(cache_source):
                return
        except FileNotFoundError:
            pass
        destination.unlink()

    try:
        os.link(cache_source, destination)
    except OSError:
        shutil.copy2(cache_source, destination)


def download_pdb(
    session: requests.Session,
    signature: CodeViewSignature,
    storage_root: Path,
    *,
    base_url: str = SYMBOL_SERVER_URL,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, Optional[str]]:
    """
    Download a single PDB described by ``signature``.

    Returns (success, error_message). When ``success`` is True, ``error_message`` is None.
    """

    destination = signature.destination_path(storage_root)
    destination.parent.mkdir(parents=True, exist_ok=True)

    candidates: List[Tuple[str, str]] = []
    pdb_name = signature.pdb_name
    identifier = signature.identifier

    candidates.append((pdb_name, f"{base_url}/{pdb_name}/{identifier}/{pdb_name}"))

    compressed_name = _compressed_name(pdb_name)
    if compressed_name != pdb_name:
        candidates.append((compressed_name, f"{base_url}/{pdb_name}/{identifier}/{compressed_name}"))

    last_error: Optional[str] = None

    for candidate_name, url in candidates:
        try:
            response = session.get(url, stream=True, timeout=timeout)
        except requests.RequestException as exc:
            LOGGER.debug("Error retrieving %s: %s", url, exc)
            last_error = str(exc)
            continue

        if response.status_code == 404:
            last_error = "not found (404)"
            continue
        if response.status_code != 200:
            last_error = f"HTTP {response.status_code}"
            continue

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if chunk:
                    tmp.write(chunk)
            temp_path = Path(tmp.name)

        try:
            _finalize_download(temp_path, destination)
            return True, None
        except Exception as exc:  # pragma: no cover - relies on external tool/environment
            LOGGER.error("Failed to finalize %s: %s", destination, exc)
            temp_path.unlink(missing_ok=True)
            last_error = str(exc)
            continue

    return False, last_error


def fetch_pdbs(
    metadata_root: Path,
    output_root: Path,
    *,
    cache_root: Optional[Path] = None,
    limit: Optional[int] = None,
    force: bool = False,
    base_url: str = SYMBOL_SERVER_URL,
    pdb_names: Optional[Iterable[str]] = None,
    max_metadata_files: Optional[int] = None,
) -> DownloadSummary:
    """
    Download PDBs for the metadata present in ``metadata_root``.

    ``limit`` restricts the number of unique PDBs attempted.
    ``pdb_names`` allows focusing on a specific subset of PDB filenames.
    ``cache_root`` allows storing downloads in a shared symbol cache before materialising
    them under ``output_root``.
    ``max_metadata_files`` bounds how many metadata JSON files are parsed.
    """

    filter_set = {name for name in pdb_names} if pdb_names else None
    signatures = gather_codeview_signatures(
        metadata_root,
        max_metadata_files=max_metadata_files,
        max_unique=limit,
        pdb_filter=filter_set,
    )
    summary = DownloadSummary()

    storage_root = cache_root if cache_root is not None else output_root
    session = requests.Session()

    for signature in signatures:
        if limit is not None and summary.attempted >= limit:
            break

        summary.attempted += 1

        destination = signature.destination_path(output_root)
        cache_destination = signature.destination_path(storage_root)

        if not force and destination.exists():
            summary.skipped_existing += 1
            continue

        if not force and cache_root is not None and cache_destination.exists():
            try:
                _materialize_from_cache(cache_destination, destination)
            except Exception as exc:  # pragma: no cover - filesystem dependent
                LOGGER.error("Failed to reuse cached PDB %s: %s", cache_destination, exc)
                summary.failed.append((signature, str(exc)))
            else:
                summary.reused_cache += 1
            continue

        success, error = download_pdb(session, signature, storage_root, base_url=base_url)
        if success:
            if cache_root is not None:
                try:
                    _materialize_from_cache(cache_destination, destination)
                except Exception as exc:  # pragma: no cover - filesystem dependent
                    LOGGER.error("Failed to materialize PDB %s from cache: %s", cache_destination, exc)
                    summary.failed.append((signature, str(exc)))
                    continue
            summary.downloaded += 1
        else:
            summary.failed.append((signature, error or "unknown error"))

    return summary
