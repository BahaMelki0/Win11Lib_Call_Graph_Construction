"""Utilities for collecting metadata about Windows PE files."""

from __future__ import annotations

import csv
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

import pefile

LOGGER = logging.getLogger(__name__)

IMAGE_DEBUG_TYPE_CODEVIEW = 2

CSV_FIELDNAMES = [
    "path",
    "size",
    "modified_utc",
    "machine",
    "subsystem",
    "image_base",
    "entry_point",
    "time_date_stamp",
    "checksum",
    "number_of_sections",
    "exports_count",
    "import_modules",
    "import_functions",
    "debug_entries",
    "rsds_entries",
    "has_rsds",
    "pdb_path",
    "pdb_guid",
    "pdb_age",
    "pdb_symbol_server_path",
]


def is_pe_file(path: Path) -> bool:
    """Return True if ``path`` points to a valid PE file."""

    try:
        with path.open("rb") as binary:
            if binary.read(2) != b"MZ":
                return False
            binary.seek(0x3C)
            pe_offset_bytes = binary.read(4)
            if len(pe_offset_bytes) != 4:
                return False
            pe_offset = int.from_bytes(pe_offset_bytes, "little")
            if pe_offset <= 0:
                return False
            binary.seek(pe_offset)
            return binary.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def _norm_bytes(value: Optional[bytes]) -> Optional[str]:
    if value is None:
        return None
    return value.decode("utf-8", errors="replace")


def _machine_name(machine: int) -> str:
    return pefile.MACHINE_TYPE.get(machine, f"0x{machine:04X}")


def _characteristics(characteristics: int) -> list[str]:
    names: set[str] = set()
    for key, value in pefile.IMAGE_CHARACTERISTICS.items():
        if isinstance(key, int) and characteristics & key:
            if isinstance(value, str):
                names.add(value)
            else:
                names.add(f"0x{key:04X}")
        if isinstance(value, int) and characteristics & value:
            if isinstance(key, str):
                names.add(key)
            else:
                names.add(f"0x{value:04X}")
    return sorted(names)


def parse_codeview_record(data: bytes) -> dict[str, str | int]:
    """Parse an RSDS/NB10 debug record and return metadata."""

    if not data:
        raise ValueError("Empty CodeView record.")

    signature = data[:4]
    if signature == b"RSDS":
        guid_bytes = data[4:20]
        age = int.from_bytes(data[20:24], "little")
        pdb_path = data[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        guid = uuid.UUID(bytes_le=guid_bytes)
        return {
            "signature": "RSDS",
            "pdb_path": pdb_path,
            "guid": str(guid).upper(),
            "age": age,
            "symbol_server_path": f"{guid.hex.upper()}{age}",
        }

    if signature == b"NB10":
        timestamp = int.from_bytes(data[8:12], "little")
        age = int.from_bytes(data[12:16], "little")
        pdb_path = data[16:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        return {
            "signature": "NB10",
            "timestamp": timestamp,
            "age": age,
            "pdb_path": pdb_path,
        }

    raise ValueError(f"Unsupported CodeView signature: {signature!r}")


def _debug_entries(path: Path, pe: pefile.PE) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return entries

    with path.open("rb") as binary:
        for debug in pe.DIRECTORY_ENTRY_DEBUG:
            entry: dict[str, object] = {
                "type": pefile.DEBUG_TYPE.get(debug.struct.Type, debug.struct.Type),
                "timestamp": debug.struct.TimeDateStamp,
                "size_of_data": debug.struct.SizeOfData,
            }

            if debug.struct.Type == IMAGE_DEBUG_TYPE_CODEVIEW and debug.struct.PointerToRawData:
                binary.seek(debug.struct.PointerToRawData)
                raw = binary.read(debug.struct.SizeOfData)
                try:
                    entry["codeview"] = parse_codeview_record(raw)
                except ValueError as exc:  # pragma: no cover - unusual signatures
                    LOGGER.warning("Failed to parse CodeView record in %s: %s", path, exc)
            entries.append(entry)

    return entries


def _export_symbols(pe: pefile.PE) -> list[dict[str, object]]:
    exports: list[dict[str, object]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exports.append(
            {
                "name": _norm_bytes(symbol.name),
                "ordinal": symbol.ordinal,
                "address": symbol.address,
            }
        )
    return exports


def _import_descriptors(pe: pefile.PE) -> list[dict[str, object]]:
    imports: list[dict[str, object]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
        functions: list[dict[str, object]] = []
        for entry in descriptor.imports:
            functions.append(
                {
                    "name": _norm_bytes(entry.name),
                    "ordinal": entry.ordinal,
                    "hint": entry.hint if hasattr(entry, "hint") else None,
                }
            )

        imports.append(
            {
                "module": _norm_bytes(descriptor.dll),
                "functions": functions,
            }
        )
    return imports


def extract_pe_metadata(path: Path) -> dict[str, object]:
    """Extract metadata, exports, imports, and debug info from a PE file."""

    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        ]
    )

    stat = path.stat()
    metadata: dict[str, object] = {
        "path": str(path),
        "size": stat.st_size,
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "machine": _machine_name(pe.FILE_HEADER.Machine),
        "characteristics": _characteristics(pe.FILE_HEADER.Characteristics),
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "time_date_stamp": pe.FILE_HEADER.TimeDateStamp,
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "checksum": getattr(pe.OPTIONAL_HEADER, "CheckSum", None),
    }

    metadata["exports"] = _export_symbols(pe)
    metadata["imports"] = _import_descriptors(pe)
    metadata["debug"] = _debug_entries(path, pe)

    return metadata


@dataclass(slots=True)
class InventoryResult:
    total_files: int
    pe_files: int
    metadata_written: int
    errors: list[str]
    sample_reports: dict[str, dict[str, object]]


def iter_candidate_files(root: Path) -> Iterator[Path]:
    """Yield filesystem entries under ``root`` that could be PE files."""

    for path in root.rglob("*"):
        if path.is_file():
            yield path


def build_inventory(
    root: Path,
    output_dir: Path,
    *,
    limit: int | None = None,
    samples: Iterable[Path] | None = None,
) -> InventoryResult:
    """
    Scan ``root`` for PE files, write metadata JSON per file, and optionally validate samples.
    """

    errors: list[str] = []
    total_files = 0
    pe_files = 0
    metadata_written = 0

    output_dir.mkdir(parents=True, exist_ok=True)
    root = root.resolve()

    for candidate in iter_candidate_files(root):
        total_files += 1
        if limit is not None and metadata_written >= limit:
            break
        if not is_pe_file(candidate):
            continue

        pe_files += 1
        try:
            metadata = extract_pe_metadata(candidate)
        except (pefile.PEFormatError, OSError) as exc:
            errors.append(f"{candidate}: {exc}")
            continue

        relative_path = candidate.relative_to(root)
        target_dir = output_dir / relative_path.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        output_path = target_dir / f"{relative_path.name}.json"

        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
        metadata_written += 1

    sample_reports: dict[str, dict[str, object]] = {}
    if samples:
        for sample_path in samples:
            try:
                metadata = extract_pe_metadata(sample_path)
            except (pefile.PEFormatError, FileNotFoundError, OSError) as exc:
                sample_reports[str(sample_path)] = {"error": str(exc)}
                continue

            debug_entries = metadata.get("debug", [])
            rsds_entries = [
                entry["codeview"]
                for entry in debug_entries
                if isinstance(entry, dict) and entry.get("codeview", {}).get("signature") == "RSDS"
            ]

            sample_reports[str(sample_path)] = {
                "machine": metadata.get("machine"),
                "has_rsds": bool(rsds_entries),
                "rsds_entries": rsds_entries,
                "exports": [exp for exp in metadata.get("exports", [])[:5]],
                "imports": [imp for imp in metadata.get("imports", [])[:3]],
            }

    return InventoryResult(
        total_files=total_files,
        pe_files=pe_files,
        metadata_written=metadata_written,
        errors=errors,
        sample_reports=sample_reports,
    )


def _relative_path(path_str: str, relative_to: Optional[Path]) -> str:
    if not path_str:
        return ""
    path = Path(path_str)
    if relative_to is None:
        return str(path)
    try:
        return str(path.resolve().relative_to(relative_to.resolve()))
    except (ValueError, OSError):
        return str(path)


def _summarize_metadata(metadata: dict[str, object], relative_to: Optional[Path]) -> dict[str, object]:
    exports = metadata.get("exports") or []
    imports = metadata.get("imports") or []
    imports_modules = 0
    imports_functions = 0
    if isinstance(imports, list):
        imports_modules = len(imports)
        imports_functions = sum(
            len(module.get("functions", [])) for module in imports if isinstance(module, dict)
        )

    debug_entries = metadata.get("debug") or []
    rsds_entries: list[dict[str, object]] = []
    if isinstance(debug_entries, list):
        for entry in debug_entries:
            if not isinstance(entry, dict):
                continue
            codeview = entry.get("codeview")
            if isinstance(codeview, dict) and codeview.get("signature") == "RSDS":
                rsds_entries.append(codeview)

    primary_rsds = rsds_entries[0] if rsds_entries else {}
    pdb_path = ""
    if isinstance(primary_rsds, dict):
        pdb_path = primary_rsds.get("pdb_path") or ""

    return {
        "path": _relative_path(str(metadata.get("path", "")), relative_to),
        "size": metadata.get("size"),
        "modified_utc": metadata.get("modified_utc"),
        "machine": metadata.get("machine"),
        "subsystem": metadata.get("subsystem"),
        "image_base": metadata.get("image_base"),
        "entry_point": metadata.get("entry_point"),
        "time_date_stamp": metadata.get("time_date_stamp"),
        "checksum": metadata.get("checksum"),
        "number_of_sections": metadata.get("number_of_sections"),
        "exports_count": len(exports) if isinstance(exports, list) else 0,
        "import_modules": imports_modules,
        "import_functions": imports_functions,
        "debug_entries": len(debug_entries) if isinstance(debug_entries, list) else 0,
        "rsds_entries": len(rsds_entries),
        "has_rsds": bool(rsds_entries),
        "pdb_path": pdb_path,
        "pdb_guid": primary_rsds.get("guid") if isinstance(primary_rsds, dict) else None,
        "pdb_age": primary_rsds.get("age") if isinstance(primary_rsds, dict) else None,
        "pdb_symbol_server_path": primary_rsds.get("symbol_server_path")
        if isinstance(primary_rsds, dict)
        else None,
    }


def export_inventory_csv(
    metadata_root: Path,
    output_csv: Path,
    *,
    relative_to: Optional[Path] = None,
) -> int:
    """
    Write a CSV summarising all metadata JSON files located under ``metadata_root``.

    Returns the number of rows written (excluding the header).
    """

    metadata_root = metadata_root.expanduser().resolve()
    output_csv = output_csv.expanduser().resolve()
    relative_to = relative_to.expanduser().resolve() if relative_to is not None else metadata_root

    if not metadata_root.exists():
        raise FileNotFoundError(f"Metadata root {metadata_root} does not exist.")

    json_files = sorted(path for path in metadata_root.rglob("*.json") if path.is_file())
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    rows_written = 0
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()

        for json_path in json_files:
            try:
                with json_path.open("r", encoding="utf-8") as infile:
                    metadata = json.load(infile)
            except (OSError, json.JSONDecodeError) as exc:
                LOGGER.warning("Skipping %s: %s", json_path, exc)
                continue

            row = _summarize_metadata(metadata, relative_to=relative_to)
            writer.writerow(row)
            rows_written += 1

    return rows_written
