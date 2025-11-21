"""Tests for PDB fetching helpers."""

from __future__ import annotations

import json
from pathlib import Path

from call_graph_win11.data.pdb_fetcher import (
    CodeViewSignature,
    _compressed_name,
    _extract_rsds_entries,
    _is_cabinet,
    gather_codeview_signatures,
)


def test_compressed_name_conversion() -> None:
    assert _compressed_name("ntdll.pdb") == "ntdll.pd_"
    assert _compressed_name("foo") == "foo_"


def test_extract_rsds_entries(tmp_path: Path) -> None:
    metadata = {
        "debug": [
            {
                "codeview": {
                    "signature": "RSDS",
                    "pdb_path": r"C:\sym\ntdll.pdb",
                    "symbol_server_path": "ABC123",
                }
            },
            {"codeview": {"signature": "NB10", "pdb_path": "ignored", "symbol_server_path": "XYZ"}},
        ]
    }

    entries = _extract_rsds_entries(metadata, Path(r"C:\Windows\System32\ntdll.dll"))
    assert len(entries) == 1
    entry = entries[0]
    assert entry.pdb_name == "ntdll.pdb"
    assert entry.identifier == "ABC123"
    assert Path(r"C:\Windows\System32\ntdll.dll") in entry.sources


def test_gather_signatures_merges_sources(tmp_path: Path) -> None:
    data_dir = tmp_path / "inventory"
    data_dir.mkdir()

    first = {
        "path": r"C:\Windows\System32\ntdll.dll",
        "debug": [
            {
                "codeview": {
                    "signature": "RSDS",
                    "pdb_path": "ntdll.pdb",
                    "symbol_server_path": "AAA111",
                }
            }
        ],
    }

    second = {
        "path": r"C:\Windows\SysWOW64\ntdll.dll",
        "debug": [
            {
                "codeview": {
                    "signature": "RSDS",
                    "pdb_path": r"C:\Symbols\ntdll.pdb",
                    "symbol_server_path": "AAA111",
                }
            }
        ],
    }

    third = {
        "path": r"C:\Windows\System32\kernel32.dll",
        "debug": [
            {
                "codeview": {
                    "signature": "RSDS",
                    "pdb_path": "kernel32.pdb",
                    "symbol_server_path": "BBB222",
                }
            }
        ],
    }

    for idx, payload in enumerate((first, second, third), start=1):
        with (data_dir / f"entry{idx}.json").open("w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    signatures = gather_codeview_signatures(data_dir)

    by_key = {(sig.pdb_name, sig.identifier): sig for sig in signatures}

    assert ("ntdll.pdb", "AAA111") in by_key
    assert ("kernel32.pdb", "BBB222") in by_key

    ntdll_sig = by_key[("ntdll.pdb", "AAA111")]
    assert len(ntdll_sig.sources) == 2


def test_gather_signatures_unique_limit(tmp_path: Path) -> None:
    data_dir = tmp_path / "inventory"
    data_dir.mkdir()

    payloads = [
        {
            "path": f"C:\\Windows\\System32\\lib{i}.dll",
            "debug": [
                {
                    "codeview": {
                        "signature": "RSDS",
                        "pdb_path": f"lib{i}.pdb",
                        "symbol_server_path": f"ID{i}",
                    }
                }
            ],
        }
        for i in range(5)
    ]

    for idx, payload in enumerate(payloads):
        with (data_dir / f"entry{idx}.json").open("w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    limited = gather_codeview_signatures(data_dir, max_unique=3)
    assert len(limited) == 3


def test_gather_signatures_with_filter(tmp_path: Path) -> None:
    data_dir = tmp_path / "inventory"
    data_dir.mkdir()

    entries = [
        {
            "path": r"C:\Windows\System32\alpha.dll",
            "debug": [
                {
                    "codeview": {
                        "signature": "RSDS",
                        "pdb_path": "alpha.pdb",
                        "symbol_server_path": "A1",
                    }
                }
            ],
        },
        {
            "path": r"C:\Windows\System32\beta.dll",
            "debug": [
                {
                    "codeview": {
                        "signature": "RSDS",
                        "pdb_path": "beta.pdb",
                        "symbol_server_path": "B2",
                    }
                }
            ],
        },
    ]

    for idx, payload in enumerate(entries):
        with (data_dir / f"item{idx}.json").open("w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    filtered = gather_codeview_signatures(data_dir, pdb_filter={"beta.pdb"})
    assert len(filtered) == 1
    assert filtered[0].pdb_name == "beta.pdb"


def test_is_cabinet(tmp_path: Path) -> None:
    cab_path = tmp_path / "sample.pd_"
    with cab_path.open("wb") as handle:
        handle.write(b"MSCF0000")

    assert _is_cabinet(cab_path) is True

    not_cab = tmp_path / "plain.bin"
    with not_cab.open("wb") as handle:
        handle.write(b"\x00\x01\x02\x03")

    assert _is_cabinet(not_cab) is False
