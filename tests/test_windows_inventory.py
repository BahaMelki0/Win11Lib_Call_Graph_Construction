"""Tests for Windows inventory helpers."""

import uuid

import pytest

from call_graph_win11.data.windows_inventory import parse_codeview_record


def test_parse_rsds_record() -> None:
    guid = uuid.UUID("12345678-9abc-def0-1234-56789abcdef0")
    age = 5
    pdb = b"kernel32.pdb\x00"
    payload = b"RSDS" + guid.bytes_le + age.to_bytes(4, "little") + pdb
    result = parse_codeview_record(payload)

    assert result["signature"] == "RSDS"
    assert result["guid"] == str(guid).upper()
    assert result["age"] == age
    assert result["pdb_path"] == "kernel32.pdb"
    assert result["symbol_server_path"] == f"{guid.hex.upper()}{age}"


def test_parse_nb10_record() -> None:
    age = 3
    timestamp = 0x12345678
    pdb = b"legacy.pdb\x00"
    payload = b"NB10" + b"\x00" * 4 + timestamp.to_bytes(4, "little") + age.to_bytes(4, "little") + pdb

    result = parse_codeview_record(payload)
    assert result["signature"] == "NB10"
    assert result["age"] == age
    assert result["timestamp"] == timestamp
    assert result["pdb_path"] == "legacy.pdb"


def test_parse_unsupported_signature() -> None:
    with pytest.raises(ValueError):
        parse_codeview_record(b"XXXX")
