from __future__ import annotations

from pathlib import Path
import subprocess

from call_graph_win11.pipelines.ghidra_callgraph import export_call_graphs


def test_export_call_graph_succeeds_when_output_exists(tmp_path, monkeypatch):
    binary = tmp_path / "bin.exe"
    binary.write_text("exe")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    # Pre-create the expected output to simulate a successful exporter.
    expected = output_dir / "bin.exe.callgraph.json"
    expected.write_text("{}")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("call_graph_win11.pipelines.ghidra_callgraph.run_headless", fake_run)

    results = export_call_graphs(
        [binary],
        ghidra_headless=Path("gh"),
        project_root=tmp_path,
        project_name="p",
        script_path=Path("scripts/ghidra/export_call_graph.py"),
        output_dir=output_dir,
        overwrite=False,
        metadata_root=None,
        pdb_root=None,
        windows_root=tmp_path,
        symbol_store=None,
        verbose=False,
        flatten_names=True,
    )

    assert len(results) == 1
    r = results[0]
    # Existing outputs are skipped by design (not a failure).
    assert r.skipped
    assert r.returncode == 0
    assert "skipped" in (r.stdout or "")


def test_export_call_graph_fails_when_output_missing(tmp_path, monkeypatch):
    binary = tmp_path / "bin2.exe"
    binary.write_text("exe")
    output_dir = tmp_path / "out2"
    output_dir.mkdir()

    def fake_run(*args, **kwargs):
        # Simulate GHIDRA returning success but not writing the output.
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("call_graph_win11.pipelines.ghidra_callgraph.run_headless", fake_run)

    results = export_call_graphs(
        [binary],
        ghidra_headless=Path("gh"),
        project_root=tmp_path,
        project_name="p",
        script_path=Path("scripts/ghidra/export_call_graph.py"),
        output_dir=output_dir,
        overwrite=False,
        metadata_root=None,
        pdb_root=None,
        windows_root=tmp_path,
        symbol_store=None,
        verbose=False,
        flatten_names=True,
    )

    assert len(results) == 1
    r = results[0]
    assert not r.succeeded
    assert r.returncode != 0
    assert "did not produce expected output" in (r.stderr or "")
    # diagnostic log should be created
    diag = output_dir / "bin2.exe.callgraph.json.ghidra.log"
    assert diag.exists()
