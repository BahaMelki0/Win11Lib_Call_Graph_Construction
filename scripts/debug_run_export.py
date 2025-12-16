from pathlib import Path
import subprocess
import importlib

import sys
from pathlib import Path as _P
# Ensure local package import works when running this ad-hoc script
sys.path.insert(0, str(_P(__file__).resolve().parents[1] / "src"))
from call_graph_win11.pipelines import ghidra_callgraph


def fake_run(*args, **kwargs):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")


def simulate_success():
    tmp = Path("tmp_sim")
    if tmp.exists():
        for p in tmp.rglob("*"):
            if p.is_file():
                p.unlink()
    else:
        tmp.mkdir()

    binary = tmp / "bin.exe"
    binary.write_text("exe")
    out = tmp / "out"
    out.mkdir()
    (out / "bin.exe.callgraph.json").write_text("{}")

    ghidra_callgraph.run_headless = fake_run
    results = ghidra_callgraph.export_call_graphs(
        [binary],
        ghidra_headless=Path("gh"),
        project_root=tmp,
        project_name="p",
        script_path=Path("scripts/ghidra/export_call_graph.py"),
        output_dir=out,
        overwrite=False,
        metadata_root=None,
        pdb_root=None,
        windows_root=tmp,
        symbol_store=None,
        verbose=False,
        flatten_names=True,
    )
    print("simulate_success ->", results[0].succeeded, results[0].returncode, results[0].stderr)


def simulate_missing_output():
    tmp = Path("tmp_sim2")
    if tmp.exists():
        for p in tmp.rglob("*"):
            if p.is_file():
                p.unlink()
    else:
        tmp.mkdir()

    binary = tmp / "bin2.exe"
    binary.write_text("exe")
    out = tmp / "out2"
    out.mkdir()

    ghidra_callgraph.run_headless = fake_run
    results = ghidra_callgraph.export_call_graphs(
        [binary],
        ghidra_headless=Path("gh"),
        project_root=tmp,
        project_name="p",
        script_path=Path("scripts/ghidra/export_call_graph.py"),
        output_dir=out,
        overwrite=False,
        metadata_root=None,
        pdb_root=None,
        windows_root=tmp,
        symbol_store=None,
        verbose=False,
        flatten_names=True,
    )
    print("simulate_missing_output ->", results[0].succeeded, results[0].returncode)
    print("stderr:", results[0].stderr)
    print("diag exists:", (out / "bin2.exe.callgraph.json.ghidra.log").exists())


if __name__ == "__main__":
    simulate_success()
    simulate_missing_output()
