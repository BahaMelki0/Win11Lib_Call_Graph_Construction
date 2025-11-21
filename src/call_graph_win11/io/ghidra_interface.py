"""Adapters for interacting with Ghidra headless projects."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence

DEFAULT_HEADLESS = Path("C:/Program Files/ghidra/support/analyzeHeadless.bat")


def run_headless(
    ghidra_install: Path,
    project_dir: Path,
    script_path: Path,
    script_args: Sequence[str],
    *,
    project_name: str | None = None,
    overwrite: bool = False,
    pre_scripts: Sequence[tuple[Path, Sequence[str]]] | None = None,
    extra_args: Sequence[str] | None = None,
    symbol_path: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Execute a Ghidra headless script.

    This is a minimal wrapper intended as a starting point for automation scripts. Extend it with
    richer logging, error handling, and retries as the project evolves.
    """

    if not ghidra_install.exists():
        raise FileNotFoundError(f"Ghidra headless launcher not found: {ghidra_install}")

    project_dir = project_dir.resolve()
    project_dir.mkdir(parents=True, exist_ok=True)
    project = project_name or project_dir.name

    cmd = [str(ghidra_install)]
    if "analyzeheadless" not in ghidra_install.name.lower():
        cmd.append("analyzeHeadless")

    cmd.extend([str(project_dir), project])

    if overwrite:
        cmd.append("-overwrite")

    if extra_args:
        cmd.extend(extra_args)

    if symbol_path:
        # Accept srv* chain strings or concrete filesystem paths.
        if isinstance(symbol_path, Path):
            symbol_path = symbol_path.expanduser().resolve()
            symbol_path.mkdir(parents=True, exist_ok=True)
            cmd.extend(["-symbolPath", str(symbol_path)])
        else:
            cmd.extend(["-symbolPath", symbol_path])

    cmd.extend(["-import", script_args[0]])

    script_paths = [script_path.parent.resolve()]
    if pre_scripts:
        for pre_script, _ in pre_scripts:
            pre_dir = pre_script.parent.resolve()
            if pre_dir not in script_paths:
                script_paths.append(pre_dir)

    for path in script_paths:
        cmd.extend(["-scriptPath", str(path)])

    if pre_scripts:
        for pre_script, args in pre_scripts:
            cmd.extend(["-preScript", pre_script.name, *args])

    cmd.extend(["-postScript", script_path.name, *script_args[1:]])

    return subprocess.run(cmd, check=False, text=True, capture_output=True)
