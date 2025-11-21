#@category CallGraph

from __future__ import print_function

import os

from java.io import File

from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer


def main():
    args = getScriptArgs()
    if not args or len(args) < 1:
        raise RuntimeError("PDB path argument is required.")

    pdb_path = args[0]
    if not os.path.exists(pdb_path):
        raise RuntimeError("PDB file not found: %s" % pdb_path)

    pdb_file = File(pdb_path)
    PdbUniversalAnalyzer.setPdbFileOption(currentProgram, pdb_file)
    print("Configured PDB for %s" % pdb_path)


if __name__ == "__main__":
    main()
