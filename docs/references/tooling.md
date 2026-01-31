# Tooling Reference

- **Ghidra**: https://ghidra-sre.org - preferred for headless automation.
- **Java (Temurin 21+)**: required for Ghidra headless; ensure `java -version` works.
- **IDA Pro**: https://hex-rays.com/ida-pro/ - alternative with powerful signature support.
- **igraph**: https://igraph.org/python/ - Python bindings for graph analysis.
- **networkx**: https://networkx.org/ - flexible graph analytics library.
- **Graphviz**: https://graphviz.org/ - rendering backend for call graph visualisations.
- **VC++ Redistributable**: required on Windows for `python-igraph` wheels (2015-2022 x64/x86).

Notes:
- PDBs are optional: the exporter can run without them, but symbol names will be weaker.
- When using the Microsoft symbol server, ensure the symbol cache path is writable.

Document installation notes, shortcuts, and troubleshooting tips here as you become familiar with
each tool.
