@echo off
REM Example headless invocation for exporting a call graph with Ghidra.
REM Update GHIDRA_HOME, PROJECT_DIR, and OUTPUT_PATH as required.

set GHIDRA_HOME=C:\Users\Baha\Tools\ghidra\ghidra_11.4.2_PUBLIC
set PROJECT_DIR=%cd%\ghidra-projects
set PROJECT_NAME=call_graph_example
set EXPORT_SCRIPT=%cd%\scripts\ghidra\export_call_graph.py
set PDB_SCRIPT=%cd%\scripts\ghidra\set_pdb_path.py
set BINARY=C:\Windows\System32\ntdll.dll
set OUTPUT_PATH=%cd%\data\interim\call_graphs\System32\ntdll.dll.callgraph.json
set PDB_PATH=%cd%\data\external\pdbs\ntdll.pdb\3DF97D250AD59D01BC65E275570F19041\ntdll.pdb

"%GHIDRA_HOME%\support\analyzeHeadless.bat" ^
  "%PROJECT_DIR%" ^
  "%PROJECT_NAME%" ^
  -overwrite ^
  -import "%BINARY%" ^
  -scriptPath "%cd%\scripts\ghidra" ^
  -preScript "%PDB_SCRIPT%" "%PDB_PATH%" ^
  -postScript "%EXPORT_SCRIPT%" "%OUTPUT_PATH%"

echo Call graph exported to %OUTPUT_PATH%
