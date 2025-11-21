[CmdletBinding()]
param(
    [string]$WindowsRoot = "C:\Windows",
    [string]$MetadataDir = "data/raw/windows_inventory",
    [string]$PdbDir = "data/external/pdbs",
    [string]$CacheDir = "",
    [string]$CallGraphDir = "data/interim/call_graphs",
    [string]$CsvOutput = "docs/windows_inventory_summary.csv",
    [string]$ReportsDir = "docs/analytics",
    [string]$GhidraHeadless = "",
    [int]$Limit = 0,
    [switch]$OverwriteCallgraphs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param([string]$PathValue)
    return [System.IO.Path]::GetFullPath($PathValue, (Get-Location))
}

function Invoke-PythonStep {
    param(
        [string]$Description,
        [string[]]$Arguments,
        [string]$OutputPath = ""
    )

    Write-Host ">>> $Description" -ForegroundColor Cyan

    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if ($parent) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        & python @Arguments | Tee-Object -FilePath $OutputPath
    }
    else {
        & python @Arguments
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Step failed: $Description"
    }

    Write-Host ">>> Completed $Description" -ForegroundColor Green
}

$windowsRootFull = Resolve-FullPath $WindowsRoot
$metadataFull = Resolve-FullPath $MetadataDir
$pdbFull = Resolve-FullPath $PdbDir
$callGraphFull = Resolve-FullPath $CallGraphDir
$csvFull = Resolve-FullPath $CsvOutput
$reportsFull = Resolve-FullPath $ReportsDir

if ($CacheDir) {
    $cacheFull = Resolve-FullPath $CacheDir
} else {
    $cacheFull = $null
}

New-Item -ItemType Directory -Path $metadataFull -Force | Out-Null
New-Item -ItemType Directory -Path $pdbFull -Force | Out-Null
New-Item -ItemType Directory -Path $callGraphFull -Force | Out-Null
New-Item -ItemType Directory -Path $reportsFull -Force | Out-Null

$inventoryArgs = @(
    "-m", "call_graph_win11.cli", "inventory",
    "--root", $windowsRootFull,
    "--output", $metadataFull
)
if ($Limit -gt 0) {
    $inventoryArgs += @("--limit", $Limit)
}
Invoke-PythonStep -Description "Inventory Windows libraries" -Arguments $inventoryArgs

$pdbArgs = @(
    "-m", "call_graph_win11.cli", "fetch-pdbs",
    "--metadata-root", $metadataFull,
    "--output-root", $pdbFull
)
if ($cacheFull) {
    $pdbArgs += @("--cache-root", $cacheFull)
}
if ($Limit -gt 0) {
    $pdbArgs += @("--limit", $Limit)
}
Invoke-PythonStep -Description "Fetch matching PDB files" -Arguments $pdbArgs

$batchArgs = @(
    "-m", "call_graph_win11.cli", "callgraph-batch",
    "--metadata-root", $metadataFull,
    "--windows-root", $windowsRootFull,
    "--output-dir", $callGraphFull,
    "--pdb-root", $pdbFull
)
if ($GhidraHeadless) {
    $batchArgs += @("--ghidra-headless", (Resolve-FullPath $GhidraHeadless))
}
if ($Limit -gt 0) {
    $batchArgs += @("--limit", $Limit)
}
if ($OverwriteCallgraphs) {
    $batchArgs += "--overwrite"
}
Invoke-PythonStep -Description "Export per-library call graphs (Ghidra)" -Arguments $batchArgs

$csvArgs = @(
    "-m", "call_graph_win11.cli", "inventory-csv",
    "--metadata-root", $metadataFull,
    "--output-csv", $csvFull,
    "--relative-to", $windowsRootFull
)
Invoke-PythonStep -Description "Render inventory CSV summary" -Arguments $csvArgs

$callGraphs = Get-ChildItem -Path $callGraphFull -Filter "*.callgraph.json" -Recurse | Sort-Object Length -Descending | Select-Object -First 5

if ($callGraphs) {
    $syscallArgs = @("-m", "call_graph_win11.cli", "callgraph-syscall-report", "--top", "20")
    foreach ($cg in $callGraphs) {
        $syscallArgs += @("--input", $cg.FullName)
    }
    $syscallReport = Join-Path $reportsFull "syscall_report.txt"
    Invoke-PythonStep -Description "Generate syscall reachability report" -Arguments $syscallArgs -OutputPath $syscallReport

    $hookArgs = @("-m", "call_graph_win11.cli", "callgraph-hook-plan", "--max-uncovered", "20")
    foreach ($cg in $callGraphs) {
        $hookArgs += @("--input", $cg.FullName)
    }
    $hookReport = Join-Path $reportsFull "hook_plan.txt"
    Invoke-PythonStep -Description "Compute greedy hook plan" -Arguments $hookArgs -OutputPath $hookReport
}
else {
    Write-Warning "No call graphs were generated; skipping analytic reports."
}

Write-Host ""
Write-Host "Pipeline completed successfully." -ForegroundColor Green
Write-Host "Inventory JSON : $metadataFull"
Write-Host "PDB store      : $pdbFull"
Write-Host "Call graphs    : $callGraphFull"
Write-Host "CSV summary    : $csvFull"
Write-Host "Reports        : $reportsFull"
