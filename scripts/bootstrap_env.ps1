<#
.SYNOPSIS
    Bootstrap a Python virtual environment for the Call Graph project.
#>

param(
    [string]$Python = "python",
    [string]$VenvPath = ".venv"
)

Write-Host "Creating virtual environment at $VenvPath..." -ForegroundColor Cyan
& $Python -m venv $VenvPath

$activate = Join-Path $VenvPath "Scripts\Activate.ps1"
Write-Host "Activating environment..." -ForegroundColor Cyan
. $activate

Write-Host "Upgrading pip..." -ForegroundColor Cyan
python -m pip install --upgrade pip

Write-Host "Installing project dependencies..." -ForegroundColor Cyan
pip install -e .[dev]

Write-Host "Environment ready." -ForegroundColor Green
