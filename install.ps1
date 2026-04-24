# Install Proc Blart TUI dependencies on Windows.

[CmdletBinding()]
param(
    [switch]$UpgradePip,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher 'py' was not found. Install Python for Windows, then rerun this script."
}

$VenvPath = Join-Path $Root ".venv"
$PythonPath = Join-Path $VenvPath "Scripts\python.exe"

if ($Force -and (Test-Path $VenvPath)) {
    Write-Host "Removing existing virtual environment: $VenvPath"
    Remove-Item -LiteralPath $VenvPath -Recurse -Force
}

if (-not (Test-Path $PythonPath)) {
    Write-Host "Creating virtual environment..."
    py -m venv .venv
}

if ($UpgradePip) {
    Write-Host "Upgrading pip..."
    & $PythonPath -m pip install --upgrade pip
}

Write-Host "Installing dependencies..."
& $PythonPath -m pip install -r requirements.txt
& $PythonPath -m pip install -e .

Write-Host ""
Write-Host "Install complete."
Write-Host "Activate with: .\.venv\Scripts\Activate.ps1"
Write-Host "Run safely with: procblart run -dry"
Write-Host 'Set VirusTotal for this shell with: $env:VIRUSTOTAL_API_KEY = "paste_key_here"'
