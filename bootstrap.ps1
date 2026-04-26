# Download and install Proc Blart from the public GitHub repository.

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $HOME "proc-blart"),
    [string]$Branch = "main",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$RepoOwner = "AlexCasF"
$RepoName = "proc-blart"
$ZipUrl = "https://github.com/$RepoOwner/$RepoName/archive/refs/heads/$Branch.zip"
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "proc-blart-bootstrap-$([guid]::NewGuid())"
$ZipPath = Join-Path $TempRoot "source.zip"
$ExtractPath = Join-Path $TempRoot "source"

if ((Test-Path $InstallDir) -and -not $Force) {
    $Installer = Join-Path $InstallDir "install.ps1"
    if (-not (Test-Path $Installer)) {
        throw "Install directory already exists but does not contain install.ps1: $InstallDir. Rerun with -Force or choose -InstallDir."
    }
    Write-Host "Using existing install directory: $InstallDir"
} else {
    if ((Test-Path $InstallDir) -and $Force) {
        Write-Host "Removing existing install directory: $InstallDir"
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $InstallDir) | Out-Null

    Write-Host "Downloading Proc Blart from $ZipUrl"
    Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath

    Write-Host "Extracting..."
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $ExtractPath -Force

    $SourceDir = Get-ChildItem -LiteralPath $ExtractPath -Directory | Select-Object -First 1
    if (-not $SourceDir) {
        throw "Downloaded archive did not contain a source directory."
    }

    Move-Item -LiteralPath $SourceDir.FullName -Destination $InstallDir
}

$Installer = Join-Path $InstallDir "install.ps1"
if (-not (Test-Path $Installer)) {
    throw "install.ps1 not found in $InstallDir"
}

Write-Host "Running installer..."
& powershell -NoProfile -ExecutionPolicy Bypass -File $Installer

Write-Host ""
Write-Host "Proc Blart is installed in: $InstallDir"
Write-Host "Start a new shell or run:"
Write-Host "  cd '$InstallDir'"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  procblart run -dry"
