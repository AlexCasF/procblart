# Launch Proc Blart TUI from the project folder.

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Execute,
    [string]$ScanFile,
    [string]$Remote,
    [string]$Policy = "policy.json",
    [string]$Workdir = "proc_blart_data",
    [double]$Interval = 2.0,
    [int]$MaxRows = 30,
    [switch]$CurrentTerminal
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$SelectedModes = @($DryRun.IsPresent, $Execute.IsPresent, -not [string]::IsNullOrWhiteSpace($ScanFile)) | Where-Object { $_ }
if ($SelectedModes.Count -gt 1) {
    throw "Choose only one mode: -DryRun, -Execute, or -ScanFile <path>."
}
if ($ScanFile -and -not [string]::IsNullOrWhiteSpace($Remote)) {
    throw "-Remote only applies to monitor mode."
}
if ($Execute -and -not [string]::IsNullOrWhiteSpace($Remote)) {
    throw "Remote mode is read-only. Use -Remote without -Execute."
}

$PythonPath = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonPath)) {
    throw "Virtual environment not found. Run .\install.ps1 first."
}

$ResolvedPolicy = (Resolve-Path -LiteralPath $Policy).Path
if ([System.IO.Path]::IsPathRooted($Workdir)) {
    $ResolvedWorkdir = $Workdir
} else {
    $ResolvedWorkdir = Join-Path $Root $Workdir
}

if (-not $env:VIRUSTOTAL_API_KEY) {
    $PersistedKey = [Environment]::GetEnvironmentVariable("VIRUSTOTAL_API_KEY", "User")
    if (-not $PersistedKey) {
        $PersistedKey = [Environment]::GetEnvironmentVariable("VIRUSTOTAL_API_KEY", "Machine")
    }
    if ($PersistedKey) {
        $env:VIRUSTOTAL_API_KEY = $PersistedKey
    }
}

if ($ScanFile) {
    $ResolvedScanFile = (Resolve-Path -LiteralPath $ScanFile).Path
    & $PythonPath "proc_blart.py" "scan-file" $ResolvedScanFile "--policy" $ResolvedPolicy "--workdir" $ResolvedWorkdir
    exit $LASTEXITCODE
}

$MonitorArgs = @(
    "proc_blart.py",
    "monitor",
    "--interval", $Interval.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "--max-rows", $MaxRows.ToString([System.Globalization.CultureInfo]::InvariantCulture),
    "--policy", $ResolvedPolicy,
    "--workdir", $ResolvedWorkdir
)
$Title = "Monitor (Dry Run)"
if ($Remote) {
    $MonitorArgs += @("--remote", $Remote)
    $Title = "Remote $Remote"
}
if ($Execute) {
    $MonitorArgs += "--execute"
    $Title = "Monitor (Execute)"
}

function ConvertTo-PowerShellSingleQuotedArgument {
    param([string]$Value)
    return "'" + ($Value -replace "'", "''") + "'"
}

$RelativePython = ".\.venv\Scripts\python.exe"
$MonitorCommand = "& " + (ConvertTo-PowerShellSingleQuotedArgument $RelativePython) + " " + (($MonitorArgs | ForEach-Object { ConvertTo-PowerShellSingleQuotedArgument $_ }) -join " ")
$AlertsCommand = "& " + (ConvertTo-PowerShellSingleQuotedArgument $RelativePython) + " 'proc_blart.py' 'tail' '--log' 'alerts' '--workdir' " + (ConvertTo-PowerShellSingleQuotedArgument $ResolvedWorkdir)
$ActionsCommand = "& " + (ConvertTo-PowerShellSingleQuotedArgument $RelativePython) + " 'proc_blart.py' 'tail' '--log' 'actions' '--workdir' " + (ConvertTo-PowerShellSingleQuotedArgument $ResolvedWorkdir)

if ((-not $CurrentTerminal) -and (Get-Command wt -ErrorAction SilentlyContinue)) {
    $WtArgs = @(
        "new-tab", "--title", $Title, "--startingDirectory", $Root,
        "powershell", "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $MonitorCommand,
        ";", "split-pane", "-H", "--title", "Alerts", "--startingDirectory", $Root,
        "powershell", "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $AlertsCommand,
        ";", "split-pane", "-V", "--title", "Actions", "--startingDirectory", $Root,
        "powershell", "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $ActionsCommand
    )
    & wt @WtArgs
    exit $LASTEXITCODE
}

& $PythonPath @MonitorArgs
exit $LASTEXITCODE
