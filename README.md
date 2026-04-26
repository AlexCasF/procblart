# Proc Blart TUI

A Windows-focused process monitor with a terminal UI, policy-based alerts, and optional VirusTotal reputation checks.

## Features

- Shows live process name, PID, CPU %, memory usage, executable path, policy status, and VirusTotal status
- Calculates SHA-256 hashes for executable files
- Looks up executable reputation with the VirusTotal API v3
- Applies editable rules from `policy.json`
- Writes alerts and actions as JSONL logs
- Runs in safe dry-run mode by default
- Freezes/resumes the live view with `Space`
- Can optionally kill, suspend, dump memory, and quarantine when started with `--execute`

## Install

From a fresh machine:

```powershell
irm https://raw.githubusercontent.com/AlexCasF/proc-blart/main/bootstrap.ps1 | iex
```

Safer review-first flow:

```powershell
curl.exe -L https://raw.githubusercontent.com/AlexCasF/proc-blart/main/bootstrap.ps1 -o bootstrap.ps1
notepad .\bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1
```

From a cloned repo:

```powershell
.\install.ps1
```

Manual install:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py -m pip install -e .
```

## VirusTotal API Key

Set the key in the same terminal before starting the monitor:

```powershell
$env:VIRUSTOTAL_API_KEY = "paste_key_here"
```

The app reads `VIRUSTOTAL_API_KEY` from the process environment.

To set it persistently for future terminal sessions:

```powershell
setx VIRUSTOTAL_API_KEY "paste_key_here"
```

After using `setx`, open a new terminal before starting the monitor. On Windows, `procblart` also checks persisted User and Machine environment variables if the current terminal has not inherited the key yet.

Keep your VirusTotal key private. Do not commit it or hard-code it into scripts. The default policy does not upload unknown files, and the default `rate_limit_seconds` value is `16`, which keeps lookups under the free public API limit of 4 requests per minute. Free public API access is for personal, non-commercial use.

## Run

Activate the virtual environment first:

```powershell
.\.venv\Scripts\Activate.ps1
```

Safe dry-run mode:

```powershell
procblart run -dry
```

Dry-run mode logs matching policy actions without killing, suspending, dumping, or quarantining processes.

Execute mode:

```powershell
procblart run -exec
```

Use execute mode only in a lab VM. Run from an elevated terminal if process-control actions need to work reliably.

Live controls:

- `Space`: freeze or resume the display
- `PageUp` / `PageDown`: scroll by one page
- `Up` / `Down`: scroll by one row
- `Home` / `End`: jump to the first or last row
- `s`: cycle sort order
- `r`: reverse the current sort

Read-only remote monitor for one Windows LAN host:

```powershell
procblart run -remote 192.168.1.25
```

Remote mode uses PowerShell CIM/WMI from the local machine, does not perform VirusTotal lookups, and does not kill, suspend, dump, or quarantine remote processes. The target must allow remote CIM/WinRM access for your account.

Typical remote requirements:

- The target computer has WinRM/CIM remote management enabled.
- Windows Firewall allows WinRM traffic from your management machine.
- Your account has permission to query CIM/WMI on the target.
- Domain/Kerberos works by name, or the host is configured appropriately for trusted-host/non-domain access.

You can also use the PowerShell launcher:

```powershell
.\launch.ps1
.\launch.ps1 -DryRun
.\launch.ps1 -Execute
.\launch.ps1 -Remote 192.168.1.25
```

Run the launcher in the current terminal instead of opening Windows Terminal panes:

```powershell
.\launch.ps1 -DryRun -CurrentTerminal
```

The launcher also accepts `-Policy`, `-Workdir`, `-Interval`, and `-MaxRows`.

## Scan a File

```powershell
procblart scan .\path\to\file.exe
```

Redirect scan output to save a JSON result:

```powershell
procblart scan .\path\to\file.exe > result.json
```

PowerShell launcher equivalent:

```powershell
.\launch.ps1 -ScanFile .\path\to\file.exe
```

## Logs

Default data folder:

```text
.\proc_blart_data\
```

Log files:

```text
proc_blart_data\logs\alerts.jsonl
proc_blart_data\logs\actions.jsonl
proc_blart_data\logs\virustotal.jsonl
proc_blart_data\logs\manual_scan.jsonl
```

Tail logs:

```powershell
procblart tail --log alerts
procblart tail --log actions
procblart tail --log virustotal
```

## Policy

Edit `policy.json` to change thresholds, rules, and actions.

Example rule:

```json
{
  "id": "memory-over-threshold",
  "description": "If RSS memory is over 500 MB, log a warning.",
  "when": { "memory_mb_gt": 500 },
  "actions": ["log_warning"]
}
```

Supported conditions:

- `process_name_equals`
- `memory_mb_gt`
- `vt_detections_gt`

Supported actions:

- `log_warning`
- `kill`
- `suspend`
- `dump_memory`
- `quarantine`

## ProcDump

Memory dumping requires Sysinternals ProcDump. Put `procdump.exe` next to this script, in `PATH`, or set the path in `policy.json`:

```json
"dump": {
  "procdump_path": "C:\\Tools\\ProcDump\\procdump.exe",
  "dump_folder": "dumps"
}
```
