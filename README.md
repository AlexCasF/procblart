# Process Defender TUI

A first-draft Python school project for a Windows process-monitoring antivirus.

## What it does

- Monitors live processes with `psutil`
- Shows process name, PID, CPU %, memory MB, executable path
- Calculates SHA-256 for executable files
- Looks up executable reputation via VirusTotal API v3
- Applies editable rules from `policy.json`
- Logs alerts and responder actions as JSONL
- Supports dry-run mode by default
- Can optionally kill, suspend, dump memory, and quarantine when started with `--execute`

## Install

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

Set your VirusTotal key:

```powershell
$env:VIRUSTOTAL_API_KEY = "paste_key_here"
```

For a persistent user-level variable:

```powershell
setx VIRUSTOTAL_API_KEY "paste_key_here"
```

## Run safely first

```powershell
py process_defender.py monitor
```

This is **dry-run** mode. It logs what it would do, but does not kill, suspend, dump, or quarantine.

## Execute mode inside a lab VM only

```powershell
py process_defender.py monitor --execute
```

Use an elevated terminal if you want process-control actions to work reliably.

## Test the VirusTotal scanner with EICAR

Download the EICAR test file from the official EICAR site, then run:

```powershell
py process_defender.py scan-file .\eicar.com.txt
```

This tests the scanner path. EICAR is useful for AV detection tests, but it is not a normal modern Windows process executable you can rely on for the live-process part.

## Logs

Default data folder:

```text
.\defender_data\
```

Important logs:

```text
defender_data\logs\alerts.jsonl
defender_data\logs\actions.jsonl
defender_data\logs\virustotal.jsonl
```

Tail logs:

```powershell
py process_defender.py tail --log alerts
py process_defender.py tail --log actions
py process_defender.py tail --log virustotal
```

## Policy changes

Edit `policy.json`.

Example rule:

```json
{
  "id": "memory-over-threshold",
  "description": "If RSS memory is over 500 MB, log a warning.",
  "when": { "memory_mb_gt": 500 },
  "actions": ["log_warning"]
}
```

Supported conditions in this draft:

- `process_name_equals`
- `memory_mb_gt`
- `vt_detections_gt`

Supported actions in this draft:

- `log_warning`
- `kill`
- `suspend`
- `dump_memory`
- `quarantine`

## ProcDump

Download Sysinternals ProcDump from Microsoft and either place `procdump.exe` next to this script / in PATH, or set the path in `policy.json`:

```json
"dump": {
  "procdump_path": "C:\\Tools\\ProcDump\\procdump.exe",
  "dump_folder": "dumps"
}
```

## Notes on pymux

The code is intentionally not hard-wired to pymux. The live UI already has process, VirusTotal, alert, and action panes inside a single terminal using Rich.

Reason: pymux is interesting but old, and its own project notes describe better scripting support as future work. You can still run the monitor inside pymux manually and use extra panes to tail logs.
