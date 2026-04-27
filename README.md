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

Windows:

```powershell
irm https://raw.githubusercontent.com/AlexCasF/procblart/main/scripts/bootstrap.ps1 | iex
```

macOS, Linux, or WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/AlexCasF/procblart/main/scripts/bootstrap.sh | bash
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
cd $HOME\procblart
.\.venv\Scripts\Activate.ps1
```

Safe dry-run mode:

```powershell
procblart run -dry
```

Without activation on Windows:

```powershell
cd $HOME\procblart
.\procblart.cmd run -dry
```

Or from anywhere:

```powershell
& "$HOME\procblart\.venv\Scripts\procblart.exe" run -dry
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
procblart run --remote-ssh username@192.168.1.25
```

Remote mode does not kill, suspend, dump, or quarantine remote processes.

`-remote` uses PowerShell CIM/WMI from the local machine. By default it tries WinRM/WSMan first and then DCOM/WMI as a fallback. Remote VirusTotal support is hash-lookup only: Proc Blart computes SHA-256 on the target and queries VirusTotal from the local machine. That requires WinRM/WSMan access even if process inventory falls back to DCOM/WMI. You can force one transport while troubleshooting:

```powershell
procblart run -remote 192.168.1.25 --remote-transport wsman
procblart run -remote 192.168.1.25 --remote-transport dcom
```

The target must allow remote CIM/WMI access for your account.

Typical remote requirements:

- The target computer has WinRM/CIM remote management enabled.
- Windows Firewall allows WinRM traffic from your management machine.
- Your account has permission to query CIM/WMI on the target.
- Domain/Kerberos works by name, or the host is configured appropriately for trusted-host/non-domain access.

Useful setup and checks for a lab LAN:

```powershell
# On the target, from elevated PowerShell:
Enable-PSRemoting -Force

# On the Proc Blart computer, from elevated PowerShell, for workgroup/IP WinRM:
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.25" -Concatenate -Force
Test-WSMan 192.168.1.25

# If using the DCOM/WMI fallback, enable the target firewall group:
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
```

`--remote-ssh` uses your local `ssh` client to run read-only PowerShell queries on the target. The target needs OpenSSH Server enabled and reachable. For a live TUI, SSH keys or ssh-agent are recommended so every refresh can connect without a password prompt. See [SSH Agent Setup](docs/ssh-agent-setup.md).

You can also use the PowerShell launcher:

```powershell
.\scripts\launch.ps1
.\scripts\launch.ps1 -DryRun
.\scripts\launch.ps1 -Execute
.\scripts\launch.ps1 -Remote 192.168.1.25
.\scripts\launch.ps1 -Remote 192.168.1.25 -RemoteTransport dcom
.\scripts\launch.ps1 -RemoteSsh username@192.168.1.25
```

Run the launcher in the current terminal instead of opening Windows Terminal panes:

```powershell
.\scripts\launch.ps1 -DryRun -CurrentTerminal
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
.\scripts\launch.ps1 -ScanFile .\path\to\file.exe
```

## Logs

Default data folder:

```text
.\procblart_data\
```

Log files:

```text
procblart_data\logs\alerts.jsonl
procblart_data\logs\actions.jsonl
procblart_data\logs\virustotal.jsonl
procblart_data\logs\manual_scan.jsonl
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
