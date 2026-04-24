# Optional Windows Terminal pane launcher.
# This is more reliable on modern Windows than pymux.
# Run from the project folder after installing requirements.

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

wt `
  new-tab powershell -NoExit -Command "cd '$root'; .\.venv\Scripts\Activate.ps1; py process_defender.py monitor" `
  `; split-pane -H powershell -NoExit -Command "cd '$root'; .\.venv\Scripts\Activate.ps1; py process_defender.py tail --log alerts" `
  `; split-pane -V powershell -NoExit -Command "cd '$root'; .\.venv\Scripts\Activate.ps1; py process_defender.py tail --log actions"
