#!/usr/bin/env python3
"""
Process Defender TUI
A small Windows-focused "process monitoring antivirus" school project.

Features:
- Live process table with PID, CPU, memory, executable path and VirusTotal status.
- SHA-256 based VirusTotal v3 file reputation lookup with local cache and rate limit.
- JSON policy rules for warnings and automated reactions.
- Dry-run mode by default. Use --execute only inside a lab VM.
- Optional ProcDump integration for memory dumps.

Install:
    py -m pip install -r requirements.txt

Run:
    set VIRUSTOTAL_API_KEY=your_key_here
    py process_defender.py monitor

Dangerous actions are simulated by default. To actually kill/suspend/quarantine:
    py process_defender.py monitor --execute

This is educational code, not production EDR software.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil
import requests
from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

APP_NAME = "Process Defender TUI"
DEFAULT_WORKDIR = Path.cwd() / "defender_data"
VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
MB = 1024 * 1024


DEFAULT_POLICY: dict[str, Any] = {
    "memory_warning_mb": 500,
    "vt_detection_threshold": 3,
    "kill_process_names": ["virus.exe"],
    "protected_process_names": [
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "winlogon.exe",
        "explorer.exe",
        "dwm.exe",
    ],
    "allow_quarantine_from_system_dirs": False,
    "system_dir_prefixes": [
        "%WINDIR%",
        "%PROGRAMFILES%",
        "%PROGRAMFILES(X86)%",
    ],
    "rules": [
        {
            "id": "name-virus-exe",
            "description": "If the process is named virus.exe, kill it and quarantine the executable.",
            "when": {"process_name_equals": "virus.exe"},
            "actions": ["kill", "quarantine"],
        },
        {
            "id": "vt-detections-over-threshold",
            "description": "If VirusTotal has more than 3 malicious/suspicious detections, suspend, dump, and quarantine.",
            "when": {"vt_detections_gt": 3},
            "actions": ["suspend", "dump_memory", "quarantine"],
        },
        {
            "id": "memory-over-threshold",
            "description": "If RSS memory is over 500 MB, log a warning.",
            "when": {"memory_mb_gt": 500},
            "actions": ["log_warning"],
        },
    ],
    "virustotal": {
        "enabled": True,
        "rate_limit_seconds": 16,
        "cache_ttl_hours": 24 * 7,
        "upload_unknown_files": False,
        "max_upload_mb": 32,
        "max_new_paths_per_cycle": 4,
    },
    "dump": {
        "procdump_path": "procdump.exe",
        "dump_folder": "dumps",
    },
    "quarantine": {
        "folder": "quarantine",
    },
}


@dataclass
class VTResult:
    status: str = "pending"  # disabled, queued, pending, clean, suspicious, malicious, unknown, submitted, error
    sha256: str | None = None
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    message: str = ""
    checked_at: str | None = None

    @property
    def detections(self) -> int:
        return int(self.malicious) + int(self.suspicious)

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "sha256": self.sha256,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "message": self.message,
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "VTResult":
        return cls(
            status=data.get("status", "unknown"),
            sha256=data.get("sha256"),
            malicious=int(data.get("malicious", 0) or 0),
            suspicious=int(data.get("suspicious", 0) or 0),
            harmless=int(data.get("harmless", 0) or 0),
            undetected=int(data.get("undetected", 0) or 0),
            message=data.get("message", ""),
            checked_at=data.get("checked_at"),
        )


@dataclass
class ProcessRow:
    pid: int
    name: str
    username: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    exe: str = ""
    vt: VTResult = field(default_factory=VTResult)
    policy_hits: list[str] = field(default_factory=list)


class JsonlLog:
    def __init__(self, path: Path, max_recent: int = 200) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.recent: deque[dict[str, Any]] = deque(maxlen=max_recent)
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        event = {"ts": utc_now(), **event}
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            self.recent.append(event)


class VirusTotalClient:
    def __init__(
        self,
        api_key: str | None,
        cache_path: Path,
        rate_limit_seconds: float,
        cache_ttl_hours: float,
        upload_unknown_files: bool,
        max_upload_mb: int,
        log: JsonlLog,
    ) -> None:
        self.api_key = api_key
        self.cache_path = cache_path
        self.rate_limit_seconds = rate_limit_seconds
        self.cache_ttl_seconds = cache_ttl_hours * 3600
        self.upload_unknown_files = upload_unknown_files
        self.max_upload_mb = max_upload_mb
        self.log = log
        self._last_request = 0.0
        self._lock = threading.Lock()
        self.cache: dict[str, dict[str, Any]] = self._load_cache()

    def _load_cache(self) -> dict[str, dict[str, Any]]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")
        tmp.replace(self.cache_path)

    def lookup_path(self, path: str) -> VTResult:
        if not self.api_key:
            return VTResult(status="disabled", message="No VIRUSTOTAL_API_KEY set")

        p = Path(path)
        if not p.exists() or not p.is_file():
            return VTResult(status="unknown", message="Executable path not accessible")

        try:
            sha256 = sha256_file(p)
        except Exception as e:
            return VTResult(status="error", message=f"Hash failed: {e}")

        cached = self._cache_get(sha256)
        if cached:
            return cached

        result = self._get_file_report(sha256)
        if result.status == "unknown" and self.upload_unknown_files:
            result = self._upload_file_for_analysis(p, sha256)

        self._cache_set(sha256, result)
        return result

    def _cache_get(self, sha256: str) -> VTResult | None:
        entry = self.cache.get(sha256)
        if not entry:
            return None
        ts = float(entry.get("_epoch", 0))
        if time.time() - ts > self.cache_ttl_seconds:
            return None
        return VTResult.from_json(entry["result"])

    def _cache_set(self, sha256: str, result: VTResult) -> None:
        result.sha256 = sha256
        self.cache[sha256] = {"_epoch": time.time(), "result": result.to_json()}
        try:
            self._save_cache()
        except Exception as e:
            self.log.write({"type": "cache_error", "message": str(e)})

    def _request_rate_limited(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        with self._lock:
            elapsed = time.time() - self._last_request
            wait_for = self.rate_limit_seconds - elapsed
            if wait_for > 0:
                time.sleep(wait_for)
            headers = kwargs.pop("headers", {})
            headers["x-apikey"] = self.api_key or ""
            response = requests.request(method, url, headers=headers, timeout=30, **kwargs)
            self._last_request = time.time()
            return response

    def _get_file_report(self, sha256: str) -> VTResult:
        url = VT_FILE_REPORT_URL.format(sha256=sha256)
        try:
            r = self._request_rate_limited("GET", url)
            if r.status_code == 404:
                return VTResult(status="unknown", sha256=sha256, message="Hash not found in VirusTotal")
            if r.status_code == 429:
                return VTResult(status="error", sha256=sha256, message="VirusTotal rate limit reached")
            r.raise_for_status()
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)
            detections = malicious + suspicious
            if detections > 0:
                status = "malicious" if malicious > 0 else "suspicious"
            else:
                status = "clean"
            return VTResult(
                status=status,
                sha256=sha256,
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                checked_at=utc_now(),
            )
        except Exception as e:
            return VTResult(status="error", sha256=sha256, message=str(e), checked_at=utc_now())

    def _upload_file_for_analysis(self, path: Path, sha256: str) -> VTResult:
        try:
            size_mb = path.stat().st_size / MB
            if size_mb > self.max_upload_mb:
                return VTResult(
                    status="unknown",
                    sha256=sha256,
                    message=f"Unknown hash; file too large to upload ({size_mb:.1f} MB)",
                    checked_at=utc_now(),
                )
            with path.open("rb") as f:
                files = {"file": (path.name, f)}
                r = self._request_rate_limited("POST", VT_UPLOAD_URL, files=files)
            if r.status_code == 429:
                return VTResult(status="error", sha256=sha256, message="VirusTotal rate limit reached")
            r.raise_for_status()
            analysis_id = r.json().get("data", {}).get("id", "")
            return VTResult(
                status="submitted",
                sha256=sha256,
                message=f"Submitted to VirusTotal; analysis id: {analysis_id}",
                checked_at=utc_now(),
            )
        except Exception as e:
            return VTResult(status="error", sha256=sha256, message=f"Upload failed: {e}", checked_at=utc_now())


class VTScanner(threading.Thread):
    def __init__(self, client: VirusTotalClient, log: JsonlLog) -> None:
        super().__init__(daemon=True)
        self.client = client
        self.log = log
        self.q: queue.Queue[str] = queue.Queue()
        self.results_by_path: dict[str, VTResult] = {}
        self.queued: set[str] = set()
        self.running = True
        self.scanned_count = 0
        self.error_count = 0
        self._lock = threading.Lock()

    def submit(self, path: str) -> None:
        if not path:
            return
        normalized = str(Path(path))
        with self._lock:
            if normalized in self.queued or normalized in self.results_by_path:
                return
            self.queued.add(normalized)
        self.q.put(normalized)

    def get_result(self, path: str) -> VTResult:
        if not path:
            return VTResult(status="unknown", message="No executable path")
        normalized = str(Path(path))
        with self._lock:
            return self.results_by_path.get(normalized, VTResult(status="queued"))

    def run(self) -> None:
        while self.running:
            try:
                path = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            result = self.client.lookup_path(path)
            with self._lock:
                self.results_by_path[path] = result
            self.scanned_count += 1
            if result.status == "error":
                self.error_count += 1
            self.log.write(
                {
                    "type": "vt_result",
                    "path": path,
                    "status": result.status,
                    "sha256": result.sha256,
                    "detections": result.detections,
                    "malicious": result.malicious,
                    "suspicious": result.suspicious,
                    "message": result.message,
                }
            )

    @property
    def queue_size(self) -> int:
        return self.q.qsize()


class PolicyEngine:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self.rules = policy.get("rules", [])
        self.protected_names = {n.lower() for n in policy.get("protected_process_names", [])}
        self.system_prefixes = [
            expand_env_vars(p).lower()
            for p in policy.get("system_dir_prefixes", [])
            if expand_env_vars(p)
        ]

    def evaluate(self, row: ProcessRow) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for rule in self.rules:
            if self._matches(rule.get("when", {}), row):
                hits.append(rule)
        return hits

    def _matches(self, condition: dict[str, Any], row: ProcessRow) -> bool:
        if "process_name_equals" in condition:
            if row.name.lower() != str(condition["process_name_equals"]).lower():
                return False
        if "memory_mb_gt" in condition:
            if row.memory_mb <= float(condition["memory_mb_gt"]):
                return False
        if "vt_detections_gt" in condition:
            if row.vt.detections <= int(condition["vt_detections_gt"]):
                return False
        return True

    def is_protected(self, row: ProcessRow) -> tuple[bool, str]:
        if row.name.lower() in self.protected_names:
            return True, f"protected process name: {row.name}"
        if not self.policy.get("allow_quarantine_from_system_dirs", False) and row.exe:
            exe_l = row.exe.lower()
            for prefix in self.system_prefixes:
                if prefix and exe_l.startswith(prefix):
                    return True, f"protected system path: {prefix}"
        return False, ""


class Responder:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        workdir: Path,
        policy: dict[str, Any],
        alert_log: JsonlLog,
        action_log: JsonlLog,
        execute: bool,
    ) -> None:
        self.policy_engine = policy_engine
        self.workdir = workdir
        self.policy = policy
        self.alert_log = alert_log
        self.action_log = action_log
        self.execute = execute
        self.acted: set[str] = set()

        quarantine_folder = policy.get("quarantine", {}).get("folder", "quarantine")
        dump_folder = policy.get("dump", {}).get("dump_folder", "dumps")
        self.quarantine_dir = (workdir / quarantine_folder).resolve()
        self.dump_dir = (workdir / dump_folder).resolve()
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.dump_dir.mkdir(parents=True, exist_ok=True)

    def apply(self, proc: psutil.Process, row: ProcessRow, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            rule_id = str(rule.get("id", "unnamed-rule"))
            action_key = f"{rule_id}:{row.pid}:{row.exe}:{row.vt.sha256}:{int(row.memory_mb)}"
            if action_key in self.acted:
                continue
            self.acted.add(action_key)

            actions = [str(a) for a in rule.get("actions", [])]
            self.alert_log.write(
                {
                    "type": "policy_hit",
                    "rule_id": rule_id,
                    "description": rule.get("description", ""),
                    "pid": row.pid,
                    "name": row.name,
                    "exe": row.exe,
                    "memory_mb": round(row.memory_mb, 1),
                    "vt_status": row.vt.status,
                    "vt_detections": row.vt.detections,
                    "actions": actions,
                    "mode": "execute" if self.execute else "dry_run",
                }
            )

            for action in actions:
                self._run_action(action, proc, row, rule_id)

    def _run_action(self, action: str, proc: psutil.Process, row: ProcessRow, rule_id: str) -> None:
        protected, reason = self.policy_engine.is_protected(row)
        destructive = action in {"kill", "suspend", "quarantine"}
        if protected and destructive:
            self._record_action(action, row, rule_id, "skipped", reason)
            return

        if action == "log_warning":
            self._record_action(action, row, rule_id, "logged", f"Memory usage {row.memory_mb:.1f} MB")
            return

        if not self.execute:
            self._record_action(action, row, rule_id, "dry_run", "Use --execute to perform this action")
            return

        try:
            if action == "kill":
                proc.kill()
                self._record_action(action, row, rule_id, "ok", "Process killed")
            elif action == "suspend":
                proc.suspend()
                self._record_action(action, row, rule_id, "ok", "Process suspended")
            elif action == "dump_memory":
                dump_path = self._dump_memory(row)
                self._record_action(action, row, rule_id, "ok", f"Dump written/requested: {dump_path}")
            elif action == "quarantine":
                quarantine_path = self._quarantine(row)
                self._record_action(action, row, rule_id, "ok", f"Moved to: {quarantine_path}")
            else:
                self._record_action(action, row, rule_id, "unknown_action", "No handler for this action")
        except Exception as e:
            self._record_action(action, row, rule_id, "error", str(e))

    def _dump_memory(self, row: ProcessRow) -> Path:
        procdump = self.policy.get("dump", {}).get("procdump_path", "procdump.exe")
        safe_name = sanitize_filename(row.name)
        out_path = self.dump_dir / f"{safe_name}_{row.pid}_{timestamp_for_filename()}.dmp"

        cmd = [
            procdump,
            "-accepteula",
            "-ma",
            str(row.pid),
            str(out_path),
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120)
        return out_path

    def _quarantine(self, row: ProcessRow) -> Path:
        if not row.exe:
            raise RuntimeError("No executable path available")
        src = Path(row.exe)
        if not src.exists():
            raise RuntimeError("Executable path does not exist or is not accessible")

        # Moving a running Windows executable often fails because the image is locked.
        # In a real EDR, quarantine is usually staged: stop process -> move/rename -> write metadata.
        sha = row.vt.sha256 or sha256_file(src)
        dest = self.quarantine_dir / f"{sha[:16]}_{sanitize_filename(src.name)}"
        meta = self.quarantine_dir / f"{dest.name}.json"

        if dest.exists():
            raise RuntimeError(f"Quarantine destination already exists: {dest}")

        shutil.move(str(src), str(dest))
        meta.write_text(
            json.dumps(
                {
                    "original_path": str(src),
                    "quarantine_path": str(dest),
                    "pid": row.pid,
                    "process_name": row.name,
                    "sha256": sha,
                    "vt": row.vt.to_json(),
                    "ts": utc_now(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return dest

    def _record_action(self, action: str, row: ProcessRow, rule_id: str, result: str, detail: str) -> None:
        self.action_log.write(
            {
                "type": "action",
                "rule_id": rule_id,
                "action": action,
                "result": result,
                "detail": detail,
                "pid": row.pid,
                "name": row.name,
                "exe": row.exe,
                "vt_status": row.vt.status,
                "vt_detections": row.vt.detections,
            }
        )


class ProcessMonitorApp:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.console = Console()
        self.workdir: Path = args.workdir.resolve()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.policy = load_policy(args.policy)
        self.policy_engine = PolicyEngine(self.policy)

        self.alert_log = JsonlLog(self.workdir / "logs" / "alerts.jsonl")
        self.action_log = JsonlLog(self.workdir / "logs" / "actions.jsonl")
        self.vt_log = JsonlLog(self.workdir / "logs" / "virustotal.jsonl")

        vt_cfg = self.policy.get("virustotal", {})
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.vt_client = VirusTotalClient(
            api_key=api_key,
            cache_path=self.workdir / "cache" / "vt_cache.json",
            rate_limit_seconds=float(vt_cfg.get("rate_limit_seconds", 16)),
            cache_ttl_hours=float(vt_cfg.get("cache_ttl_hours", 24 * 7)),
            upload_unknown_files=bool(vt_cfg.get("upload_unknown_files", False)),
            max_upload_mb=int(vt_cfg.get("max_upload_mb", 32)),
            log=self.vt_log,
        )
        self.vt_scanner = VTScanner(self.vt_client, self.vt_log)
        self.responder = Responder(
            policy_engine=self.policy_engine,
            workdir=self.workdir,
            policy=self.policy,
            alert_log=self.alert_log,
            action_log=self.action_log,
            execute=args.execute,
        )
        self.rows: list[ProcessRow] = []
        self.start_time = time.time()
        self.max_new_paths_per_cycle = int(vt_cfg.get("max_new_paths_per_cycle", 4))

    def run(self) -> None:
        self.alert_log.write({"type": "startup", "mode": "execute" if self.args.execute else "dry_run"})
        self.vt_scanner.start()

        # Prime per-process CPU counters. First cpu_percent(None) call is usually 0.0.
        for p in psutil.process_iter(["pid"]):
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass

        with Live(self._render(), console=self.console, refresh_per_second=2, screen=True) as live:
            while True:
                self.rows = self._collect_processes()
                live.update(self._render())
                time.sleep(float(self.args.interval))

    def _collect_processes(self) -> list[ProcessRow]:
        rows: list[ProcessRow] = []
        submitted_this_cycle = 0

        for proc in psutil.process_iter(["pid", "name", "username", "exe"]):
            try:
                with proc.oneshot():
                    pid = proc.pid
                    name = proc.name() or ""
                    username = proc.username() or ""
                    exe = proc.exe() or ""
                    cpu = proc.cpu_percent(interval=None)
                    mem = proc.memory_info().rss / MB
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

            if exe and submitted_this_cycle < self.max_new_paths_per_cycle:
                self.vt_scanner.submit(exe)
                submitted_this_cycle += 1

            vt_result = self.vt_scanner.get_result(exe)
            row = ProcessRow(
                pid=pid,
                name=name,
                username=username,
                cpu_percent=cpu,
                memory_mb=mem,
                exe=exe,
                vt=vt_result,
            )
            rules = self.policy_engine.evaluate(row)
            if rules:
                row.policy_hits = [str(r.get("id", "unnamed-rule")) for r in rules]
                try:
                    self.responder.apply(proc, row, rules)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            rows.append(row)

        rows.sort(key=lambda r: (r.vt.detections, r.memory_mb, r.cpu_percent), reverse=True)
        return rows

    def _render(self) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(self._header(), size=3),
            Layout(name="main", ratio=1),
            Layout(self._footer(), size=3),
        )
        layout["main"].split_row(
            Layout(self._process_table(), ratio=3),
            Layout(name="side", ratio=2),
        )
        layout["side"].split_column(
            Layout(self._vt_panel(), ratio=1),
            Layout(self._alerts_panel(), ratio=1),
            Layout(self._actions_panel(), ratio=1),
        )
        return layout

    def _header(self) -> Panel:
        mode = "[bold red]EXECUTE[/bold red]" if self.args.execute else "[bold yellow]DRY RUN[/bold yellow]"
        api = "[green]enabled[/green]" if os.getenv("VIRUSTOTAL_API_KEY") else "[red]missing key[/red]"
        uptime = int(time.time() - self.start_time)
        text = (
            f"[bold]{APP_NAME}[/bold] | mode: {mode} | VT: {api} | "
            f"queue: {self.vt_scanner.queue_size} | uptime: {uptime}s | Ctrl+C to exit"
        )
        return Panel(Align.left(text), box=box.SIMPLE)

    def _footer(self) -> Panel:
        return Panel(
            "Policy is loaded from policy.json. Logs: "
            f"{self.workdir / 'logs' / 'alerts.jsonl'} and {self.workdir / 'logs' / 'actions.jsonl'}",
            box=box.SIMPLE,
        )

    def _process_table(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("PID", justify="right", no_wrap=True)
        table.add_column("Name", overflow="fold")
        table.add_column("CPU %", justify="right")
        table.add_column("Mem MB", justify="right")
        table.add_column("VT", justify="center")
        table.add_column("Det", justify="right")
        table.add_column("Policy")
        table.add_column("Executable", overflow="fold")

        for row in self.rows[: self.args.max_rows]:
            style = ""
            if row.vt.detections > int(self.policy.get("vt_detection_threshold", 3)):
                style = "bold red"
            elif row.policy_hits:
                style = "yellow"
            elif row.vt.status == "clean":
                style = "green"

            table.add_row(
                str(row.pid),
                row.name,
                f"{row.cpu_percent:.1f}",
                f"{row.memory_mb:.1f}",
                self._format_vt(row.vt),
                str(row.vt.detections),
                ",".join(row.policy_hits),
                row.exe,
                style=style,
            )

        return Panel(table, title="Live processes", border_style="cyan")

    def _vt_panel(self) -> Panel:
        lines = [
            f"Scanned: {self.vt_scanner.scanned_count}",
            f"Errors: {self.vt_scanner.error_count}",
            f"Queue: {self.vt_scanner.queue_size}",
            f"Cache entries: {len(self.vt_client.cache)}",
            f"Upload unknown files: {self.policy.get('virustotal', {}).get('upload_unknown_files', False)}",
        ]
        recent = list(self.vt_log.recent)[-5:]
        if recent:
            lines.append("")
            lines.append("[bold]Recent VT results[/bold]")
            for ev in recent:
                if ev.get("type") == "vt_result":
                    name = Path(str(ev.get("path", ""))).name
                    lines.append(f"{name}: {ev.get('status')} det={ev.get('detections')}")
        return Panel("\n".join(lines), title="VirusTotal", border_style="magenta")

    def _alerts_panel(self) -> Panel:
        return Panel(self._recent_events_text(self.alert_log.recent), title="Alerts", border_style="yellow")

    def _actions_panel(self) -> Panel:
        return Panel(self._recent_events_text(self.action_log.recent), title="Actions", border_style="red")

    def _recent_events_text(self, events: deque[dict[str, Any]]) -> Text:
        text = Text()
        recent = list(events)[-8:]
        if not recent:
            text.append("No events yet.")
            return text
        for ev in recent:
            ts = str(ev.get("ts", ""))[11:19]
            if ev.get("type") == "policy_hit":
                text.append(f"{ts} HIT {ev.get('rule_id')} pid={ev.get('pid')} {ev.get('name')}\n", style="yellow")
            elif ev.get("type") == "action":
                style = "green" if ev.get("result") in {"ok", "logged"} else "red" if ev.get("result") == "error" else "yellow"
                text.append(
                    f"{ts} {ev.get('action')} {ev.get('result')} pid={ev.get('pid')} {ev.get('name')}\n",
                    style=style,
                )
            else:
                text.append(f"{ts} {ev.get('type')} {ev.get('message','')}\n")
        return text

    @staticmethod
    def _format_vt(vt: VTResult) -> str:
        if vt.status == "clean":
            return "[green]clean[/green]"
        if vt.status in {"malicious", "suspicious"}:
            return "[red]bad[/red]"
        if vt.status == "submitted":
            return "[blue]submitted[/blue]"
        if vt.status == "queued":
            return "[dim]queued[/dim]"
        if vt.status == "disabled":
            return "[dim]disabled[/dim]"
        if vt.status == "error":
            return "[red]error[/red]"
        return "[dim]unknown[/dim]"


def tail_log(path: Path, interval: float = 0.5) -> None:
    console = Console()
    console.print(f"[bold]Tailing[/bold] {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with path.open("r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(interval)
                continue
            try:
                obj = json.loads(line)
                console.print_json(json.dumps(obj))
            except Exception:
                console.print(line.rstrip())


def scan_file_once(path: Path, policy_path: Path | None, workdir: Path) -> None:
    console = Console()
    policy = load_policy(policy_path)
    log = JsonlLog(workdir / "logs" / "manual_scan.jsonl")
    vt_cfg = policy.get("virustotal", {})
    client = VirusTotalClient(
        api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        cache_path=workdir / "cache" / "vt_cache.json",
        rate_limit_seconds=float(vt_cfg.get("rate_limit_seconds", 16)),
        cache_ttl_hours=float(vt_cfg.get("cache_ttl_hours", 24 * 7)),
        upload_unknown_files=bool(vt_cfg.get("upload_unknown_files", False)),
        max_upload_mb=int(vt_cfg.get("max_upload_mb", 32)),
        log=log,
    )
    result = client.lookup_path(str(path))
    table = Table(title=f"VirusTotal scan: {path.name}", box=box.SIMPLE_HEAVY)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Status", result.status)
    table.add_row("SHA-256", result.sha256 or "")
    table.add_row("Malicious", str(result.malicious))
    table.add_row("Suspicious", str(result.suspicious))
    table.add_row("Harmless", str(result.harmless))
    table.add_row("Undetected", str(result.undetected))
    table.add_row("Message", result.message)
    console.print(table)


def write_default_policy(path: Path) -> None:
    path.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
    print(f"Wrote default policy to {path}")


def write_pymux_note(path: Path) -> None:
    # Pymux's own README says better scripting support is still a future idea.
    # This note is intentionally conservative. The app itself provides panes using Rich.
    content = """# pymux integration note

# This project is designed so that the core monitor is not dependent on pymux.
# The reliable school-demo mode is:
#
#     py process_defender.py monitor
#
# That command draws a multi-pane TUI with Rich inside a single terminal.
#
# You can still use pymux manually as a wrapper:
#
#     pymux
#     py process_defender.py monitor
#
# Then open another pane and tail logs:
#
#     py process_defender.py tail --log alerts
#     py process_defender.py tail --log actions
#
# I do not recommend making pymux a hard dependency on Windows because the
# published package is old and its own README describes scripting support as incomplete.
"""
    path.write_text(content, encoding="utf-8")
    print(f"Wrote pymux note to {path}")


def load_policy(path: Path | None) -> dict[str, Any]:
    if not path:
        return DEFAULT_POLICY
    if not path.exists():
        return DEFAULT_POLICY
    loaded = json.loads(path.read_text(encoding="utf-8"))
    # shallow merge: user file overrides top-level keys
    merged = dict(DEFAULT_POLICY)
    merged.update(loaded)
    return merged


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def expand_env_vars(s: str) -> str:
    return os.path.expandvars(s)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def timestamp_for_filename() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:120]


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=APP_NAME)
    sub = parser.add_subparsers(dest="command", required=True)

    monitor = sub.add_parser("monitor", help="Run live process monitor TUI")
    monitor.add_argument("--interval", type=float, default=2.0, help="Refresh interval in seconds")
    monitor.add_argument("--max-rows", type=int, default=30, help="Max process rows to display")
    monitor.add_argument("--policy", type=Path, default=Path("policy.json"), help="Path to policy JSON")
    monitor.add_argument("--workdir", type=Path, default=DEFAULT_WORKDIR, help="Data folder for logs/cache/dumps/quarantine")
    monitor.add_argument("--execute", action="store_true", help="Actually perform kill/suspend/quarantine actions")

    scan = sub.add_parser("scan-file", help="Scan one file with VirusTotal hash lookup/upload policy")
    scan.add_argument("path", type=Path)
    scan.add_argument("--policy", type=Path, default=Path("policy.json"))
    scan.add_argument("--workdir", type=Path, default=DEFAULT_WORKDIR)

    tail = sub.add_parser("tail", help="Tail JSONL logs")
    tail.add_argument("--workdir", type=Path, default=DEFAULT_WORKDIR)
    tail.add_argument("--log", choices=["alerts", "actions", "virustotal", "manual_scan"], default="alerts")

    sub.add_parser("write-default-policy", help="Write default policy.json")
    sub.add_parser("write-pymux-note", help="Write conservative pymux integration note")

    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    if args.command == "write-default-policy":
        write_default_policy(Path("policy.json"))
        return 0

    if args.command == "write-pymux-note":
        write_pymux_note(Path("pymux-notes.conf"))
        return 0

    if args.command == "tail":
        log_path = args.workdir / "logs" / f"{args.log}.jsonl"
        tail_log(log_path)
        return 0

    if args.command == "scan-file":
        scan_file_once(args.path, args.policy if args.policy.exists() else None, args.workdir)
        return 0

    if args.command == "monitor":
        if args.execute and not is_admin():
            Console().print(
                "[bold red]Warning:[/bold red] --execute was requested but this terminal is probably not elevated. "
                "Some actions may fail."
            )
            time.sleep(2)
        app = ProcessMonitorApp(args)
        app.run()
        return 0

    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nStopped.")
