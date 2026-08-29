"""Xray-core process management: spawn, monitor, capture stderr, restart."""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

from app.logger import get_logger
from app.metrics import default_metrics
from app.security import safe_subprocess_args

logger = get_logger()


class XrayProcess:
    """Manage the lifecycle of an xray-core process."""

    def __init__(self, config_path: str | Path, binary: str = "xray", timeout: float = 30.0):
        self.config_path = Path(config_path)
        self.binary = binary
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._stderr_lines: list[str] = []
        self._lock = threading.Lock()
        self._running = False

    def spawn(self) -> subprocess.Popen:
        """Spawn the xray process and capture stderr."""
        args = safe_subprocess_args([self.binary, "run", "-c", str(self.config_path)])
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._running = True
        # Drain stderr in a background thread so we capture crash logs.
        threading.Thread(target=self._read_stderr, daemon=True).start()
        return self.proc

    def _read_stderr(self) -> None:
        assert self.proc is not None
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            with self._lock:
                self._stderr_lines.append(line.rstrip("\n"))
        self._running = False

    def wait_ready(self, health_check: Callable[[], bool] | None = None, interval: float = 0.5) -> bool:
        """Wait until the process is alive (and optionally healthy)."""
        elapsed = 0.0
        while elapsed < self.timeout:
            if self.proc and self.proc.poll() is not None:
                # Process already exited — capture reason.
                self._collect_logs()
                return False
            if health_check is None or health_check():
                return True
            time.sleep(interval)
            elapsed += interval
        return False

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _collect_logs(self) -> list[str]:
        with self._lock:
            return list(self._stderr_lines)

    def diagnose_failure(self) -> dict[str, Any]:
        """Collect logs and diagnose why the process exited."""
        logs = self._collect_logs()
        exit_code = self.proc.returncode if self.proc else None
        return {
            "exit_code": exit_code,
            "stderr": logs[-50:],
            "config_path": str(self.config_path),
        }

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._running = False
        self._collect_logs()


class XrayManager:
    """High-level manager: start, health-check, auto-restart with backoff."""

    def __init__(self, config_path: str | Path, binary: str = "xray", max_restarts: int = 3):
        self.config_path = config_path
        self.binary = binary
        self.max_restarts = max_restarts
        self._process: XrayProcess | None = None

    def start(self, health_check: Callable[[], bool] | None = None) -> dict[str, Any]:
        """Start xray; if it crashes, collect logs, validate config, stop retrying."""
        backoffs = [0.5, 1.0, 2.0]
        for attempt in range(self.max_restarts):
            proc = XrayProcess(self.config_path, binary=self.binary)
            self._process = proc
            proc.spawn()
            logger.info("xray_spawn", details={"attempt": attempt + 1})
            if proc.wait_ready(health_check):
                return {"ok": True, "attempt": attempt + 1}
            # Crash — diagnose and stop retry loop.
            diag = proc.diagnose_failure()
            default_metrics.record_xray_restart()
            logger.error("xray_crash", details=diag)
            proc.stop()
            if attempt < self.max_restarts - 1:
                time.sleep(backoffs[min(attempt, len(backoffs) - 1)])
        return {"ok": False, "error": "xray failed to start after retries", "diagnostics": self._process.diagnose_failure()}

    def stop(self) -> None:
        if self._process:
            self._process.stop()
