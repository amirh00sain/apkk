"""gui/backend.py — ConnectionController: testable core for the Flet GUI.

This module owns all xray/TUN lifecycle logic so the GUI layer (`main.py`) stays
a thin event-loop wrapper and the unit tests can mock every external dependency.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


class ConnectionController:
    """Owns the xray + TUN lifecycle for a single connection attempt.

    Public surface::

        ctrl = ConnectionController(config_path, binary_path, tun_cfg)
        result = ctrl.connect()          # blocks until ready or failed
        ctrl.disconnect()                # tear down
        ctrl.state -> "idle"|"connecting"|"connected"|"error"
    """

    def __init__(
        self,
        config_path: str | Path,
        binary_path: str | Path = "xray",
        tun_cfg: dict[str, Any] | None = None,
    ):
        self.config_path = Path(config_path)
        self.binary_path = Path(binary_path)
        self.tun_cfg = tun_cfg or {}
        self._state = "idle"
        self._state_lock = threading.Lock()
        self._xray_mgr: Any = None
        self._tun: Any = None
        self._stop_event = threading.Event()

    @property
    def state(self) -> str:
        with self._state_lock:
            return self._state

    def _set_state(self, new_state: str) -> None:
        with self._state_lock:
            self._state = new_state

    def connect(self) -> dict[str, Any]:
        """Bring up the full anti-DPI tunnel (DoH + Tor + Fragment + TUN).

        Returns a result dict::

            {"ok": True, "message": "...", "pid": 1234}
            {"ok": False, "error": "...", "diagnostics": {...}}
        """
        self._stop_event.clear()
        self._set_state("connecting")

        # Phase 1: validate the xray binary.
        binary_ok, binary_err = self._check_binary()
        if not binary_ok:
            self._set_state("error")
            return {"ok": False, "error": f"xray binary: {binary_err}"}

        # Phase 2: generate + write the config (DoH + Tor + Fragment).
        try:
            self._write_config()
        except Exception as exc:
            self._set_state("error")
            return {"ok": False, "error": f"config write failed: {exc}"}

        # Phase 3: smoke-test the config.
        smoke = self._smoke_test_config()
        if not smoke["ok"]:
            self._set_state("error")
            return smoke

        # Phase 4: open TUN (Linux only, requires CAP_NET_ADMIN).
        tun_result = self._open_tun()
        if not tun_result["ok"]:
            # TUN is best-effort — warn but continue with proxy-only mode.
            logger.warning("TUN open skipped", extra={"reason": tun_result.get("error")})

        # Phase 5: start xray.
        xray_result = self._start_xray()
        if not xray_result["ok"]:
            self._teardown()
            self._set_state("error")
            return xray_result

        self._set_state("connected")
        return {"ok": True, "message": "Connected (DoH + Fragment + Tor + TUN)", "pid": xray_result.get("pid")}

    def disconnect(self) -> dict[str, Any]:
        """Tear down everything."""
        self._stop_event.set()
        diag = self._teardown()
        self._set_state("idle")
        return {"ok": True, "message": "Disconnected", "diagnostics": diag}

    # -- private helpers -------------------------------------------------------

    def _check_binary(self) -> tuple[bool, str]:
        if not self.binary_path.exists() and not _which(str(self.binary_path)):
            return False, f"{self.binary_path} not found — run `python -m app update` or download from Xray-core releases"
        return True, ""

    def _write_config(self) -> None:
        from app.config_loader import load_config, load_dns_providers
        from app.xray.config import generate_xray_config

        cfg = load_config()
        doh = load_dns_providers()
        proxy: dict[str, Any] = {}
        if self.tun_cfg.get("tor", False):
            proxy["tor"] = True
            proxy["tor_socks_host"] = self.tun_cfg.get("tor_socks_host", "127.0.0.1")
            proxy["tor_socks_port"] = int(self.tun_cfg.get("tor_socks_port", 9050))
        proxy["fragment"] = self.tun_cfg.get("fragment", True)

        self._last_config = generate_xray_config(cfg, doh, output_path=self.config_path, proxy=proxy)

    def _smoke_test_config(self) -> dict[str, Any]:
        if _which("xray"):
            result = _subprocess_run(["xray", "test", "-config", str(self.config_path)], timeout=15)
            if result["returncode"] != 0:
                stderr = result.get("stderr", "")
                return {"ok": False, "error": f"xray config invalid: {stderr[:300]}"}
        return {"ok": True}

    def _open_tun(self) -> dict[str, Any]:
        if not _is_linux():
            return {"ok": True, "message": "TUN not supported on this platform (proxy-only mode)"}
        try:
            from app.tun_linux import TunDevice
            name = self.tun_cfg.get("tun_name", "tun0")
            mtu = int(self.tun_cfg.get("mtu", 1500))
            self._tun = TunDevice(name=name, mtu=mtu)
            self._tun.open()
            return {"ok": True}
        except PermissionError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": f"TUN open error: {exc}"}

    def _start_xray(self) -> dict[str, Any]:
        from app.xray.health import check_port_open
        from app.xray.process import XrayManager

        port = self.tun_cfg.get("port", 10808)
        health_check: Callable[[], bool] = lambda: check_port_open("127.0.0.1", port)

        mgr = XrayManager(self.config_path, binary=str(self.binary_path), max_restarts=2)
        result = mgr.start(health_check=health_check)
        if result["ok"]:
            self._xray_mgr = mgr
            # Grab PID from the underlying process.
            try:
                pid = mgr._process.proc.pid  # type: ignore[attr-defined]
            except Exception:
                pid = None
            return {"ok": True, "pid": pid}
        return {
            "ok": False,
            "error": result.get("error", "xray failed to start"),
            "diagnostics": result.get("diagnostics", {}),
        }

    def _teardown(self) -> dict[str, Any]:
        diagnostics: dict[str, Any] = {}
        if self._xray_mgr:
            try:
                self._xray_mgr.stop()
            except Exception as exc:
                diagnostics["xray_stop_error"] = str(exc)
            self._xray_mgr = None
        if self._tun:
            try:
                self._tun.close()
            except Exception as exc:
                diagnostics["tun_close_error"] = str(exc)
            self._tun = None
        return diagnostics


# -- small helpers (kept outside the class so tests can patch them) -----------

def _which(name: str) -> str | None:
    """Return the resolved path of *name*, or None."""
    import shutil
    return shutil.which(name)


def _is_linux() -> bool:
    import sys
    return sys.platform == "linux"


def _subprocess_run(args: list[str], timeout: float = 15.0) -> dict[str, Any]:
    """Run a subprocess and return a dict (never raises)."""
    import subprocess
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": "not found"}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "timeout"}
    except TimeoutError:
        return {"returncode": 124, "stdout": "", "stderr": "timeout"}
    except Exception as exc:
        return {"returncode": 1, "stdout": "", "stderr": str(exc)}


