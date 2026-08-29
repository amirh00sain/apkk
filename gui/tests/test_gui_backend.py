"""Offline tests for gui/backend.ConnectionController (no Flet, no real xray)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from gui.backend import ConnectionController


@pytest.fixture
def cfg_path(tmp_path: Path) -> Path:
    return tmp_path / "xray.json"


def test_initial_state_idle(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    assert ctrl.state == "idle"


def test_connect_missing_binary(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="/nope/xray")
    with patch("gui.backend._which", return_value=None):
        result = ctrl.connect()
    assert result["ok"] is False
    assert "xray binary" in result["error"]
    assert ctrl.state == "error"


def test_connect_writes_config_and_starts(cfg_path: Path) -> None:
    ctrl = ConnectionController(
        config_path=cfg_path,
        binary_path="xray",
        tun_cfg={"tor": True, "fragment": True, "port": 10808},
    )
    with patch("gui.backend._which", return_value="/usr/bin/xray"), \
         patch.object(ConnectionController, "_write_config") as w, \
         patch.object(ConnectionController, "_smoke_test_config", return_value={"ok": True}), \
         patch.object(ConnectionController, "_open_tun", return_value={"ok": True}), \
         patch.object(ConnectionController, "_start_xray", return_value={"ok": True, "pid": 4242}):
        result = ctrl.connect()
        assert w.called
        assert result["ok"] is True
        assert result["pid"] == 4242
        assert ctrl.state == "connected"


def test_connect_proxy_only_when_tun_fails_and_xray_ok(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._which", return_value="/usr/bin/xray"), \
         patch.object(ConnectionController, "_write_config"), \
         patch.object(ConnectionController, "_smoke_test_config", return_value={"ok": True}), \
         patch.object(ConnectionController, "_open_tun", return_value={"ok": False, "error": "no cap"}), \
         patch.object(ConnectionController, "_start_xray", return_value={"ok": True, "pid": 7}):
        result = ctrl.connect()
        assert result["ok"] is True
        assert ctrl.state == "connected"


def test_connect_fails_when_smoke_test_fails(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._which", return_value="/usr/bin/xray"), \
         patch.object(ConnectionController, "_write_config"), \
         patch.object(ConnectionController, "_smoke_test_config",
                      return_value={"ok": False, "error": "invalid config"}):
        result = ctrl.connect()
        assert result["ok"] is False
        assert "invalid config" in result["error"]
        assert ctrl.state == "error"
        # Nothing was started yet, so teardown is a no-op (no xray, no TUN).
        assert ctrl._xray_mgr is None
        assert ctrl._tun is None


def test_connect_fails_when_xray_fails(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._which", return_value="/usr/bin/xray"), \
         patch.object(ConnectionController, "_write_config"), \
         patch.object(ConnectionController, "_smoke_test_config", return_value={"ok": True}), \
         patch.object(ConnectionController, "_open_tun", return_value={"ok": True}), \
         patch.object(ConnectionController, "_start_xray",
                      return_value={"ok": False, "error": "crash", "diagnostics": {}}), \
         patch.object(ConnectionController, "_teardown") as td:
        result = ctrl.connect()
        assert result["ok"] is False
        assert "crash" in result["error"]
        assert td.called


def test_disconnect_teardown(tmp_path: Path) -> None:
    cfg_path = tmp_path / "xray.json"
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    fake_mgr = MagicMock()
    fake_tun = MagicMock()
    ctrl._xray_mgr = fake_mgr
    ctrl._tun = fake_tun
    result = ctrl.disconnect()
    assert result["ok"] is True
    assert ctrl.state == "idle"
    fake_mgr.stop.assert_called_once()
    fake_tun.close.assert_called_once()


def test_write_config_passes_tor_fragment(cfg_path: Path) -> None:
    ctrl = ConnectionController(
        config_path=cfg_path,
        binary_path="xray",
        tun_cfg={"tor": True, "fragment": True, "port": 10808},
    )
    captured = {}

    def fake_gen(cfg, doh=None, output_path=None, proxy=None):
        captured["proxy"] = proxy
        return {"ok": True}

    with patch("app.config_loader.load_config", return_value=MagicMock()), \
         patch("app.config_loader.load_dns_providers", return_value={}), \
         patch("app.xray.config.generate_xray_config", side_effect=fake_gen):
        ctrl._write_config()
    assert captured["proxy"]["tor"] is True
    assert captured["proxy"]["fragment"] is True
    assert captured["proxy"]["tor_socks_port"] == 9050


def test_smoke_test_calls_xray_test(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._which", return_value="/usr/bin/xray"), \
         patch("gui.backend._subprocess_run",
               return_value={"returncode": 0, "stdout": "ok", "stderr": ""}):
        result = ctrl._smoke_test_config()
    assert result["ok"] is True


def test_smoke_test_detects_invalid(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._which", return_value="/usr/bin/xray"), \
         patch("gui.backend._subprocess_run",
               return_value={"returncode": 1, "stdout": "", "stderr": "bad json"}):
        result = ctrl._smoke_test_config()
    assert result["ok"] is False
    assert "bad json" in result["error"]


def test_open_tun_non_linux_returns_ok(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._is_linux", return_value=False):
        result = ctrl._open_tun()
    assert result["ok"] is True
    assert ctrl._tun is None


def test_open_tun_linux_permission_error(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._is_linux", return_value=True), \
         patch("app.tun_linux.TunDevice") as tun_cls:
        tun_cls.return_value.open.side_effect = PermissionError("no cap")
        result = ctrl._open_tun()
    assert result["ok"] is False
    assert "CAP_NET_ADMIN" in result["error"] or "no cap" in result["error"]


def test_open_tun_linux_success(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    fake = MagicMock()
    with patch("gui.backend._is_linux", return_value=True), \
         patch("app.tun_linux.TunDevice", return_value=fake):
        result = ctrl._open_tun()
    assert result["ok"] is True
    fake.open.assert_called_once()
    assert ctrl._tun is fake


def test_check_binary_which_found(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="xray")
    with patch("gui.backend._which", return_value="/usr/bin/xray"):
        ok, err = ctrl._check_binary()
    assert ok is True
    assert err == ""


def test_check_binary_missing(cfg_path: Path) -> None:
    ctrl = ConnectionController(config_path=cfg_path, binary_path="/nope/xray")
    with patch("gui.backend._which", return_value=None):
        ok, err = ctrl._check_binary()
    assert ok is False
    assert "not found" in err


def test_subprocess_run_timeout() -> None:
    import subprocess
    from gui.backend import _subprocess_run
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="xray", timeout=1)):
        result = _subprocess_run(["xray", "test"])
    assert result["returncode"] == 124


def test_subprocess_run_not_found() -> None:
    from gui.backend import _subprocess_run
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = _subprocess_run(["xray", "test"])
    assert result["returncode"] == 127


def test_subprocess_run_success() -> None:
    from gui.backend import _subprocess_run
    proc = SimpleNamespace(returncode=0, stdout="out", stderr="")
    with patch("subprocess.run", return_value=proc):
        result = _subprocess_run(["xray", "test"])
    assert result["returncode"] == 0


def test_which_and_is_linux() -> None:
    from gui.backend import _which, _is_linux
    assert _which("python") is not None
    assert _is_linux() == (sys.platform == "linux")
