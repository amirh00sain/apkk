"""Tests for xray process / health / binary (offline, mocked subprocess)."""

import subprocess
import threading
import time
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from app.xray.process import XrayProcess, XrayManager
from app.xray.health import check_process_alive, check_port_open, health_check
from app.xray.binary import find_xray, get_version, validate_binary


class FakeProc:
    def __init__(self, returncode=None, stderr_lines=(), alive=True):
        self.returncode = returncode
        self._stderr_lines = list(stderr_lines)
        self._alive = alive
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self._alive else self.returncode

    @property
    def stderr(self):
        class _Iter:
            def __init__(self, lines):
                self._it = iter(lines)
            def __iter__(self):
                return self
            def __next__(self):
                return next(self._it)
        return _Iter(self._stderr_lines)

    def terminate(self):
        self.terminated = True
        self._alive = False
        self.returncode = -15

    def kill(self):
        self.killed = True
        self._alive = False
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class TestXrayProcess:
    def test_spawn_and_read_stderr(self):
        proc = FakeProc(alive=True, stderr_lines=["line1", "line2"])
        with patch("subprocess.Popen", return_value=proc):
            xp = XrayProcess("config/xray.json")
            xp.spawn()
            time.sleep(0.1)  # let stderr thread drain
            logs = xp._collect_logs()
            assert "line1" in logs
            xp.stop()
            assert proc.terminated

    def test_wait_ready_alive(self):
        proc = FakeProc(alive=True)
        with patch("subprocess.Popen", return_value=proc):
            xp = XrayProcess("config/xray.json")
            xp.spawn()
            assert xp.wait_ready() is True
            xp.stop()

    def test_wait_ready_not_alive(self):
        proc = FakeProc(alive=False, returncode=1, stderr_lines=["boom"])
        with patch("subprocess.Popen", return_value=proc):
            xp = XrayProcess("config/xray.json")
            xp.spawn()
            time.sleep(0.05)
            assert xp.wait_ready(interval=0.01) is False
            assert xp.diagnose_failure()["exit_code"] == 1
            xp.stop()

    def test_is_alive(self):
        proc = FakeProc(alive=True)
        with patch("subprocess.Popen", return_value=proc):
            xp = XrayProcess("config/xray.json")
            xp.spawn()
            assert xp.is_alive() is True
            xp.stop()
            assert xp.is_alive() is False


class TestXrayManager:
    def test_start_ok(self):
        proc = FakeProc(alive=True)
        with patch("subprocess.Popen", return_value=proc):
            mgr = XrayManager("config/xray.json", max_restarts=3)
            res = mgr.start()
            assert res["ok"] is True
            mgr.stop()

    def test_start_fails(self):
        proc = FakeProc(alive=False, returncode=2, stderr_lines=["crash"])
        with patch("subprocess.Popen", return_value=proc):
            mgr = XrayManager("config/xray.json", max_restarts=2)
            res = mgr.start()
            assert res["ok"] is False
            assert "error" in res


class TestXrayHealth:
    def test_check_process_alive(self):
        assert check_process_alive(None) is False
        assert check_process_alive(FakeProc(alive=True)) is True
        assert check_process_alive(FakeProc(alive=False, returncode=1)) is False

    def test_check_port_open(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            assert check_port_open("127.0.0.1", port) is True
        finally:
            srv.close()
        assert check_port_open("127.0.0.1", 1) is False

    def test_health_check(self):
        proc = FakeProc(alive=True)
        cfg = {"inbounds": [{"port": 10808, "tag": "mixed-in"}]}
        with patch("app.xray.health.check_port_open", return_value=True):
            res = health_check(cfg, proc)
            assert res["process_alive"] is True
            assert res["healthy"] is True
        res2 = health_check(cfg, None)
        assert res2["healthy"] is False


class TestXrayBinary:
    def test_find_none(self):
        with patch("shutil.which", return_value=None):
            assert find_xray() is None

    def test_get_version_none(self):
        with patch("app.xray.binary.find_xray", return_value=None):
            assert get_version() is None

    def test_validate_binary_missing(self):
        with patch("app.xray.binary.find_xray", return_value=None):
            r = validate_binary()
            assert r["ok"] is False

    def test_validate_binary_ok(self):
        with patch("app.xray.binary.find_xray", return_value="/usr/bin/xray"), \
             patch("app.xray.binary.get_version", return_value="Xray 1.8.0"):
            r = validate_binary()
            assert r["ok"] is True
            assert r["version"] == "Xray 1.8.0"
