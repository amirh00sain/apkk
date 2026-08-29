"""Tests for packet_backend.py — offline (abstraction + factories, no real TUN)."""

import platform
from unittest.mock import patch

import pytest

from app.packet_backend import (
    PacketBackend,
    LinuxTunBackend,
    WindowsWinDivertBackend,
    OfflinePcapBackend,
    select_backend,
)


class TestBackendAbc:
    def test_abstract_raises(self):
        # Cannot instantiate abstract backend directly without implementations.
        class Partial(PacketBackend):
            pass
        with pytest.raises(TypeError):
            Partial()

    def test_detect_default_false(self):
        assert PacketBackend.detect() is False


class TestLinuxTunBackend:
    def test_detect_false_when_no_tun(self):
        with patch("pathlib.Path.exists", return_value=False):
            assert LinuxTunBackend.detect() is False

    def test_detect_false_on_non_linux(self):
        with patch("sys.platform", "win32"):
            assert LinuxTunBackend.detect() is False

    def test_read_write_without_fd(self):
        b = LinuxTunBackend()
        b._fd = None
        assert b.read_packet() is None
        b.write_packet(b"x")  # no-op

    def test_stop_no_fd(self):
        b = LinuxTunBackend()
        b.stop()  # should be safe

    def test_start_success(self):
        with patch("os.open", return_value=7) as m_open, \
             patch("fcntl.ioctl") as m_ioctl, \
             patch("os.close") as m_close, \
             patch("app.packet_backend.LinuxTunBackend.configure_address") as m_cfg:
            b = LinuxTunBackend(name="tun0", mtu=1500)
            b.start()
            assert b._fd == 7
            m_open.assert_called_once()
            m_ioctl.assert_called_once()
            m_cfg.assert_called_once()
            b.stop()
            assert b._fd is None
            m_close.assert_called_once_with(7)

    def test_configure_address_ok(self):
        with patch("subprocess.run") as run:
            run.return_value = type("P", (), {"returncode": 0, "stderr": ""})()
            b = LinuxTunBackend()
            b.configure_address("10.0.0.1", 24)  # should not raise

    def test_configure_address_raises(self):
        with patch("subprocess.run") as run:
            run.return_value = type("P", (), {"returncode": 1, "stderr": "fail"})()
            b = LinuxTunBackend()
            with pytest.raises(RuntimeError):
                b.configure_address("10.0.0.1", 24)

    def test_set_mtu_raises(self):
        with patch("subprocess.run") as run:
            run.return_value = type("P", (), {"returncode": 1, "stderr": "fail"})()
            b = LinuxTunBackend()
            with pytest.raises(RuntimeError):
                b.set_mtu(1400)

    def test_read_write_with_fd(self):
        b = LinuxTunBackend()
        b._fd = 5
        with patch("os.read", return_value=b"data") as m_read, \
             patch("os.write") as m_write:
            assert b.read_packet() == b"data"
            m_read.assert_called_once()
            b.write_packet(b"out")
            m_write.assert_called_once_with(5, b"out")


class TestWindowsBackend:
    def test_detect_non_windows(self):
        with patch("platform.system", return_value="Linux"):
            assert WindowsWinDivertBackend.detect() is False

    def test_detect_no_pydivert(self):
        import sys
        fake_mod = type("FakePydivert", (), {})()
        with patch("platform.system", return_value="Windows"), \
             patch.dict("sys.modules", {"pydivert": fake_mod}):
            # The module is importable, so detect() should return True (no ImportError).
            assert WindowsWinDivertBackend.detect() is True

    def test_detect_pydivert_missing(self):
        import sys
        with patch("platform.system", return_value="Windows"), \
             patch.dict("sys.modules", {"pydivert": None}):
            # Simulate ImportError by making the import raise.
            import builtins
            real_import = builtins.__import__

            def _blocked_import(name, *a, **k):
                if name == "pydivert" or name.startswith("pydivert."):
                    raise ImportError("no pydivert")
                return real_import(name, *a, **k)

            with patch("builtins.__import__", side_effect=_blocked_import):
                assert WindowsWinDivertBackend.detect() is False

    def test_read_write_no_handle(self):
        b = WindowsWinDivertBackend()
        assert b.read_packet() is None
        b.write_packet(b"x")  # no-op

    def test_start_stop(self):
        class FakeHandle:
            def open(self):
                pass
            def close(self):
                pass
            def recv(self):
                return type("P", (), {"raw": b"pkt"})()
            def send(self, data):
                pass

        fake_mod = type("FakePydivert", (), {"WinDivert": staticmethod(lambda f: FakeHandle())})
        with patch.dict("sys.modules", {"pydivert": fake_mod}):
            b = WindowsWinDivertBackend()
            b.start()
            assert b.read_packet() == b"pkt"
            b.write_packet(b"out")
            b.stop()
            assert b._handle is None


class TestOfflinePcapBackend:
    def test_detect_no_scapy(self):
        import builtins
        real_import = builtins.__import__

        def _blocked_import(name, *a, **k):
            if name == "scapy" or name.startswith("scapy."):
                raise ImportError("no scapy")
            return real_import(name, *a, **k)

        with patch("builtins.__import__", side_effect=_blocked_import):
            assert OfflinePcapBackend.detect() is False

    def test_read_write(self):
        fake_reader = iter([b"pkt1", b"pkt2"])
        b = OfflinePcapBackend("x.pcap")
        b._reader = fake_reader
        assert b.read_packet() == b"pkt1"
        assert b.read_packet() == b"pkt2"
        assert b.read_packet() is None
        with pytest.raises(NotImplementedError):
            b.write_packet(b"x")

    def test_read_with_no_reader(self):
        b = OfflinePcapBackend("x.pcap")
        assert b.read_packet() is None

    def test_start_calls_rdpcap(self):
        pytest.importorskip("scapy")
        import scapy.all
        b = OfflinePcapBackend("x.pcap")
        with patch("scapy.all.rdpcap", return_value=iter([])) as m_rdpcap:
            b.start()
            m_rdpcap.assert_called_once_with("x.pcap")
            assert b._reader is not None
            b.stop()
            assert b._reader is None

    def test_detect_with_scapy_installed(self):
        # scapy is installed in the venv, so detect() should return True.
        pytest.importorskip("scapy")
        assert OfflinePcapBackend.detect() is True


class TestSelectBackend:
    def test_offline(self):
        b = select_backend("offline", pcap_path="capture.pcap")
        assert isinstance(b, OfflinePcapBackend)

    def test_auto_falls_to_offline(self):
        with patch("app.packet_backend.LinuxTunBackend.detect", return_value=False), \
             patch("app.packet_backend.WindowsWinDivertBackend.detect", return_value=False):
            b = select_backend("auto")
            assert isinstance(b, OfflinePcapBackend)
