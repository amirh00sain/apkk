"""TUN device tests — offline (mocked backend)."""

import pytest

from app.tun_linux import TunDevice
from app.packet_backend import (
    PacketBackend,
    LinuxTunBackend,
    WindowsWinDivertBackend,
    OfflinePcapBackend,
    select_backend,
)


class FakeBackend(PacketBackend):
    name = "fake"

    def __init__(self):
        self.started = False
        self.stopped = False
        self.sent = []
        self.read_queue = [b"\x45\x00\x00\x1c", None]

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def read_packet(self):
        return self.read_queue.pop(0) if self.read_queue else None

    def write_packet(self, data):
        self.sent.append(data)


class TestTunDevice:
    def test_open_close(self):
        dev = TunDevice(backend=FakeBackend())
        dev.open()
        assert dev.backend.started
        dev.close()
        assert dev.backend.stopped

    def test_read_write(self):
        dev = TunDevice(backend=FakeBackend())
        dev.open()
        dev.write(b"hello")
        assert dev.backend.sent == [b"hello"]
        assert dev.read() == b"\x45\x00\x00\x1c"
        assert dev.read() is None

    def test_requires_privileges_flag(self):
        dev = TunDevice(backend=FakeBackend())
        assert dev.requires_privileges is True


class TestBackendFactory:
    def test_select_offline(self):
        b = select_backend("offline", pcap_path="x.pcap")
        assert isinstance(b, OfflinePcapBackend)

    def test_select_auto_no_privileges(self):
        # On this machine without root, auto should fall back to offline.
        b = select_backend("auto")
        assert isinstance(b, (OfflinePcapBackend, LinuxTunBackend))
