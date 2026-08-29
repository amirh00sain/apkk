"""Linux TUN device abstraction.  Thin convenience layer over the TUN backend.

This module is allowed to import Linux-specific APIs (ctypes, fcntl).  Tests
mock this out by passing a fake backend, so it stays importable everywhere.
"""

from __future__ import annotations

import os
from typing import Any

from app.packet_backend import LinuxTunBackend, PacketBackend


class TunDevice:
    """User-facing TUN device wrapper on Linux."""

    def __init__(self, name: str = "tun0", mtu: int = 1500, backend: PacketBackend | None = None):
        self.name = name
        self.mtu = mtu
        self._backend = backend or LinuxTunBackend(name=name, mtu=mtu)
        self._privilege_warning_emitted = False

    @property
    def backend(self) -> PacketBackend:
        return self._backend

    def open(self) -> None:
        """Open the TUN device.  Requires CAP_NET_ADMIN."""
        try:
            self._backend.start()
        except (PermissionError, OSError, RuntimeError) as exc:
            raise PermissionError(
                f"Cannot open TUN device {self.name}: {exc}. "
                "This requires CAP_NET_ADMIN (root or setcap). "
                "Use offline/PCAP mode for analysis without privileges."
            ) from exc

    def close(self) -> None:
        self._backend.stop()

    def read(self, size: int = 65536) -> bytes | None:
        return self._backend.read_packet()

    def write(self, data: bytes) -> None:
        self._backend.write_packet(data)

    def set_mtu(self, mtu: int) -> None:
        self._backend.set_mtu(mtu)

    def configure_address(self, ip: str = "10.0.0.1", mask: int = 24) -> None:
        try:
            self._backend.configure_address(ip, mask)
        except RuntimeError as exc:
            raise PermissionError(str(exc)) from exc

    @property
    def requires_privileges(self) -> bool:
        return True

    @staticmethod
    def is_supported() -> bool:
        return LinuxTunBackend.detect()
