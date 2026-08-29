"""Packet interception backend abstraction.

The original SNI-Spoofing project was hard-wired to WinDivert (Windows only).
This module provides a platform-agnostic abstraction:

    PacketBackend (ABC)
        ├── WindowsWinDivertBackend  (Windows, optional)
        ├── LinuxTunBackend          (Linux TUN)
        └── OfflinePcapBackend       (PCAP file analysis)

The Linux backend is a real TUN implementation.  WinDivert is kept as a thin
optional shim; we do NOT attempt to force it onto Linux.

IMPORTANT: This backend is for *analysis and measurement*.  It does not perform
any packet injection.  Injection is out of scope of this tool (see task spec:
no fabricated identity, measurement-first).
"""

from __future__ import annotations

import abc
import platform
from typing import Any, Protocol

from app.models import ProbeTarget
from app.security import safe_subprocess_args


class Packet(Protocol):
    """Minimal packet representation."""

    direction: str  # "inbound" | "outbound"
    data: bytes


class PacketBackend(abc.ABC):
    """Abstract packet interception backend."""

    name: str = "abstract"

    @classmethod
    def detect(cls) -> bool:
        """Return True if this backend is usable on the current platform."""
        return False

    @abc.abstractmethod
    def start(self) -> None: ...

    @abc.abstractmethod
    def stop(self) -> None: ...

    @abc.abstractmethod
    def read_packet(self) -> bytes | None:
        """Read one raw packet (bytes), or None if none available."""
        ...

    @abc.abstractmethod
    def write_packet(self, data: bytes) -> None:
        """Write one raw packet to the interface."""
        ...


# ---------------------------------------------------------------------------
# Linux TUN backend
# ---------------------------------------------------------------------------

class LinuxTunBackend(PacketBackend):
    name = "linux_tun"

    def __init__(self, name: str = "tun0", mtu: int = 1500):
        self.name = name
        self.mtu = mtu
        self._fd: int | None = None

    @classmethod
    def detect(cls) -> bool:
        import sys
        if sys.platform != "linux":
            return False
        # /dev/net/tun must exist to use TUN.
        from pathlib import Path
        return Path("/dev/net/tun").exists()

    def start(self) -> None:
        import fcntl
        import os
        import struct

        TUNSETIFF = 0x400454CA
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000

        self._fd = os.open("/dev/net/tun", os.O_RDWR)
        ifreq = self.name.encode()[:15].ljust(16, b"\x00") + \
                struct.pack("H", IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifreq)
        self.configure_address()

    def configure_address(self, ip: str = "10.0.0.1", mask: int = 24) -> None:
        """Configure the TUN interface address via `ip` (requires privileges)."""
        args = safe_subprocess_args([
            "ip", "addr", "add", f"{ip}/{mask}", "dev", self.name,
        ])
        import subprocess
        # This may require root.  Failure is surfaced, not silently swallowed.
        proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0 and "exists" not in proc.stderr:
            raise RuntimeError(f"failed to configure {self.name}: {proc.stderr}")
        up_args = safe_subprocess_args(["ip", "link", "set", "dev", self.name, "up"])
        proc = subprocess.run(up_args, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            raise RuntimeError(f"failed to bring up {self.name}: {proc.stderr}")

    def set_mtu(self, mtu: int) -> None:
        import subprocess
        self.mtu = mtu
        args = safe_subprocess_args(["ip", "link", "set", "dev", self.name, "mtu", str(mtu)])
        proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            raise RuntimeError(f"failed to set MTU on {self.name}: {proc.stderr}")

    def stop(self) -> None:
        if self._fd is not None:
            import os
            os.close(self._fd)
            self._fd = None

    def read_packet(self) -> bytes | None:
        import os
        if self._fd is None:
            return None
        try:
            return os.read(self._fd, 65536)
        except OSError:
            return None

    def write_packet(self, data: bytes) -> None:
        import os
        if self._fd is None:
            return
        os.write(self._fd, data)


# ---------------------------------------------------------------------------
# Windows WinDivert backend (optional, not used on Linux)
# ---------------------------------------------------------------------------

class WindowsWinDivertBackend(PacketBackend):
    name = "windows_windivert"

    def __init__(self, w_filter: str = "tcp"):
        self.w_filter = w_filter
        self._handle = None

    @classmethod
    def detect(cls) -> bool:
        if platform.system() != "Windows":
            return False
        try:
            import pydivert  # type: ignore
            return True
        except ImportError:
            return False

    def start(self) -> None:
        import pydivert  # type: ignore
        self._handle = pydivert.WinDivert(self.w_filter)
        self._handle.open()

    def stop(self) -> None:
        if self._handle:
            self._handle.close()
            self._handle = None

    def read_packet(self) -> bytes | None:
        if not self._handle:
            return None
        pkt = self._handle.recv()
        return pkt.raw if pkt else None

    def write_packet(self, data: bytes) -> None:
        if self._handle:
            self._handle.send(data)


# ---------------------------------------------------------------------------
# Offline PCAP backend
# ---------------------------------------------------------------------------

class OfflinePcapBackend(PacketBackend):
    name = "offline_pcap"

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self._reader = None

    @classmethod
    def detect(cls) -> bool:
        try:
            import scapy  # type: ignore
            return True
        except ImportError:
            return False

    def start(self) -> None:
        from scapy.all import rdpcap
        self._reader = rdpcap(self.pcap_path)

    def stop(self) -> None:
        self._reader = None

    def read_packet(self) -> bytes | None:
        if not self._reader:
            return None
        try:
            pkt = next(self._reader)
            return bytes(pkt)
        except StopIteration:
            return None

    def write_packet(self, data: bytes) -> None:  # pragma: no cover - write not supported offline
        raise NotImplementedError("OfflinePcapBackend is read-only")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def select_backend(mode: str = "auto", **kwargs: Any) -> PacketBackend:
    """Select a backend appropriate to the platform / requested mode."""
    if mode == "offline":
        return OfflinePcapBackend(kwargs.get("pcap_path", "capture.pcap"))
    if mode == "windows" and WindowsWinDivertBackend.detect():
        return WindowsWinDivertBackend(kwargs.get("w_filter", "tcp"))
    if mode in ("linux", "auto") and LinuxTunBackend.detect():
        return LinuxTunBackend(kwargs.get("name", "tun0"), kwargs.get("mtu", 1500))
    # Default: offline analysis mode (no privileged device required).
    return OfflinePcapBackend(kwargs.get("pcap_path", "capture.pcap"))
