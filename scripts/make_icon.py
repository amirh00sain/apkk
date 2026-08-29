#!/usr/bin/env python3
"""Generate the NetProbe PNG launcher icon (green background, white N).

Used by the Linux AppImage CI job. Writes a 256x256 PNG to the path given
as the first CLI argument (or stdout's directory fallback).
"""
import struct
import sys
import zlib

W = H = 256


def build_pixels() -> bytes:
    px = bytearray()
    for y in range(H):
        px.append(0)  # PNG filter type 0 (none) per scanline
        for x in range(W):
            r, g, b = 31, 138, 76  # NetProbe green
            # Draw a simple white "N"
            if (x < 70 and y > 60) or (x > 186 and y < 200) or (
                50 < x < 206 and abs(y - (H - x)) < 18
            ):
                r, g, b = 255, 255, 255
            px += struct.pack("BBB", r, g, b)
    return bytes(px)


def chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def build_png() -> bytes:
    px = build_pixels()
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(px, 9))
    png += chunk(b"IEND", b"")
    return png


def main() -> int:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "netprobe.png"
    data = build_png()
    with open(out_path, "wb") as fh:
        fh.write(data)
    print(f"wrote {out_path} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
