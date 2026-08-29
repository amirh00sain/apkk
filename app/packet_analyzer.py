"""Packet analyzer — measurement of TCP/TLS packet characteristics.

This module reports (does not modify):
    TCP flags, sequence numbers, ACK, RST, window, SNI, ALPN,
    TLS record sizes, MTU, fragmentation.

It is used for the fragmentation-analysis research profile (measurement only).
"""

from __future__ import annotations

from typing import Any

from app.sni_parser import parse_client_hello


class PacketAnalyzer:
    """Stateless analyzer for captured packets."""

    def analyze_tcp(self, raw: bytes) -> dict[str, Any]:
        """Parse an IPv4 TCP packet and report header fields."""
        if len(raw) < 20:
            return {"error": "packet too short for IP header"}
        ihl = (raw[0] & 0x0F) * 4
        if ihl < 20 or len(raw) < ihl + 20:
            return {"error": "invalid IP/TCP header"}
        protocol = raw[9]
        if protocol != 6:  # TCP
            return {"error": f"not TCP (protocol={protocol})"}
        src_ip = ".".join(str(b) for b in raw[12:16])
        dst_ip = ".".join(str(b) for b in raw[16:20])
        tcp = raw[ihl:]
        src_port = (tcp[0] << 8) | tcp[1]
        dst_port = (tcp[2] << 8) | tcp[3]
        seq = int.from_bytes(tcp[4:8], "big")
        ack = int.from_bytes(tcp[8:12], "big")
        data_offset = (tcp[12] >> 4) * 4
        flags = tcp[13]
        window = (tcp[14] << 8) | tcp[15]
        payload_len = len(raw) - ihl - data_offset
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": {
                "syn": bool(flags & 0x02),
                "ack_flag": bool(flags & 0x10),
                "rst": bool(flags & 0x04),
                "fin": bool(flags & 0x01),
                "psh": bool(flags & 0x08),
            },
            "window": window,
            "payload_len": payload_len,
            "total_len": len(raw),
        }

    def analyze_tls_record(self, tcp_payload: bytes) -> dict[str, Any]:
        """Analyze a TLS record (e.g. ClientHello) from a TCP payload."""
        if len(tcp_payload) < 5:
            return {"error": "payload too short for TLS record"}
        content_type = tcp_payload[0]
        version = f"{tcp_payload[1]}.{tcp_payload[2]:02d}"
        record_len = (tcp_payload[3] << 8) | tcp_payload[4]
        result: dict[str, Any] = {
            "content_type": content_type,
            "version": version,
            "record_length": record_len,
        }
        if content_type == 0x16 and len(tcp_payload) >= 6:
            # It's a handshake; try SNI parse.
            sni_info = parse_client_hello(tcp_payload[:5 + record_len] if len(tcp_payload) >= 5 + record_len else tcp_payload)
            result["sni"] = sni_info.get("sni")
            result["alpn"] = sni_info.get("alpn")
            result["sni_valid_utf8"] = sni_info.get("valid_utf8")
        return result

    def fragmentation_report(self, before_sizes: list[int], after_sizes: list[int]) -> dict[str, Any]:
        """Compare packet-size distributions before/after (measurement only).

        This does NOT perform fragmentation — it reports what *would* change
        if a policy were applied.  Used for the fragmentation_analysis profile.
        """
        def _stats(sizes: list[int]) -> dict[str, Any]:
            if not sizes:
                return {"count": 0, "min": None, "max": None, "avg": None}
            return {
                "count": len(sizes),
                "min": min(sizes),
                "max": max(sizes),
                "avg": round(sum(sizes) / len(sizes), 2),
            }
        return {
            "before": _stats(before_sizes),
            "after": _stats(after_sizes),
            "note": "Measurement only. No packets were modified by this tool.",
        }

    def mtu_report(self, payload_sizes: list[int], mtu: int = 1500) -> dict[str, Any]:
        """Report MTU-related fragmentation risk for a set of payload sizes."""
        oversized = [s for s in payload_sizes if s > mtu]
        return {
            "mtu": mtu,
            "samples": len(payload_sizes),
            "oversized_count": len(oversized),
            "fragmentation_likely": len(oversized) > 0,
        }
