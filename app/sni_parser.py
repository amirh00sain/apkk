"""SNI parser for TLS ClientHello.

Parses a raw ClientHello (TLS record) and extracts:
    - SNI (server_name extension)
    - whether the SNI is valid UTF-8
    - the SNI byte length

Only measurement/analysis — never constructs an unrelated SNI.
"""

from __future__ import annotations

from typing import Any


def parse_client_hello(data: bytes) -> dict[str, Any]:
    """Parse a TLS ClientHello and extract SNI and metadata.

    Returns dict with keys: sni, valid_utf8, length, tls_version, alpn, error.
    If the input is not a ClientHello, returns error.
    """
    result: dict[str, Any] = {
        "sni": None,
        "valid_utf8": False,
        "length": 0,
        "tls_version": None,
        "alpn": [],
        "error": None,
    }

    try:
        # TLS record: content type(1) version(2) length(2)
        if len(data) < 5:
            result["error"] = "too short to be a TLS record"
            return result

        content_type = data[0]
        if content_type != 0x16:  # handshake
            result["error"] = f"not a handshake record (type=0x{content_type:02x})"
            return result

        record_version = (data[1] << 8) | data[2]
        record_len = (data[3] << 8) | data[4]
        result["tls_version"] = f"{data[1]}.{data[2]:02d}"

        handshake = data[5:]
        if len(handshake) < 4:
            result["error"] = "handshake message too short"
            return result

        hs_type = handshake[0]
        if hs_type != 0x01:  # client_hello
            result["error"] = f"not a ClientHello (hs_type=0x{hs_type:02x})"
            return result

        # ClientHello length (3 bytes) + 2-byte version + 32-byte random
        body = handshake[4:]
        # client_version (2) + random (32) = 34
        if len(body) < 34:
            result["error"] = "ClientHello body too short"
            return result

        # Session ID
        pos = 34
        sid_len = body[pos]
        pos += 1 + sid_len
        # Cipher suites
        if len(body) < pos + 2:
            result["error"] = "missing cipher suites"
            return result
        cs_len = (body[pos] << 8) | body[pos + 1]
        pos += 2 + cs_len
        # Compression methods
        if len(body) < pos + 1:
            result["error"] = "missing compression methods"
            return result
        comp_len = body[pos]
        pos += 1 + comp_len
        # Extensions
        if len(body) < pos + 2:
            result["error"] = "no extensions"
            return result
        ext_total = (body[pos] << 8) | body[pos + 1]
        pos += 2
        end = pos + ext_total
        if len(body) < end:
            result["error"] = "extensions truncated"
            return result

        while pos + 4 <= end:
            ext_type = (body[pos] << 8) | body[pos + 1]
            ext_len = (body[pos + 2] << 8) | body[pos + 3]
            ext_data = body[pos + 4: pos + 4 + ext_len]
            pos += 4 + ext_len

            if ext_type == 0x00:  # server_name
                # server_name_list length (2), then entries
                if len(ext_data) < 2:
                    continue
                sni_list_len = (ext_data[0] << 8) | ext_data[1]
                p = 2
                while p + 3 <= 2 + sni_list_len and p + 3 <= len(ext_data):
                    name_type = ext_data[p]
                    name_len = (ext_data[p + 1] << 8) | ext_data[p + 2]
                    name_bytes = ext_data[p + 3: p + 3 + name_len]
                    if name_type == 0:  # host_name
                        try:
                            sni = name_bytes.decode("utf-8")
                            result["sni"] = sni
                            result["valid_utf8"] = True
                            result["length"] = name_len
                        except UnicodeDecodeError:
                            result["sni"] = repr(name_bytes)
                            result["valid_utf8"] = False
                            result["length"] = name_len
                    p += 3 + name_len
            elif ext_type == 0x10:  # ALPN
                if len(ext_data) >= 2:
                    alpn_list_len = (ext_data[0] << 8) | ext_data[1]
                    ap = 2
                    while ap + 1 < 2 + alpn_list_len and ap + 1 < len(ext_data):
                        proto_len = ext_data[ap]
                        proto = ext_data[ap + 1: ap + 1 + proto_len]
                        try:
                            result["alpn"].append(proto.decode("ascii"))
                        except UnicodeDecodeError:
                            pass
                        ap += 1 + proto_len

    except Exception as exc:  # pragma: no cover - defensive
        result["error"] = f"parse error: {exc}"
    return result


def sni_consistency(sni: str, certificate_names: list[str]) -> str:
    """Return MATCH | MISMATCH | UNKNOWN for SNI vs cert names."""
    if not sni:
        return "UNKNOWN"
    sni = sni.lower()
    if sni in [n.lower() for n in certificate_names]:
        return "MATCH"
    for name in certificate_names:
        if name.startswith("*.") and sni.endswith(name[1:].lower()):
            return "MATCH"
    return "MISMATCH"
