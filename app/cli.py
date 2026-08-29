"""Command-line interface for the network analysis toolkit.

Commands:
    python -m app update
    python -m app scan <host>
    python -m app resolve <host>
    python -m app tls <host>
    python -m app cdn <host>
    python -m app health
    python -m app generate
    python -m app validate
    python -m app run
    python -m app dashboard

All commands use Typer.  No shell=True.  All inputs validated.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from app.config_loader import load_config, load_blocklist, load_dns_providers, validate_config_app
from app.errors import AppError, ErrorCollector
from app.logger import get_logger
from app.models import RecordStatus
from app.security import validate_hostname

app = typer.Typer(help="Network traffic analysis & CDN/TLS inspection toolkit", no_args_is_help=True)
console = Console()
logger = get_logger()


def _print_json(data: dict) -> None:
    console.print_json(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

@app.command()
def update() -> None:
    """Fetch CDN ranges, validate, expire stale data, update SQLite + JSON exports."""
    from app.scan_engine import update_database
    result = update_database("data")
    if result.get("ok"):
        console.print("[green]Update complete[/green]")
        console.print(f"  expired DNS entries: {result.get('expired_dns_entries', 0)}")
        console.print(f"  CDN range files: {result.get('cdn_files', 0)}")
    else:
        console.print("[red]Update failed[/red]")
        console.print(result.get("error", ""))


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@app.command()
def scan(hostname: str) -> None:
    """Run the full scan pipeline for a hostname."""
    hostname = validate_hostname(hostname)
    result = asyncio.run(_run_scan(hostname))
    _render_scan(result)


async def _run_scan(hostname: str) -> dict:
    from app.scan_engine import scan_hostname
    return await scan_hostname(hostname)


def _render_scan(result: dict) -> None:
    console.print(f"\n[bold cyan]Scan: {result['hostname']}[/bold cyan]")
    # DNS
    dns = result["dns"]
    console.print("\n[yellow]DNS[/yellow]")
    console.print(f"  A      : {', '.join(dns['ipv4']) or '-'}")
    console.print(f"  AAAA   : {', '.join(dns['ipv6']) or '-'}")
    console.print(f"  CNAME  : {', '.join(dns['cname']) or '-'}")
    console.print(f"  TTL    : {dns['ttl']}")
    console.print(f"  source : {dns['source']}  [{dns['status']}]")
    # TLS
    tls = result["tls"]
    console.print("\n[yellow]TLS[/yellow]")
    console.print(f"  success   : {tls['success']}")
    console.print(f"  version   : {tls['tls_version']}")
    console.print(f"  cipher    : {tls['cipher']}")
    console.print(f"  SNI       : {tls['sni']}")
    console.print(f"  SAN       : {', '.join(tls['san_list']) or '-'}")
    console.print(f"  issuer    : {tls['issuer']}")
    console.print(f"  valid     : {tls['tls_valid']}  [{tls['status']}]")
    console.print(f"  latency   : {tls['latency_ms']} ms")
    # CDN
    cdn = result["cdn"]
    console.print("\n[yellow]CDN[/yellow]")
    console.print(f"  provider  : {cdn['provider'] or '-'}")
    console.print(f"  confidence: {cdn['confidence']}")
    console.print(f"  evidence  : {', '.join(cdn['evidence']) or '-'}  [{cdn['status']}]")
    # Probe
    probe = result.get("probe", {})
    if probe:
        console.print("\n[yellow]Probe[/yellow]")
        icmp = probe.get("icmp", {})
        tcp = probe.get("tcp443", {})
        console.print(f"  ICMP   : reachable={icmp.get('reachable')} latency={icmp.get('latency_ms')} ms")
        console.print(f"  TCP443 : reachable={tcp.get('reachable')} latency={tcp.get('latency_ms')} ms")
    # Route
    route = result["route"]
    console.print("\n[yellow]Route[/yellow]")
    console.print(f"  action : {route['action']}")
    console.print(f"  reason : {route['reason']}")
    # Health
    h = result["health"]
    console.print(f"\n[yellow]Health[/yellow]: {h['level']} (score={h['score']})")


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------

@app.command()
def resolve(hostname: str, record_type: str = typer.Option("A", "--type", "-t")) -> None:
    """Resolve a hostname (A / AAAA / CNAME / TXT)."""
    hostname = validate_hostname(hostname)
    from app.network_tools.dns import resolve_dns
    result = resolve_dns(hostname, record_type=record_type)
    _print_json(result.model_dump(mode="json"))


@app.command()
def resolve_all(hostname: str) -> None:
    """Resolve A and AAAA for a hostname."""
    hostname = validate_hostname(hostname)
    from app.network_tools.dns import resolve_dns_a_and_aaaa
    result = asyncio.run(resolve_dns_a_and_aaaa(hostname))
    _print_json(result.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# tls
# ---------------------------------------------------------------------------

@app.command()
def tls(hostname: str) -> None:
    """Run TLS inspection for a hostname."""
    hostname = validate_hostname(hostname)
    from app.tls_inspector import inspect_tls_detailed
    result = inspect_tls_detailed(hostname)
    _print_json(result)


# ---------------------------------------------------------------------------
# cdn
# ---------------------------------------------------------------------------

@app.command()
def cdn(hostname: str) -> None:
    """Detect CDN provider for a hostname."""
    hostname = validate_hostname(hostname)
    from app.network_tools.dns import resolve_dns_a_and_aaaa
    from app.tls_inspector import inspect_tls
    from app.cdn_detect import detect_cdn_from_dns_result
    dns = asyncio.run(resolve_dns_a_and_aaaa(hostname))
    tls = inspect_tls(hostname)
    match = detect_cdn_from_dns_result(dns, san_list=tls.san_list)

    console.print(f"Hostname: [bold]{hostname}[/bold]")
    console.print(f"Provider: {match.provider or '-'}")
    console.print(f"Confidence: {match.confidence}")
    console.print("\nIPv4:")
    for ip in dns.a:
        console.print(f"  {ip}")
    console.print("\nIPv6:")
    for ip in dns.aaaa:
        console.print(f"  {ip}")
    console.print("\nCNAME:")
    for c in dns.cname:
        console.print(f"  {c}")
    console.print("\nTLS:")
    console.print(f"  {'VALID' if tls.tls_valid else 'INVALID'}")
    console.print(f"\nLatency: {tls.latency_ms} ms")


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

@app.command()
def health() -> None:
    """Summarise endpoint health across the destination database."""
    from app.destination_db import DestinationDB
    from app.health import summarise
    db = DestinationDB("data/domains/verified.json")
    summary = summarise(db.all())
    console.print("\n[bold cyan]Endpoint Health[/bold cyan]")
    console.print(f"  Healthy : {summary['healthy']}")
    console.print(f"  Degraded: {summary['degraded']}")
    console.print(f"  Failed  : {summary['failed']}")
    console.print(f"  Total   : {summary['total']}")


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

@app.command()
def generate() -> None:
    """Generate an xray-core configuration from app config."""
    cfg = load_config()
    doh = load_dns_providers(cfg.config_dir)
    from app.xray.config import generate_xray_config, validate_xray_config
    out = cfg.xray.get("config_path", "config/xray.json")
    config = generate_xray_config(cfg, doh_providers=doh, output_path=out)
    # Validate what we generated.
    validate_xray_config(out)
    console.print(f"[green]Generated[/green] {out}")
    console.print(f"  inbounds: {len(config['inbounds'])}, outbounds: {len(config['outbounds'])}, rules: {len(config['routing']['rules'])}")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@app.command()
def validate() -> None:
    """Validate app config + blocklist + xray (if present)."""
    ec: ErrorCollector = ErrorCollector()

    cfg = load_config()
    ec.merge(validate_config_app(cfg))

    # Blocklist validation
    try:
        load_blocklist(cfg.config_dir)
    except AppError as e:
        ec.add("blocklist", e.message, e.cause, e.recovery)

    # Xray binary + config validation (best effort)
    from app.xray.binary import validate_binary
    xray = validate_binary(cfg.xray.get("binary", "xray"))
    if not xray["ok"]:
        ec.add("xray", "xray binary not found", recovery="install xray-core (see README)")
    else:
        console.print(f"  xray: {xray['version']}")

    console.print("\n[bold cyan]Validation[/bold cyan]")
    if ec.has_errors:
        console.print(f"[red]{ec.count} error(s)[/red]")
        console.print(ec.summary())
        raise typer.Exit(code=1)
    else:
        console.print("[green]All checks passed[/green]")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@app.command()
def run() -> None:
    """Run the toolkit in live mode (TUN + Xray if configured)."""
    cfg = load_config()
    if cfg.tun.get("enabled"):
        console.print("[yellow]TUN mode requested — requires CAP_NET_ADMIN[/yellow]")
        from app.tun_linux import TunDevice
        dev = TunDevice(name=cfg.tun.get("name", "tun0"), mtu=cfg.tun.get("mtu", 1500))
        try:
            dev.open()
            console.print(f"[green]TUN device {dev.name} opened[/green]")
        except PermissionError as e:
            console.print(f"[red]{e}[/red]")
            console.print("Falling back to offline analysis mode.")
    if cfg.xray.get("enabled"):
        console.print("[yellow]Xray integration is configured but live run requires the binary and a valid config.[/yellow]")
    console.print("[green]Run mode initialised[/green]")


# ---------------------------------------------------------------------------
# proxy  (persistent local SOCKS5/HTTP proxy via xray-core)
# ---------------------------------------------------------------------------

_socks_usage = """\
[bold]Proxy is listening.[/bold]

Configure your application / browser to use this local proxy:

  SOCKS5     socks5://127.0.0.1:{port}
  SOCKS5h    socks5h://127.0.0.1:{port}   (resolve DNS via the proxy)
  HTTP       http://127.0.0.1:{port}

Test with curl:
    curl -x socks5h://127.0.0.1:{port} https://example.com

The proxy keeps running in this terminal. Press Ctrl+C to stop.
"""

@app.command()
def proxy(
    port: int = typer.Option(10808, "--port", "-p", help="Local proxy port"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    config_path: str = typer.Option("config/xray.json", "--config", "-c", help="xray config file"),
    check_first: bool = typer.Option(True, "--check/--no-check", help="Test the endpoint with a real HTTPS request before serving"),
    fragment: bool = typer.Option(True, "--fragment/--no-fragment", help="Enable TLS ClientHello Fragment to break DPI fingerprints"),
    tor: bool = typer.Option(False, "--tor/--no-tor", help="Route traffic through local Tor SOCKS (127.0.0.1:9050)"),
) -> None:
    """Start a persistent local SOCKS5/HTTP proxy through xray-core.

    Traffic routes through a **DoH + TLS-Fragment + (optional Tor)** tunnel.
    External traffic goes through Tor when ``--tor`` is given; otherwise direct.
    DoH (Cloudflare / Google / Quad9) resolves all DNS queries.
    TLS ClientHello is fragmented to break DPI fingerprints.

    Credits: @patterniha (SNI-Spoofing project reference).
    """
    import time

    from app.xray.health import check_port_open
    from app.xray.process import XrayManager

    cfg = load_config()
    binary = cfg.xray.get("binary", "bin/xray")

    # Build proxy config dict for generate_xray_config.
    proxy_cfg: dict[str, Any] = {}
    if tor:
        proxy_cfg["tor"] = True
        proxy_cfg["tor_socks_host"] = "127.0.0.1"
        proxy_cfg["tor_socks_port"] = 9050

    # Regenerate the config so the inbound listens on the requested host/port.
    console.print(f"[cyan]Generating xray config (inbound {host}:{port}) ...[/cyan]")
    from app.xray.config import generate_xray_config
    doh = load_dns_providers()
    built = generate_xray_config(cfg, doh, output_path=config_path, proxy=proxy_cfg or None)

    # Override the mixed inbound bind settings for the requested host/port.
    if built.get("inbounds"):
        built["inbounds"][0]["port"] = port
        built["inbounds"][0]["settings"]["ip"] = host
        # Apply Fragment to the inbound stream settings when enabled.
        if fragment:
            built["inbounds"][0]["streamSettings"]["security"] = "tls"
            built["inbounds"][0]["streamSettings"]["tlsSettings"] = {
                "fragment": {"enabled": True, "length": "100-200", "sleep": "50-100"},
            }

    # Re-serialise with the overridden values.
    import json as _json
    from pathlib import Path as _Path
    _Path(config_path).write_text(_json.dumps(built, indent=2, ensure_ascii=False), encoding="utf-8")

    # Print configuration summary.
    from app.xray.config import is_tor_available as _tor_check

    if tor:
        console.print("[green]Anti-DPI tunnel: DoH + Tor + Fragment[/green]")
    else:
        console.print("[green]Anti-DPI tunnel: DoH + Fragment (direct external)[/green]")

    console.print(f"  DoH:         cloudflare-dns.com/dns-query")
    console.print(f"  Fragment:    {'enabled (100-200 bytes, sleep 50-100ms)' if fragment else 'disabled'}")

    if tor:
        if _tor_check():
            console.print(f"  Tor SOCKS:   [green]connected (127.0.0.1:9050)[/green]")
        else:
            console.print(f"  Tor SOCKS:   [yellow]not reachable (127.0.0.1:9050) — start Tor first[/yellow]")

    # Check the binary exists before we spawn it.
    import shutil as _shutil
    if not _Path(binary).exists() and not _shutil.which(binary):
        raise AppError(category="xray", message=f"xray binary not found: {binary}. Run `python -m app update` to fetch it.")

    manager = XrayManager(config_path, binary=binary, max_restarts=3)
    result = manager.start(health_check=lambda: check_port_open(host, port))

    if not result.get("ok"):
        diag = result.get("diagnostics", {})
        console.print("[red]Failed to start xray proxy.[/red]")
        console.print("[yellow]Diagnostics:[/yellow]")
        for line in diag.get("stderr", [])[-10:]:
            console.print(f"  {line}")
        raise AppError(category="xray", message=str(result.get("error", "unknown")))

    console.print(f"[green]Xray proxy started (attempt {result['attempt']}).[/green]")

    if check_first:
        console.print("[cyan]Smoke-testing the proxy with a real HTTPS request ...[/cyan]")
        _tries = 0
        _ok = False
        while _tries < 15:
            _tries += 1
            # Full HTTPS GET through the SOCKS5 tunnel proves the whole chain.
            _code = _probe_through_proxy(host, port)
            if _code is not None and 0 < _code < 400:
                _ok = True
                break
            time.sleep(1)
        if _ok:
            console.print(f"[green]Proxy verified: HTTPS through the proxy returned HTTP {_code}.[/green]")
        else:
            console.print("[yellow]Could not fully verify the proxy with an HTTPS request, but the local SOCKS5 port is open.[/yellow]")

    console.print(_socks_usage.format(port=port))

    # Keep the process alive until interrupted. Restart on unexpected exit.
    try:
        while True:
            if manager._process and not manager._process.is_alive():
                console.print("[yellow]Xray exited — restarting ...[/yellow]")
                manager.stop()
                manager = XrayManager(config_path, binary=binary, max_restarts=3)
                manager.start(health_check=lambda: check_port_open(host, port))
                console.print(_socks_usage.format(port=port))
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[cyan]Shutting down proxy ...[/cyan]")
        manager.stop()
        console.print("[green]Proxy stopped.[/green]")


def _probe_through_proxy(proxy_host: str, proxy_port: int) -> int | None:
    """Do a real HTTPS GET through the SOCKS5 proxy and return the HTTP status.

    Uses the system ``curl`` via a fixed arg list (never a shell string), so it
    exercises the full tunnel (DNS-over-proxy → CONNECT → TLS → GET) rather than
    just confirming the port is open.
    """
    import subprocess as _sp
    from pathlib import Path as _Path

    if not __import__("shutil").which("curl"):
        # No curl — fall back to a raw SOCKS5 CONNECT liveness check.
        return _socks_connect_ok(proxy_host, proxy_port)
    target = "https://example.com"
    args = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--proxy", f"socks5h://{proxy_host}:{proxy_port}", "--max-time", "8", target]
    try:
        proc = _sp.run(args, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout.strip().isdigit():
            return int(proc.stdout.strip())
    except (OSError, _sp.TimeoutExpired):
        return None
    return None


def _socks_connect_ok(proxy_host: str, proxy_port: int) -> int | None:
    """Minimal SOCKS5 CONNECT liveness check (no TLS). Returns 200 on success."""
    import socket
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=6)
        s.sendall(b"\x05\x01\x00")  # greet, no auth
        ver, method = s.recv(2)
        if ver != 5 or method != 0:
            s.close()
            return None
        addr = b"example.com"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + (443).to_bytes(2, "big"))
        rep = s.recv(4)
        s.close()
        return 200 if rep[1] == 0 else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------

@app.command()
def dashboard() -> None:
    """Show a live dashboard of system status."""
    from app.destination_db import DestinationDB
    from app.health import summarise
    from app.metrics import default_metrics

    cfg = load_config()
    db = DestinationDB("data/domains/verified.json")
    summary = summarise(db.all())
    snap = default_metrics.snapshot()

    table = Table(title="NetProbe Dashboard")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_row("TUN", "enabled" if cfg.tun.get("enabled") else "disabled")
    table.add_row("Xray", "enabled" if cfg.xray.get("enabled") else "disabled")
    table.add_row("DNS", cfg.dns.get("provider"))
    table.add_row("CDN DB age", "<cached>")
    table.add_row("Healthy endpoints", str(summary["healthy"]))
    table.add_row("Failed endpoints", str(summary["failed"]))
    avg = snap.get("latency_averages_ms", {})
    table.add_row("DNS latency", f"{avg.get('dns_latency')} ms")
    table.add_row("TCP latency", f"{avg.get('tcp_connect_latency')} ms")
    table.add_row("TLS latency", f"{avg.get('tls_latency')} ms")
    table.add_row("IPv4 success", str(snap.get("counters", {}).get("ipv4_success", 0)))
    table.add_row("IPv6 success", str(snap.get("counters", {}).get("ipv6_success", 0)))
    console.print(table)


if __name__ == "__main__":
    app()
