"""gui/main.py — Flet GUI: a single centered Connect/Disconnect button.

The connect flow runs on a worker thread so the Flet UI never blocks.  All the
real work lives in :mod:`gui.backend` (``ConnectionController``), which is
unit-testable without Flet.
"""

from __future__ import annotations

import threading
from typing import Any

import flet as ft

from gui.backend import ConnectionController

# Where the CI/local build puts the xray binary relative to the app.
XRAY_BINARY_DEFAULT = "bin/xray"
XRAY_CONFIG_DEFAULT = "config/xray-gui.json"


def main(page: ft.Page) -> None:  # noqa: C901 — UI code, branchiness is fine
    page.title = "NetProbe — DoH + Tor + Fragment (TUN)"
    page.theme_mode = ft.ThemeMode.SYSTEM
    page.padding = 40
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    # --- state ---------------------------------------------------------------
    controller: ConnectionController | None = None
    worker: threading.Thread | None = None

    # --- widgets -------------------------------------------------------------
    title = ft.Text(
        "NetProbe",
        size=32,
        weight=ft.FontWeight.BOLD,
    )
    subtitle = ft.Text(
        "DoH + Tor + Fragment on TUN",
        size=14,
        color=ft.Colors.with_opacity(0.6, ft.Colors.ON_SURFACE),
    )

    status = ft.Text(
        "Idle — press Connect",
        size=16,
        text_align=ft.TextAlign.CENTER,
        color=ft.Colors.ON_SURFACE_VARIANT,
    )
    detail = ft.Text(
        "",
        size=12,
        text_align=ft.TextAlign.CENTER,
        max_lines=8,
        overflow=ft.TextOverflow.ELLIPSIS,
        color=ft.Colors.with_opacity(0.7, ft.Colors.ON_SURFACE),
    )

    connect_btn = ft.ElevatedButton(
        text="Connect",
        width=220,
        height=56,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=28),
            bgcolor=ft.Colors.GREEN_700,
            color=ft.Colors.WHITE,
        ),
    )

    def set_busy(busy: bool) -> None:
        connect_btn.disabled = busy
        connect_btn.text = "…" if busy else connect_btn_text()
        page.update()

    def connect_btn_text() -> str:
        if controller and controller.state in ("connecting", "connected"):
            return "Disconnect"
        return "Connect"

    def on_result(result: dict[str, Any]) -> None:
        """Called (on the UI thread via page.run_thread wrapper) after connect/disconnect."""
        nonlocal controller, worker
        ok = result.get("ok", False)
        if ok:
            status.value = "Connected"
            status.color = ft.Colors.GREEN_400
            detail.value = result.get("message", "")
            connect_btn.text = "Disconnect"
            connect_btn.style = ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=28),
                bgcolor=ft.Colors.RED_700,
                color=ft.Colors.WHITE,
            )
        else:
            status.value = "Failed"
            status.color = ft.Colors.RED_400
            detail.value = str(result.get("error", "unknown error"))
            connect_btn.text = "Connect"
            connect_btn.style = ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=28),
                bgcolor=ft.Colors.GREEN_700,
                color=ft.Colors.WHITE,
            )
        connect_btn.disabled = False
        page.update()

    def worker_connect() -> None:
        nonlocal controller
        controller = ConnectionController(
            config_path=XRAY_CONFIG_DEFAULT,
            binary_path=XRAY_BINARY_DEFAULT,
            tun_cfg={"tor": True, "fragment": True, "port": 10808},
        )
        try:
            result = controller.connect()
        except Exception as exc:  # defensive: never crash the UI thread
            result = {"ok": False, "error": f"unexpected: {exc}"}
        # Marshal back onto the UI thread.
        page.run_thread(lambda: on_result(result))

    def worker_disconnect() -> None:
        nonlocal controller
        if controller is None:
            on_result({"ok": True, "message": "Idle"})
            return
        try:
            result = controller.disconnect()
        except Exception as exc:
            result = {"ok": False, "error": f"unexpected: {exc}"}
        page.run_thread(lambda: on_result(result))

    def on_button_click(_e: ft.ControlEvent) -> None:
        nonlocal worker
        if controller and controller.state in ("connecting", "connected"):
            status.value = "Disconnecting…"
            status.color = ft.Colors.ON_SURFACE_VARIANT
            detail.value = ""
            connect_btn.disabled = True
            page.update()
            worker = threading.Thread(target=worker_disconnect, daemon=True)
            worker.start()
        else:
            status.value = "Connecting…"
            status.color = ft.Colors.ON_SURFACE_VARIANT
            detail.value = ""
            connect_btn.disabled = True
            page.update()
            worker = threading.Thread(target=worker_connect, daemon=True)
            worker.start()

    connect_btn.on_click = on_button_click

    page.add(
        ft.Column(
            [
                title,
                subtitle,
                ft.Container(height=20),
                connect_btn,
                ft.Container(height=12),
                status,
                detail,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            tight=True,
        )
    )


def app_entry() -> None:
    """Entry point used by `flet run gui/main.py` and the packaged builds."""
    ft.app(target=main)


if __name__ == "__main__":
    app_entry()
