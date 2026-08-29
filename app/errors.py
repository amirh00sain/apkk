"""Centralised error types."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AppError(Exception):
    """Structured error with category, message, cause and recovery.

    Inherits from Exception so that ``raise AppError(...)`` works with
    Typer's error handling and ``except AppError`` in calling code.
    """

    category: str = "unknown"
    message: str = ""
    cause: str = ""
    recovery: str = ""

    def __str__(self) -> str:
        parts = [f"[{self.category}] {self.message}"]
        if self.cause:
            parts.append(f"  cause: {self.cause}")
        if self.recovery:
            parts.append(f"  recovery: {self.recovery}")
        return "\n".join(parts)

    def __str__(self) -> str:
        parts = [f"[{self.category}] {self.message}"]
        if self.cause:
            parts.append(f"  cause: {self.cause}")
        if self.recovery:
            parts.append(f"  recovery: {self.recovery}")
        return "\n".join(parts)


@dataclass
class ErrorCollector:
    """Thread-safe collector for errors during an operation."""

    errors: list[AppError] = field(default_factory=list)

    def add(self, category: str, message: str, cause: str = "", recovery: str = "") -> None:
        self.errors.append(AppError(category=category, message=message, cause=cause, recovery=recovery))

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def merge(self, other: "ErrorCollector") -> None:
        """Merge another collector's errors into this one."""
        self.errors.extend(other.errors)

    @property
    def count(self) -> int:
        return len(self.errors)

    def summary(self) -> str:
        if not self.errors:
            return "No errors."
        lines = [f"{len(self.errors)} error(s):"]
        for e in self.errors:
            lines.append(f"  - {e}")
        return "\n".join(lines)
