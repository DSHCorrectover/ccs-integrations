"""Verification errors."""

from __future__ import annotations


class VerificationError(Exception):
    """Raised when a CCS receipt fails structural or cryptographic verification."""

    def __init__(self, reason: str, field: str | None = None) -> None:
        self.reason = reason
        self.field = field
        super().__init__(f"{field}: {reason}" if field else reason)
