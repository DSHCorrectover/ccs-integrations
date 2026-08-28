"""JCS canonical JSON (RFC 8785) and SHA-256 hashing helpers.

All CCS receipts are signed over JCS-canonicalized JSON so that signatures are
byte-reproducible across languages and implementations. These helpers centralise
the canonicalization so that :mod:`ccs_crewai.signer` and
:mod:`ccs_crewai.receipt_builder` never diverge from the canonical form used by
``ccs-verifier``.
"""

from __future__ import annotations

import hashlib
from typing import Any

import jcs

__all__ = [
    "canonical_json",
    "sha256_hex",
    "sha256_digest",
    "canonical_sha256_hex",
    "jcs_digest",
]


def canonical_json(data: Any) -> bytes:
    """Return the RFC 8785 JCS canonical JSON byte representation of *data*.

    Raises:
        ValueError: if *data* contains integers outside the RFC 8785 safe range
            (plus/minus (2**53 - 1)).
    """
    _validate_safe_integers(data)
    return jcs.canonicalize(data)


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of raw *data* bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_digest(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def canonical_sha256_hex(data: Any) -> str:
    """Canonicalize *data* with JCS and return its hex SHA-256 digest.

    Used for ``request_hash``, ``response_hash``, ``params_hash``,
    ``args_digest``, ``runtime_context_hash``, ``config_hash`` and the
    ``linked_l1_receipt_digest`` chain link.
    """
    return sha256_hex(canonical_json(data))


# Semantically explicit alias used for the chain link.
jcs_digest = canonical_sha256_hex


_MAX_SAFE_INTEGER = (1 << 53) - 1
_MIN_SAFE_INTEGER = -(1 << 53) + 1


def _validate_safe_integers(data: Any) -> None:
    """Reject integers outside the RFC 8785 section 6.2 safe-integer range.

    Mirrors the check performed by the CCS verifier's canonicalization helper.
    Booleans (``int`` subclasses) are excluded.
    """
    if isinstance(data, bool):
        return
    if isinstance(data, int):
        if data > _MAX_SAFE_INTEGER or data < _MIN_SAFE_INTEGER:
            raise ValueError(
                f"Integer {data} is outside the RFC 8785 safe range "
                f"[{_MIN_SAFE_INTEGER}, {_MAX_SAFE_INTEGER}]; cannot canonicalize."
            )
    elif isinstance(data, dict):
        for key, value in data.items():
            _validate_safe_integers(key)
            _validate_safe_integers(value)
    elif isinstance(data, (list, tuple)):
        for item in data:
            _validate_safe_integers(item)
