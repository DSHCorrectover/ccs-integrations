"""L1 receipt structural and cryptographic verification (MIT, open-source)."""

from __future__ import annotations

import base64
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..hashing import canonical_json
from .errors import VerificationError

# Must match ReceiptBuilder.L1_FIELDS exactly (30 fields).
L1_FIELDS: frozenset[str] = frozenset({
    "trace_id",
    "receipt_version",
    "verdict",
    "timestamp",
    "tool",
    "tool_call_id",
    "params_hash",
    "args_digest",
    "rule_summary",
    "rule_version",
    "request_hash",
    "response_hash",
    "runtime_context_hash",
    "config_hash",
    "verifier_source_class",
    "deployment_mode",
    "issuer",
    "audience",
    "nonce",
    "sequence",
    "issued_at",
    "expires_at",
    "max_clock_skew",
    "action",
    "signature",
    "signing_algorithm",
    "public_key_fingerprint",
    "public_key",
    "verified_at",
    "latency_us",
})

_REQUIRED_NONEMPTY = (
    "trace_id",
    "receipt_version",
    "verdict",
    "tool",
    "tool_call_id",
    "issuer",
    "audience",
    "nonce",
    "action",
    "signing_algorithm",
    "public_key",
    "signature",
)


def verify_l1_signature(receipt: dict[str, Any]) -> tuple[bool, str]:
    """Verify the Ed25519 signature over JCS(receipt minus signature)."""
    try:
        signature_b64 = receipt["signature"]
        public_key_b64 = receipt["public_key"]
    except KeyError as exc:
        return False, f"missing field: {exc}"

    try:
        pub_bytes = base64.b64decode(public_key_b64)
        sig_bytes = base64.b64decode(signature_b64)
    except Exception as exc:  # noqa: BLE001
        return False, f"base64 decode error: {exc}"

    if len(pub_bytes) != 32:
        return False, f"public key must be 32 bytes, got {len(pub_bytes)}"
    if len(sig_bytes) != 64:
        return False, f"signature must be 64 bytes, got {len(sig_bytes)}"

    signed = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, canonical_json(signed))
    except InvalidSignature:
        return False, "signature does not verify"
    except Exception as exc:  # noqa: BLE001
        return False, f"verification error: {exc}"

    return True, "ok"


def validate_l1_structure(receipt: dict[str, Any]) -> tuple[bool, str]:
    """Check that *receipt* has exactly 30 known fields and required values."""
    if not isinstance(receipt, dict):
        return False, "receipt must be a dict"

    keys = set(receipt.keys())
    extra = keys - L1_FIELDS
    missing = L1_FIELDS - keys
    if extra:
        return False, f"unknown fields: {sorted(extra)}"
    if missing:
        return False, f"missing fields: {sorted(missing)}"

    for field in _REQUIRED_NONEMPTY:
        val = receipt.get(field)
        if val is None or (isinstance(val, str) and not val):
            return False, f"field {field!r} must be non-empty"

    if receipt["verdict"] not in ("allow", "block"):
        return False, f"verdict must be 'allow' or 'block', got {receipt['verdict']!r}"

    if receipt["signing_algorithm"] != "Ed25519":
        return False, (
            f"signing_algorithm must be 'Ed25519', "
            f"got {receipt['signing_algorithm']!r}"
        )

    if not isinstance(receipt["sequence"], int) or receipt["sequence"] < 0:
        return False, "sequence must be a non-negative integer"

    for ts_field in ("timestamp", "issued_at", "expires_at", "verified_at"):
        val = receipt.get(ts_field)
        if not isinstance(val, (int, float)):
            return False, f"{ts_field} must be numeric"

    if receipt["expires_at"] < receipt["issued_at"]:
        return False, "expires_at must be >= issued_at"

    fpr = receipt.get("public_key_fingerprint", "")
    if not (isinstance(fpr, str) and len(fpr) == 16):
        return False, "public_key_fingerprint must be 16 hex characters"
    try:
        int(fpr, 16)
    except ValueError:
        return False, "public_key_fingerprint must be hex"

    return True, "ok"


def verify_l1_receipt(
    receipt: dict[str, Any],
    *,
    check_expiry: bool = False,
    now: float | None = None,
) -> tuple[bool, str]:
    """Full L1 verification: structure + signature."""
    ok, reason = validate_l1_structure(receipt)
    if not ok:
        return False, reason

    ok, reason = verify_l1_signature(receipt)
    if not ok:
        return False, reason

    if check_expiry:
        current = now if now is not None else time.time()
        if current > receipt["expires_at"] + receipt.get("max_clock_skew", 0):
            return False, "receipt has expired"

    return True, "ok"
