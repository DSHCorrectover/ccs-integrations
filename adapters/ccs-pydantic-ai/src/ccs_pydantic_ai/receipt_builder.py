"""Build signed CCS L1 action receipts and linked behavior evidence receipts.

The :class:`ReceiptBuilder` is intentionally framework-agnostic: it receives
plain Python values (tool name, args dict, response/exception, timing, runtime
context) and produces the exact 30-field dict that
``ccs_verifier.ccs_verifier_l1.L1Receipt.from_dict(data, strict=True)`` accepts,
plus the linked ``ccs.behavior_evidence.v1`` receipt.

Field/hash semantics
--------------------
The L1 receipt binds four layers of context with SHA-256 over JCS:

* ``args_digest``  — canonical hash of the tool arguments alone.
* ``params_hash``  — canonical hash of the parameter *schema/shape* (sorted
  argument keys + tool name), independent of values.
* ``request_hash`` — canonical hash of the full request envelope
  ``{"tool": name, "args": args, "tool_call_id": id}``.
* ``response_hash``— canonical hash of the (JSON-serialisable) response, or of
  ``{"error": "<type>", "message": str}`` for blocked/failed calls.
* ``runtime_context_hash`` / ``config_hash`` — hash of the runtime context
  (run/step/message ids) and the static CCS configuration, respectively.

All hashes use :func:`ccs_pydantic_ai.hashing.canonical_sha256_hex` so they
match the canonicalization used by ``ccs-verifier`` and the conformance vectors.
"""

from __future__ import annotations

import json
import secrets
import time
import traceback
from dataclasses import dataclass
from typing import Any, Optional

from .hashing import canonical_json, canonical_sha256_hex, sha256_hex
from .signer import CCSSigner

__all__ = [
    "ReceiptBuilder",
    "BuiltReceipts",
    "L1_RECEIPT_VERSION",
    "BEHAVIOR_RECEIPT_TYPE",
]

L1_RECEIPT_VERSION = "1.1"
BEHAVIOR_RECEIPT_TYPE = "ccs.behavior_evidence.v1"

# Exact field set of ccs_verifier.L1Receipt (30 fields). Used to guarantee the
# generated dict is accepted by ``from_dict(..., strict=True)`` with no unknown
# fields and no missing fields.
L1_FIELDS: tuple[str, ...] = (
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
)

BEHAVIOR_FIELDS: tuple[str, ...] = (
    "receipt_type",
    "trace_id",
    "tool_call_id",
    "sequence",
    "linked_l1_receipt_digest",
    "behavior_evidence_verdict",
    "evidence_ref",
    "issuer",
    "audience",
    "issued_at",
    "deployment_mode",
    "signing_algorithm",
    "public_key_fingerprint",
    "public_key",
    "signature",
)


@dataclass
class BuiltReceipts:
    """The two signed receipts produced for a single tool call."""

    l1: dict[str, Any]
    behavior: Optional[dict[str, Any]]

    @property
    def verdict(self) -> str:
        return self.l1["verdict"]

    def as_record(self) -> dict[str, Any]:
        """Return a JSON-serialisable record suitable for a receipt sink."""
        return {"l1": self.l1, "behavior": self.behavior}


def _json_safe(value: Any) -> Any:
    """Coerce arbitrary tool responses/errors into JSON/JCS-serialisable form."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    # Fall back to repr for unknown objects (datetimes, custom classes, etc.).
    return repr(value)


def _error_envelope(exc: BaseException) -> dict[str, str]:
    return {
        "error": type(exc).__name__,
        "message": str(exc),
    }


class ReceiptBuilder:
    """Builds and signs L1 + behavior receipts for tool calls."""

    def __init__(
        self,
        signer: CCSSigner,
        *,
        rule_version: str,
        rule_summary: str,
        issuer: str,
        audience: str,
        trace_id: str,
        verifier_source_class: str = "PydanticAIAdapter",
        receipt_ttl_seconds: float = 300.0,
        max_clock_skew: float = 0.0,
        action_suffix: str = "execute",
        include_behavior: bool = True,
    ) -> None:
        self._signer = signer
        self._rule_version = rule_version
        self._rule_summary = rule_summary
        self._issuer = issuer
        self._audience = audience
        self._trace_id = trace_id
        self._verifier_source_class = verifier_source_class
        self._receipt_ttl = float(receipt_ttl_seconds)
        self._max_clock_skew = float(max_clock_skew)
        self._action_suffix = action_suffix
        self._include_behavior = include_behavior

        # Deterministic-ish config hash: all static config that affects receipt
        # content, canonicalized once.
        config_envelope = {
            "rule_version": rule_version,
            "issuer": issuer,
            "audience": audience,
            "deployment_mode": signer.deployment_mode,
            "verifier_source_class": verifier_source_class,
            "receipt_ttl_seconds": receipt_ttl_seconds,
            "max_clock_skew": max_clock_skew,
            "public_key_fingerprint": signer.public_key_fingerprint,
        }
        self._config_hash = canonical_sha256_hex(config_envelope)

        self._sequence = 0

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def build(
        self,
        *,
        tool: str,
        tool_call_id: str,
        args: dict[str, Any],
        runtime_context: Optional[dict[str, Any]] = None,
        result: Any = None,
        error: Optional[BaseException] = None,
        blocked: bool = False,
        block_reason: Optional[str] = None,
        started_at: Optional[float] = None,
        ended_at: Optional[float] = None,
    ) -> BuiltReceipts:
        """Build and sign the L1 + behavior receipts for one tool call.

        Args:
            tool: Tool name as known to the agent.
            tool_call_id: The model-provided tool call id.
            args: Validated tool arguments.
            runtime_context: Optional dict of runtime context (run id, step,
                message ids, model name, …). Canonicalised into
                ``runtime_context_hash``.
            result: The raw return value of the tool (when allowed).
            error: The exception raised by the tool (when failed).
            blocked: ``True`` if the call was blocked by a CCS rule before the
                tool body ran.
            block_reason: Human-readable rule summary for the block.
            started_at / ended_at: Wall-clock timestamps (``time.time()``). If
                omitted, both default to the current time.

        Returns:
            A :class:`BuiltReceipts` with the signed L1 and behavior dicts.
        """
        now = time.time()
        started_at = now if started_at is None else started_at
        ended_at = now if ended_at is None else ended_at
        latency_us = max(0.0, (ended_at - started_at) * 1_000_000)

        sequence = self._sequence
        self._sequence += 1

        # --- verdict / rule summary --------------------------------------
        if blocked or error is not None:
            verdict = "block"
            rule_summary = block_reason or (
                f"{type(error).__name__}: {error}" if error is not None else "blocked"
            )
            behavior_verdict = "observed_and_rejected"
        else:
            verdict = "allow"
            rule_summary = self._rule_summary
            behavior_verdict = "not_observed"

        # --- hashes -------------------------------------------------------
        safe_args = _json_safe(args) if isinstance(args, dict) else _json_safe(args)
        args_digest = canonical_sha256_hex(safe_args)

        # Parameter shape: sorted arg keys + tool name (value-independent).
        param_keys = sorted(safe_args.keys()) if isinstance(safe_args, dict) else []
        params_hash = canonical_sha256_hex({"tool": tool, "param_keys": param_keys})

        request_envelope = {
            "tool": tool,
            "tool_call_id": tool_call_id,
            "args": safe_args,
        }
        request_hash = canonical_sha256_hex(request_envelope)

        if blocked:
            response_body: Any = {"blocked": True, "reason": block_reason or "blocked"}
        elif error is not None:
            response_body = _error_envelope(error)
        else:
            response_body = _json_safe(result)
        response_hash = canonical_sha256_hex(response_body)

        ctx_envelope = {
            "trace_id": self._trace_id,
            "tool_call_id": tool_call_id,
            "runtime": _json_safe(runtime_context or {}),
        }
        runtime_context_hash = canonical_sha256_hex(ctx_envelope)

        # --- assemble unsigned L1 ----------------------------------------
        issued_at = ended_at
        expires_at = issued_at + self._receipt_ttl
        nonce = secrets.token_hex(16)
        action = f"{tool}.{self._action_suffix}"

        l1_unsigned: dict[str, Any] = {
            "trace_id": self._trace_id,
            "receipt_version": L1_RECEIPT_VERSION,
            "verdict": verdict,
            "timestamp": started_at,
            "tool": tool,
            "tool_call_id": tool_call_id,
            "params_hash": params_hash,
            "args_digest": args_digest,
            "rule_summary": rule_summary,
            "rule_version": self._rule_version,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "runtime_context_hash": runtime_context_hash,
            "config_hash": self._config_hash,
            "verifier_source_class": self._verifier_source_class,
            "deployment_mode": self._signer.deployment_mode,
            "issuer": self._issuer,
            "audience": self._audience,
            "nonce": nonce,
            "sequence": sequence,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "max_clock_skew": self._max_clock_skew,
            "action": action,
            "signing_algorithm": self._signer.signing_algorithm,
            "public_key_fingerprint": self._signer.public_key_fingerprint,
            "public_key": self._signer.public_key_b64,
            "verified_at": ended_at,
            "latency_us": round(latency_us, 3),
        }

        # Sign (signature field excluded inside signer).
        signature = self._signer.sign(l1_unsigned)
        l1 = dict(l1_unsigned)
        l1["signature"] = signature

        # Guarantee exact 30-field shape / key order for strict parse.
        assert set(l1.keys()) == set(L1_FIELDS), (
            f"L1 field mismatch: extra={set(l1)-set(L1_FIELDS)} "
            f"missing={set(L1_FIELDS)-set(l1)}"
        )
        l1 = {k: l1[k] for k in L1_FIELDS}

        # --- linked behavior evidence receipt ----------------------------
        behavior: Optional[dict[str, Any]] = None
        if self._include_behavior:
            behavior = self._build_behavior(
                l1=l1,
                sequence=sequence,
                behavior_verdict=behavior_verdict,
                rule_summary=rule_summary,
                issued_at=issued_at,
            )

        return BuiltReceipts(l1=l1, behavior=behavior)

    # ------------------------------------------------------------------ #
    # Behavior evidence
    # ------------------------------------------------------------------ #
    def _build_behavior(
        self,
        *,
        l1: dict[str, Any],
        sequence: int,
        behavior_verdict: str,
        rule_summary: str,
        issued_at: float,
    ) -> dict[str, Any]:
        # linked_l1_receipt_digest = sha256(JCS(L1 excluding signature))
        l1_excluding_sig = {k: v for k, v in l1.items() if k != "signature"}
        linked_digest = "sha256:" + sha256_hex(canonical_json(l1_excluding_sig))

        evidence_ref = {
            "type": "rule_scan_complete",
            "rule_id": rule_summary,
            "verifier": "ccs-pydantic-ai",
            "rule_version": self._rule_version,
        }

        behavior_unsigned: dict[str, Any] = {
            "receipt_type": BEHAVIOR_RECEIPT_TYPE,
            "trace_id": l1["trace_id"],
            "tool_call_id": l1["tool_call_id"],
            "sequence": sequence,
            "linked_l1_receipt_digest": linked_digest,
            "behavior_evidence_verdict": behavior_verdict,
            "evidence_ref": evidence_ref,
            "issuer": self._issuer,
            "audience": self._audience,
            "issued_at": issued_at,
            "deployment_mode": self._signer.deployment_mode,
            "signing_algorithm": self._signer.signing_algorithm,
            "public_key_fingerprint": self._signer.public_key_fingerprint,
            "public_key": self._signer.public_key_b64,
        }

        signature = self._signer.sign(behavior_unsigned)
        behavior = dict(behavior_unsigned)
        behavior["signature"] = signature

        assert set(behavior.keys()) == set(BEHAVIOR_FIELDS)
        return {k: behavior[k] for k in BEHAVIOR_FIELDS}


def linked_l1_digest(l1_receipt: dict[str, Any]) -> str:
    """Compute the ``linked_l1_receipt_digest`` for an L1 receipt.

    Exposed for tests and for callers that want to verify a chain link without a
    full :class:`ReceiptBuilder`.
    """
    excluding_sig = {k: v for k, v in l1_receipt.items() if k != "signature"}
    return "sha256:" + sha256_hex(canonical_json(excluding_sig))
