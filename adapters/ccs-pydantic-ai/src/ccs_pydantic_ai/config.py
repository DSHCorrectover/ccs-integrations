"""Configuration for the CCS Pydantic AI adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

__all__ = ["CCSConfig", "ReceiptSink", "ReceiptRecord"]

# A receipt sink receives every signed receipt (L1 + behavior) as a record.
ReceiptSink = Callable[["ReceiptRecord"], None]


def _stdout_sink(record: "ReceiptRecord") -> None:
    """Default sink: emit each receipt pair as a single line of JSON to stdout."""
    import json

    print(json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True), flush=True)


@dataclass
class ReceiptRecord:
    """A pair of signed receipts emitted for a single tool call.

    Attributes:
        l1: The 30-field CCS L1 action receipt (authorization / chain integrity).
        behavior: The linked ``ccs.behavior_evidence.v1`` receipt (semantic
            observation). ``None`` if behavior evidence was not produced.
        trace_id: The trace/session identifier shared by both receipts.
        tool_call_id: The tool call identifier shared by both receipts.
        verdict: ``"allow"`` or ``"block"`` mirroring ``l1["verdict"]``.
    """

    l1: dict[str, Any]
    behavior: Optional[dict[str, Any]]
    trace_id: str
    tool_call_id: str
    verdict: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "l1": self.l1,
            "behavior": self.behavior,
            "trace_id": self.trace_id,
            "tool_call_id": self.tool_call_id,
            "verdict": self.verdict,
        }


@dataclass
class CCSConfig:
    """Configuration for :class:`~ccs_pydantic_ai.CCSToolset`.

    Two deployment modes are supported:

    * ``"in-process"`` (default): the Ed25519 signing key is derived
      deterministically from *seed* using
      ``Ed25519PrivateKey.from_private_bytes(sha256(seed))``. This gives
      byte-reproducible receipts across runs. The private key lives inside the
      agent process, so process compromise enables forgery.
    * ``"sidecar"``: the private key never enters the agent process. The adapter
      calls an external signing endpoint (*sidecar_url*) for every signature.
      Supply the trusted base64 *public_key* for local verification.

    Args:
        deployment_mode: ``"in-process"`` or ``"sidecar"``.
        seed: Deterministic seed bytes for in-process key derivation.
        sidecar_url: HTTP(S) endpoint of the external CCS signer.
        signer: Optional custom signer. Overrides *seed* / *sidecar_url*.
        public_key: Base64 raw 32-byte Ed25519 public key (sidecar mode).
        rule_version: CCS rule set version stamped into every L1 receipt.
        rule_summary: Static rule summary for allowed calls.
        issuer: Identifier of the receipt issuer.
        audience: Intended audience for the receipts.
        trace_id: Optional fixed trace/session id. If ``None`` one is generated
            per run.
        receipt_ttl_seconds: Validity window for ``expires_at``.
        max_clock_skew: Clock-tolerance seconds stamped into L1 receipts.
        verifier_source_class: Value for the L1 ``verifier_source_class`` field.
        sink: Callback invoked with each :class:`ReceiptRecord`. Defaults to
            stdout JSON lines. Pass a no-op to suppress output.
        include_behavior_receipts: When ``True`` (default) a linked
            ``ccs.behavior_evidence.v1`` receipt is produced for every call.
        action_suffix: Suffix used to build the L1 ``action`` field as
            ``"<tool>.<action_suffix>"``.
    """

    deployment_mode: str = "in-process"
    seed: Optional[bytes] = None
    sidecar_url: Optional[str] = None
    signer: Optional[Any] = None
    public_key: Optional[str] = None

    rule_version: str = "1.3.0"
    rule_summary: str = "no_rules_matched"
    issuer: str = "ccs-pydantic-ai"
    audience: str = "pydantic-ai-agent"
    trace_id: Optional[str] = None

    receipt_ttl_seconds: float = 300.0
    max_clock_skew: float = 0.0
    verifier_source_class: str = "PydanticAIAdapter"

    sink: ReceiptSink = field(default=_stdout_sink)
    include_behavior_receipts: bool = True
    action_suffix: str = "execute"

    def __post_init__(self) -> None:
        if self.deployment_mode not in ("in-process", "sidecar"):
            raise ValueError(
                f"deployment_mode must be 'in-process' or 'sidecar', "
                f"got {self.deployment_mode!r}"
            )
        if self.signer is None:
            if self.deployment_mode == "in-process":
                if self.seed is None:
                    raise ValueError(
                        "seed is required for in-process mode "
                        "(or supply a custom signer)."
                    )
            else:
                if self.sidecar_url is None and self.public_key is None:
                    raise ValueError(
                        "sidecar mode requires sidecar_url or an explicit "
                        "public_key (or supply a custom signer)."
                    )
        if self.receipt_ttl_seconds < 0:
            raise ValueError("receipt_ttl_seconds must be non-negative")
