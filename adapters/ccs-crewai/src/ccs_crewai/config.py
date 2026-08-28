"""Configuration for the CCS CrewAI adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

__all__ = ["CCSConfig", "ReceiptSink", "ReceiptRecord", "PolicyDecision"]


# A receipt sink receives every signed receipt (L1 + behavior) as a record.
ReceiptSink = Callable[["ReceiptRecord"], None]


def _stdout_sink(record: "ReceiptRecord") -> None:
    """Default sink: emit each receipt pair as a single line of JSON to stdout."""
    import json

    print(json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True), flush=True)


@dataclass
class ReceiptRecord:
    """A pair of signed receipts emitted for a single tool call."""

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
class PolicyDecision:
    """A pre-admission policy decision for a tool call.

    Attributes:
        allowed: ``True`` when the tool may execute; ``False`` blocks it.
        reason: Human-readable reason for the decision. For blocked calls this
            is stamped into the L1 ``rule_summary``.
        metadata: Optional structured metadata preserved for audit/sinks.

    Class-level constants :data:`ALLOW` and :data:`BLOCK` are provided for
    convenience so callers may write ``return PolicyDecision.BLOCK``.
    """

    allowed: bool
    reason: str = "no_rules_matched"
    metadata: dict[str, Any] = field(default_factory=dict)


# Sentinel constants for the common allow/block cases. They are populated
# after the class is defined so they can be used as ``PolicyDecision.ALLOW``.
PolicyDecision.ALLOW = PolicyDecision(allowed=True, reason="allowed_by_policy")
PolicyDecision.BLOCK = PolicyDecision(allowed=False, reason="blocked_by_policy")


# A policy callable receives the tool name, arguments, and runtime context and
# returns a :class:`PolicyDecision`.
PolicyCallable = Callable[[str, dict[str, Any], dict[str, Any]], PolicyDecision]


def _default_policy(
    tool_name: str,
    tool_input: dict[str, Any],
    runtime_context: dict[str, Any],
) -> PolicyDecision:
    """Default allow-all policy. Override with a custom callable for rules."""
    return PolicyDecision(allowed=True, reason="no_rules_matched")


@dataclass
class CCSConfig:
    """Configuration for :class:`~ccs_crewai.CCSGuardrailProvider`.

    Two deployment modes are supported:

    * ``"in-process"`` (default): the Ed25519 signing key is derived
      deterministically from *seed* using
      ``Ed25519PrivateKey.from_private_bytes(sha256(seed))``.
    * ``"sidecar"``: the private key never enters the CrewAI process. The
      adapter calls an external signing endpoint (*sidecar_url*) for every
      signature.

    Args:
        deployment_mode: ``"in-process"`` or ``"sidecar"``.
        seed: Deterministic seed bytes for in-process key derivation.
        sidecar_url: HTTP(S) endpoint of the external CCS signer.
        signer: Optional custom signer. Overrides *seed* / *sidecar_url*.
        public_key: Base64 raw 32-byte Ed25519 public key (sidecar mode).
        policy: Callable invoked before every tool execution. It must return a
            :class:`PolicyDecision`; blocked decisions prevent execution and
            emit an L1 receipt with ``verdict="block"``.
        rule_version: CCS rule set version stamped into every L1 receipt.
        rule_summary: Static rule summary for allowed calls.
        issuer: Identifier of the receipt issuer.
        audience: Intended audience for the receipts.
        trace_id: Optional fixed trace/session id. If ``None`` one is generated.
        receipt_ttl_seconds: Validity window for ``expires_at``.
        max_clock_skew: Clock-tolerance seconds stamped into L1 receipts.
        verifier_source_class: Value for the L1 ``verifier_source_class`` field.
        sink: Callback invoked with each :class:`ReceiptRecord`. Defaults to
            stdout JSON lines. Pass a no-op to suppress output.
        include_behavior_receipts: When ``True`` (default) a linked
            ``ccs.behavior_evidence.v1`` receipt is produced for every call.
        action_suffix: Suffix used to build the L1 ``action`` field.
        fail_closed: When ``True`` (default), exceptions in the policy callable
            block the tool call. When ``False``, exceptions allow execution.
    """

    deployment_mode: str = "in-process"
    seed: Optional[bytes] = None
    sidecar_url: Optional[str] = None
    signer: Optional[Any] = None
    public_key: Optional[str] = None

    policy: PolicyCallable = field(default=_default_policy)
    rule_version: str = "1.3.0"
    rule_summary: str = "no_rules_matched"
    issuer: str = "ccs-crewai"
    audience: str = "crewai-agent"
    trace_id: Optional[str] = None

    receipt_ttl_seconds: float = 300.0
    max_clock_skew: float = 0.0
    verifier_source_class: str = "CrewAIAdapter"

    sink: ReceiptSink = field(default=_stdout_sink)
    include_behavior_receipts: bool = True
    action_suffix: str = "execute"
    fail_closed: bool = True

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
