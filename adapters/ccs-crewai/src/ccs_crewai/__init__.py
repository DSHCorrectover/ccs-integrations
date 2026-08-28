"""ccs-crewai — CCS runtime receipts for CrewAI agents.

Two-line integration::

    from ccs_crewai import CCSConfig, CCSGuardrailProvider, enable_guardrail

    provider = CCSGuardrailProvider(
        CCSConfig(seed=b"my-app-seed", policy=my_policy)
    )
    enable_guardrail(provider)

Every tool call then emits a signed 30-field CCS L1 action receipt and a linked
``ccs.behavior_evidence.v1`` receipt to the configured sink. Denied calls are
blocked before execution and documented with a signed ``verdict="block"``
receipt. Receipts can be independently verified without CrewAI installed::

    from ccs_crewai import verify_l1_receipt, verify_chain
    ok, reason = verify_l1_receipt(receipt_dict)

Or from the command line::

    ccs-crewai-verify receipt.json
"""

from __future__ import annotations

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Lightweight imports (no crewai dependency) — available to everyone, including
# the CLI which must work in environments without crewai.
# ---------------------------------------------------------------------------
from .config import (
    CCSConfig,
    PolicyDecision,
    ReceiptRecord,
    ReceiptSink,
)
from .hashing import canonical_json, canonical_sha256_hex
from .receipt_builder import (
    BEHAVIOR_RECEIPT_TYPE,
    L1_RECEIPT_VERSION,
    BuiltReceipts,
    ReceiptBuilder,
    linked_l1_digest,
)
from .signer import (
    CCSSigner,
    InProcessSigner,
    SidecarSigner,
    build_signer,
    derive_in_process_key,
    fingerprint,
    verify_ed25519,
)

from .verifier import (
    L1_FIELDS as VERIFIER_L1_FIELDS,
    VerificationError,
    verify_l1_receipt,
    verify_l1_signature,
    verify_chain,
    verify_behavior_linkage,
    verify_behavior_signature,
)

__all__ = [
    # Primary API
    "CCSConfig",
    "CCSGuardrailProvider",
    "enable_guardrail",
    "GuardrailRequest",
    "GuardrailDecision",
    "ToolCallBlocked",
    "GuardedToolResult",
    # Policy / sink
    "PolicyDecision",
    "ReceiptRecord",
    "ReceiptSink",
    # Builder / hashing
    "ReceiptBuilder",
    "BuiltReceipts",
    "canonical_json",
    "canonical_sha256_hex",
    "linked_l1_digest",
    "L1_RECEIPT_VERSION",
    "BEHAVIOR_RECEIPT_TYPE",
    # Signers
    "CCSSigner",
    "InProcessSigner",
    "SidecarSigner",
    "build_signer",
    "derive_in_process_key",
    "fingerprint",
    "verify_ed25519",
    # Verifier
    "VerificationError",
    "verify_l1_receipt",
    "verify_l1_signature",
    "verify_chain",
    "verify_behavior_linkage",
    "verify_behavior_signature",
    "VERIFIER_L1_FIELDS",
    # Metadata
    "__version__",
]

# ---------------------------------------------------------------------------
# Lazy imports for crewai-dependent components.
# This allows the CLI and verifier to work without crewai installed.
# ---------------------------------------------------------------------------
_LAZY = {
    "CCSGuardrailProvider": (".guardrail", "CCSGuardrailProvider"),
    "enable_guardrail": (".guardrail", "enable_guardrail"),
    "GuardrailRequest": (".guardrail", "GuardrailRequest"),
    "GuardrailDecision": (".guardrail", "GuardrailDecision"),
    "ToolCallBlocked": (".guardrail", "ToolCallBlocked"),
    "GuardedToolResult": (".guardrail", "GuardedToolResult"),
}


def __getattr__(name: str):  # PEP 562
    if name in _LAZY:
        module_path, attr = _LAZY[name]
        import importlib

        mod = importlib.import_module(module_path, __name__)
        value = getattr(mod, attr)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
