"""ccs-pydantic-ai — CCS runtime receipts for Pydantic AI agents.

Two-line integration::

    from ccs_pydantic_ai import CCSCapability, CCSConfig

    agent = Agent(
        "openai:gpt-4o",
        capabilities=[CCSCapability(CCSConfig(seed=b"my-app-seed"))],
    )

Every tool call then emits a signed 30-field CCS L1 action receipt and a linked
``ccs.behavior_evidence.v1`` receipt to the configured sink (stdout JSON lines
by default). Receipts can be independently verified with the open-source
verifier (no proprietary dependency)::

    from ccs_pydantic_ai import verify_l1_receipt, verify_chain
    ok, reason = verify_l1_receipt(receipt_dict)

Or from the command line::

    ccs-verify receipt.json
"""

from __future__ import annotations

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Lightweight imports (no pydantic-ai dependency) — available to everyone,
# including the CLI which must work in environments without pydantic-ai.
# ---------------------------------------------------------------------------
from .config import CCSConfig, ReceiptRecord, ReceiptSink
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

# Open-source minimal verifier (MIT, no proprietary dependency).
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
    # Primary API (lazy, requires pydantic-ai)
    "CCSCapability",
    "CCSToolset",
    # Config
    "CCSConfig",
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
    # Open-source verifier
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
# Lazy imports for pydantic-ai–dependent components.
# This allows the CLI and verifier to work without pydantic-ai installed.
# ---------------------------------------------------------------------------
_LAZY = {
    "CCSCapability": (".toolset", "CCSCapability"),
    "CCSToolset": (".toolset", "CCSToolset"),
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
