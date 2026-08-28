"""ccs-pydantic-ai — CCS runtime receipts for Pydantic AI agents.

Two-line integration::

    from ccs_pydantic_ai import CCSCapability, CCSConfig

    agent = Agent(
        "openai:gpt-4o",
        capabilities=[CCSCapability(CCSConfig(seed=b"my-app-seed"))],
    )

Every tool call then emits a signed 30-field CCS L1 action receipt and a linked
``ccs.behavior_evidence.v1`` receipt to the configured sink (stdout JSON lines
by default). Receipts can be independently verified with
``ccs-verifier==1.3.0``::

    from ccs_verifier.ccs_verifier_l1 import L1Receipt
    receipt = L1Receipt.from_dict(data, strict=True)
    assert receipt.verify_signature()
"""

from __future__ import annotations

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
from .toolset import CCSCapability, CCSToolset

__version__ = "0.1.0"

__all__ = [
    # Primary API
    "CCSCapability",
    "CCSToolset",
    "CCSConfig",
    "ReceiptRecord",
    "ReceiptSink",
    # Builder / hashing (advanced / verification helpers)
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