"""Open-source minimal CCS receipt verifier (MIT licensed).

This module provides cryptographic verification only — signature validity,
field completeness, hash-chain integrity, and behavior-linkage binding. It does
not implement the proprietary rule engine or compliance checks.

Usage::

    from ccs_crewai.verifier import verify_l1_receipt, verify_chain

    ok, reason = verify_l1_receipt(receipt_dict)
    ok, reason = verify_chain(l1_dict, behavior_dict)
"""

from __future__ import annotations

from .l1 import L1_FIELDS, verify_l1_receipt, verify_l1_signature
from .chain import (
    verify_chain,
    verify_behavior_linkage,
    verify_behavior_signature,
    BEHAVIOR_FIELDS,
    BEHAVIOR_RECEIPT_TYPE,
)
from .errors import VerificationError

__all__ = [
    "L1_FIELDS",
    "BEHAVIOR_FIELDS",
    "BEHAVIOR_RECEIPT_TYPE",
    "VerificationError",
    "verify_l1_receipt",
    "verify_l1_signature",
    "verify_chain",
    "verify_behavior_linkage",
    "verify_behavior_signature",
]
