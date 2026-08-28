"""Open-source minimal CCS receipt verifier (MIT licensed).

This module provides **cryptographic verification only** — signature validity,
field completeness, hash-chain integrity, and behavior-linkage binding. It does
**not** implement the 7-dimension rule engine, latency/cost policy enforcement,
or any enterprise compliance checks; those remain in the proprietary
``ccs-verifier`` package (ELv2).

The goal is simple: anyone who receives a CCS receipt can independently confirm
that it was signed by the claimed key and that no field has been tampered with,
using only open-source dependencies (``cryptography`` + ``jcs``).

Usage::

    from ccs_pydantic_ai.verifier import verify_l1_receipt, verify_chain

    # Verify a single L1 receipt's signature and structure
    ok, reason = verify_l1_receipt(receipt_dict)

    # Verify L1 + behavior linkage
    ok, reason = verify_chain(l1_dict, behavior_dict)
"""

from __future__ import annotations

from .l1 import L1_FIELDS, verify_l1_receipt, verify_l1_signature
from .chain import verify_chain, verify_behavior_linkage, verify_behavior_signature
from .errors import VerificationError

__all__ = [
    "L1_FIELDS",
    "VerificationError",
    "verify_l1_receipt",
    "verify_l1_signature",
    "verify_chain",
    "verify_behavior_linkage",
    "verify_behavior_signature",
]
