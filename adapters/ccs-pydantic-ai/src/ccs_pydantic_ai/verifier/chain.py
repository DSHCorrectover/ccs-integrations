"""Behavior evidence receipt and L1<->behavior chain verification."""
from __future__ import annotations
import base64
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ..hashing import canonical_json, sha256_hex
from .l1 import verify_l1_receipt

BEHAVIOR_FIELDS: frozenset[str] = frozenset({
    "receipt_type","trace_id","tool_call_id","sequence",
    "linked_l1_receipt_digest","behavior_evidence_verdict","evidence_ref",
    "issuer","audience","issued_at","deployment_mode","signing_algorithm",
    "public_key_fingerprint","public_key","signature",
})
BEHAVIOR_RECEIPT_TYPE = "ccs.behavior_evidence.v1"
_VALID_BEHAVIOR_VERDICTS = frozenset({
    "not_observed","observed_and_allowed","observed_and_rejected",
})

def verify_behavior_signature(behavior: dict[str, Any]) -> tuple[bool, str]:
    try:
        sig_b64 = behavior["signature"]
        pk_b64 = behavior["public_key"]
    except KeyError as exc:
        return False, f"missing field: {exc}"
    try:
        pk = base64.b64decode(pk_b64)
        sig = base64.b64decode(sig_b64)
    except Exception as exc:
        return False, f"base64 decode error: {exc}"
    if len(pk)!=32: return False, "public key must be 32 bytes"
    if len(sig)!=64: return False, "signature must be 64 bytes"
    signed = {k:v for k,v in behavior.items() if k!="signature"}
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, canonical_json(signed))
    except InvalidSignature:
        return False, "behavior signature does not verify"
    except Exception as exc:
        return False, f"verification error: {exc}"
    return True, "ok"

def validate_behavior_structure(behavior: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(behavior, dict):
        return False, "behavior receipt must be a dict"
    keys = set(behavior.keys())
    extra = keys - BEHAVIOR_FIELDS
    missing = BEHAVIOR_FIELDS - keys
    if extra: return False, f"unknown behavior fields: {sorted(extra)}"
    if missing: return False, f"missing behavior fields: {sorted(missing)}"
    if behavior["receipt_type"] != BEHAVIOR_RECEIPT_TYPE:
        return False, f"receipt_type must be {BEHAVIOR_RECEIPT_TYPE!r}, got {behavior['receipt_type']!r}"
    if behavior["signing_algorithm"] != "Ed25519":
        return False, "signing_algorithm must be 'Ed25519'"
    if behavior["behavior_evidence_verdict"] not in _VALID_BEHAVIOR_VERDICTS:
        return False, f"invalid behavior_evidence_verdict: {behavior['behavior_evidence_verdict']!r}"
    d = behavior.get("linked_l1_receipt_digest","")
    if not d.startswith("sha256:") or len(d) != 71:
        return False, "linked_l1_receipt_digest must be 'sha256:' + 64 hex chars"
    fpr = behavior.get("public_key_fingerprint","")
    if not (isinstance(fpr,str) and len(fpr)==16):
        return False, "public_key_fingerprint must be 16 hex chars"
    if not isinstance(behavior.get("sequence"),int) or behavior["sequence"]<0:
        return False, "sequence must be a non-negative integer"
    return True, "ok"

def verify_behavior_linkage(l1: dict[str, Any], behavior: dict[str, Any]) -> tuple[bool, str]:
    l1_no_sig = {k:v for k,v in l1.items() if k!="signature"}
    expected = "sha256:" + sha256_hex(canonical_json(l1_no_sig))
    actual = behavior.get("linked_l1_receipt_digest","")
    if actual != expected:
        return False, f"linked_l1_receipt_digest mismatch"
    for f in ("trace_id","tool_call_id","sequence"):
        if l1.get(f) != behavior.get(f):
            return False, f"{f} mismatch between L1 and behavior"
    if l1.get("public_key_fingerprint") != behavior.get("public_key_fingerprint"):
        return False, "public_key_fingerprint differs between L1 and behavior"
    return True, "ok"

def verify_chain(l1: dict[str, Any], behavior: dict[str, Any]|None, *, check_expiry: bool=False) -> tuple[bool, str]:
    ok, reason = verify_l1_receipt(l1, check_expiry=check_expiry)
    if not ok: return False, f"L1: {reason}"
    if behavior is None: return True, "ok"
    ok, reason = validate_behavior_structure(behavior)
    if not ok: return False, f"behavior structure: {reason}"
    ok, reason = verify_behavior_signature(behavior)
    if not ok: return False, f"behavior signature: {reason}"
    ok, reason = verify_behavior_linkage(l1, behavior)
    if not ok: return False, f"chain linkage: {reason}"
    return True, "ok"
