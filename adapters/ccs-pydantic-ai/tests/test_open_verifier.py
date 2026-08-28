"""Tests for the open-source minimal verifier (no ccs-verifier dependency)."""
from __future__ import annotations

import copy

import pytest

from ccs_pydantic_ai import (
    CCSConfig,
    ReceiptBuilder,
    verify_chain,
    verify_l1_receipt,
    verify_behavior_linkage,
)
from ccs_pydantic_ai.signer import build_signer


@pytest.fixture
def built_pair():
    """Build a valid L1 + behavior receipt pair."""
    config = CCSConfig(
        seed=b"verifier-test-seed",
        trace_id="verify-trace-001",
        sink=lambda r: None,
    )
    builder = ReceiptBuilder(
        signer=build_signer(config),
        rule_version=config.rule_version,
        rule_summary=config.rule_summary,
        issuer=config.issuer,
        audience=config.audience,
        trace_id=config.trace_id,
    )
    built = builder.build(
        tool="search",
        tool_call_id="call_verify_1",
        args={"q": "hello"},
        result=["doc1"],
    )
    return built.l1, built.behavior


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_verify_valid_l1(built_pair):
    l1, _ = built_pair
    ok, reason = verify_l1_receipt(l1)
    assert ok, reason


def test_verify_valid_chain(built_pair):
    l1, behavior = built_pair
    ok, reason = verify_chain(l1, behavior)
    assert ok, reason


def test_verify_chain_without_behavior(built_pair):
    l1, _ = built_pair
    ok, reason = verify_chain(l1, None)
    assert ok, reason


# --------------------------------------------------------------------------- #
# Structure validation
# --------------------------------------------------------------------------- #
def test_reject_extra_field(built_pair):
    l1, behavior = built_pair
    bad = dict(l1)
    bad["evil_field"] = "injected"
    ok, reason = verify_l1_receipt(bad)
    assert not ok
    assert "unknown fields" in reason


def test_reject_missing_field(built_pair):
    l1, behavior = built_pair
    bad = {k: v for k, v in l1.items() if k != "nonce"}
    ok, reason = verify_l1_receipt(bad)
    assert not ok
    assert "missing" in reason


def test_reject_empty_required_field(built_pair):
    l1, _ = built_pair
    bad = dict(l1)
    bad["tool"] = ""
    ok, reason = verify_l1_receipt(bad)
    assert not ok
    assert "non-empty" in reason


def test_reject_invalid_verdict(built_pair):
    l1, _ = built_pair
    bad = dict(l1)
    bad["verdict"] = "maybe"
    ok, reason = verify_l1_receipt(bad)
    assert not ok
    assert "verdict" in reason


def test_reject_wrong_algorithm(built_pair):
    l1, _ = built_pair
    bad = dict(l1)
    bad["signing_algorithm"] = "RSA-SHA256"
    # Need to re-sign with the "new" algorithm label — the signature won't match
    ok, reason = verify_l1_receipt(bad)
    assert not ok


# --------------------------------------------------------------------------- #
# Signature verification
# --------------------------------------------------------------------------- #
def test_tamper_verdict(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    bad["verdict"] = "block"
    ok, reason = verify_l1_receipt(bad)
    assert not ok
    assert "signature" in reason.lower() or "verify" in reason.lower()


def test_tamper_tool_name(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    bad["tool"] = "rm_rf"
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_tamper_response_hash(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    bad["response_hash"] = "0" * 64
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_tamper_args_digest(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    bad["args_digest"] = "0" * 64
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_tamper_nonce(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    bad["nonce"] = "tampered-nonce-value"
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_tamper_issuer(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    bad["issuer"] = "evil-issuer"
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_tamper_public_key(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    # Replace with a different valid base64 key
    bad["public_key"] = "A" * 44  # 32 bytes of 0x03? wrong but valid b64 length
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_cross_key_rejection(built_pair):
    """A receipt signed by key A must not verify under key B."""
    l1, _ = built_pair
    # Build a second signer with a different seed
    config_b = CCSConfig(seed=b"different-seed", sink=lambda r: None)
    builder_b = ReceiptBuilder(
        signer=build_signer(config_b),
        rule_version="1.3.0",
        rule_summary="no_rules_matched",
        issuer="ccs-pydantic-ai",
        audience="pydantic-ai-agent",
        trace_id="other-trace",
    )
    other = builder_b.build(
        tool="other",
        tool_call_id="other_call",
        args={},
        result=None,
    )
    # Swap public key but keep original signature → must fail
    bad = copy.deepcopy(l1)
    bad["public_key"] = other.l1["public_key"]
    bad["public_key_fingerprint"] = other.l1["public_key_fingerprint"]
    ok, reason = verify_l1_receipt(bad)
    assert not ok


# --------------------------------------------------------------------------- #
# Chain linkage
# --------------------------------------------------------------------------- #
def test_behavior_tamper_breaks_chain(built_pair):
    l1, behavior = built_pair
    bad = copy.deepcopy(behavior)
    bad["behavior_evidence_verdict"] = "observed_and_allowed"
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_wrong_l1_digest(built_pair):
    l1, behavior = built_pair
    bad = copy.deepcopy(behavior)
    bad["linked_l1_receipt_digest"] = "sha256:" + "0" * 64
    ok, reason = verify_chain(l1, bad)
    assert not ok
    assert not ok  # signature or linkage failure


def test_behavior_trace_mismatch(built_pair):
    l1, behavior = built_pair
    bad = copy.deepcopy(behavior)
    bad["trace_id"] = "wrong-trace"
    # Recompute signature? No — the digest won't match because L1 has the
    # correct trace_id. The linkage check catches this.
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_wrong_key(built_pair):
    l1, behavior = built_pair
    config_b = CCSConfig(seed=b"yet-another-seed", sink=lambda r: None)
    builder_b = ReceiptBuilder(
        signer=build_signer(config_b),
        rule_version="1.3.0",
        rule_summary="no_rules_matched",
        issuer="ccs-pydantic-ai",
        audience="pydantic-ai-agent",
        trace_id="other",
    )
    other = builder_b.build(tool="t", tool_call_id="c", args={}, result=None)
    # Use L1 from key A but behavior from key B
    ok, reason = verify_chain(l1, other.behavior)
    assert not ok


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def test_reject_non_dict():
    ok, reason = verify_l1_receipt("not a dict")  # type: ignore[arg-type]
    assert not ok
    assert "dict" in reason


def test_reject_corrupt_base64_signature(built_pair):
    l1, _ = built_pair
    bad = copy.deepcopy(l1)
    bad["signature"] = "!!!not-base64!!!"
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_block_verdict_receipt(built_pair):
    """Block receipts should also verify cleanly."""
    config = CCSConfig(seed=b"block-test", sink=lambda r: None)
    builder = ReceiptBuilder(
        signer=build_signer(config),
        rule_version="1.3.0",
        rule_summary="blocked_rule",
        issuer="test",
        audience="test",
        trace_id="block-trace",
    )
    built = builder.build(
        tool="dangerous",
        tool_call_id="call_block",
        args={"cmd": "rm -rf /"},
        blocked=True,
        block_reason="dangerous_command",
    )
    ok, reason = verify_chain(built.l1, built.behavior)
    assert ok, reason
    assert built.l1["verdict"] == "block"
