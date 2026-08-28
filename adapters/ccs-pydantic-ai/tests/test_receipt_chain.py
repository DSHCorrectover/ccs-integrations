"""Tests for L1 strict parse, behavior linkage, and tamper detection.

These tests require ``ccs-verifier==1.3.0`` (the ``verify`` extra). They verify
that every receipt emitted by the adapter is byte-compatible with the closed
core verifier and that the L1 <-> behavior evidence chain is cryptographically
bound.
"""
from __future__ import annotations

import copy

import pytest

from ccs_pydantic_ai import (
    CCSConfig,
    ReceiptBuilder,
    linked_l1_digest,
    verify_ed25519,
)
from ccs_pydantic_ai.signer import InProcessSigner, build_signer

ccs_verifier = pytest.importorskip("ccs_verifier")
from ccs_verifier.ccs_verifier_l1 import L1Receipt  # noqa: E402


@pytest.fixture
def builder() -> ReceiptBuilder:
    config = CCSConfig(
        seed=b"receipt-chain-seed",
        issuer="ccs-pydantic-ai/chain-test",
        audience="pytest",
        trace_id="chain-trace-001",
        sink=lambda r: None,
    )
    return ReceiptBuilder(
        signer=build_signer(config),
        rule_version=config.rule_version,
        rule_summary=config.rule_summary,
        issuer=config.issuer,
        audience=config.audience,
        trace_id=config.trace_id,
        verifier_source_class=config.verifier_source_class,
        receipt_ttl_seconds=config.receipt_ttl_seconds,
        max_clock_skew=config.max_clock_skew,
        action_suffix=config.action_suffix,
        include_behavior=True,
    )


# --------------------------------------------------------------------------- #
# L1 strict parse + signature
# --------------------------------------------------------------------------- #
def test_l1_receipt_has_exactly_30_fields(builder: ReceiptBuilder) -> None:
    built = builder.build(
        tool="search",
        tool_call_id="call_1",
        args={"q": "pydantic"},
        result=["doc1", "doc2"],
    )
    assert len(built.l1) == 30
    expected = {
        "trace_id", "receipt_version", "verdict", "timestamp", "tool",
        "tool_call_id", "params_hash", "args_digest", "rule_summary",
        "rule_version", "request_hash", "response_hash", "runtime_context_hash",
        "config_hash", "verifier_source_class", "deployment_mode", "issuer",
        "audience", "nonce", "sequence", "issued_at", "expires_at",
        "max_clock_skew", "action", "signature", "signing_algorithm",
        "public_key_fingerprint", "public_key", "verified_at", "latency_us",
    }
    assert set(built.l1.keys()) == expected


def test_l1_strict_parse_and_verify(builder: ReceiptBuilder) -> None:
    built = builder.build(
        tool="search",
        tool_call_id="call_1",
        args={"q": "pydantic"},
        result="ok",
    )
    receipt = L1Receipt.from_dict(built.l1, strict=True)
    assert receipt.verify_signature() is True
    assert receipt.verdict == "allow"
    assert receipt.receipt_version == "1.1"
    assert receipt.signing_algorithm == "Ed25519"
    assert receipt.deployment_mode == "in-process"


def test_l1_block_receipt_strict_parse_and_verify(builder: ReceiptBuilder) -> None:
    try:
        raise RuntimeError("tool exploded")
    except RuntimeError as exc:
        built = builder.build(
            tool="dangerous",
            tool_call_id="call_2",
            args={"cmd": "rm -rf /"},
            error=exc,
        )
    receipt = L1Receipt.from_dict(built.l1, strict=True)
    assert receipt.verify_signature() is True
    assert receipt.verdict == "block"
    assert "RuntimeError" in receipt.rule_summary


def test_l1_rejects_unknown_fields(builder: ReceiptBuilder) -> None:
    built = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    bad = dict(built.l1)
    bad["unexpected_extra"] = "value"
    with pytest.raises(ValueError, match="Unknown fields"):
        L1Receipt.from_dict(bad, strict=True)


# --------------------------------------------------------------------------- #
# Behavior evidence
# --------------------------------------------------------------------------- #
def test_behavior_receipt_signature_verifies(builder: ReceiptBuilder) -> None:
    built = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    beh = built.behavior
    assert beh is not None
    assert beh["receipt_type"] == "ccs.behavior_evidence.v1"
    assert verify_ed25519(beh["public_key"], beh, beh["signature"]) is True


def test_linked_l1_receipt_digest_is_correct(builder: ReceiptBuilder) -> None:
    built = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    assert built.behavior is not None
    assert built.behavior["linked_l1_receipt_digest"] == linked_l1_digest(built.l1)
    # Digest must start with sha256: prefix and be 64 hex chars after.
    digest = built.behavior["linked_l1_receipt_digest"]
    assert digest.startswith("sha256:")
    assert len(digest.removeprefix("sha256:")) == 64


def test_behavior_verdict_matches_l1(builder: ReceiptBuilder) -> None:
    allow = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    assert allow.behavior is not None
    assert allow.behavior["behavior_evidence_verdict"] == "not_observed"
    assert allow.l1["verdict"] == "allow"

    try:
        raise ValueError("bad")
    except ValueError as exc:
        block = builder.build(tool="t", tool_call_id="c2", args={}, error=exc)
    assert block.behavior is not None
    assert block.behavior["behavior_evidence_verdict"] == "observed_and_rejected"
    assert block.l1["verdict"] == "block"


# --------------------------------------------------------------------------- #
# Tamper detection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "field,new_value",
    [
        ("verdict", "block"),
        ("tool", "different_tool"),
        ("response_hash", "0" * 64),
        ("request_hash", "0" * 64),
        ("args_digest", "0" * 64),
        ("nonce", "tampered-nonce"),
        ("issuer", "evil-issuer"),
        ("public_key_fingerprint", "0" * 16),
    ],
)
def test_tampered_l1_field_breaks_signature(
    builder: ReceiptBuilder, field: str, new_value: object
) -> None:
    built = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    tampered = copy.deepcopy(built.l1)
    tampered[field] = new_value
    receipt = L1Receipt.from_dict(tampered, strict=True)
    # The embedded signature no longer matches the tampered payload.
    assert receipt.verify_signature() is False


def test_tampered_l1_breaks_behavior_linkage(builder: ReceiptBuilder) -> None:
    built = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    assert built.behavior is not None

    tampered = copy.deepcopy(built.l1)
    tampered["tool"] = "tampered_tool"

    # New digest of the tampered L1 must differ from the behavior link.
    assert linked_l1_digest(tampered) != built.behavior["linked_l1_receipt_digest"]
    # The original linkage still matches the unmodified L1.
    assert linked_l1_digest(built.l1) == built.behavior["linked_l1_receipt_digest"]


def test_tampered_behavior_field_breaks_signature(builder: ReceiptBuilder) -> None:
    built = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    beh = copy.deepcopy(built.behavior)
    assert beh is not None
    beh["behavior_evidence_verdict"] = "observed_and_allowed"
    assert verify_ed25519(beh["public_key"], beh, beh["signature"]) is False


# --------------------------------------------------------------------------- #
# Sequence / determinism
# --------------------------------------------------------------------------- #
def test_sequence_increments_per_call(builder: ReceiptBuilder) -> None:
    first = builder.build(tool="t", tool_call_id="c1", args={}, result="r")
    second = builder.build(tool="t", tool_call_id="c2", args={}, result="r")
    assert first.l1["sequence"] == 0
    assert second.l1["sequence"] == 1
    assert first.behavior is not None and second.behavior is not None
    assert first.behavior["sequence"] == 0
    assert second.behavior["sequence"] == 1


def test_in_process_receipts_are_byte_reproducible_with_same_nonce() -> None:
    """Two builders with the same seed produce the same signature for identical
    input (nonce/timestamps fixed)."""
    import json

    def build_once(nonce_value: str, ts: float):
        cfg = CCSConfig(seed=b"reproducible", sink=lambda r: None, trace_id="rep")
        b = ReceiptBuilder(
            signer=build_signer(cfg),
            rule_version=cfg.rule_version,
            rule_summary=cfg.rule_summary,
            issuer=cfg.issuer,
            audience=cfg.audience,
            trace_id=cfg.trace_id,
            verifier_source_class=cfg.verifier_source_class,
            receipt_ttl_seconds=cfg.receipt_ttl_seconds,
            max_clock_skew=cfg.max_clock_skew,
            action_suffix=cfg.action_suffix,
            include_behavior=False,
        )
        # Patch nonce + timestamps for determinism.
        import secrets as _secrets

        _secrets.token_hex = lambda n: nonce_value  # type: ignore[assignment]
        return b.build(
            tool="t",
            tool_call_id="c1",
            args={"x": 1},
            result="ok",
            started_at=ts,
            ended_at=ts,
        ).l1

    a = build_once("fixed-nonce", 1_000_000.0)
    b = build_once("fixed-nonce", 1_000_000.0)
    assert a["signature"] == b["signature"]
    # Canonical JSON is byte-identical (excluding signature, which is identical).
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
