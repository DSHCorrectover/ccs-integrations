"""Tests for ReceiptBuilder producing well-formed L1 + behavior receipts."""
from __future__ import annotations

from ccs_crewai import ReceiptBuilder
from ccs_crewai.signer import InProcessSigner
from ccs_crewai import linked_l1_digest
from ccs_crewai.verifier import verify_l1_receipt, verify_chain


SEED = b"ccs-crewai-unit-test-seed"


def _builder(**overrides):
    kwargs = dict(
        signer=InProcessSigner(SEED),
        rule_version="1.3.0",
        rule_summary="no_rules_matched",
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="pytest-trace-001",
        verifier_source_class="CrewAIAdapter",
    )
    kwargs.update(overrides)
    return ReceiptBuilder(**kwargs)


def test_l1_receipt_has_all_30_fields():
    b = _builder()
    result = b.build(
        tool="search",
        tool_call_id="call-001",
        args={"q": "hello"},
        runtime_context={"agent": "Researcher"},
        result={"answer": "hi"},
        started_at=1700000000.0,
        ended_at=1700000001.0,
    )
    assert len(result.l1) == 30
    for field in (
        "trace_id", "receipt_version", "verdict", "timestamp", "tool",
        "tool_call_id", "params_hash", "args_digest", "rule_summary",
        "rule_version", "request_hash", "response_hash",
        "runtime_context_hash", "config_hash", "verifier_source_class",
        "deployment_mode", "issuer", "audience", "nonce", "sequence",
        "issued_at", "expires_at", "max_clock_skew", "action", "signature",
        "signing_algorithm", "public_key_fingerprint", "public_key",
        "verified_at", "latency_us",
    ):
        assert field in result.l1, f"missing {field}"


def test_l1_receipt_signature_verifies():
    b = _builder()
    result = b.build(
        tool="search", tool_call_id="call-001",
        args={"q": "hi"}, runtime_context={},
        result={"answer": "ok"},
        started_at=1700000000.0, ended_at=1700000001.0,
    )
    ok, reason = verify_l1_receipt(result.l1)
    assert ok, f"verification failed: {reason}"


def test_sequence_increments_across_builds():
    b = _builder()
    r1 = b.build(
        tool="search", tool_call_id="call-001",
        args={"q": "hi"}, runtime_context={},
        result={"answer": "ok"},
        started_at=1700000000.0, ended_at=1700000001.0,
    )
    r2 = b.build(
        tool="lookup", tool_call_id="call-002",
        args={"id": 42}, runtime_context={},
        result={"data": True},
        started_at=1700000002.0, ended_at=1700000003.0,
    )
    assert r1.l1["sequence"] == 0
    assert r2.l1["sequence"] == 1
    assert r1.l1["trace_id"] == r2.l1["trace_id"]


def test_blocked_receipt_verifies():
    b = _builder()
    result = b.build(
        tool="danger", tool_call_id="call-block",
        args={"cmd": "rm -rf /"}, runtime_context={},
        blocked=True, block_reason="policy_denied",
        started_at=1700000000.0, ended_at=1700000001.0,
    )
    assert result.l1["verdict"] == "block"
    assert "policy_denied" in result.l1["rule_summary"]
    ok, reason = verify_l1_receipt(result.l1)
    assert ok, f"blocked receipt verification failed: {reason}"


def test_behavior_receipt_links_l1():
    b = _builder()
    result = b.build(
        tool="search", tool_call_id="call-001",
        args={"q": "hi"}, runtime_context={},
        result={"answer": "ok"},
        started_at=1700000000.0, ended_at=1700000001.0,
    )
    assert result.behavior is not None
    assert result.behavior["linked_l1_receipt_digest"]
    assert result.behavior["behavior_evidence_verdict"] == "not_observed"
    # Verify the full L1 + behavior chain
    ok, reason = verify_chain(result.l1, result.behavior)
    assert ok, f"chain verification failed: {reason}"


def test_behavior_disabled():
    b = _builder(include_behavior=False)
    result = b.build(
        tool="search", tool_call_id="call-001",
        args={"q": "hi"}, runtime_context={},
        result={"answer": "ok"},
        started_at=1700000000.0, ended_at=1700000001.0,
    )
    assert result.behavior is None


def test_linked_l1_digest_matches():
    b = _builder()
    result = b.build(
        tool="search", tool_call_id="call-001",
        args={"q": "hi"}, runtime_context={},
        result={"answer": "ok"},
        started_at=1700000000.0, ended_at=1700000001.0,
    )
    expected = linked_l1_digest(result.l1)
    assert result.behavior["linked_l1_receipt_digest"] == expected
