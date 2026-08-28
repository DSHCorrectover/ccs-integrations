"""Tests for CCSGuardrailProvider — allow, block, error, intercept paths."""
from __future__ import annotations

import pytest

from ccs_crewai import CCSConfig, PolicyDecision
from ccs_crewai.guardrail import (
    CCSGuardrailProvider,
    GuardedToolResult,
    ToolCallBlocked,
)
from ccs_crewai.verifier import verify_l1_receipt


SEED = b"ccs-crewai-unit-test-seed"


def test_intercept_allows_and_emits_receipt():
    records = []
    cfg = CCSConfig(
        deployment_mode="in-process",
        seed=SEED,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="trace-allow",
        sink=records.append,
    )
    provider = CCSGuardrailProvider(cfg)
    out = provider.intercept_tool_call(
        tool_name="search",
        tool_args={"q": "hi"},
        runner=lambda: {"answer": "ok"},
    )
    assert isinstance(out, GuardedToolResult)
    assert out.result == {"answer": "ok"}
    assert len(records) >= 1
    l1 = records[0].l1
    assert l1["verdict"] == "allow"
    ok, reason = verify_l1_receipt(l1)
    assert ok, reason


def test_intercept_blocks_before_execution():
    records = []
    executed = []

    def deny_all(tool_name, tool_args, runtime_context=None):
        return PolicyDecision(allowed=False, reason="blocked_for_test")

    cfg = CCSConfig(
        deployment_mode="in-process",
        seed=SEED,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="trace-block",
        sink=records.append,
        policy=deny_all,
    )
    provider = CCSGuardrailProvider(cfg)
    with pytest.raises(ToolCallBlocked) as exc:
        provider.intercept_tool_call(
            tool_name="danger",
            tool_args={"cmd": "rm -rf /"},
            runner=lambda: executed.append("RAN") or "pwned",
        )
    assert "blocked_for_test" in str(exc.value)
    assert executed == []  # runner never called
    assert len(records) == 1
    assert records[0].verdict == "block"
    ok, reason = verify_l1_receipt(records[0].l1)
    assert ok, reason


def test_error_during_runner_still_emits_receipt():
    records = []
    cfg = CCSConfig(
        deployment_mode="in-process",
        seed=SEED,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="trace-err",
        sink=records.append,
    )
    provider = CCSGuardrailProvider(cfg)

    def boom():
        raise RuntimeError("tool exploded")

    with pytest.raises(RuntimeError):
        provider.intercept_tool_call(
            tool_name="flaky",
            tool_args={},
            runner=boom,
        )
    assert len(records) == 1
    # Error receipt is still a valid signed allow receipt; callers can inspect
    # action field for the error.
    ok, reason = verify_l1_receipt(records[0].l1)
    assert ok, reason


def test_reset_changes_trace_id_and_sequence():
    records = []
    cfg = CCSConfig(
        deployment_mode="in-process",
        seed=SEED,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="first",
        sink=records.append,
    )
    provider = CCSGuardrailProvider(cfg)
    provider.intercept_tool_call(
        tool_name="a", tool_args={}, runner=lambda: 1,
    )
    provider.reset(trace_id="second")
    provider.intercept_tool_call(
        tool_name="b", tool_args={}, runner=lambda: 2,
    )
    assert records[0].trace_id == "first"
    assert records[1].trace_id == "second"
    assert records[0].l1["sequence"] == 0
    assert records[1].l1["sequence"] == 0  # reset counter
