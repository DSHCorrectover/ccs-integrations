"""Tests for :class:`ccs_pydantic_ai.CCSToolset` and :class:`CCSCapability`.

These use Pydantic AI's :class:`TestModel` so no real LLM credentials are
required. They verify that receipts are generated for both allow and block
paths, that sequence/trace binding is correct, and that receipts survive strict
parse + signature verification through the core ``ccs-verifier`` package.
"""
from __future__ import annotations

import pytest

from ccs_pydantic_ai import (
    CCSCapability,
    CCSConfig,
    CCSToolset,
    ReceiptRecord,
)

pytest.importorskip("pydantic_ai")
from pydantic_ai import Agent, FunctionToolset  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

ccs_verifier = pytest.importorskip("ccs_verifier")
from ccs_verifier.ccs_verifier_l1 import L1Receipt  # noqa: E402


# --------------------------------------------------------------------------- #
# CCSToolset (explicit wrapping)
# --------------------------------------------------------------------------- #
def test_toolset_emits_allow_receipt_for_successful_tool() -> None:
    records: list[ReceiptRecord] = []

    def search(query: str) -> str:
        return f"results for {query}"

    toolset = FunctionToolset(tools=[search])
    config = CCSConfig(
        seed=b"toolset-test",
        trace_id="trace-allow",
        sink=records.append,
    )
    agent = Agent(TestModel(), toolsets=[CCSToolset(toolset, config)])

    result = agent.run_sync("search for something")

    assert result is not None
    assert len(records) == 1
    record = records[0]
    assert record.verdict == "allow"
    assert record.trace_id == "trace-allow"
    assert record.tool_call_id  # non-empty
    assert record.l1["tool"] == "search"
    assert record.l1["verdict"] == "allow"
    assert record.behavior is not None
    assert record.behavior["behavior_evidence_verdict"] == "not_observed"


def test_toolset_emits_block_receipt_when_tool_raises() -> None:
    records: list[ReceiptRecord] = []

    def dangerous() -> str:
        raise RuntimeError("blocked by tool logic")

    toolset = FunctionToolset(tools=[dangerous])
    config = CCSConfig(
        seed=b"toolset-test",
        trace_id="trace-block",
        sink=records.append,
    )
    agent = Agent(TestModel(), toolsets=[CCSToolset(toolset, config)])

    with pytest.raises(RuntimeError, match="blocked by tool logic"):
        agent.run_sync("do dangerous thing")

    assert len(records) == 1
    record = records[0]
    assert record.verdict == "block"
    assert record.l1["verdict"] == "block"
    assert "RuntimeError" in record.l1["rule_summary"]
    assert record.behavior is not None
    assert record.behavior["behavior_evidence_verdict"] == "observed_and_rejected"


def test_toolset_multiple_calls_increment_sequence() -> None:
    records: list[ReceiptRecord] = []

    def add(a: int, b: int) -> int:
        return a + b

    toolset = FunctionToolset(tools=[add])
    config = CCSConfig(
        seed=b"seq-test",
        trace_id="trace-seq",
        sink=records.append,
    )
    agent = Agent(TestModel(), toolsets=[CCSToolset(toolset, config)])

    # TestModel calls each registered tool at least once per run.
    agent.run_sync("call add")

    sequences = [r.l1["sequence"] for r in records]
    assert sequences == list(range(len(records)))
    # All receipts share the same trace id.
    assert all(r.trace_id == "trace-seq" for r in records)


def test_toolset_receipt_passes_ccs_verifier() -> None:
    records: list[ReceiptRecord] = []

    def echo(msg: str) -> str:
        return msg

    toolset = FunctionToolset(tools=[echo])
    config = CCSConfig(seed=b"verify-test", sink=records.append)
    agent = Agent(TestModel(), toolsets=[CCSToolset(toolset, config)])
    agent.run_sync("echo hello")

    assert len(records) == 1
    l1 = records[0].l1
    receipt = L1Receipt.from_dict(l1, strict=True)
    assert receipt.verify_signature() is True


# --------------------------------------------------------------------------- #
# CCSCapability (recommended integration)
# --------------------------------------------------------------------------- #
def test_capability_intercepts_all_tools() -> None:
    records: list[ReceiptRecord] = []

    def tool_a(x: str) -> str:
        return f"a:{x}"

    def tool_b(y: str) -> str:
        return f"b:{y}"

    config = CCSConfig(
        seed=b"capability-test",
        trace_id="cap-trace",
        sink=records.append,
    )
    agent = Agent(
        TestModel(),
        tools=[tool_a, tool_b],
        capabilities=[CCSCapability(config)],
    )
    agent.run_sync("use the tools")

    assert len(records) >= 2
    tools_seen = {r.l1["tool"] for r in records}
    assert "tool_a" in tools_seen
    assert "tool_b" in tools_seen
    assert all(r.verdict == "allow" for r in records)
    # Each run gets its own trace id when config.trace_id is fixed it is reused.
    assert all(r.trace_id == "cap-trace" for r in records)


def test_capability_block_path() -> None:
    records: list[ReceiptRecord] = []

    def fail() -> str:
        raise ValueError("nope")

    config = CCSConfig(seed=b"cap-block", trace_id="cap-block", sink=records.append)
    agent = Agent(TestModel(), tools=[fail], capabilities=[CCSCapability(config)])

    with pytest.raises(ValueError, match="nope"):
        agent.run_sync("call fail")

    assert len(records) == 1
    assert records[0].verdict == "block"


def test_capability_fresh_trace_per_run_when_unset() -> None:
    """When trace_id is not fixed, each agent run gets a distinct trace id."""

    def noop() -> str:
        return "ok"

    run_records: list[list[ReceiptRecord]] = []
    config = CCSConfig(seed=b"per-run", sink=lambda r: run_records[-1].append(r))
    agent = Agent(TestModel(), tools=[noop], capabilities=[CCSCapability(config)])

    run_records.append([])
    agent.run_sync("first")
    run_records.append([])
    agent.run_sync("second")

    traces = {r.trace_id for batch in run_records for r in batch}
    assert len(traces) == 2  # two distinct trace ids


def test_sink_can_be_noop() -> None:
    """A no-op sink must not interfere with agent execution."""

    def greet(name: str) -> str:
        return f"hi {name}"

    config = CCSConfig(seed=b"noop-sink", sink=lambda r: None)
    agent = Agent(
        TestModel(),
        tools=[greet],
        capabilities=[CCSCapability(config)],
    )
    result = agent.run_sync("greet")
    assert result is not None


# --------------------------------------------------------------------------- #
# Config validation
# --------------------------------------------------------------------------- #
def test_in_process_requires_seed() -> None:
    with pytest.raises(ValueError, match="seed is required"):
        CCSConfig(deployment_mode="in-process")


def test_invalid_deployment_mode() -> None:
    with pytest.raises(ValueError, match="deployment_mode"):
        CCSConfig(deployment_mode="invalid", seed=b"x")


def test_sidecar_requires_url_or_public_key() -> None:
    with pytest.raises(ValueError, match="sidecar"):
        CCSConfig(deployment_mode="sidecar")
