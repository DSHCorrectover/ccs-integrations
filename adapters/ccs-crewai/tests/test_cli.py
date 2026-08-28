"""Tests for the ccs-crewai-verify CLI."""
from __future__ import annotations

import json
import subprocess
import sys

from ccs_crewai import CCSConfig, ReceiptBuilder
from ccs_crewai.signer import InProcessSigner


SEED = b"ccs-crewai-cli-test-seed"


def _make_receipt(tmp_path):
    b = ReceiptBuilder(
        signer=InProcessSigner(SEED),
        rule_version="1.3.0",
        rule_summary="no_rules_matched",
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="cli-trace-001",
        verifier_source_class="CrewAIAdapter",
    )
    result = b.build(
        tool="search",
        tool_call_id="call-cli",
        args={"q": "test"},
        runtime_context={},
        result={"answer": "42"},
        started_at=1700000000.0,
        ended_at=1700000001.0,
    )
    p = tmp_path / "receipt.json"
    p.write_text(json.dumps(result.l1, indent=2))
    return p


def test_cli_version():
    out = subprocess.run(
        [sys.executable, "-m", "ccs_crewai.cli", "--version"],
        capture_output=True, text=True, timeout=15,
    )
    assert out.returncode == 0
    assert "0.1.0" in out.stdout


def test_cli_verify_valid_receipt(tmp_path):
    receipt = _make_receipt(tmp_path)
    out = subprocess.run(
        [sys.executable, "-m", "ccs_crewai.cli", str(receipt)],
        capture_output=True, text=True, timeout=15,
    )
    assert out.returncode == 0, f"stderr: {out.stderr}"
    assert "VALID" in out.stdout.upper() or "PASS" in out.stdout.upper()
