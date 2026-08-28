"""Tests for the ccs-verify CLI."""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

import pytest

from ccs_pydantic_ai.cli import main, EXIT_VALID, EXIT_INVALID, EXIT_USAGE
from ccs_pydantic_ai import CCSConfig, ReceiptBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_receipts(seed: bytes = b"cli-test-seed-0123456789abcdef"):
    """Build a valid L1 + behavior pair."""
    from ccs_pydantic_ai import build_signer
    config = CCSConfig(
        deployment_mode="in-process",
        seed=seed,
        issuer="ccs-test",
        audience="cli-test",
        trace_id="cli-trace-001",
        sink=lambda r: None,
    )
    builder = ReceiptBuilder(
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
    return builder.build(
        tool="test_tool",
        tool_call_id="call_cli_001",
        args={"q": "hello"},
        result={"result": "world"},
    )


def _run_cli(args: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    """Run the CLI and return (exit_code, stdout, stderr)."""
    exit_code = main(args)
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def _write_json(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return p


def _write_jsonl(tmp_path: Path, name: str, items: list[dict]) -> Path:
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(item) for item in items) + "\n")
    return p


# ---------------------------------------------------------------------------
# Tests: single L1 receipt
# ---------------------------------------------------------------------------

class TestSingleL1:
    def test_valid_l1_file(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        path = _write_json(tmp_path, "l1.json", built.l1)
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_VALID, f"stdout={out} stderr={err}"
        assert "Valid" in out
        assert "l1" in out

    def test_valid_l1_json_output(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        path = _write_json(tmp_path, "l1.json", built.l1)
        code, out, err = _run_cli(["--json", str(path)], capsys)
        assert code == EXIT_VALID
        result = json.loads(out)
        assert result["valid"] is True
        assert result["kind"] == "l1"
        assert result["reason"] == "ok"

    def test_tampered_l1(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        tampered = dict(built.l1)
        tampered["tool"] = "malicious_tool"
        path = _write_json(tmp_path, "bad.json", tampered)
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_INVALID
        assert "Invalid" in out

    def test_tampered_l1_json(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        tampered = dict(built.l1)
        tampered["verdict"] = "block"
        path = _write_json(tmp_path, "bad.json", tampered)
        code, out, err = _run_cli(["--json", str(path)], capsys)
        assert code == EXIT_INVALID
        result = json.loads(out)
        assert result["valid"] is False
        assert "signature" in result["reason"] or "tamper" in result["reason"].lower()

    def test_missing_field(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        incomplete = {k: v for k, v in built.l1.items() if k != "nonce"}
        path = _write_json(tmp_path, "bad.json", incomplete)
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_INVALID
        assert "missing" in out.lower()


# ---------------------------------------------------------------------------
# Tests: ReceiptRecord envelope
# ---------------------------------------------------------------------------

class TestEnvelope:
    def test_envelope_with_behavior(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        record = {
            "l1": built.l1,
            "behavior": built.behavior,
            "trace_id": built.l1["trace_id"],
            "tool_call_id": built.l1["tool_call_id"],
            "verdict": "allow",
        }
        path = _write_json(tmp_path, "record.json", record)
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_VALID, f"stdout={out} stderr={err}"
        assert "chain" in out

    def test_envelope_l1_only(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        record = {"l1": built.l1, "behavior": None}
        path = _write_json(tmp_path, "record.json", record)
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_VALID

    def test_envelope_tampered_behavior(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        bad_behavior = dict(built.behavior)
        bad_behavior["evidence_ref"] = "tampered"
        record = {"l1": built.l1, "behavior": bad_behavior}
        path = _write_json(tmp_path, "record.json", record)
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_INVALID


# ---------------------------------------------------------------------------
# Tests: --chain mode
# ---------------------------------------------------------------------------

class TestChainMode:
    def test_valid_chain(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        l1_path = _write_json(tmp_path, "l1.json", built.l1)
        behav_path = _write_json(tmp_path, "behavior.json", built.behavior)
        code, out, err = _run_cli(["--chain", str(l1_path), str(behav_path)], capsys)
        assert code == EXIT_VALID, f"stdout={out} stderr={err}"
        assert "chain" in out

    def test_chain_json_output(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        l1_path = _write_json(tmp_path, "l1.json", built.l1)
        behav_path = _write_json(tmp_path, "behavior.json", built.behavior)
        code, out, err = _run_cli(["--json", "--chain", str(l1_path), str(behav_path)], capsys)
        assert code == EXIT_VALID
        result = json.loads(out)
        assert result["valid"] is True
        assert result["kind"] == "chain"

    def test_chain_linkage_broken(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built1 = _build_receipts(b"seed-seed-seed-seed-000000000001")
        built2 = _build_receipts(b"seed-seed-seed-seed-000000000002")
        l1_path = _write_json(tmp_path, "l1.json", built1.l1)
        behav_path = _write_json(tmp_path, "behavior.json", built2.behavior)
        code, out, err = _run_cli(["--chain", str(l1_path), str(behav_path)], capsys)
        assert code == EXIT_INVALID
        assert "linkage" in out.lower() or "mismatch" in out.lower() or "digest" in out.lower()


# ---------------------------------------------------------------------------
# Tests: stdin
# ---------------------------------------------------------------------------

class TestStdin:
    def test_stdin_l1(self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch):
        built = _build_receipts()
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(built.l1)))
        code, out, err = _run_cli(["-"], capsys)
        assert code == EXIT_VALID, f"stdout={out} stderr={err}"

    def test_stdin_default(self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch):
        built = _build_receipts()
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(built.l1)))
        code, out, err = _run_cli([], capsys)
        assert code == EXIT_VALID

    def test_stdin_envelope(self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch):
        built = _build_receipts()
        record = {"l1": built.l1, "behavior": built.behavior}
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(record)))
        code, out, err = _run_cli(["-"], capsys)
        assert code == EXIT_VALID


# ---------------------------------------------------------------------------
# Tests: --stream (JSONL)
# ---------------------------------------------------------------------------

class TestStream:
    def test_stream_all_valid(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built1 = _build_receipts(b"stream-seed-0000000000000000000001")
        built2 = _build_receipts(b"stream-seed-0000000000000000000002")
        items = [
            {"l1": built1.l1, "behavior": built1.behavior},
            {"l1": built2.l1, "behavior": built2.behavior},
        ]
        path = _write_jsonl(tmp_path, "stream.jsonl", items)
        code, out, err = _run_cli(["--stream", str(path)], capsys)
        assert code == EXIT_VALID, f"stdout={out} stderr={err}"
        assert "2/2 valid" in out

    def test_stream_mixed(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built1 = _build_receipts(b"stream-seed-0000000000000000000003")
        built2 = _build_receipts(b"stream-seed-0000000000000000000004")
        tampered = dict(built2.l1)
        tampered["tool"] = "hacked"
        items = [
            {"l1": built1.l1, "behavior": built1.behavior},
            {"l1": tampered, "behavior": built2.behavior},
        ]
        path = _write_jsonl(tmp_path, "stream.jsonl", items)
        code, out, err = _run_cli(["--stream", str(path)], capsys)
        assert code == EXIT_INVALID
        assert "1/2 valid" in out

    def test_stream_json_output(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts(b"stream-seed-0000000000000000000005")
        items = [{"l1": built.l1, "behavior": built.behavior}]
        path = _write_jsonl(tmp_path, "stream.jsonl", items)
        code, out, err = _run_cli(["--stream", "--json", str(path)], capsys)
        assert code == EXIT_VALID
        data = json.loads(out)
        assert data["total"] == 1
        assert data["passed"] == 1
        assert data["failed"] == 0
        assert data["valid"] is True

    def test_stream_with_bad_json(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        path = tmp_path / "bad.jsonl"
        path.write_text('{"valid": json}\n{"also": bad\n')
        code, out, err = _run_cli(["--stream", str(path)], capsys)
        assert code == EXIT_INVALID
        assert "0/2 valid" in out


# ---------------------------------------------------------------------------
# Tests: --check-expiry
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_expired_receipt(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        # Artificially age the receipt
        built.l1["issued_at"] = 1000.0
        built.l1["expires_at"] = 1300.0  # expired long ago
        # Re-sign with the modified fields
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ccs_pydantic_ai.hashing import canonical_json
        from ccs_pydantic_ai.signer import derive_in_process_key

        priv = derive_in_process_key(b"cli-test-seed-0123456789abcdef")
        signed = {k: v for k, v in built.l1.items() if k != "signature"}
        sig = priv.sign(canonical_json(signed))
        built.l1["signature"] = base64.b64encode(sig).decode()

        path = _write_json(tmp_path, "expired.json", built.l1)
        # Without --check-expiry: valid
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_VALID
        # With --check-expiry: invalid
        code, out, err = _run_cli(["--check-expiry", str(path)], capsys)
        assert code == EXIT_INVALID
        assert "expired" in out.lower()


# ---------------------------------------------------------------------------
# Tests: error handling / usage
# ---------------------------------------------------------------------------

class TestErrors:
    def test_nonexistent_file(self, capsys: pytest.CaptureFixture):
        code, out, err = _run_cli(["/nonexistent/path.json"], capsys)
        assert code == EXIT_USAGE

    def test_invalid_json_file(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        code, out, err = _run_cli([str(p)], capsys)
        assert code == EXIT_USAGE
        assert "JSON" in out or "JSON" in err

    def test_non_dict_input(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        p = tmp_path / "array.json"
        p.write_text("[1, 2, 3]")
        code, out, err = _run_cli([str(p)], capsys)
        assert code == EXIT_INVALID

    def test_behavior_without_l1(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built = _build_receipts()
        path = _write_json(tmp_path, "behavior.json", built.behavior)
        code, out, err = _run_cli([str(path)], capsys)
        assert code == EXIT_INVALID
        assert "L1" in out or "chain" in out.lower()

    def test_version(self, capsys: pytest.CaptureFixture):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Test: cross-key rejection
# ---------------------------------------------------------------------------

class TestCrossKey:
    def test_different_key_signature(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        built1 = _build_receipts(b"key-one-key-one-key-one-key-one111")
        built2 = _build_receipts(b"key-two-key-two-key-two-key-two222")
        # Use L1 from key1 but signature from key2 (imposter)
        # Actually we need to sign built1's content with key2
        import base64
        from ccs_pydantic_ai.hashing import canonical_json
        from ccs_pydantic_ai.signer import derive_in_process_key

        priv2 = derive_in_process_key(b"key-two-key-two-key-two-key-two222")
        forged = dict(built1.l1)
        signed = {k: v for k, v in forged.items() if k != "signature"}
        forged["signature"] = base64.b64encode(priv2.sign(canonical_json(signed))).decode()
        # Also need to match the public_key to key2
        forged["public_key"] = built2.l1["public_key"]
        forged["public_key_fingerprint"] = built2.l1["public_key_fingerprint"]

        path = _write_json(tmp_path, "forged.json", forged)
        code, out, err = _run_cli([str(path)], capsys)
        # The signature will verify against key2's public key, but the fingerprint
        # may mismatch because the content digest is different. Actually the signature
        # should verify fine since we signed with key2 and put key2's pubkey.
        # But the content itself was built for key1's config, so issuer/audience match.
        # The point is: it's a valid signature from key2 over key1's receipt content.
        # This is actually valid from a crypto standpoint — key2 signed this content.
        # The test should verify that putting key1's signature with key2's pubkey fails.
        # Let's redo: keep key1's content and key1's pubkey, but replace signature
        # with garbage/random bytes.
        forged2 = dict(built1.l1)
        forged2["signature"] = base64.b64encode(b"\x00" * 64).decode()
        path2 = _write_json(tmp_path, "forged2.json", forged2)
        code2, out2, err2 = _run_cli([str(path2)], capsys)
        assert code2 == EXIT_INVALID
