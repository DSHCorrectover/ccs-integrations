"""Tests for :mod:`ccs_pydantic_ai.signer`."""
from __future__ import annotations

import base64

import pytest

from ccs_pydantic_ai.signer import (
    InProcessSigner,
    SidecarSigner,
    derive_in_process_key,
    fingerprint,
    verify_ed25519,
)
from ccs_pydantic_ai.hashing import canonical_json


# --------------------------------------------------------------------------- #
# Deterministic key derivation
# --------------------------------------------------------------------------- #
def test_same_seed_produces_same_key() -> None:
    a = InProcessSigner(b"the same seed")
    b = InProcessSigner(b"the same seed")
    assert a.public_key_b64 == b.public_key_b64
    assert a.public_key_fingerprint == b.public_key_fingerprint


def test_different_seeds_produce_different_keys() -> None:
    a = InProcessSigner(b"seed one")
    b = InProcessSigner(b"seed two")
    assert a.public_key_b64 != b.public_key_b64
    assert a.public_key_fingerprint != b.public_key_fingerprint


def test_key_matches_conformance_vector_derivation() -> None:
    """The in-process seed derivation must match the CCS conformance vector."""
    import hashlib

    # The conformance vector's raw seed is the literal string; InProcessSigner
    # applies sha256() internally to derive the 32-byte curve seed.
    vector_seed = b"ccs-verifier/in-process-test/v1"
    signer = InProcessSigner(vector_seed)
    assert signer.public_key_b64 == "6PPlM1taN/Ws4SnxaypgY2CGcKvGPw/eC54cUNesSb8="
    assert signer.public_key_fingerprint == "bbca301d8848dfdb"


def test_fingerprint_is_16_hex_chars_of_sha256() -> None:
    signer = InProcessSigner(b"any seed")
    raw = base64.b64decode(signer.public_key_b64)
    import hashlib

    assert signer.public_key_fingerprint == hashlib.sha256(raw).hexdigest()[:16]
    assert len(signer.public_key_fingerprint) == 16


# --------------------------------------------------------------------------- #
# Sign / verify
# --------------------------------------------------------------------------- #
def test_signature_roundtrip_verifies() -> None:
    signer = InProcessSigner(b"signing seed")
    payload = {"tool": "search", "q": "hello", "n": 3}
    sig = signer.sign(payload)
    assert signer.verify(payload, sig) is True


def test_signature_excludes_signature_field() -> None:
    signer = InProcessSigner(b"seed")
    payload = {"a": 1, "signature": "should-be-ignored"}
    sig = signer.sign(payload)
    # The same payload minus signature must verify.
    assert signer.verify({"a": 1}, sig) is True
    # Changing the ignored signature field must not affect verification.
    assert signer.verify({"a": 1, "signature": "tampered"}, sig) is True


def test_signature_uses_jcs_canonical_form() -> None:
    """Signature must be over JCS (sorted keys), so key order is irrelevant."""
    signer = InProcessSigner(b"seed")
    payload_ordered = {"a": 1, "b": 2, "c": 3}
    payload_reversed = {"c": 3, "b": 2, "a": 1}
    assert canonical_json(payload_ordered) == canonical_json(payload_reversed)
    sig = signer.sign(payload_ordered)
    assert signer.verify(payload_reversed, sig) is True


def test_tampered_payload_fails_verification() -> None:
    signer = InProcessSigner(b"seed")
    payload = {"verdict": "allow", "tool": "shell"}
    sig = signer.sign(payload)
    tampered = dict(payload)
    tampered["verdict"] = "block"
    assert signer.verify(tampered, sig) is False


def test_cross_key_rejection() -> None:
    """A signature from key A must not verify under key B."""
    signer_a = InProcessSigner(b"key A")
    signer_b = InProcessSigner(b"key B")
    payload = {"trace_id": "abc"}
    sig_a = signer_a.sign(payload)
    assert signer_a.verify(payload, sig_a) is True
    assert signer_b.verify(payload, sig_a) is False


def test_verify_returns_false_on_invalid_inputs() -> None:
    signer = InProcessSigner(b"seed")
    payload = {"x": 1}
    assert verify_ed25519(signer.public_key_b64, payload, "not-base64!!!") is False
    assert verify_ed25519(signer.public_key_b64, payload, "") is False


# --------------------------------------------------------------------------- #
# Empty/invalid seeds
# --------------------------------------------------------------------------- #
def test_empty_seed_rejected() -> None:
    with pytest.raises(ValueError):
        InProcessSigner(b"")


def test_non_bytes_seed_rejected() -> None:
    with pytest.raises(TypeError):
        derive_in_process_key("not bytes")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Sidecar signer (HTTP mocked)
# --------------------------------------------------------------------------- #
def test_sidecar_signer_verifies_locally() -> None:
    # Use a real in-process key to act as the "remote sidecar" signer.
    remote = InProcessSigner(b"sidecar-private")

    def fake_post(url: str, payload: dict) -> dict:
        return {"signature": remote.sign(payload)}

    sidecar = SidecarSigner(
        "http://localhost:9100",
        remote.public_key_b64,
        http_post=fake_post,
    )
    assert sidecar.deployment_mode == "sidecar"
    payload = {"tool": "search"}
    sig = sidecar.sign(payload)
    assert sidecar.verify(payload, sig) is True


def test_sidecar_rejects_invalid_signature() -> None:
    good = InProcessSigner(b"good key")
    evil = InProcessSigner(b"evil key")

    # The "sidecar" is compromised and signs with a different key than the
    # trusted public key configured on the adapter.
    def fake_post(url: str, payload: dict) -> dict:
        return {"signature": evil.sign(payload)}

    sidecar = SidecarSigner(
        "http://localhost:9100",
        good.public_key_b64,  # trusted key
        http_post=fake_post,
    )
    with pytest.raises(RuntimeError, match="does not verify"):
        sidecar.sign({"tool": "search"})
