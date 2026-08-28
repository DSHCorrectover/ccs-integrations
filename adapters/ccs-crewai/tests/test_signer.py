"""Tests for Ed25519 signer and fingerprint derivation."""
from __future__ import annotations

import base64

import pytest

from ccs_crewai.signer import (
    InProcessSigner,
    derive_in_process_key,
    fingerprint,
    verify_ed25519,
)


SEED = b"ccs-crewai-unit-test-seed"


def test_derive_key_deterministic():
    k1 = derive_in_process_key(SEED)
    k2 = derive_in_process_key(SEED)
    # Ed25519PrivateKey objects support equality via public_key comparison
    assert k1.public_key().public_bytes_raw() == k2.public_key().public_bytes_raw()


def test_derive_key_rejects_empty_seed():
    with pytest.raises(ValueError):
        derive_in_process_key(b"")


def test_fingerprint_length_and_format():
    signer = InProcessSigner(SEED)
    fp = fingerprint(signer.public_key_b64)
    assert isinstance(fp, str)
    assert len(fp) == 16
    int(fp, 16)  # must be valid hex


def test_sign_and_verify_roundtrip():
    signer = InProcessSigner(SEED)
    payload = {"tool": "search", "q": "hello"}
    sig = signer.sign(payload)
    # signature is base64-encoded Ed25519 (64 raw bytes)
    assert len(base64.b64decode(sig)) == 64
    assert signer.verify(payload, sig) is True


def test_verify_rejects_tampered_payload():
    signer = InProcessSigner(SEED)
    payload = {"tool": "search", "q": "hello"}
    sig = signer.sign(payload)
    tampered = {"tool": "search", "q": "evil"}
    assert signer.verify(tampered, sig) is False


def test_verify_ed25519_helper():
    signer = InProcessSigner(SEED)
    payload = {"x": 1}
    sig = signer.sign(payload)
    assert verify_ed25519(signer.public_key_b64, payload, sig) is True
