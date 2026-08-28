"""Ed25519 signing for CCS receipts.

Two signer implementations are provided:

* :class:`InProcessSigner` — derives the private key deterministically from a
  seed via ``Ed25519PrivateKey.from_private_bytes(sha256(seed))``, matching the
  key derivation used by the CCS conformance vectors. The private key lives in
  the CrewAI process; receipts are byte-reproducible across runs.
* :class:`SidecarSigner` — keeps the private key out of the CrewAI process. It
  delegates signing to an external HTTP signer endpoint (the CCS sidecar) and
  only ever holds the trusted public key for local signature verification.

Both implement the same :class:`CCSSigner` protocol so that
:class:`~ccs_crewai.receipt_builder.ReceiptBuilder` can sign either L1 or
behavior receipts without knowing the deployment model.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Optional, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .hashing import canonical_json

__all__ = [
    "CCSSigner",
    "InProcessSigner",
    "SidecarSigner",
    "derive_in_process_key",
    "fingerprint",
    "verify_ed25519",
    "build_signer",
]

SIGNING_ALGORITHM = "Ed25519"


@runtime_checkable
class CCSSigner(Protocol):
    """Protocol for objects that can sign canonical receipt payloads."""

    @property
    def signing_algorithm(self) -> str: ...

    @property
    def deployment_mode(self) -> str: ...

    @property
    def public_key_b64(self) -> str: ...

    @property
    def public_key_fingerprint(self) -> str: ...

    def sign(self, payload: dict[str, Any]) -> str:
        """Sign *payload* (excluding its own ``signature`` field) and return
        the base64-encoded Ed25519 signature."""
        ...

    def verify(self, payload: dict[str, Any], signature_b64: str) -> bool:
        """Verify *signature_b64* against the JCS canonical form of *payload*."""
        ...


def _public_key_b64(pub: Ed25519PublicKey) -> str:
    return base64.b64encode(
        pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def fingerprint(public_key_b64: str) -> str:
    """Return the 16-hex-char SHA-256 fingerprint of a base64 public key.

    Matches the CCS convention used by ``ccs-verifier`` and the conformance
    vectors: first 16 hex chars of ``sha256(raw 32-byte public key)``.
    """
    raw = base64.b64decode(public_key_b64)
    return hashlib.sha256(raw).hexdigest()[:16]


def derive_in_process_key(seed: bytes) -> Ed25519PrivateKey:
    """Derive an Ed25519 private key deterministically from *seed*.

    The 32-byte seed for the curve is ``sha256(seed)``, matching the CCS
    in-process conformance vector key derivation.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) == 0:
        raise ValueError("seed must not be empty")
    key_seed = hashlib.sha256(bytes(seed)).digest()
    return Ed25519PrivateKey.from_private_bytes(key_seed)


def verify_ed25519(
    public_key_b64: str, payload: dict[str, Any], signature_b64: str
) -> bool:
    """Verify an Ed25519 signature over JCS(*payload*) using *public_key_b64*.

    The ``signature`` key is stripped from *payload* before canonicalization if
    present, so callers may pass the full receipt dict. Returns ``False`` on any
    verification or decoding error rather than raising.
    """
    try:
        signed = {k: v for k, v in payload.items() if k != "signature"}
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), canonical_json(signed))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class InProcessSigner:
    """Deterministic in-process Ed25519 signer."""

    def __init__(self, seed: bytes) -> None:
        self._private_key = derive_in_process_key(seed)
        pub = self._private_key.public_key()
        self._public_key_b64 = _public_key_b64(pub)
        self._fingerprint = fingerprint(self._public_key_b64)

    @property
    def signing_algorithm(self) -> str:
        return SIGNING_ALGORITHM

    @property
    def deployment_mode(self) -> str:
        return "in-process"

    @property
    def public_key_b64(self) -> str:
        return self._public_key_b64

    @property
    def public_key_fingerprint(self) -> str:
        return self._fingerprint

    def sign(self, payload: dict[str, Any]) -> str:
        signed = {k: v for k, v in payload.items() if k != "signature"}
        signature = self._private_key.sign(canonical_json(signed))
        return base64.b64encode(signature).decode("ascii")

    def verify(self, payload: dict[str, Any], signature_b64: str) -> bool:
        return verify_ed25519(self._public_key_b64, payload, signature_b64)


class SidecarSigner:
    """External sidecar Ed25519 signer.

    The private key never enters the CrewAI process. Signing is delegated to an
    HTTP endpoint that accepts the canonical payload and returns the base64
    signature. The trusted public key is held locally so signatures returned by
    the sidecar are verified before being attached to receipts.

    The HTTP contract is intentionally minimal and can be adapted to any CCS
    sidecar implementation::

        POST {sidecar_url}/sign
        Content-Type: application/json
        { "payload": <canonical-JSON-as-object>, "deployment_mode": "sidecar" }

        200 OK
        { "signature": "<base64 Ed25519 signature>" }

    A custom ``http_post`` callable may be injected for testing or for sidecars
    that use a different wire protocol.
    """

    def __init__(
        self,
        sidecar_url: str,
        public_key_b64: str,
        *,
        http_post: Optional[Any] = None,
        timeout: float = 5.0,
    ) -> None:
        self._sidecar_url = sidecar_url.rstrip("/")
        self._public_key_b64 = public_key_b64
        self._fingerprint = fingerprint(public_key_b64)
        self._timeout = timeout
        self._http_post = http_post

    @property
    def signing_algorithm(self) -> str:
        return SIGNING_ALGORITHM

    @property
    def deployment_mode(self) -> str:
        return "sidecar"

    @property
    def public_key_b64(self) -> str:
        return self._public_key_b64

    @property
    def public_key_fingerprint(self) -> str:
        return self._fingerprint

    def sign(self, payload: dict[str, Any]) -> str:
        signed = {k: v for k, v in payload.items() if k != "signature"}
        signature_b64 = self._request_signature(signed)
        # Never attach a signature we cannot locally verify.
        if not verify_ed25519(self._public_key_b64, signed, signature_b64):
            raise RuntimeError(
                "Sidecar returned a signature that does not verify against the "
                "configured public key; refusing to emit receipt."
            )
        return signature_b64

    def verify(self, payload: dict[str, Any], signature_b64: str) -> bool:
        return verify_ed25519(self._public_key_b64, payload, signature_b64)

    def _request_signature(self, payload: dict[str, Any]) -> str:
        if self._http_post is not None:
            result = self._http_post(self._sidecar_url, payload)
            if isinstance(result, dict):
                return result["signature"]
            return str(result)

        import json
        import urllib.error
        import urllib.request

        body = json.dumps(
            {"payload": payload, "deployment_mode": "sidecar"}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self._sidecar_url}/sign",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:  # pragma: no cover - network
            raise RuntimeError(f"CCS sidecar signing request failed: {exc}") from exc
        return data["signature"]


def build_signer(config: Any) -> CCSSigner:
    """Construct the appropriate signer for a CCS configuration object.

    If ``config.signer`` is already set it is returned unchanged (allowing
    arbitrary custom signers). Otherwise an :class:`InProcessSigner` or
    :class:`SidecarSigner` is constructed from the config fields.
    """
    if config.signer is not None:
        return config.signer

    if config.deployment_mode == "in-process":
        return InProcessSigner(config.seed)

    # sidecar
    if config.sidecar_url is None or config.public_key is None:
        raise ValueError(
            "Sidecar mode requires both sidecar_url and public_key "
            "(or supply a custom signer)."
        )
    return SidecarSigner(config.sidecar_url, config.public_key)
