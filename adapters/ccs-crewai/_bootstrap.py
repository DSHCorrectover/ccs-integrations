"""One-shot bootstrap that writes the complete ccs-crewai adapter.

This script is intentionally self-contained: it recreates every source, test,
example, and packaging file for the adapter and then removes itself.
"""
from __future__ import annotations

from pathlib import Path
import textwrap
import os

ROOT = Path(__file__).resolve().parent

FILES: dict[str, str] = {}

FILES["LICENSE"] = r'''MIT License

Copyright (c) 2026 Correctover / CCS Integrations

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

FILES["pyproject.toml"] = r'''[build-system]
requires = ["hatchling>=1.21"]
build-backend = "hatchling.build"

[project]
name = "ccs-crewai"
version = "0.1.0"
description = "Cryptographic runtime receipts for CrewAI agents — signed Ed25519 audit evidence for every tool call. CCS (Correctover Conformance Shape) L1 + behavior receipts with pre-admission guardrails."
readme = "README.md"
requires-python = ">=3.10"
license = "MIT"
license-files = ["LICENSE"]
authors = [
    { name = "Correctover / CCS Integrations" },
]
keywords = [
    "ai-security", "agent-security", "guardrails", "runtime-security", "llm-security",
    "cryptographic-receipts", "audit-trail", "non-repudiation", "compliance", "governance",
    "ed25519", "jcs", "rfc8785", "signed-receipts", "tamper-evidence", "verifiable",
    "runtime-verification", "tool-call-validation", "observability",
    "crewai", "crew-ai", "multi-agent", "supply-chain-security", "owasp-asi", "ai-agents",
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
    "Topic :: Security",
    "Topic :: Software Development :: Libraries :: Python Modules",
]
dependencies = [
    "jcs>=0.2.0",
    "cryptography>=41.0.0",
]

[project.optional-dependencies]
# CrewAI is optional: receipt production/verification and the CLI work without it.
crewai = ["crewai>=0.100.0"]
dev = [
    "pytest>=7.0",
    "build>=1.0",
]

[project.scripts]
ccs-crewai-verify = "ccs_crewai.cli:main"

[project.urls]
Homepage = "https://github.com/DSHCorrectover/ccs-integrations"
Documentation = "https://github.com/DSHCorrectover/ccs-integrations/tree/main/adapters/ccs-crewai#readme"
Issues = "https://github.com/DSHCorrectover/ccs-integrations/issues"
Specification = "https://www.ietf.org/archive/id/draft-correctover-ccs-08.txt"
Conformance = "https://github.com/DSHCorrectover/ccs-conformance-vectors"

[tool.hatch.build.targets.wheel]
packages = ["src/ccs_crewai"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]

[tool.ruff]
line-length = 100
target-version = "py310"
'''

FILES["src/ccs_crewai/__init__.py"] = r'''"""ccs-crewai — CCS runtime receipts for CrewAI agents.

Two-line integration::

    from ccs_crewai import CCSConfig, CCSGuardrailProvider, enable_guardrail

    provider = CCSGuardrailProvider(
        CCSConfig(seed=b"my-app-seed", policy=my_policy)
    )
    enable_guardrail(provider)

Every tool call then emits a signed 30-field CCS L1 action receipt and a linked
``ccs.behavior_evidence.v1`` receipt to the configured sink. Denied calls are
blocked before execution and documented with a signed ``verdict="block"``
receipt. Receipts can be independently verified without CrewAI installed::

    from ccs_crewai import verify_l1_receipt, verify_chain
    ok, reason = verify_l1_receipt(receipt_dict)

Or from the command line::

    ccs-crewai-verify receipt.json
"""

from __future__ import annotations

__version__ = "0.1.0"

from .config import (
    CCSConfig,
    PolicyDecision,
    ReceiptRecord,
    ReceiptSink,
)
from .hashing import canonical_json, canonical_sha256_hex
from .receipt_builder import (
    BEHAVIOR_RECEIPT_TYPE,
    L1_RECEIPT_VERSION,
    BuiltReceipts,
    ReceiptBuilder,
    linked_l1_digest,
)
from .signer import (
    CCSSigner,
    InProcessSigner,
    SidecarSigner,
    build_signer,
    derive_in_process_key,
    fingerprint,
    verify_ed25519,
)
from .verifier import (
    L1_FIELDS as VERIFIER_L1_FIELDS,
    VerificationError,
    verify_l1_receipt,
    verify_l1_signature,
    verify_chain,
    verify_behavior_linkage,
    verify_behavior_signature,
)

__all__ = [
    "CCSConfig",
    "CCSGuardrailProvider",
    "enable_guardrail",
    "GuardrailRequest",
    "GuardrailDecision",
    "ToolCallBlocked",
    "GuardedToolResult",
    "PolicyDecision",
    "ReceiptRecord",
    "ReceiptSink",
    "ReceiptBuilder",
    "BuiltReceipts",
    "canonical_json",
    "canonical_sha256_hex",
    "linked_l1_digest",
    "L1_RECEIPT_VERSION",
    "BEHAVIOR_RECEIPT_TYPE",
    "CCSSigner",
    "InProcessSigner",
    "SidecarSigner",
    "build_signer",
    "derive_in_process_key",
    "fingerprint",
    "verify_ed25519",
    "VerificationError",
    "verify_l1_receipt",
    "verify_l1_signature",
    "verify_chain",
    "verify_behavior_linkage",
    "verify_behavior_signature",
    "VERIFIER_L1_FIELDS",
    "__version__",
]

_LAZY = {
    "CCSGuardrailProvider": (".guardrail", "CCSGuardrailProvider"),
    "enable_guardrail": (".guardrail", "enable_guardrail"),
    "GuardrailRequest": (".guardrail", "GuardrailRequest"),
    "GuardrailDecision": (".guardrail", "GuardrailDecision"),
    "ToolCallBlocked": (".guardrail", "ToolCallBlocked"),
    "GuardedToolResult": (".guardrail", "GuardedToolResult"),
}


def __getattr__(name: str):  # PEP 562
    if name in _LAZY:
        import importlib
        module_path, attr = _LAZY[name]
        mod = importlib.import_module(module_path, __name__)
        value = getattr(mod, attr)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
'''

FILES["src/ccs_crewai/hashing.py"] = r'''"""JCS canonical JSON (RFC 8785) and SHA-256 hashing helpers.

All CCS receipts are signed over JCS-canonicalized JSON so that signatures are
byte-reproducible across languages and implementations.
"""

from __future__ import annotations

import hashlib
from typing import Any

import jcs

__all__ = [
    "canonical_json",
    "sha256_hex",
    "sha256_digest",
    "canonical_sha256_hex",
    "jcs_digest",
]


def canonical_json(data: Any) -> bytes:
    """Return the RFC 8785 JCS canonical JSON byte representation of *data*."""
    _validate_safe_integers(data)
    return jcs.canonicalize(data)


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of raw *data* bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_digest(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def canonical_sha256_hex(data: Any) -> str:
    """Canonicalize *data* with JCS and return its hex SHA-256 digest."""
    return sha256_hex(canonical_json(data))


jcs_digest = canonical_sha256_hex

_MAX_SAFE_INTEGER = (1 << 53) - 1
_MIN_SAFE_INTEGER = -(1 << 53) + 1


def _validate_safe_integers(data: Any) -> None:
    """Reject integers outside the RFC 8785 section 6.2 safe-integer range."""
    if isinstance(data, bool):
        return
    if isinstance(data, int):
        if data > _MAX_SAFE_INTEGER or data < _MIN_SAFE_INTEGER:
            raise ValueError(
                f"Integer {data} is outside the RFC 8785 safe range "
                f"[{_MIN_SAFE_INTEGER}, {_MAX_SAFE_INTEGER}]; cannot canonicalize."
            )
    elif isinstance(data, dict):
        for key, value in data.items():
            _validate_safe_integers(key)
            _validate_safe_integers(value)
    elif isinstance(data, (list, tuple)):
        for item in data:
            _validate_safe_integers(item)
'''

FILES["src/ccs_crewai/signer.py"] = r'''"""Ed25519 signing for CCS receipts.

Two signer implementations are provided:

* :class:`InProcessSigner` derives the private key deterministically from a seed
  via ``Ed25519PrivateKey.from_private_bytes(sha256(seed))``.
* :class:`SidecarSigner` delegates signing to an external HTTP signer endpoint
  and holds only the trusted public key locally.
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
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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

    def sign(self, payload: dict[str, Any]) -> str: ...

    def verify(self, payload: dict[str, Any], signature_b64: str) -> bool: ...


def _public_key_b64(pub: Ed25519PublicKey) -> str:
    return base64.b64encode(
        pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def fingerprint(public_key_b64: str) -> str:
    """Return the 16-hex-char SHA-256 fingerprint of a base64 public key."""
    raw = base64.b64decode(public_key_b64)
    return hashlib.sha256(raw).hexdigest()[:16]


def derive_in_process_key(seed: bytes) -> Ed25519PrivateKey:
    """Derive an Ed25519 private key deterministically from *seed*."""
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) == 0:
        raise ValueError("seed must not be empty")
    key_seed = hashlib.sha256(bytes(seed)).digest()
    return Ed25519PrivateKey.from_private_bytes(key_seed)


def verify_ed25519(
    public_key_b64: str, payload: dict[str, Any], signature_b64: str
) -> bool:
    """Verify an Ed25519 signature over JCS(*payload* excluding signature)."""
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

    The private key never enters the CrewAI process. A custom ``http_post``
    callable may be injected for testing or sidecars with a different wire
    protocol.
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
    """Construct the appropriate signer for a CCS configuration object."""
    if config.signer is not None:
        return config.signer

    if config.deployment_mode == "in-process":
        return InProcessSigner(config.seed)

    if config.sidecar_url is None or config.public_key is None:
        raise ValueError(
            "Sidecar mode requires both sidecar_url and public_key "
            "(or supply a custom signer)."
        )
    return SidecarSigner(config.sidecar_url, config.public_key)
'''

FILES["src/ccs_crewai/config.py"] = r'''"""Configuration for the CCS CrewAI adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

__all__ = ["CCSConfig", "ReceiptSink", "ReceiptRecord", "PolicyDecision"]

ReceiptSink = Callable[["ReceiptRecord"], None]


def _stdout_sink(record: "ReceiptRecord") -> None:
    """Default sink: emit each receipt pair as one JSON line on stdout."""
    import json

    print(json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True), flush=True)


@dataclass
class ReceiptRecord:
    """A pair of signed receipts emitted for a single tool call."""

    l1: dict[str, Any]
    behavior: Optional[dict[str, Any]]
    trace_id: str
    tool_call_id: str
    verdict: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "l1": self.l1,
            "behavior": self.behavior,
            "trace_id": self.trace_id,
            "tool_call_id": self.tool_call_id,
            "verdict": self.verdict,
        }


@dataclass
class PolicyDecision:
    """A pre-admission policy decision for a tool call."""

    allowed: bool
    reason: str = "no_rules_matched"
    metadata: dict[str, Any] = field(default_factory=dict)


PolicyCallable = Callable[[str, dict[str, Any], dict[str, Any]], PolicyDecision]


def _default_policy(
    tool_name: str,
    tool_input: dict[str, Any],
    runtime_context: dict[str, Any],
) -> PolicyDecision:
    """Default allow-all policy."""
    return PolicyDecision(allowed=True, reason="no_rules_matched")


@dataclass
class CCSConfig:
    """Configuration for :class:`~ccs_crewai.CCSGuardrailProvider`."""

    deployment_mode: str = "in-process"
    seed: Optional[bytes] = None
    sidecar_url: Optional[str] = None
    signer: Optional[Any] = None
    public_key: Optional[str] = None

    policy: PolicyCallable = field(default=_default_policy)
    rule_version: str = "1.3.0"
    rule_summary: str = "no_rules_matched"
    issuer: str = "ccs-crewai"
    audience: str = "crewai-agent"
    trace_id: Optional[str] = None

    receipt_ttl_seconds: float = 300.0
    max_clock_skew: float = 0.0
    verifier_source_class: str = "CrewAIAdapter"

    sink: ReceiptSink = field(default=_stdout_sink)
    include_behavior_receipts: bool = True
    action_suffix: str = "execute"
    fail_closed: bool = True

    def __post_init__(self) -> None:
        if self.deployment_mode not in ("in-process", "sidecar"):
            raise ValueError(
                f"deployment_mode must be 'in-process' or 'sidecar', "
                f"got {self.deployment_mode!r}"
            )
        if self.signer is None:
            if self.deployment_mode == "in-process":
                if self.seed is None:
                    raise ValueError(
                        "seed is required for in-process mode "
                        "(or supply a custom signer)."
                    )
            else:
                if self.sidecar_url is None and self.public_key is None:
                    raise ValueError(
                        "sidecar mode requires sidecar_url or an explicit "
                        "public_key (or supply a custom signer)."
                    )
        if self.receipt_ttl_seconds < 0:
            raise ValueError("receipt_ttl_seconds must be non-negative")
'''

FILES["src/ccs_crewai/receipt_builder.py"] = r'''"""Build signed CCS L1 action receipts and linked behavior evidence receipts."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional

from .hashing import canonical_json, canonical_sha256_hex, sha256_hex
from .signer import CCSSigner

__all__ = [
    "ReceiptBuilder",
    "BuiltReceipts",
    "L1_RECEIPT_VERSION",
    "BEHAVIOR_RECEIPT_TYPE",
    "L1_FIELDS",
    "BEHAVIOR_FIELDS",
    "linked_l1_digest",
]

L1_RECEIPT_VERSION = "1.1"
BEHAVIOR_RECEIPT_TYPE = "ccs.behavior_evidence.v1"

L1_FIELDS: tuple[str, ...] = (
    "trace_id", "receipt_version", "verdict", "timestamp", "tool",
    "tool_call_id", "params_hash", "args_digest", "rule_summary", "rule_version",
    "request_hash", "response_hash", "runtime_context_hash", "config_hash",
    "verifier_source_class", "deployment_mode", "issuer", "audience", "nonce",
    "sequence", "issued_at", "expires_at", "max_clock_skew", "action",
    "signature", "signing_algorithm", "public_key_fingerprint", "public_key",
    "verified_at", "latency_us",
)

BEHAVIOR_FIELDS: tuple[str, ...] = (
    "receipt_type", "trace_id", "tool_call_id", "sequence",
    "linked_l1_receipt_digest", "behavior_evidence_verdict", "evidence_ref",
    "issuer", "audience", "issued_at", "deployment_mode", "signing_algorithm",
    "public_key_fingerprint", "public_key", "signature",
)


@dataclass
class BuiltReceipts:
    """The two signed receipts produced for a single tool call."""

    l1: dict[str, Any]
    behavior: Optional[dict[str, Any]]

    @property
    def verdict(self) -> str:
        return self.l1["verdict"]

    def as_record(self) -> dict[str, Any]:
        return {"l1": self.l1, "behavior": self.behavior}


def _json_safe(value: Any) -> Any:
    """Coerce arbitrary values into JSON/JCS-serialisable form."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return repr(value)


def _error_envelope(exc: BaseException) -> dict[str, str]:
    return {"error": type(exc).__name__, "message": str(exc)}


class ReceiptBuilder:
    """Builds and signs L1 + behavior receipts for CrewAI tool calls."""

    def __init__(
        self,
        signer: CCSSigner,
        *,
        rule_version: str,
        rule_summary: str,
        issuer: str,
        audience: str,
        trace_id: str,
        verifier_source_class: str = "CrewAIAdapter",
        receipt_ttl_seconds: float = 300.0,
        max_clock_skew: float = 0.0,
        action_suffix: str = "execute",
        include_behavior: bool = True,
        nonce_generator: Any = None,
        clock: Any = None,
    ) -> None:
        self._signer = signer
        self._rule_version = rule_version
        self._rule_summary = rule_summary
        self._issuer = issuer
        self._audience = audience
        self._trace_id = trace_id
        self._verifier_source_class = verifier_source_class
        self._receipt_ttl = float(receipt_ttl_seconds)
        self._max_clock_skew = float(max_clock_skew)
        self._action_suffix = action_suffix
        self._include_behavior = include_behavior
        self._nonce_generator = nonce_generator or (lambda: secrets.token_hex(16))
        self._clock = clock or time.time

        config_envelope = {
            "rule_version": rule_version,
            "issuer": issuer,
            "audience": audience,
            "deployment_mode": signer.deployment_mode,
            "verifier_source_class": verifier_source_class,
            "receipt_ttl_seconds": receipt_ttl_seconds,
            "max_clock_skew": max_clock_skew,
            "public_key_fingerprint": signer.public_key_fingerprint,
        }
        self._config_hash = canonical_sha256_hex(config_envelope)
        self._sequence = 0

    def build(
        self,
        *,
        tool: str,
        tool_call_id: str,
        args: dict[str, Any],
        runtime_context: Optional[dict[str, Any]] = None,
        result: Any = None,
        error: Optional[BaseException] = None,
        blocked: bool = False,
        block_reason: Optional[str] = None,
        started_at: Optional[float] = None,
        ended_at: Optional[float] = None,
    ) -> BuiltReceipts:
        """Build and sign the L1 + behavior receipts for one tool call."""
        now = self._clock()
        started_at = now if started_at is None else started_at
        ended_at = now if ended_at is None else ended_at
        latency_us = max(0.0, (ended_at - started_at) * 1_000_000)
        sequence = self._sequence
        self._sequence += 1

        if blocked or error is not None:
            verdict = "block"
            rule_summary = block_reason or (
                f"{type(error).__name__}: {error}" if error is not None else "blocked"
            )
            behavior_verdict = "observed_and_rejected"
        else:
            verdict = "allow"
            rule_summary = self._rule_summary
            behavior_verdict = "not_observed"

        safe_args = _json_safe(args)
        args_digest = canonical_sha256_hex(safe_args)
        param_keys = sorted(safe_args.keys()) if isinstance(safe_args, dict) else []
        params_hash = canonical_sha256_hex({"tool": tool, "param_keys": param_keys})
        request_hash = canonical_sha256_hex(
            {"tool": tool, "tool_call_id": tool_call_id, "args": safe_args}
        )

        if blocked:
            response_body: Any = {"blocked": True, "reason": block_reason or "blocked"}
        elif error is not None:
            response_body = _error_envelope(error)
        else:
            response_body = _json_safe(result)
        response_hash = canonical_sha256_hex(response_body)

        runtime_context_hash = canonical_sha256_hex(
            {
                "trace_id": self._trace_id,
                "tool_call_id": tool_call_id,
                "runtime": _json_safe(runtime_context or {}),
            }
        )

        issued_at = ended_at
        nonce = self._nonce_generator()
        l1_unsigned: dict[str, Any] = {
            "trace_id": self._trace_id,
            "receipt_version": L1_RECEIPT_VERSION,
            "verdict": verdict,
            "timestamp": started_at,
            "tool": tool,
            "tool_call_id": tool_call_id,
            "params_hash": params_hash,
            "args_digest": args_digest,
            "rule_summary": rule_summary,
            "rule_version": self._rule_version,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "runtime_context_hash": runtime_context_hash,
            "config_hash": self._config_hash,
            "verifier_source_class": self._verifier_source_class,
            "deployment_mode": self._signer.deployment_mode,
            "issuer": self._issuer,
            "audience": self._audience,
            "nonce": nonce,
            "sequence": sequence,
            "issued_at": issued_at,
            "expires_at": issued_at + self._receipt_ttl,
            "max_clock_skew": self._max_clock_skew,
            "action": f"{tool}.{self._action_suffix}",
            "signing_algorithm": self._signer.signing_algorithm,
            "public_key_fingerprint": self._signer.public_key_fingerprint,
            "public_key": self._signer.public_key_b64,
            "verified_at": ended_at,
            "latency_us": round(latency_us, 3),
        }

        signature = self._signer.sign(l1_unsigned)
        l1 = dict(l1_unsigned)
        l1["signature"] = signature
        assert set(l1.keys()) == set(L1_FIELDS)
        l1 = {k: l1[k] for k in L1_FIELDS}

        behavior: Optional[dict[str, Any]] = None
        if self._include_behavior:
            behavior = self._build_behavior(
                l1=l1,
                sequence=sequence,
                behavior_verdict=behavior_verdict,
                rule_summary=rule_summary,
                issued_at=issued_at,
            )
        return BuiltReceipts(l1=l1, behavior=behavior)

    def _build_behavior(
        self,
        *,
        l1: dict[str, Any],
        sequence: int,
        behavior_verdict: str,
        rule_summary: str,
        issued_at: float,
    ) -> dict[str, Any]:
        l1_excluding_sig = {k: v for k, v in l1.items() if k != "signature"}
        linked_digest = "sha256:" + sha256_hex(canonical_json(l1_excluding_sig))
        behavior_unsigned: dict[str, Any] = {
            "receipt_type": BEHAVIOR_RECEIPT_TYPE,
            "trace_id": l1["trace_id"],
            "tool_call_id": l1["tool_call_id"],
            "sequence": sequence,
            "linked_l1_receipt_digest": linked_digest,
            "behavior_evidence_verdict": behavior_verdict,
            "evidence_ref": {
                "type": "rule_scan_complete",
                "rule_id": rule_summary,
                "verifier": "ccs-crewai",
                "rule_version": self._rule_version,
            },
            "issuer": self._issuer,
            "audience": self._audience,
            "issued_at": issued_at,
            "deployment_mode": self._signer.deployment_mode,
            "signing_algorithm": self._signer.signing_algorithm,
            "public_key_fingerprint": self._signer.public_key_fingerprint,
            "public_key": self._signer.public_key_b64,
        }
        signature = self._signer.sign(behavior_unsigned)
        behavior = dict(behavior_unsigned)
        behavior["signature"] = signature
        assert set(behavior.keys()) == set(BEHAVIOR_FIELDS)
        return {k: behavior[k] for k in BEHAVIOR_FIELDS}


def linked_l1_digest(l1_receipt: dict[str, Any]) -> str:
    """Compute the ``linked_l1_receipt_digest`` for an L1 receipt."""
    excluding_sig = {k: v for k, v in l1_receipt.items() if k != "signature"}
    return "sha256:" + sha256_hex(canonical_json(excluding_sig))
'''

FILES["src/ccs_crewai/guardrail.py"] = r'''"""CrewAI guardrail integration for CCS runtime receipts.

This module uses CrewAI's documented tool-call hook system:
https://docs.crewai.com/en/learn/tool-hooks. A formal ``GuardrailProvider`` base
class is not yet shipped upstream (crewAIInc/crewAI#4877), so the provider
protocol and hook adapters are implemented here. The ``crewai`` import is lazy,
which keeps the core provider and all tests independent of the CrewAI package.
"""

from __future__ import annotations

import secrets
import time
import uuid
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, Optional, TypeVar

from .config import CCSConfig, PolicyDecision, ReceiptRecord
from .receipt_builder import BuiltReceipts, ReceiptBuilder
from .signer import build_signer

__all__ = [
    "GuardrailRequest",
    "GuardrailDecision",
    "CCSGuardrailProvider",
    "ToolCallBlocked",
    "GuardedToolResult",
    "enable_guardrail",
]


@dataclass
class GuardrailRequest:
    """Context passed to a guardrail provider for each tool call."""

    tool_name: str
    tool_input: dict[str, Any]
    agent_role: Optional[str] = None
    task_description: Optional[str] = None
    crew_id: Optional[str] = None
    timestamp: str = ""

    def runtime_context(self) -> dict[str, Any]:
        return {
            "agent_role": self.agent_role,
            "task_description": self.task_description,
            "crew_id": self.crew_id,
            "timestamp": self.timestamp,
        }


@dataclass
class GuardrailDecision:
    """Provider's allow/deny verdict."""

    allow: bool
    reason: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolCallBlocked(Exception):
    """Raised by direct interception when a policy denies a tool call."""

    def __init__(self, reason: str, receipts: BuiltReceipts) -> None:
        super().__init__(reason)
        self.reason = reason
        self.receipts = receipts


T = TypeVar("T")


@dataclass
class GuardedToolResult(Generic[T]):
    """Result returned by :meth:`CCSGuardrailProvider.intercept_tool_call`."""

    result: T
    receipts: BuiltReceipts

    @property
    def verdict(self) -> str:
        return self.receipts.verdict


class _HookState:
    __slots__ = (
        "tool_call_id", "started_at", "tool_name", "tool_input",
        "runtime_context", "receipts",
    )

    def __init__(
        self, *, tool_call_id: str, started_at: float, tool_name: str,
        tool_input: dict[str, Any], runtime_context: dict[str, Any],
    ) -> None:
        self.tool_call_id = tool_call_id
        self.started_at = started_at
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.runtime_context = runtime_context
        self.receipts: Optional[BuiltReceipts] = None


class CCSGuardrailProvider:
    """CCS-backed CrewAI tool-call guardrail.

    Args:
        config: CCS configuration, including signing key, policy callable, and
            receipt sink.
        builder: Optional pre-built receipt builder.
        clock/id_generator/nonce_generator: Determinism hooks for tests.
    """

    name: str = "ccs-crewai-guardrail"

    def __init__(
        self,
        config: CCSConfig,
        *,
        builder: Optional[ReceiptBuilder] = None,
        clock: Optional[Callable[[], float]] = None,
        id_generator: Optional[Callable[[], str]] = None,
        nonce_generator: Optional[Callable[[], str]] = None,
    ) -> None:
        self.config = config
        self._clock = clock or time.time
        self._id_generator = id_generator or (lambda: f"ccs-{uuid.uuid4().hex}")
        self._nonce_generator = nonce_generator or (lambda: secrets.token_hex(16))

        if builder is None:
            signer = build_signer(config)
            trace_id = config.trace_id or f"ccs-{uuid.uuid4().hex}"
            builder = ReceiptBuilder(
                signer=signer,
                rule_version=config.rule_version,
                rule_summary=config.rule_summary,
                issuer=config.issuer,
                audience=config.audience,
                trace_id=trace_id,
                verifier_source_class=config.verifier_source_class,
                receipt_ttl_seconds=config.receipt_ttl_seconds,
                max_clock_skew=config.max_clock_skew,
                action_suffix=config.action_suffix,
                include_behavior=config.include_behavior_receipts,
                nonce_generator=self._nonce_generator,
                clock=self._clock,
            )
        self._builder = builder
        self._hook_states: "weakref.WeakKeyDictionary[Any, _HookState]" = (
            weakref.WeakKeyDictionary()
        )

    @property
    def builder(self) -> ReceiptBuilder:
        return self._builder

    def health_check(self) -> bool:
        """Readiness probe for the CrewAI GuardrailProvider protocol."""
        return True

    def evaluate(self, request: GuardrailRequest) -> GuardrailDecision:
        """Evaluate the configured policy without importing CrewAI."""
        try:
            decision: PolicyDecision = self.config.policy(
                request.tool_name,
                dict(request.tool_input),
                request.runtime_context(),
            )
        except Exception as exc:  # noqa: BLE001
            if self.config.fail_closed:
                return GuardrailDecision(
                    allow=False,
                    reason=f"policy_error: {type(exc).__name__}: {exc}",
                )
            return GuardrailDecision(allow=True, reason="policy_error_fail_open")
        return GuardrailDecision(
            allow=decision.allowed,
            reason=decision.reason,
            metadata=dict(decision.metadata),
        )

    def before_tool_call(self, context: Any) -> Optional[bool]:
        """CrewAI before-tool hook. Return ``False`` to block execution."""
        request = self._request_from_context(context)
        started_at = self._clock()
        tool_call_id = self._extract_tool_call_id(context) or self._id_generator()
        state = _HookState(
            tool_call_id=tool_call_id,
            started_at=started_at,
            tool_name=request.tool_name,
            tool_input=dict(request.tool_input),
            runtime_context=request.runtime_context(),
        )
        self._hook_states[context] = state

        decision = self.evaluate(request)
        if decision.allow:
            return None

        state.receipts = self._builder.build(
            tool=request.tool_name,
            tool_call_id=tool_call_id,
            args=request.tool_input,
            runtime_context=state.runtime_context,
            blocked=True,
            block_reason=decision.reason or "blocked_by_policy",
            started_at=started_at,
            ended_at=self._clock(),
        )
        self._emit(state.receipts, tool_call_id=tool_call_id)
        return False

    def after_tool_call(self, context: Any) -> Optional[str]:
        """CrewAI after-tool hook. Emits receipts for allowed/error calls."""
        state = self._hook_states.pop(context, None)
        if state is None:
            request = self._request_from_context(context)
            state = _HookState(
                tool_call_id=self._extract_tool_call_id(context) or self._id_generator(),
                started_at=self._clock(),
                tool_name=request.tool_name,
                tool_input=dict(request.tool_input),
                runtime_context=request.runtime_context(),
            )

        # A blocked call already emitted receipts in before_tool_call.
        if state.receipts is not None:
            return None

        raw_result = getattr(context, "raw_tool_result", None)
        error: Optional[BaseException] = None
        result: Any = raw_result
        if isinstance(raw_result, BaseException):
            error = raw_result
            result = None

        receipts = self._builder.build(
            tool=state.tool_name,
            tool_call_id=state.tool_call_id,
            args=state.tool_input,
            runtime_context=state.runtime_context,
            result=result,
            error=error,
            started_at=state.started_at,
            ended_at=self._clock(),
        )
        self._emit(receipts, tool_call_id=state.tool_call_id)
        return None

    def intercept_tool_call(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        func: Callable[[], Any],
        *,
        runtime_context: Optional[dict[str, Any]] = None,
        tool_call_id: Optional[str] = None,
        agent_role: Optional[str] = None,
        task_description: Optional[str] = None,
        crew_id: Optional[str] = None,
    ) -> GuardedToolResult[Any]:
        """Run *func* under pre-admission and post-execution receipting."""
        started_at = self._clock()
        tool_call_id = tool_call_id or self._id_generator()
        runtime = runtime_context or {
            "agent_role": agent_role,
            "task_description": task_description,
            "crew_id": crew_id,
        }
        request = GuardrailRequest(
            tool_name=tool_name,
            tool_input=dict(tool_input),
            agent_role=agent_role,
            task_description=task_description,
            crew_id=crew_id,
        )
        decision = self.evaluate(request)
        if not decision.allow:
            receipts = self._builder.build(
                tool=tool_name,
                tool_call_id=tool_call_id,
                args=tool_input,
                runtime_context=runtime,
                blocked=True,
                block_reason=decision.reason or "blocked_by_policy",
                started_at=started_at,
                ended_at=self._clock(),
            )
            self._emit(receipts, tool_call_id=tool_call_id)
            raise ToolCallBlocked(decision.reason or "blocked_by_policy", receipts)

        try:
            result = func()
        except BaseException as exc:
            receipts = self._builder.build(
                tool=tool_name,
                tool_call_id=tool_call_id,
                args=tool_input,
                runtime_context=runtime,
                error=exc,
                started_at=started_at,
                ended_at=self._clock(),
            )
            self._emit(receipts, tool_call_id=tool_call_id)
            raise

        receipts = self._builder.build(
            tool=tool_name,
            tool_call_id=tool_call_id,
            args=tool_input,
            runtime_context=runtime,
            result=result,
            started_at=started_at,
            ended_at=self._clock(),
        )
        self._emit(receipts, tool_call_id=tool_call_id)
        return GuardedToolResult(result=result, receipts=receipts)

    def _emit(self, receipts: BuiltReceipts, *, tool_call_id: str) -> None:
        record = ReceiptRecord(
            l1=receipts.l1,
            behavior=receipts.behavior,
            trace_id=receipts.l1["trace_id"],
            tool_call_id=tool_call_id,
            verdict=receipts.verdict,
        )
        try:
            self.config.sink(record)
        except Exception as sink_exc:  # noqa: BLE001
            import sys
            print(
                f"[ccs-crewai] WARNING: receipt sink raised: {sink_exc}",
                file=sys.stderr,
                flush=True,
            )

    @staticmethod
    def _request_from_context(context: Any) -> GuardrailRequest:
        agent = getattr(context, "agent", None)
        task = getattr(context, "task", None)
        crew = getattr(context, "crew", None)
        return GuardrailRequest(
            tool_name=getattr(context, "tool_name", "unknown_tool"),
            tool_input=dict(getattr(context, "tool_input", {}) or {}),
            agent_role=getattr(agent, "role", None),
            task_description=getattr(task, "description", None),
            crew_id=getattr(crew, "id", None),
        )

    @staticmethod
    def _extract_tool_call_id(context: Any) -> Optional[str]:
        for attr in ("tool_call_id", "call_id", "id"):
            value = getattr(context, attr, None)
            if value:
                return str(value)
        tool = getattr(context, "tool", None)
        for attr in ("tool_call_id", "call_id"):
            value = getattr(tool, attr, None)
            if value:
                return str(value)
        return None


def enable_guardrail(
    provider: CCSGuardrailProvider,
    *,
    fail_closed: Optional[bool] = None,
) -> CCSGuardrailProvider:
    """Register *provider* with CrewAI's global tool-call hook system.

    CrewAI is imported lazily so receipt construction and verification remain
    usable in environments where CrewAI is not installed.
    """
    _ = fail_closed  # Failure behavior is controlled by CCSConfig.fail_closed.
    from crewai.hooks import (  # type: ignore[import-not-found]
        register_after_tool_call_hook,
        register_before_tool_call_hook,
    )

    register_before_tool_call_hook(provider.before_tool_call)
    register_after_tool_call_hook(provider.after_tool_call)
    return provider
'''

FILES["src/ccs_crewai/verifier/__init__.py"] = r'''"""Open-source minimal CCS receipt verifier (MIT licensed)."""

from __future__ import annotations

from .l1 import L1_FIELDS, verify_l1_receipt, verify_l1_signature
from .chain import (
    verify_chain,
    verify_behavior_linkage,
    verify_behavior_signature,
    BEHAVIOR_FIELDS,
    BEHAVIOR_RECEIPT_TYPE,
)
from .errors import VerificationError

__all__ = [
    "L1_FIELDS",
    "BEHAVIOR_FIELDS",
    "BEHAVIOR_RECEIPT_TYPE",
    "VerificationError",
    "verify_l1_receipt",
    "verify_l1_signature",
    "verify_chain",
    "verify_behavior_linkage",
    "verify_behavior_signature",
]
'''

FILES["src/ccs_crewai/verifier/errors.py"] = r'''"""Verification errors."""

from __future__ import annotations


class VerificationError(Exception):
    """Raised when a CCS receipt fails structural or cryptographic verification."""

    def __init__(self, reason: str, field: str | None = None) -> None:
        self.reason = reason
        self.field = field
        super().__init__(f"{field}: {reason}" if field else reason)
'''

FILES["src/ccs_crewai/verifier/l1.py"] = r'''"""L1 receipt structural and cryptographic verification."""

from __future__ import annotations

import base64
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..hashing import canonical_json

L1_FIELDS: frozenset[str] = frozenset({
    "trace_id", "receipt_version", "verdict", "timestamp", "tool",
    "tool_call_id", "params_hash", "args_digest", "rule_summary", "rule_version",
    "request_hash", "response_hash", "runtime_context_hash", "config_hash",
    "verifier_source_class", "deployment_mode", "issuer", "audience", "nonce",
    "sequence", "issued_at", "expires_at", "max_clock_skew", "action",
    "signature", "signing_algorithm", "public_key_fingerprint", "public_key",
    "verified_at", "latency_us",
})

_REQUIRED_NONEMPTY = (
    "trace_id", "receipt_version", "verdict", "tool", "tool_call_id", "issuer",
    "audience", "nonce", "action", "signing_algorithm", "public_key", "signature",
)


def verify_l1_signature(receipt: dict[str, Any]) -> tuple[bool, str]:
    """Verify the Ed25519 signature over JCS(receipt minus signature)."""
    try:
        signature_b64 = receipt["signature"]
        public_key_b64 = receipt["public_key"]
    except KeyError as exc:
        return False, f"missing field: {exc}"

    try:
        pub_bytes = base64.b64decode(public_key_b64)
        sig_bytes = base64.b64decode(signature_b64)
    except Exception as exc:  # noqa: BLE001
        return False, f"base64 decode error: {exc}"

    if len(pub_bytes) != 32:
        return False, f"public key must be 32 bytes, got {len(pub_bytes)}"
    if len(sig_bytes) != 64:
        return False, f"signature must be 64 bytes, got {len(sig_bytes)}"

    signed = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(
            sig_bytes, canonical_json(signed)
        )
    except InvalidSignature:
        return False, "signature does not verify"
    except Exception as exc:  # noqa: BLE001
        return False, f"verification error: {exc}"
    return True, "ok"


def validate_l1_structure(receipt: dict[str, Any]) -> tuple[bool, str]:
    """Check that *receipt* has exactly 30 known fields and required values."""
    if not isinstance(receipt, dict):
        return False, "receipt must be a dict"

    keys = set(receipt.keys())
    extra = keys - L1_FIELDS
    missing = L1_FIELDS - keys
    if extra:
        return False, f"unknown fields: {sorted(extra)}"
    if missing:
        return False, f"missing fields: {sorted(missing)}"

    for field in _REQUIRED_NONEMPTY:
        val = receipt.get(field)
        if val is None or (isinstance(val, str) and not val):
            return False, f"field {field!r} must be non-empty"

    if receipt["verdict"] not in ("allow", "block"):
        return False, f"verdict must be 'allow' or 'block', got {receipt['verdict']!r}"
    if receipt["signing_algorithm"] != "Ed25519":
        return False, "signing_algorithm must be 'Ed25519'"
    if not isinstance(receipt["sequence"], int) or receipt["sequence"] < 0:
        return False, "sequence must be a non-negative integer"

    for ts_field in ("timestamp", "issued_at", "expires_at", "verified_at"):
        if not isinstance(receipt.get(ts_field), (int, float)):
            return False, f"{ts_field} must be numeric"
    if receipt["expires_at"] < receipt["issued_at"]:
        return False, "expires_at must be >= issued_at"

    fpr = receipt.get("public_key_fingerprint", "")
    if not (isinstance(fpr, str) and len(fpr) == 16):
        return False, "public_key_fingerprint must be 16 hex characters"
    try:
        int(fpr, 16)
    except ValueError:
        return False, "public_key_fingerprint must be hex"
    return True, "ok"


def verify_l1_receipt(
    receipt: dict[str, Any],
    *,
    check_expiry: bool = False,
    now: float | None = None,
) -> tuple[bool, str]:
    """Full L1 verification: structure + optional expiry + signature."""
    ok, reason = validate_l1_structure(receipt)
    if not ok:
        return False, reason
    ok, reason = verify_l1_signature(receipt)
    if not ok:
        return False, reason
    if check_expiry:
        current = now if now is not None else time.time()
        if current > receipt["expires_at"] + receipt.get("max_clock_skew", 0):
            return False, "receipt has expired"
    return True, "ok"
'''

FILES["src/ccs_crewai/verifier/chain.py"] = r'''"""Behavior evidence receipt and L1<->behavior chain verification."""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..hashing import canonical_json, sha256_hex
from .l1 import verify_l1_receipt

BEHAVIOR_FIELDS: frozenset[str] = frozenset({
    "receipt_type", "trace_id", "tool_call_id", "sequence",
    "linked_l1_receipt_digest", "behavior_evidence_verdict", "evidence_ref",
    "issuer", "audience", "issued_at", "deployment_mode", "signing_algorithm",
    "public_key_fingerprint", "public_key", "signature",
})
BEHAVIOR_RECEIPT_TYPE = "ccs.behavior_evidence.v1"
_VALID_BEHAVIOR_VERDICTS = frozenset({
    "not_observed", "observed_and_allowed", "observed_and_rejected",
})


def verify_behavior_signature(behavior: dict[str, Any]) -> tuple[bool, str]:
    try:
        sig_b64 = behavior["signature"]
        pk_b64 = behavior["public_key"]
    except KeyError as exc:
        return False, f"missing field: {exc}"
    try:
        pk = base64.b64decode(pk_b64)
        sig = base64.b64decode(sig_b64)
    except Exception as exc:  # noqa: BLE001
        return False, f"base64 decode error: {exc}"
    if len(pk) != 32:
        return False, "public key must be 32 bytes"
    if len(sig) != 64:
        return False, "signature must be 64 bytes"
    signed = {k: v for k, v in behavior.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, canonical_json(signed))
    except InvalidSignature:
        return False, "behavior signature does not verify"
    except Exception as exc:  # noqa: BLE001
        return False, f"verification error: {exc}"
    return True, "ok"


def validate_behavior_structure(behavior: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(behavior, dict):
        return False, "behavior receipt must be a dict"
    keys = set(behavior.keys())
    extra = keys - BEHAVIOR_FIELDS
    missing = BEHAVIOR_FIELDS - keys
    if extra:
        return False, f"unknown behavior fields: {sorted(extra)}"
    if missing:
        return False, f"missing behavior fields: {sorted(missing)}"
    if behavior["receipt_type"] != BEHAVIOR_RECEIPT_TYPE:
        return False, f"receipt_type must be {BEHAVIOR_RECEIPT_TYPE!r}"
    if behavior["signing_algorithm"] != "Ed25519":
        return False, "signing_algorithm must be 'Ed25519'"
    if behavior["behavior_evidence_verdict"] not in _VALID_BEHAVIOR_VERDICTS:
        return False, "invalid behavior_evidence_verdict"
    digest = behavior.get("linked_l1_receipt_digest", "")
    if not digest.startswith("sha256:") or len(digest) != 71:
        return False, "linked_l1_receipt_digest must be 'sha256:' + 64 hex chars"
    fpr = behavior.get("public_key_fingerprint", "")
    if not (isinstance(fpr, str) and len(fpr) == 16):
        return False, "public_key_fingerprint must be 16 hex chars"
    if not isinstance(behavior.get("sequence"), int) or behavior["sequence"] < 0:
        return False, "sequence must be a non-negative integer"
    return True, "ok"


def verify_behavior_linkage(
    l1: dict[str, Any], behavior: dict[str, Any]
) -> tuple[bool, str]:
    l1_no_sig = {k: v for k, v in l1.items() if k != "signature"}
    expected = "sha256:" + sha256_hex(canonical_json(l1_no_sig))
    if behavior.get("linked_l1_receipt_digest") != expected:
        return False, "linked_l1_receipt_digest mismatch"
    for field in ("trace_id", "tool_call_id", "sequence"):
        if l1.get(field) != behavior.get(field):
            return False, f"{field} mismatch between L1 and behavior"
    if l1.get("public_key_fingerprint") != behavior.get("public_key_fingerprint"):
        return False, "public_key_fingerprint differs between L1 and behavior"
    return True, "ok"


def verify_chain(
    l1: dict[str, Any],
    behavior: dict[str, Any] | None,
    *,
    check_expiry: bool = False,
) -> tuple[bool, str]:
    ok, reason = verify_l1_receipt(l1, check_expiry=check_expiry)
    if not ok:
        return False, f"L1: {reason}"
    if behavior is None:
        return True, "ok"
    ok, reason = validate_behavior_structure(behavior)
    if not ok:
        return False, f"behavior structure: {reason}"
    ok, reason = verify_behavior_signature(behavior)
    if not ok:
        return False, f"behavior signature: {reason}"
    ok, reason = verify_behavior_linkage(l1, behavior)
    if not ok:
        return False, f"chain linkage: {reason}"
    return True, "ok"
'''

FILES["src/ccs_crewai/cli.py"] = r'''"""Command-line receipt verifier for ccs-crewai.

Usage::

    ccs-crewai-verify --version
    ccs-crewai-verify receipt.json
    ccs-crewai-verify --chain receipt.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .verifier import verify_chain, verify_l1_receipt


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _verify_receipt_file(path: str, *, chain: bool, check_expiry: bool) -> int:
    try:
        data = _load_json(path)
    except FileNotFoundError:
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2

    if chain:
        if not isinstance(data, dict) or "l1" not in data:
            print(
                "error: chain verification expects an object with an 'l1' key.",
                file=sys.stderr,
            )
            return 2
        ok, reason = verify_chain(
            data.get("l1"), data.get("behavior"), check_expiry=check_expiry
        )
        label = "L1 + behavior chain"
    else:
        l1 = data.get("l1", data) if isinstance(data, dict) else data
        if not isinstance(l1, dict):
            print("error: receipt must be a JSON object", file=sys.stderr)
            return 2
        ok, reason = verify_l1_receipt(l1, check_expiry=check_expiry)
        label = "L1 receipt"

    if ok:
        print(f"VALID: {label} ({Path(path).name})")
        return 0
    print(f"INVALID: {label} ({Path(path).name}): {reason}", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccs-crewai-verify",
        description="Verify CCS L1 and behavior receipts produced by ccs-crewai.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("receipt", nargs="?", help="Path to a receipt JSON file.")
    parser.add_argument(
        "--chain",
        action="store_true",
        help="Verify an L1 + behavior chain wrapper.",
    )
    parser.add_argument(
        "--check-expiry",
        action="store_true",
        help="Also reject expired receipts.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.receipt:
        parser.print_help()
        return 2
    return _verify_receipt_file(
        args.receipt, chain=args.chain, check_expiry=args.check_expiry
    )


if __name__ == "__main__":
    raise SystemExit(main())
'''

# Tests
FILES["tests/__init__.py"] = ""

FILES["tests/conftest.py"] = r'''"""Shared pytest fixtures for ccs-crewai tests."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from ccs_crewai import CCSConfig, CCSGuardrailProvider, ReceiptRecord
from ccs_crewai.config import PolicyDecision

TEST_SEED = b"ccs-crewai-unit-test-seed"
FIXED_CLOCK_VALUE = 1_700_000_000.0
FIXED_NONCE = "00112233445566778899aabbccddeeff"


@pytest.fixture
def records() -> list[ReceiptRecord]:
    return []


@pytest.fixture
def allow_all_config(records: list[ReceiptRecord]) -> CCSConfig:
    return CCSConfig(
        deployment_mode="in-process",
        seed=TEST_SEED,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="pytest-trace-001",
        sink=records.append,
    )


@pytest.fixture
def deny_policy():
    def _policy(tool_name: str, tool_input: dict[str, Any], ctx: dict[str, Any]):
        if tool_name in {"shell_exec", "delete_database", "rm_rf"}:
            return PolicyDecision(
                allowed=False,
                reason=f"denied_tool:{tool_name}",
                metadata={"risk": "high"},
            )
        return PolicyDecision(allowed=True, reason="no_rules_matched")

    return _policy


@pytest.fixture
def denying_config(records: list[ReceiptRecord], deny_policy) -> CCSConfig:
    return CCSConfig(
        deployment_mode="in-process",
        seed=TEST_SEED,
        policy=deny_policy,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="pytest-trace-deny",
        sink=records.append,
    )


def _make_provider(config: CCSConfig) -> CCSGuardrailProvider:
    counter = {"id": 0}

    def id_gen() -> str:
        counter["id"] += 1
        return f"call-{counter['id']}"

    return CCSGuardrailProvider(
        config,
        clock=lambda: FIXED_CLOCK_VALUE,
        id_generator=id_gen,
        nonce_generator=lambda: FIXED_NONCE,
    )


@pytest.fixture
def provider(allow_all_config: CCSConfig) -> CCSGuardrailProvider:
    return _make_provider(allow_all_config)


@pytest.fixture
def denying_provider(denying_config: CCSConfig) -> CCSGuardrailProvider:
    return _make_provider(denying_config)


class FakeContext:
    """Minimal stand-in for CrewAI's ToolCallHookContext."""

    def __init__(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        *,
        raw_tool_result: Any = None,
        agent_role: str | None = "researcher",
        task_description: str | None = "test task",
        crew_id: str | None = "crew-1",
    ) -> None:
        self.tool_name = tool_name
        self.tool_input = tool_input or {}
        self.raw_tool_result = raw_tool_result
        self.tool_result = None
        self.tool = SimpleNamespace()
        self.agent = SimpleNamespace(role=agent_role)
        self.task = SimpleNamespace(description=task_description)
        self.crew = SimpleNamespace(id=crew_id)
'''

FILES["tests/test_hashing.py"] = r'''"""Tests for JCS canonicalization and SHA-256 helpers."""
from __future__ import annotations

import hashlib

import pytest

from ccs_crewai.hashing import (
    canonical_json,
    canonical_sha256_hex,
    jcs_digest,
    sha256_digest,
    sha256_hex,
)


def test_canonical_json_sorts_object_keys():
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_sha256_known_vector():
    assert sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert sha256_digest(b"abc") == hashlib.sha256(b"abc").digest()


def test_canonical_sha256_is_stable_and_order_independent():
    value = {"z": [1, 2], "a": {"nested": True}}
    reordered = {"a": {"nested": True}, "z": [1, 2]}
    assert canonical_sha256_hex(value) == canonical_sha256_hex(reordered)
    assert jcs_digest(value) == canonical_sha256_hex(value)


def test_unsafe_large_positive_integer_rejected():
    with pytest.raises(ValueError, match="RFC 8785"):
        canonical_json({"x": 2**63})


def test_unsafe_large_negative_integer_rejected():
    with pytest.raises(ValueError, match="RFC 8785"):
        canonical_json([-(2**63)])


def test_booleans_are_not_treated_as_unsafe_integers():
    assert canonical_json({"ok": True}) == b'{"ok":true}'


def test_nested_safe_integer_validation():
    with pytest.raises(ValueError):
        canonical_json({"outer": [{"inner": 2**100}]})
'''

FILES["tests/test_signer.py"] = r'''"""Tests for Ed25519 signers."""
from __future__ import annotations

import base64
import hashlib

import pytest

from ccs_crewai.hashing import canonical_json
from ccs_crewai.signer import (
    InProcessSigner,
    SidecarSigner,
    derive_in_process_key,
    fingerprint,
    verify_ed25519,
)


def test_same_seed_produces_same_key():
    a = InProcessSigner(b"same seed")
    b = InProcessSigner(b"same seed")
    assert a.public_key_b64 == b.public_key_b64
    assert a.public_key_fingerprint == b.public_key_fingerprint


def test_different_seeds_produce_different_keys():
    assert InProcessSigner(b"a").public_key_b64 != InProcessSigner(b"b").public_key_b64


def test_key_matches_conformance_vector_derivation():
    signer = InProcessSigner(b"ccs-verifier/in-process-test/v1")
    assert signer.public_key_b64 == "6PPlM1taN/Ws4SnxaypgY2CGcKvGPw/eC54cUNesSb8="
    assert signer.public_key_fingerprint == "bbca301d8848dfdb"


def test_fingerprint_is_16_hex_chars_of_sha256():
    signer = InProcessSigner(b"seed")
    raw = base64.b64decode(signer.public_key_b64)
    assert signer.public_key_fingerprint == hashlib.sha256(raw).hexdigest()[:16]
    assert len(signer.public_key_fingerprint) == 16


def test_signature_roundtrip_verifies():
    signer = InProcessSigner(b"signing seed")
    payload = {"tool": "search", "q": "hello", "n": 3}
    sig = signer.sign(payload)
    assert signer.verify(payload, sig) is True


def test_signature_excludes_signature_field():
    signer = InProcessSigner(b"seed")
    sig = signer.sign({"a": 1, "signature": "ignored"})
    assert signer.verify({"a": 1}, sig) is True
    assert signer.verify({"a": 1, "signature": "tampered"}, sig) is True


def test_signature_uses_jcs_canonical_form():
    signer = InProcessSigner(b"seed")
    sig = signer.sign({"a": 1, "b": 2, "c": 3})
    assert signer.verify({"c": 3, "b": 2, "a": 1}, sig) is True
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_tampered_payload_fails_verification():
    signer = InProcessSigner(b"seed")
    sig = signer.sign({"verdict": "allow", "tool": "shell"})
    assert signer.verify({"verdict": "block", "tool": "shell"}, sig) is False


def test_cross_key_rejection():
    a = InProcessSigner(b"key A")
    b = InProcessSigner(b"key B")
    sig = a.sign({"trace_id": "abc"})
    assert b.verify({"trace_id": "abc"}, sig) is False


def test_verify_returns_false_on_invalid_inputs():
    signer = InProcessSigner(b"seed")
    assert verify_ed25519(signer.public_key_b64, {"x": 1}, "not-base64!!!") is False
    assert verify_ed25519(signer.public_key_b64, {"x": 1}, "") is False


def test_empty_seed_rejected():
    with pytest.raises(ValueError):
        InProcessSigner(b"")


def test_non_bytes_seed_rejected():
    with pytest.raises(TypeError):
        derive_in_process_key("not bytes")  # type: ignore[arg-type]


def test_sidecar_signer_verifies_locally():
    remote = InProcessSigner(b"sidecar-private")

    def fake_post(url, payload):
        return {"signature": remote.sign(payload)}

    sidecar = SidecarSigner(
        "http://localhost:9100", remote.public_key_b64, http_post=fake_post
    )
    assert sidecar.deployment_mode == "sidecar"
    sig = sidecar.sign({"tool": "search"})
    assert sidecar.verify({"tool": "search"}, sig) is True


def test_sidecar_rejects_invalid_signature():
    good = InProcessSigner(b"good key")
    evil = InProcessSigner(b"evil key")

    def fake_post(url, payload):
        return {"signature": evil.sign(payload)}

    sidecar = SidecarSigner(
        "http://localhost:9100", good.public_key_b64, http_post=fake_post
    )
    with pytest.raises(RuntimeError, match="does not verify"):
        sidecar.sign({"tool": "search"})
'''

FILES["tests/test_receipt_builder.py"] = r'''"""Tests for L1 and behavior receipt construction."""
from __future__ import annotations

import copy

import pytest

from ccs_crewai import CCSConfig, ReceiptBuilder, build_signer, linked_l1_digest
from ccs_crewai.receipt_builder import BEHAVIOR_FIELDS, L1_FIELDS
from ccs_crewai.verifier import verify_chain, verify_l1_receipt

FIXED_TS = 1_700_000_000.0
FIXED_NONCE = "fixednonce00000000000000000000"


def make_builder(**overrides) -> ReceiptBuilder:
    config = CCSConfig(seed=b"builder-seed", trace_id="builder-trace", sink=lambda r: None)
    signer = build_signer(config)
    kwargs = dict(
        signer=signer,
        rule_version=config.rule_version,
        rule_summary=config.rule_summary,
        issuer=config.issuer,
        audience=config.audience,
        trace_id=config.trace_id,
        clock=lambda: FIXED_TS,
        nonce_generator=lambda: FIXED_NONCE,
    )
    kwargs.update(overrides)
    return ReceiptBuilder(**kwargs)


def test_l1_has_exactly_30_fields():
    built = make_builder().build(tool="search", tool_call_id="c1", args={"q": "x"})
    assert len(built.l1) == 30
    assert tuple(built.l1.keys()) == L1_FIELDS


def test_behavior_has_exactly_15_fields():
    built = make_builder().build(tool="search", tool_call_id="c1", args={})
    assert built.behavior is not None
    assert len(built.behavior) == 15
    assert tuple(built.behavior.keys()) == BEHAVIOR_FIELDS


def test_allow_receipt_values():
    built = make_builder().build(
        tool="search", tool_call_id="c1", args={"q": "hi"}, result=["doc1"]
    )
    assert built.l1["verdict"] == "allow"
    assert built.l1["tool"] == "search"
    assert built.l1["tool_call_id"] == "c1"
    assert built.l1["receipt_version"] == "1.1"
    assert built.l1["signing_algorithm"] == "Ed25519"
    assert built.l1["deployment_mode"] == "in-process"
    assert built.l1["action"] == "search.execute"
    assert built.l1["sequence"] == 0
    assert built.l1["nonce"] == FIXED_NONCE
    assert built.l1["latency_us"] == 0
    assert built.behavior is not None
    assert built.behavior["behavior_evidence_verdict"] == "not_observed"


def test_block_receipt_values():
    built = make_builder().build(
        tool="shell_exec", tool_call_id="c2", args={"cmd": "ls"},
        blocked=True, block_reason="denied_tool:shell_exec",
    )
    assert built.l1["verdict"] == "block"
    assert built.l1["rule_summary"] == "denied_tool:shell_exec"
    assert built.behavior is not None
    assert built.behavior["behavior_evidence_verdict"] == "observed_and_rejected"


def test_error_receipt_values():
    try:
        raise RuntimeError("boom")
    except RuntimeError as exc:
        built = make_builder().build(
            tool="bad", tool_call_id="c3", args={}, error=exc
        )
    assert built.l1["verdict"] == "block"
    assert "RuntimeError" in built.l1["rule_summary"]
    assert "boom" in built.l1["rule_summary"]


def test_sequence_increments_per_call():
    builder = make_builder()
    first = builder.build(tool="a", tool_call_id="c1", args={})
    second = builder.build(tool="b", tool_call_id="c2", args={})
    assert first.l1["sequence"] == 0
    assert second.l1["sequence"] == 1
    assert first.behavior and second.behavior
    assert first.behavior["sequence"] == 0
    assert second.behavior["sequence"] == 1


def test_linked_digest_matches_behavior():
    built = make_builder().build(tool="t", tool_call_id="c", args={})
    assert built.behavior is not None
    assert built.behavior["linked_l1_receipt_digest"] == linked_l1_digest(built.l1)


def test_deterministic_receipts_with_fixed_nonce_and_clock():
    b1 = make_builder()
    b2 = make_builder()
    r1 = b1.build(tool="t", tool_call_id="c", args={"x": 1}, result="ok")
    r2 = b2.build(tool="t", tool_call_id="c", args={"x": 1}, result="ok")
    assert r1.l1["signature"] == r2.l1["signature"]
    assert r1.behavior and r2.behavior
    assert r1.behavior["signature"] == r2.behavior["signature"]


def test_hashes_reflect_inputs():
    builder = make_builder()
    r1 = builder.build(tool="t", tool_call_id="c", args={"x": 1}, result="r")
    r2 = builder.build(tool="t", tool_call_id="c2", args={"x": 2}, result="r2")
    assert r1.l1["args_digest"] != r2.l1["args_digest"]
    assert r1.l1["request_hash"] != r2.l1["request_hash"]
    assert r1.l1["response_hash"] != r2.l1["response_hash"]


def test_params_hash_is_value_independent_but_key_sensitive():
    builder = make_builder()
    r1 = builder.build(tool="t", tool_call_id="c1", args={"x": 1})
    r2 = builder.build(tool="t", tool_call_id="c2", args={"x": 2})
    r3 = builder.build(tool="t", tool_call_id="c3", args={"x": 1, "y": 2})
    assert r1.l1["params_hash"] == r2.l1["params_hash"]
    assert r1.l1["params_hash"] != r3.l1["params_hash"]


def test_generated_receipts_verify():
    built = make_builder().build(tool="t", tool_call_id="c", args={"q": "x"}, result="ok")
    ok, reason = verify_l1_receipt(built.l1)
    assert ok, reason
    ok, reason = verify_chain(built.l1, built.behavior)
    assert ok, reason


def test_behavior_can_be_disabled():
    builder = make_builder(include_behavior=False)
    built = builder.build(tool="t", tool_call_id="c", args={})
    assert built.behavior is None
    ok, reason = verify_chain(built.l1, None)
    assert ok, reason


def test_unknown_objects_are_serialized_via_repr():
    class Weird:
        def __repr__(self):
            return "Weird()"

    built = make_builder().build(
        tool="t", tool_call_id="c", args={}, result={"obj": Weird()}
    )
    assert built.l1["verdict"] == "allow"
    assert built.l1["response_hash"]
'''

FILES["tests/test_l1_verifier.py"] = r'''"""Tests for open-source L1 receipt verification."""
from __future__ import annotations

import copy

import pytest

from ccs_crewai import CCSConfig, ReceiptBuilder, build_signer
from ccs_crewai.verifier import verify_l1_receipt, verify_l1_signature

FIXED_TS = 1_000_000.0


@pytest.fixture
def l1_receipt():
    config = CCSConfig(seed=b"l1-verify-seed", trace_id="l1-verify", sink=lambda r: None)
    builder = ReceiptBuilder(
        build_signer(config),
        rule_version=config.rule_version,
        rule_summary=config.rule_summary,
        issuer=config.issuer,
        audience=config.audience,
        trace_id=config.trace_id,
        clock=lambda: FIXED_TS,
        nonce_generator=lambda: "n" * 32,
        receipt_ttl_seconds=10,
    )
    return builder.build(tool="search", tool_call_id="c1", args={"q": "x"}, result="ok").l1


def test_valid_l1(l1_receipt):
    ok, reason = verify_l1_receipt(l1_receipt)
    assert ok, reason


def test_valid_l1_signature_helper(l1_receipt):
    ok, reason = verify_l1_signature(l1_receipt)
    assert ok, reason


def test_reject_extra_field(l1_receipt):
    bad = dict(l1_receipt)
    bad["evil"] = "injected"
    ok, reason = verify_l1_receipt(bad)
    assert not ok and "unknown" in reason


def test_reject_missing_field(l1_receipt):
    bad = {k: v for k, v in l1_receipt.items() if k != "nonce"}
    ok, reason = verify_l1_receipt(bad)
    assert not ok and "missing" in reason


def test_reject_empty_required_field(l1_receipt):
    bad = dict(l1_receipt)
    bad["tool"] = ""
    ok, reason = verify_l1_receipt(bad)
    assert not ok and "non-empty" in reason


def test_reject_invalid_verdict(l1_receipt):
    bad = dict(l1_receipt)
    bad["verdict"] = "maybe"
    ok, reason = verify_l1_receipt(bad)
    assert not ok and "verdict" in reason


def test_reject_wrong_algorithm(l1_receipt):
    bad = dict(l1_receipt)
    bad["signing_algorithm"] = "RSA-SHA256"
    ok, reason = verify_l1_receipt(bad)
    assert not ok


@pytest.mark.parametrize("field", ["timestamp", "issued_at", "expires_at", "verified_at"])
def test_reject_non_numeric_timestamps(l1_receipt, field):
    bad = dict(l1_receipt)
    bad[field] = "soon"
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_reject_negative_sequence(l1_receipt):
    bad = dict(l1_receipt)
    bad["sequence"] = -1
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_reject_expired_receipt(l1_receipt):
    ok, reason = verify_l1_receipt(
        l1_receipt, check_expiry=True, now=FIXED_TS + 100
    )
    assert not ok and "expired" in reason


def test_valid_unexpired_receipt(l1_receipt):
    ok, reason = verify_l1_receipt(
        l1_receipt, check_expiry=True, now=FIXED_TS + 5
    )
    assert ok, reason


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("verdict", "block"),
        ("tool", "rm_rf"),
        ("response_hash", "0" * 64),
        ("request_hash", "0" * 64),
        ("args_digest", "0" * 64),
        ("nonce", "tampered"),
        ("issuer", "evil"),
        ("public_key_fingerprint", "0" * 16),
    ],
)
def test_tampered_field_breaks_signature(l1_receipt, field, new_value):
    bad = copy.deepcopy(l1_receipt)
    bad[field] = new_value
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_reject_corrupt_base64_signature(l1_receipt):
    bad = dict(l1_receipt)
    bad["signature"] = "!!!not-base64!!!"
    ok, reason = verify_l1_receipt(bad)
    assert not ok


def test_reject_non_dict():
    ok, reason = verify_l1_receipt("not a dict")  # type: ignore[arg-type]
    assert not ok and "dict" in reason


def test_reject_bad_public_key_length(l1_receipt):
    bad = dict(l1_receipt)
    bad["public_key"] = "AAAA"
    ok, reason = verify_l1_receipt(bad)
    assert not ok
'''

FILES["tests/test_chain_verifier.py"] = r'''"""Tests for L1 + behavior chain verification."""
from __future__ import annotations

import copy

import pytest

from ccs_crewai import CCSConfig, ReceiptBuilder, build_signer
from ccs_crewai.verifier import verify_chain


@pytest.fixture
def pair():
    config = CCSConfig(seed=b"chain-seed", trace_id="chain-trace", sink=lambda r: None)
    builder = ReceiptBuilder(
        build_signer(config),
        rule_version=config.rule_version,
        rule_summary=config.rule_summary,
        issuer=config.issuer,
        audience=config.audience,
        trace_id=config.trace_id,
        clock=lambda: 2_000_000.0,
        nonce_generator=lambda: "n" * 32,
    )
    built = builder.build(tool="search", tool_call_id="c1", args={"q": "x"}, result="ok")
    return built.l1, built.behavior


def test_valid_chain(pair):
    ok, reason = verify_chain(pair[0], pair[1])
    assert ok, reason


def test_chain_without_behavior(pair):
    ok, reason = verify_chain(pair[0], None)
    assert ok, reason


def test_behavior_extra_field(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["extra"] = "x"
    ok, reason = verify_chain(l1, bad)
    assert not ok and "unknown" in reason


def test_behavior_missing_field(pair):
    l1, behavior = pair
    bad = {k: v for k, v in behavior.items() if k != "evidence_ref"}
    ok, reason = verify_chain(l1, bad)
    assert not ok and "missing" in reason


def test_behavior_wrong_receipt_type(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["receipt_type"] = "wrong"
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_wrong_verdict(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["behavior_evidence_verdict"] = "maybe"
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_wrong_digest_format(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["linked_l1_receipt_digest"] = "sha256:short"
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_digest_mismatch(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["linked_l1_receipt_digest"] = "sha256:" + "0" * 64
    ok, reason = verify_chain(l1, bad)
    assert not ok and "digest" in reason


def test_behavior_trace_mismatch(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["trace_id"] = "wrong"
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_tool_call_mismatch(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["tool_call_id"] = "wrong"
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_sequence_mismatch(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["sequence"] = 999
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_fingerprint_mismatch(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["public_key_fingerprint"] = "0" * 16
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_behavior_signature_tamper(pair):
    l1, behavior = pair
    bad = copy.deepcopy(behavior)
    bad["behavior_evidence_verdict"] = "observed_and_allowed"
    ok, reason = verify_chain(l1, bad)
    assert not ok


def test_invalid_l1_propagates(pair):
    _, behavior = pair
    ok, reason = verify_chain({"verdict": "allow"}, behavior)
    assert not ok and "L1" in reason


def test_behavior_wrong_signing_key(pair):
    l1, _ = pair
    config_b = CCSConfig(seed=b"other-chain-seed", trace_id="other", sink=lambda r: None)
    builder_b = ReceiptBuilder(
        build_signer(config_b),
        rule_version=config_b.rule_version,
        rule_summary=config_b.rule_summary,
        issuer=config_b.issuer,
        audience=config_b.audience,
        trace_id=config_b.trace_id,
        clock=lambda: 2_000_000.0,
        nonce_generator=lambda: "n" * 32,
    )
    other = builder_b.build(tool="t", tool_call_id="c", args={}, result=None)
    ok, reason = verify_chain(l1, other.behavior)
    assert not ok
'''

FILES["tests/test_guardrail.py"] = r'''"""Tests for the CrewAI CCS guardrail provider."""
from __future__ import annotations

import copy

import pytest

from ccs_crewai import (
    CCSConfig,
    CCSGuardrailProvider,
    GuardrailRequest,
    PolicyDecision,
    ToolCallBlocked,
    verify_chain,
    verify_l1_receipt,
)

from .conftest import FIXED_CLOCK_VALUE, FIXED_NONCE, FakeContext


def test_provider_metadata(provider):
    assert provider.name == "ccs-crewai-guardrail"
    assert provider.health_check() is True


def test_direct_allowed_tool_call_emits_allow_receipt(provider, records):
    result = provider.intercept_tool_call(
        "search", {"q": "crewai"}, lambda: ["doc1", "doc2"],
        tool_call_id="fixed-call-1",
    )
    assert result.result == ["doc1", "doc2"]
    assert result.verdict == "allow"
    assert len(records) == 1
    record = records[0]
    assert record.verdict == "allow"
    assert record.tool_call_id == "fixed-call-1"
    assert record.l1["tool"] == "search"
    assert record.behavior is not None
    ok, reason = verify_chain(record.l1, record.behavior)
    assert ok, reason


def test_direct_blocked_tool_call_raises_and_does_not_execute(denying_provider, records):
    calls = []

    def dangerous():
        calls.append("executed")
        return "should not happen"

    with pytest.raises(ToolCallBlocked) as exc_info:
        denying_provider.intercept_tool_call(
            "shell_exec", {"cmd": "rm -rf /"}, dangerous, tool_call_id="block-1"
        )

    assert calls == []
    assert "denied_tool:shell_exec" in str(exc_info.value)
    assert exc_info.value.receipts.l1["verdict"] == "block"
    assert len(records) == 1
    assert records[0].verdict == "block"
    ok, reason = verify_l1_receipt(records[0].l1)
    assert ok, reason


def test_direct_tool_exception_emits_block_receipt_and_reraises(provider, records):
    def explode():
        raise RuntimeError("tool exploded")

    with pytest.raises(RuntimeError, match="tool exploded"):
        provider.intercept_tool_call(
            "bad", {}, explode, tool_call_id="error-1"
        )
    assert len(records) == 1
    assert records[0].verdict == "block"
    assert "RuntimeError" in records[0].l1["rule_summary"]
    assert "tool exploded" in records[0].l1["rule_summary"]


def test_policy_exception_fails_closed(records):
    def broken_policy(tool_name, tool_input, ctx):
        raise RuntimeError("policy down")

    config = CCSConfig(
        seed=b"fail-closed",
        policy=broken_policy,
        fail_closed=True,
        trace_id="fc",
        sink=records.append,
    )
    provider = CCSGuardrailProvider(config, clock=lambda: FIXED_CLOCK_VALUE)
    with pytest.raises(ToolCallBlocked):
        provider.intercept_tool_call("t", {}, lambda: "ok")
    assert records[-1].verdict == "block"
    assert "policy_error" in records[-1].l1["rule_summary"]


def test_policy_exception_can_fail_open(records):
    def broken_policy(tool_name, tool_input, ctx):
        raise RuntimeError("policy down")

    config = CCSConfig(
        seed=b"fail-open",
        policy=broken_policy,
        fail_closed=False,
        trace_id="fo",
        sink=records.append,
    )
    provider = CCSGuardrailProvider(config, clock=lambda: FIXED_CLOCK_VALUE)
    result = provider.intercept_tool_call("t", {}, lambda: "ok")
    assert result.result == "ok"
    assert result.verdict == "allow"


def test_before_hook_allows_and_after_hook_emits(provider, records):
    ctx = FakeContext("search", {"q": "x"})
    assert provider.before_tool_call(ctx) is None
    ctx.raw_tool_result = "result"
    assert provider.after_tool_call(ctx) is None
    assert len(records) == 1
    assert records[0].verdict == "allow"
    assert records[0].l1["tool"] == "search"


def test_before_hook_blocks_execution(denying_provider, records):
    ctx = FakeContext("delete_database", {"name": "prod"})
    assert denying_provider.before_tool_call(ctx) is False
    assert len(records) == 1
    assert records[0].verdict == "block"
    # If CrewAI invokes after anyway, it must not emit a duplicate receipt.
    assert denying_provider.after_tool_call(ctx) is None
    assert len(records) == 1


def test_after_hook_records_tool_exception(provider, records):
    ctx = FakeContext("bad", {})
    provider.before_tool_call(ctx)
    ctx.raw_tool_result = ValueError("bad value")
    provider.after_tool_call(ctx)
    assert records[-1].verdict == "block"
    assert "ValueError" in records[-1].l1["rule_summary"]


def test_chain_of_three_receipts(provider, records):
    for i, tool in enumerate(["search", "scrape", "summarize"]):
        result = provider.intercept_tool_call(
            tool, {"index": i}, lambda i=i: f"result-{i}",
            runtime_context={"step": i},
        )
        assert result.verdict == "allow"

    assert len(records) == 3
    assert [r.l1["sequence"] for r in records] == [0, 1, 2]
    for record in records:
        ok, reason = verify_chain(record.l1, record.behavior)
        assert ok, reason
    # Sequence and trace bind the chain as one ordered receipt trail.
    assert len({r.trace_id for r in records}) == 1
    assert [r.tool_call_id for r in records] == ["call-1", "call-2", "call-3"]


def test_tampered_receipt_is_detected(provider):
    result = provider.intercept_tool_call(
        "search", {"q": "x"}, lambda: "ok", tool_call_id="tamper-1"
    )
    tampered = copy.deepcopy(result.receipts.l1)
    tampered["verdict"] = "block"
    ok, reason = verify_l1_receipt(tampered)
    assert not ok
    assert "verify" in reason.lower() or "signature" in reason.lower()


def test_runtime_context_extracted_from_context(provider):
    ctx = FakeContext("t", {}, agent_role="analyst", task_description="read", crew_id="c9")
    request = provider._request_from_context(ctx)
    assert request.agent_role == "analyst"
    assert request.task_description == "read"
    assert request.crew_id == "c9"
    assert request.runtime_context()["agent_role"] == "analyst"


def test_evaluate_translates_policy_decision(provider):
    request = GuardrailRequest(tool_name="search", tool_input={"q": "x"})
    decision = provider.evaluate(request)
    assert decision.allow is True
    assert decision.reason == "no_rules_matched"


def test_sink_exception_does_not_break_allowed_call():
    config = CCSConfig(
        seed=b"sink-exc",
        trace_id="sink",
        sink=lambda record: (_ for _ in ()).throw(RuntimeError("sink down")),
    )
    provider = CCSGuardrailProvider(config, clock=lambda: FIXED_CLOCK_VALUE)
    result = provider.intercept_tool_call("t", {}, lambda: "ok")
    assert result.result == "ok"


def test_config_requires_seed_for_in_process():
    with pytest.raises(ValueError, match="seed is required"):
        CCSConfig(deployment_mode="in-process")


def test_config_rejects_invalid_deployment_mode():
    with pytest.raises(ValueError, match="deployment_mode"):
        CCSConfig(deployment_mode="invalid", seed=b"x")
'''

FILES["tests/test_cli.py"] = r'''"""Tests for ccs-crewai-verify CLI."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ccs_crewai import __version__
from ccs_crewai.cli import main
from ccs_crewai.verifier import verify_l1_receipt


def _write_json(path: Path, data) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def valid_receipt():
    from ccs_crewai import CCSConfig, ReceiptBuilder, build_signer

    config = CCSConfig(seed=b"cli-seed", trace_id="cli-trace", sink=lambda r: None)
    builder = ReceiptBuilder(
        build_signer(config),
        rule_version=config.rule_version,
        rule_summary=config.rule_summary,
        issuer=config.issuer,
        audience=config.audience,
        trace_id=config.trace_id,
    )
    return builder.build(tool="search", tool_call_id="cli-1", args={"q": "x"}, result="ok")


def test_version_flag(capsys):
    assert main(["--version"]) == 0
    out = capsys.readouterr().out
    assert __version__ in out


def test_module_version_flag():
    repo = Path(__file__).resolve().parents[1]
    env = dict(PYTHONPATH=str(repo / "src"))
    proc = subprocess.run(
        [sys.executable, "-m", "ccs_crewai.cli", "--version"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0
    assert __version__ in proc.stdout


def test_verify_valid_l1_file(tmp_path, valid_receipt):
    path = _write_json(tmp_path / "l1.json", valid_receipt.l1)
    assert main([str(path)]) == 0


def test_verify_valid_chain_file(tmp_path, valid_receipt):
    path = _write_json(
        tmp_path / "chain.json",
        {"l1": valid_receipt.l1, "behavior": valid_receipt.behavior},
    )
    assert main(["--chain", str(path)]) == 0


def test_invalid_tampered_l1_returns_1(tmp_path, valid_receipt):
    bad = dict(valid_receipt.l1)
    bad["verdict"] = "block"
    path = _write_json(tmp_path / "bad.json", bad)
    assert main([str(path)]) == 1


def test_missing_file_returns_2(tmp_path):
    assert main([str(tmp_path / "missing.json")]) == 2


def test_invalid_json_returns_2(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{not json", encoding="utf-8")
    assert main([str(path)]) == 2


def test_chain_wrapper_requires_l1(tmp_path, valid_receipt):
    path = _write_json(tmp_path / "no_l1.json", {"behavior": valid_receipt.behavior})
    assert main(["--chain", str(path)]) == 2


def test_no_args_prints_help_and_returns_2(capsys):
    assert main([]) == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.out
'''

FILES["examples/basic_crew.py"] = r'''"""Lightweight end-to-end ccs-crewai example.

This example runs without API keys and without a heavy CrewAI installation. It
uses the same :class:`CCSGuardrailProvider` that would be registered through
CrewAI's ``register_before_tool_call_hook`` / ``register_after_tool_call_hook``
APIs, but invokes it directly so the script is deterministic and offline.

Run::

    pip install -e ".[dev]"
    python examples/basic_crew.py

When CrewAI is installed, use::

    from ccs_crewai import CCSConfig, CCSGuardrailProvider, enable_guardrail
    provider = CCSGuardrailProvider(CCSConfig(seed=b"change-me", policy=policy))
    enable_guardrail(provider)
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from ccs_crewai import (
    CCSConfig,
    CCSGuardrailProvider,
    PolicyDecision,
    ReceiptRecord,
    verify_chain,
)


def policy(tool_name: str, tool_input: dict, runtime_context: dict) -> PolicyDecision:
    """Deny destructive tools; allow everything else."""
    if tool_name in {"shell_exec", "delete_database", "rm_rf"}:
        return PolicyDecision(
            allowed=False,
            reason=f"policy_denied:{tool_name}",
            metadata={"severity": "high"},
        )
    return PolicyDecision(allowed=True, reason="no_rules_matched")


class SimulatedCrewContext:
    """Minimal object shaped like CrewAI's ToolCallHookContext."""

    def __init__(self, tool_name: str, tool_input: dict, raw_result=None):
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.raw_tool_result = raw_result
        self.tool_result = None
        self.tool = SimpleNamespace()
        self.agent = SimpleNamespace(role="researcher")
        self.task = SimpleNamespace(description="Research CrewAI guardrails")
        self.crew = SimpleNamespace(id="demo-crew")


def main() -> None:
    receipts: list[ReceiptRecord] = []
    config = CCSConfig(
        seed=b"ccs-crewai-example-seed",
        policy=policy,
        issuer="ccs-crewai-example",
        audience="demo-audience",
        trace_id="example-trace-001",
        sink=receipts.append,
    )
    provider = CCSGuardrailProvider(config)

    # 1. Allowed tool via the same hook methods CrewAI calls.
    search_ctx = SimulatedCrewContext("web_search", {"query": "CrewAI tool hooks"})
    assert provider.before_tool_call(search_ctx) is None
    search_ctx.raw_tool_result = ["CrewAI tool hook docs", "CCS receipt spec"]
    provider.after_tool_call(search_ctx)

    # 2. Allowed direct tool invocation.
    summary = provider.intercept_tool_call(
        "summarize",
        {"documents": ["doc-a", "doc-b"]},
        lambda: "CrewAI hooks can block tools before execution.",
    )
    print("Summary result:", summary.result)

    # 3. Blocked tool does not execute.
    blocked_ctx = SimulatedCrewContext("shell_exec", {"command": "rm -rf /"})
    decision = provider.before_tool_call(blocked_ctx)
    assert decision is False
    print("Blocked tool as required by policy")

    print(f"\nEmitted {len(receipts)} receipt records")
    for i, record in enumerate(receipts, start=1):
        l1 = record.l1
        print(
            f"  {i}. tool={l1['tool']!r} verdict={record.verdict} "
            f"sequence={l1['sequence']} action={l1['action']}"
        )
        ok, reason = verify_chain(l1, record.behavior)
        assert ok, reason

    out = Path("receipts.jsonl")
    with out.open("w", encoding="utf-8") as fh:
        for record in receipts:
            fh.write(json.dumps(record.as_dict(), ensure_ascii=False) + "\n")
    print(f"\nWrote receipts to {out.resolve()}")
    print("All receipts independently verified with ccs_crewai.verifier.")


if __name__ == "__main__":
    main()
'''

FILES["README.md"] = r'''# ccs-crewai

Cryptographic runtime receipts for [CrewAI](https://github.com/crewAIInc/crewAI)
agents. Every tool call can produce a signed 30-field CCS L1 action receipt and
a linked 15-field `ccs.behavior_evidence.v1` receipt. Pre-admission policy
checks block unauthorized calls before tool execution and emit a signed
`verdict="block"` receipt.

The adapter follows the same CCS shape as `ccs-pydantic-ai` and uses:

- Ed25519 signatures over RFC 8785 JCS canonical JSON
- deterministic in-process keys or external sidecar signing
- an MIT-licensed verifier with no CrewAI dependency
- a `ccs-crewai-verify` CLI for offline receipt verification

## Installation

```bash
pip install -e ".[dev]"
```

CrewAI itself is optional: receipt construction, verification, and the CLI work
without it. Install the extra only when wiring the provider into a real CrewAI
application:

```bash
pip install -e ".[crewai]"
```

## Quick start

```python
from ccs_crewai import CCSConfig, CCSGuardrailProvider, PolicyDecision, enable_guardrail

def policy(tool_name, tool_input, runtime_context):
    if tool_name in {"shell_exec", "delete_database"}:
        return PolicyDecision(False, f"denied:{tool_name}")
    return PolicyDecision(True, "no_rules_matched")

provider = CCSGuardrailProvider(
    CCSConfig(
        seed=b"change-this-seed",
        policy=policy,
        issuer="my-app/ccs",
        audience="my-crew",
    )
)

# Registers CrewAI before_tool_call / after_tool_call hooks globally.
enable_guardrail(provider)
```

For tests or non-hook integrations, call the provider directly:

```python
result = provider.intercept_tool_call(
    "web_search", {"query": "CrewAI"}, lambda: search_tool(query="CrewAI")
)
```

Denied calls raise `ToolCallBlocked`, whose `receipts` attribute contains the
signed block receipt.

## Receipt fields

The L1 receipt contains exactly:

```text
trace_id, receipt_version, verdict, timestamp, tool, tool_call_id,
params_hash, args_digest, rule_summary, rule_version, request_hash,
response_hash, runtime_context_hash, config_hash, verifier_source_class,
deployment_mode, issuer, audience, nonce, sequence, issued_at, expires_at,
max_clock_skew, action, signature, signing_algorithm,
public_key_fingerprint, public_key, verified_at, latency_us
```

The behavior receipt contains exactly:

```text
receipt_type, trace_id, tool_call_id, sequence, linked_l1_receipt_digest,
behavior_evidence_verdict, evidence_ref, issuer, audience, issued_at,
deployment_mode, signing_algorithm, public_key_fingerprint, public_key,
signature
```

## Deployment modes

- **in-process** (default): the Ed25519 private key is derived from `seed` using
  `SHA-256(seed)`. This is deterministic and useful for tests, but the private
  key lives in the agent process.
- **sidecar**: the private key never enters the agent process. Signing is
  delegated to an HTTP endpoint; supply the trusted base64 public key for local
  signature verification.

```python
CCSConfig(deployment_mode="sidecar", sidecar_url="http://localhost:9100", public_key="...")
```

## Verification

Python API:

```python
from ccs_crewai import verify_l1_receipt, verify_chain

ok, reason = verify_l1_receipt(l1_receipt)
ok, reason = verify_chain(l1_receipt, behavior_receipt)
```

CLI:

```bash
ccs-crewai-verify receipt.json
ccs-crewai-verify --chain chain.json
ccs-crewai-verify --version
python -m ccs_crewai.cli --version
```

## Development

```bash
pytest tests/ -v
python examples/basic_crew.py
python -m build
```

## License

MIT
'''


def main() -> None:
    for rel, content in FILES.items():
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"Wrote {len(FILES)} files under {ROOT}")
    # Self-delete: this script is only a temporary authoring aid.
    os.remove(__file__)


if __name__ == "__main__":
    main()
