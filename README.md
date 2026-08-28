# CCS Integrations

> Framework-native adapters for the Correctover Conformance Shape (CCS) runtime verification standard.

## What is CCS?

CCS is a cryptographically verifiable runtime receipt standard for AI agents. Every tool call produces a signed, chain-linked receipt proving:

- **What was called** — tool name, args digest, request hash
- **What happened** — verdict (allow/block), response hash, behavior evidence
- **Who verified it** — issuer identity, signing key fingerprint, deployment mode
- **When** — timestamp, nonce, sequence number, expiry
- **Tamper evidence** — Ed25519 signature over JCS-canonical JSON, previous-receipt hash chain

Receipts are 30-field L1 artifacts compatible with [`ccs-verifier==1.3.0`](https://pypi.org/project/ccs-verifier/), plus optional signed behavior evidence receipts.

## Why integrations?

Instead of asking framework maintainers to build CCS support, we provide drop-in adapters. Install, configure, and your agent gets signed receipts — no framework fork, no PR to merge.

```bash
pip install ccs-pydantic-ai
```

```python
from ccs_pydantic_ai import CCSToolset, CCSConfig

agent = Agent("openai:gpt-4o", toolsets=[CCSToolset(CCSConfig(deployment_mode="in-process"))])
result = await agent.run("Search for Q3 revenue")
# Receipts emitted automatically — signed, chain-linked, verifiable
```

## Available Adapters

| Framework | Package | Status | Conformance |
|-----------|---------|--------|-------------|
| Pydantic AI | `ccs-pydantic-ai` | 🚧 In Development | — |
| CrewAI | `ccs-crewai` | 📋 Planned | — |
| AutoGen | `ccs-autogen` | 📋 Planned | — |
| LangChain | `ccs-langchain` | 📋 Planned | — |
| LlamaIndex | `ccs-llamaindex` | 📋 Planned | — |
| MCP (generic) | `ccs-mcp` | 📋 Planned | — |

## Architecture

```
┌─────────────────────────────────────────┐
│  Your Agent (Pydantic AI / CrewAI / …) │
└──────────────┬──────────────────────────┘
               │ tool call
               ▼
┌─────────────────────────────────────────┐
│  CCS Adapter (this repo)                │
│  ├── WrapperToolset / GuardrailProvider │
│  ├── Receipt Builder (30 fields)        │
│  ├── Ed25519 Signer                     │
│  └── Behavior Evidence Builder          │
└──────────────┬──────────────────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
   ┌─────────┐  ┌───────────┐
   │In-process│  │  Sidecar   │
   │ Key (seed)│  │  Key (ext) │
   └─────────┘  └───────────┘
               │
               ▼
        Signed Receipt (JSON)
        ├── L1 Receipt (authorization + chain integrity)
        └── Behavior Evidence (semantic verdict)
               │
               ▼
        ccs-verifier==1.3.0
        (strict parse + verify)
```

## Two Deployment Modes

| | In-process | Sidecar |
|---|---|---|
| **Key storage** | Deterministic seed in app memory | Private key outside agent process |
| **Isolation** | Key shares process memory | Key boundary enforced by OS |
| **Use case** | Testing, dev, low-stakes | Production, compliance, multi-tenant |
| **Performance** | Native speed | Local HTTP/loopback |
| **Threat model** | Runtime integrity only | Runtime + key exfiltration |

## Conformance Vectors

Reference test vectors are available at [DSHCorrectover/ccs-conformance-vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors):

- 10 signed vectors covering valid receipts, tamper detection, cross-key rejection, canonicalization, hash chain breaks, and replay
- Two key models: sidecar (private key not in repo) and in-process (deterministic, reproducible)
- Every L1 receipt is 30 fields, strict-compatible with `ccs-verifier==1.3.0`

Run verification:
```bash
git clone https://github.com/DSHCorrectover/ccs-conformance-vectors.git
cd ccs-conformance-vectors
pip install ccs-verifier==1.3.0 jcs cryptography
python3 verify_v131.py
```

## Ecosystem Map

CCS interoperates with or is referenced by:

- **IETF SCITT** — CCS as a reference receipt format for transparent auditing
- **IETF DMSC** — CCS as application/runtime verification layer above DMSG
- **EMILIA** — PR #668 merged, upstream tests pass with pinned ccs-verifier
- **x402** — Independent review identified 4 specification defects in their evidence binding
- **RootSign/PDR** — Paired conformance vectors and field crosswalk in [rootsign#37](https://github.com/Providex-AI/rootsign/issues/37)
- **AgenTrust** — Third-party conformance run passed and merged

## Specification

- IETF draft: [draft-correctover-ccs-08](https://www.ietf.org/archive/id/draft-correctover-ccs-08.txt)
- Submission ID: 168143

## License

- Adapters in this repository: **MIT**
- `ccs-verifier` core: **ELv2** (pip-installable, closed-source)
- Conformance vectors: **CC0**

## Contributing

We need adapter maintainers for every major agent framework. If you use a framework that's not listed, open an issue or PR. Each adapter should:

1. Use the framework's native interception point (not a fork)
2. Produce 30-field L1 receipts strict-compatible with `ccs-verifier==1.3.0`
3. Support both in-process and sidecar key modes
4. Include tamper detection tests
5. Pass the reference conformance vectors
