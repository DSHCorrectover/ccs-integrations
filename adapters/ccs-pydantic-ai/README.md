# ccs-pydantic-ai

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![CI](https://github.com/DSHCorrectover/ccs-integrations/actions/workflows/test.yml/badge.svg)](https://github.com/DSHCorrectover/ccs-integrations/actions)

> **The flight recorder for AI agents.** Every tool call gets a signed,
> tamper-evident receipt before the next step runs. If your agent freezes,
> crashes, or goes silent, the last signed receipt tells you exactly what it
> did, with what arguments, and what came back.

CCS (**Correctover Conformance Shape**) is a cryptographic runtime receipt
format for AI agent tool calls. This adapter adds CCS receipts to
[Pydantic AI](https://ai.pydantic.dev/) agents with **2 lines of code**.

```python
from ccs_pydantic_ai import CCSCapability, CCSConfig
from pydantic_ai import Agent

agent = Agent(
    "openai:gpt-4o",
    capabilities=[CCSCapability(CCSConfig(seed=b"my-app-seed"))],
)
```

No changes to your tools, agent structure, or prompts. Every tool call —
including MCP tools — is intercepted at the framework's native wrapper layer
and emits a signed receipt before the result reaches the model.

---

## Why?

**When an agent freezes, you have nothing.**

- [CrewAI #6380](https://github.com/crewAIInc/crewAI/issues/6380) — async task freezes without exception or log
- [Smolagents #2432](https://github.com/huggingface/smolagents/issues/2432) — missing fallbacks cause silent hang
- [LlamaIndex #22180](https://github.com/run-llama/llama_index/issues/22180) — brittle examples lead to opaque failures

Logs can be lost. Exceptions can be swallowed. But a signed receipt is written
the moment a tool call completes — before the model sees the result. If the
agent dies, the receipt survives. That is your black box.

**This is not another guardrail.** Guardrails decide what goes in. CCS receipts
prove what happened.

---

## What you get

Every tool call produces two linked receipts:

### L1 Action Receipt (30 fields)

Signed Ed25519 receipt covering authorization, timing, and content hashes:

| Field | Purpose |
|-------|---------|
| `verdict` | `allow` or `block` |
| `tool`, `tool_call_id`, `action` | What was called |
| `args_digest` | SHA-256 over JCS canonical arguments |
| `request_hash` | Hash of full request envelope |
| `response_hash` | Hash of tool response or error |
| `params_hash` | Value-independent parameter shape |
| `runtime_context_hash` | Run/step/message binding |
| `issuer`, `audience`, `nonce`, `sequence` | Provenance and ordering |
| `signature`, `public_key`, `signing_algorithm` | Ed25519 over JCS (RFC 8785) |
| `latency_us`, `timestamp`, `issued_at`, `expires_at` | Timing |

### Behavior Evidence Receipt (15 fields)

Linked `ccs.behavior_evidence.v1` receipt with a `linked_l1_receipt_digest`
that binds it to the exact L1 receipt it describes.

### Open-source verifier

Every receipt can be verified with **zero proprietary dependencies**:

```python
from ccs_pydantic_ai import verify_chain

ok, reason = verify_chain(l1_receipt, behavior_receipt)
if not ok:
    raise RuntimeError(f"Receipt verification failed: {reason}")
```

The verifier checks exact 30-field structure, Ed25519 signature over JCS
(RFC 8785), cross-key rejection, and L1-to-behavior chain linkage. For
enterprise use, the optional `ccs-verifier==1.3.0` adds the full 7-dimension
rule engine. It is not required for cryptographic verification.

---

## Installation

```bash
pip install ccs-pydantic-ai
```

For strict L1 verification with the full rule engine (ELv2 licensed):

```bash
pip install "ccs-pydantic-ai[verify]"
```

---

## Quick start

```python
from pydantic_ai import Agent
from ccs_pydantic_ai import CCSCapability, CCSConfig

def search_docs(query: str) -> str:
    """Search documentation."""
    return f"Results for: {query}"

agent = Agent(
    "openai:gpt-4o",
    tools=[search_docs],
    capabilities=[CCSCapability(CCSConfig(
        seed=b"deterministic-seed-for-reproducible-keys",
        issuer="my-app",
        audience="production",
    ))],
)

result = agent.run_sync("Search for deployment guides")
```

### Custom receipt sink (write to files)

```python
import json, pathlib

receipts_dir = pathlib.Path("receipts")
receipts_dir.mkdir(exist_ok=True)

def file_sink(record):
    path = receipts_dir / f"{record.tool_call_id}.json"
    path.write_text(json.dumps(record.as_dict(), indent=2))

config = CCSConfig(seed=b"seed", sink=file_sink)
```

### Sidecar deployment (key never enters agent process)

```python
config = CCSConfig(
    deployment_mode="sidecar",
    sidecar_url="http://localhost:9100",
    public_key="BASE64_ED25519_PUBLIC_KEY",
)
```

The adapter POSTs the canonical payload to the sidecar, receives a signature,
and locally verifies it before attaching.

---

## Architecture

```
Agent.run()
  |
  +-- CCSCapability.for_run()
  |     +-- creates per-run ReceiptBuilder (sequence counter, trace_id)
  |
  +-- CCSCapability.get_wrapper_toolset(combined_toolset)
        +-- CCSToolset wraps every tool (local + MCP)
             |
             +-- before: record started_at, capture context
             +-- super().call_tool()  <- actual tool execution
             +-- after:
                  +-- build L1 receipt (30 fields, signed Ed25519)
                  +-- build behavior receipt (linked via sha256 digest)
                  +-- emit to sink (stdout / file / callback)
```

The interception point is `WrapperToolset.call_tool`, confirmed in
[pydantic/pydantic-ai#4262](https://github.com/pydantic/pydantic-ai/issues/4262).

---

## Verification

```python
from ccs_pydantic_ai import verify_l1_receipt, verify_chain

ok, reason = verify_l1_receipt(receipt_dict)
ok, reason = verify_chain(l1_dict, behavior_dict)
```

If any field changes after signing, verification fails:

```python
tampered = dict(receipt)
tampered["verdict"] = "allow"  # was "block"
ok, reason = verify_l1_receipt(tampered)
# ok == False, reason contains "signature does not verify"
```


### Command-line verification

After `pip install ccs-pydantic-ai`, a `ccs-verify` command is available:

```bash
# Verify a single L1 receipt
ccs-verify receipt.json

# Verify from stdin
cat receipt.json | ccs-verify -

# Verify a full chain (L1 + behavior as separate files)
ccs-verify --chain l1.json behavior.json

# Verify a ReceiptRecord envelope (contains "l1" and "behavior")
ccs-verify record.json

# Verify a JSONL stream of receipts
ccs-verify --stream receipts.jsonl

# Machine-readable JSON output (for CI/CD pipelines)
ccs-verify --json receipt.json

# Check expiry
ccs-verify --check-expiry receipt.json
```

You can also run it as a module without installing the console script:

```bash
python -m ccs_pydantic_ai.cli receipt.json
```

**Exit codes:** `0` = valid, `1` = invalid, `2` = usage/input error.

The CLI uses the open-source MIT verifier — no proprietary `ccs-verifier`
dependency required.

---

## Security model

- **Algorithm**: Ed25519 over JCS canonical JSON ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785))
- **In-process key**: SHA-256(seed) derives deterministic Ed25519 key
- **Sidecar mode**: private key never enters agent process
- **Hash chain**: behavior bound to L1 via sha256(JCS(L1 excluding signature))
- **Replay**: each receipt has unique nonce and monotonic sequence
- **No bypass**: interception at framework wrapper layer

Receipts are tamper-evident and issuer-authenticated under an accepted key
policy. They do not by themselves prevent replay; consumers should enforce
single-use nonce checks bound to the same caller and execution context.

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

64 tests covering 30-field L1 structure, Ed25519 signatures, 20+ tamper
scenarios, cross-key rejection, behavior chain linkage, in-process and sidecar
signers, toolset interception, and the open-source verifier.

---

## Specification and ecosystem

- **IETF draft**: [draft-correctover-ccs-08](https://www.ietf.org/archive/id/draft-correctover-ccs-08.txt)
- **Conformance vectors**: [DSHCorrectover/ccs-conformance-vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors)
- **Adapter registry**: [DSHCorrectover/ccs-integrations](https://github.com/DSHCorrectover/ccs-integrations)

CCS receipts are complementary to schema validation. Schema validation
controls what results enter model-visible history; CCS receipts provide
cryptographic proof of what actually happened. They are independent guarantees.

---

## License

MIT for the adapter. The optional `ccs-verifier` package (7-dimension rule
engine, strict L1 parser) is ELv2 licensed. Conformance vectors are CC0.
