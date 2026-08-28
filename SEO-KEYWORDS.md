# CCS Integrations — SEO & Discoverability Strategy

## Competitor Keyword Landscape (researched 2026-08-28)

### Direct competitors (cryptographic receipts / runtime governance)

| Project | PyPI/GitHub Tags | Differentiator |
|---------|-----------------|----------------|
| Attested Intelligence (AGA) | Ed25519+ML-DSA-65, MCP-native, 37 vectors | Patent pending; **admits no tool-execution verification** — our gap |
| AAR (Cyberweasel777) | Ed25519, JCS, hash-chain, x402, SCC | TypeScript-only; AutoGen #7353; no L1 30-field strict schema |
| XAIP (draft-xkumakichi) | Ed25519, JCS, DID, co-signature | IETF draft; executor+caller dual-sign; 9 fields only |
| AgentLedger (draft-dembowski) | Ed25519, hash-chain, policy gate | IETF draft; agent_id=pubkey; no schema strictness |

### Adjacent guardrail/security packages (high-traffic keywords)

| Package | Tags used |
|---------|----------|
| `agent-aegis` | a2a, agent, ai, anthropic, approval, audit, audit-trail, auto-instrumentation, compliance, cost-management, crewai, eu-ai-act, governance, guardrails, langchain, mcp, observability, openai, pii-detection, policy, policy-as-code, prompt-injection, runtime-security, safety, security, supply-chain-security |
| `agentguard-llm` | (circuit-breaker, idempotency, loop-detection, fallback) |
| `parry-ai` | (prompt-injection, jailbreak, PII, secret-leak, <5ms) |
| `dfx-agentguard` | ai-security, agent-security, owasp-asi, prompt-injection, mcp, static-analysis, llm-security |
| `pydantic-ai-guardrails` | (native AbstractCapability, PII, prompt-injection, cost-limit) — **Pydantic AI's official guardrail pattern** |
| `pydantic-ai-middleware` | (7 lifecycle hooks, before_tool_call, after_tool_call) |
| `agent-security` | (prompt-injection, jailbreak, PII, tool-call-validation, audit, HIPAA/SOX/GDPR) |
| ToolGuard | (MCP, 7-layer, semantic, observability, "Cloudflare for AI Agents") |

### Key insight
- `pydantic-ai-guardrails` (July 2026) already ships native `AbstractCapability` guardrails for PII/injection/cost — **but no cryptographic receipts**. Our slot: post-execution verifiable evidence, not pre-execution filtering.
- `pydantic-ai-middleware` provides `before_tool_call`/`after_tool_call` hooks but is generic — our adapter can use either the native `WrapperToolset` or the middleware pattern.
- AGA is the closest competitor but explicitly **doesn't verify tool execution** — that's our exact moat.
- High-volume search terms: `guardrails`, `audit-trail`, `runtime-security`, `prompt-injection`, `mcp`, `compliance`, `observability`, `governance`.

---

## PyPI package metadata — `ccs-pydantic-ai`

### Name strategy
- Primary: `ccs-pydantic-ai` (matches framework naming convention like `pydantic-ai-guardrails`)
- The `ccs-` prefix creates a namespace pattern that scales: `ccs-crewai`, `ccs-autogen`, `ccs-langchain`
- Consider also claiming: `ccs-runtime`, `ccs-receipts` as umbrella packages later

### pyproject.toml keywords (max traffic, ordered by search volume)
```toml
[project]
keywords = [
    # High-volume umbrella terms
    "ai-security",
    "agent-security",
    "guardrails",
    "runtime-security",
    "llm-security",
    # Framework-specific (directly searchable)
    "pydantic-ai",
    "pydantic",
    "mcp",
    # Evidence/compliance (our differentiator)
    "cryptographic-receipts",
    "audit-trail",
    "non-repudiation",
    "compliance",
    "governance",
    "supply-chain-security",
    # Technical terms (searched by security engineers)
    "ed25519",
    "jcs",
    "rfc8785",
    "signed-receipts",
    "tamper-evidence",
    "verifiable",
    "runtime-verification",
    "tool-call-validation",
    "observability",
    # Standards/ecosystem
    "scitt",
    "dmsc",
    "x402",
    "agent-protocol",
    "owasp-asi",
]

classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
    "Topic :: Security",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Monitoring",
]
```

### GitHub topics (ccs-integrations repo)
```
ai-security agent-security llm-security guardrails runtime-security
cryptographic-receipts ed25519 jcs rfc8785 signed-receipts tamper-evidence
non-repudiation audit-trail compliance governance verifiable
pydantic-ai mcp model-context-protocol tool-call-validation
runtime-verification observability supply-chain-security
scitt dmsc agent-governance owasp-asi ai-agents
```

### GitHub topics (ccs-conformance-vectors repo — add/update)
```
conformance testing test-vectors cryptographic-receipts ed25519 jcs
ai-security agent-security mcp interoperability
```

---

## README SEO strategy

### Title/H1 pattern
Match search intent: people search for "[framework] guardrails", "[framework] security", "agent audit trail", "signed tool calls".

```markdown
# CCS for Pydantic AI — Cryptographic runtime receipts for agent tool calls

**Signed, tamper-evident audit receipts for every Pydantic AI tool call.**
Ed25519 + JCS (RFC 8785). Sub-millisecond. Drop-in.
```

### First paragraph must include keywords naturally
> ccs-pydantic-ai brings cryptographic runtime verification to Pydantic AI agents.
> Every tool call produces a signed receipt (Ed25519 over RFC 8785 canonical JSON)
> that proves what was called, what happened, and who verified it — non-repudiable
> audit evidence for compliance, governance, and security teams.

### Section structure (SEO-optimized)
1. What it does (keywords: agent security, guardrails, runtime verification)
2. Install (pip install ccs-pydantic-ai)
3. Quick start (2-line integration)
4. What gets signed (field list)
5. Deployment modes (in-process / sidecar)
6. Verification (how to verify receipts independently)
7. Conformance (link to vectors, 26/26 tests)
3. Comparison with alternatives (table vs guardrails, vs logs, vs AAR/AGA)
9. Ecosystem (SCITT, DMSC, x402, RootSign)

### Differentiation phrases to own
- "cryptographic runtime receipts" (not just "guardrails")
- "non-repudiable tool call evidence"
- "signed execution receipt"
- "30-field L1 receipt, strict-verified"
- "Ed25519 + JCS (RFC 8785)"
- "tamper-evident, independently verifiable"
- "post-execution evidence layer" (complements, doesn't replace, schema validation)

### Avoid (overused/empty terms)
- "AI safety" (too broad, associated with content filtering)
- "prompt injection" (we don't primarily do this; let competitors fight over it)
- "zero trust" (buzzword, no technical meaning here)
- "military-grade" (red flag)
- "revolutionary" / "game-changing"

---

## Package naming for future adapters

| Package | Framework | Priority |
|---------|-----------|----------|
| `ccs-pydantic-ai` | Pydantic AI | 🔨 Building now |
| `ccs-crewai` | CrewAI (GuardrailProvider) | High — active thread #4877 |
| `ccs-mcp` | Generic MCP server/client | High — protocol-level |
| `ccs-autogen` | AutoGen | Medium — wait for #7353 maintainer response |
| `ccs-langchain` | LangChain/LangGraph | Medium — large user base but complex API |
| `ccs-openai-agents` | OpenAI Agents SDK | Medium |
| `ccs-llamaindex` | LlamaIndex | Low |

Claim all names on PyPI early (even empty placeholder packages) to prevent squatting.
