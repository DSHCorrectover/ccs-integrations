"""Minimal runnable example: Pydantic AI agent + CCS runtime receipts.

This example uses Pydantic AI's ``TestModel`` so it runs with **no API key** and
no network access. Every tool call produces a signed 30-field CCS L1 action
receipt plus a linked ``ccs.behavior_evidence.v1`` receipt, which are collected
and pretty-printed.

Run::

    pip install -e ".[dev]"
    python examples/basic_agent.py

To use a real model, replace ``TestModel()`` with e.g. ``"openai:gpt-4o"`` and
set ``OPENAI_API_KEY``.
"""

from __future__ import annotations

import asyncio
import json

from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

from ccs_pydantic_ai import CCSCapability, CCSConfig, ReceiptRecord


async def main() -> None:
    # Collect receipts instead of printing them one-per-line so we can render
    # a summary at the end.
    receipts: list[ReceiptRecord] = []

    config = CCSConfig(
        deployment_mode="in-process",
        seed=b"my-app-seed-change-me-in-production",
        rule_version="1.3.0",
        issuer="my-app/ccs",
        audience="my-audience",
        trace_id="example-trace-001",
        sink=receipts.append,  # default sink prints JSON lines to stdout
    )

    def search(query: str) -> str:
        """Search the knowledge base for the given query."""
        return f"Top results for {query!r}: [doc-A, doc-B, doc-C]"

    agent = Agent(
        TestModel(),  # replace with "openai:gpt-4o" for a real run
        tools=[search],
        capabilities=[CCSCapability(config)],
    )

    result = await agent.run("Search for pydantic AI toolsets")
    print("=== Agent output ===")
    print(result.output)
    print()

    print(f"=== CCS receipts emitted: {len(receipts)} ===")
    for i, record in enumerate(receipts):
        l1 = record.l1
        print(f"\n--- Receipt {i + 1}: tool={l1['tool']!r} verdict={record.verdict} ---")
        print(f"  trace_id          : {record.trace_id}")
        print(f"  tool_call_id      : {record.tool_call_id}")
        print(f"  sequence          : {l1['sequence']}")
        print(f"  action            : {l1['action']}")
        print(f"  deployment_mode   : {l1['deployment_mode']}")
        print(f"  public key fp     : {l1['public_key_fingerprint']}")
        print(f"  signature (b64)   : {l1['signature'][:48]}...")
        if record.behavior is not None:
            print(
                f"  behavior verdict  : "
                f"{record.behavior['behavior_evidence_verdict']}"
            )
            print(
                f"  linked L1 digest  : "
                f"{record.behavior['linked_l1_receipt_digest']}"
            )

    # Independently verify the first L1 receipt with the closed core verifier.
    try:
        from ccs_verifier.ccs_verifier_l1 import L1Receipt

        first = receipts[0].l1
        receipt = L1Receipt.from_dict(first, strict=True)
        assert receipt.verify_signature() is True
        print("\n=== Independent verification ===")
        print("L1 receipt parsed by ccs-verifier (strict) and signature VALID")
    except ImportError:
        print(
            "\n(Install the 'verify' extra (ccs-verifier==1.3.0) to independently "
            "verify receipts.)"
        )

    # Dump full receipts to a file for inspection.
    with open("receipts.jsonl", "w", encoding="utf-8") as fh:
        for record in receipts:
            fh.write(json.dumps(record.as_dict(), ensure_ascii=False) + "\n")
    print("\nFull receipts written to receipts.jsonl")


if __name__ == "__main__":
    asyncio.run(main())
