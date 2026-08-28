"""End-to-end demo: real Pydantic AI agent → signed CCS receipts → ccs-verify CLI.

This is the **representative** example. Unlike ``basic_agent.py`` which only
prints receipts, this script demonstrates a *production* verification pipeline:

1. A Pydantic AI agent with three real business tools
   (``lookup_customer``, ``check_balance``, ``process_refund``) runs under
   CCS instrumentation using ``TestModel`` (no API key needed).
2. Every tool call emits a signed 30-field L1 action receipt plus a linked
   behavior-evidence receipt — exactly as it would in production.
3. Receipts are written as JSONL to stdout, which can be piped directly into
   the ``ccs-verify`` CLI:

   .. code-block:: console

       # Run the agent, verify every receipt in one streaming pass:
       python examples/e2e_agent_verify.py | ccs-verify --stream -

       # Pretty-print results as JSON for SIEM/CI consumption:
       python examples/e2e_agent_verify.py | ccs-verify --stream --json -

       # Save receipts then verify:
       python examples/e2e_agent_verify.py > receipts.jsonl
       ccs-verify --stream receipts.jsonl

To use a real LLM, replace ``TestModel()`` with e.g. ``"openai:gpt-4o"`` and
set ``OPENAI_API_KEY``. Everything else — CCS signing, receipt structure, CLI
verification — stays identical.

Exit codes from ``ccs-verify``:
  0 = all receipts valid
  1 = one or more receipts failed verification (tampering, broken chain, etc.)
  2 = usage error
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.test import TestModel

from ccs_pydantic_ai import CCSCapability, CCSConfig, ReceiptRecord


# ---------------------------------------------------------------------------
# Business tools — these look like real production functions, not stubs.
# ---------------------------------------------------------------------------

_CUSTOMERS: dict[str, dict[str, Any]] = {
    "C-1001": {"name": "Alice Zhang", "tier": "gold", "email": "alice@example.com"},
    "C-1002": {"name": "Bob Li",       "tier": "silver", "email": "bob@example.com"},
}

_BALANCES: dict[str, float] = {
    "ACC-9001": 12500.00,
    "ACC-9002":   830.50,
}


async def lookup_customer(ctx: RunContext[dict], customer_id: str) -> str:
    """Look up a customer record by ID."""
    record = _CUSTOMERS.get(customer_id)
    if record is None:
        return f"Customer {customer_id} not found"
    return f"{record['name']} ({record['tier']} tier) — {record['email']}"


async def check_balance(ctx: RunContext[dict], account: str) -> str:
    """Check the current balance of a financial account."""
    balance = _BALANCES.get(account)
    if balance is None:
        return f"Account {account} not found"
    return f"Account {account}: ¥{balance:,.2f}"


async def process_refund(
    ctx: RunContext[dict], order_id: str, amount: float
) -> str:
    """Process a refund for a given order. Requires manager approval."""
    # Simulate a permission check that can fail.
    if amount > 10000:
        raise PermissionError(
            f"Refund of ¥{amount:,.2f} for {order_id} exceeds limit; "
            "manager approval required"
        )
    return f"Refund ¥{amount:,.2f} for {order_id} processed successfully"


# ---------------------------------------------------------------------------
# Agent assembly
# ---------------------------------------------------------------------------

def build_agent() -> Agent[None, str]:
    """Create a Pydantic AI agent with CCS capability and business tools."""
    config = CCSConfig(
        deployment_mode="in-process",
        seed=b"production-demo-seed-2026-08-28",
        rule_version="1.3.0",
        issuer="payment-agent-cluster-03",
        audience="soc-audit-team",
        trace_id="trace_payment_incident_a7f3c9",
        # Default sink writes one JSON object per line to stdout — perfect for
        # piping into ccs-verify --stream.
        sink=lambda record: sys.stdout.write(
            json.dumps(record.as_dict(), ensure_ascii=False) + "\n"
        ),
    )

    agent = Agent(
        TestModel(),  # replace with "openai:gpt-4o" for a real run
        capabilities=[CCSCapability(config)],
    )

    # Register tools via the decorator so Pydantic AI picks up signatures.
    agent.tool(lookup_customer)
    agent.tool(check_balance)
    agent.tool(process_refund)

    return agent


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    agent = build_agent()

    # The agent will call all three registered tools in sequence because
    # TestModel calls every registered tool by default. In production the LLM
    # decides which tools to call based on the user prompt.
    result = await agent.run(
        "Look up customer C-1001, check their account ACC-9001 balance, "
        "and process a refund of ¥500 for order ORD-2026-0888."
    )

    # Write agent output to stderr so stdout stays pure JSONL for piping.
    print(f"\n=== Agent final output ===\n{result.output}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
