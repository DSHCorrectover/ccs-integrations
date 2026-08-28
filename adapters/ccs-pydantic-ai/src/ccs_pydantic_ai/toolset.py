"""Pydantic AI integration: :class:`CCSToolset` and :class:`CCSCapability`.

Every tool call executed by a Pydantic AI agent is intercepted in
:meth:`CCSToolset.call_tool` (the correct interception point confirmed in
pydantic/pydantic-ai#4262). A signed 30-field CCS L1 action receipt and a linked
``ccs.behavior_evidence.v1`` receipt are produced for every call and emitted to
the configured sink.

Two integration styles are supported:

* **Recommended (intercepts local + MCP tools uniformly):** register
  :class:`CCSCapability` via the agent's ``capabilities=[...]`` argument. It
  wraps the agent's already-assembled combined toolset each run via
  :meth:`AbstractCapability.get_wrapper_toolset`, so *every* tool — function
  tools and MCP tools alike — is covered with no code changes.
* **Explicit toolset wrapping:** wrap a specific toolset with
  :class:`CCSToolset` and pass it in ``toolsets=[...]``. This covers only the
  tools in the wrapped toolset and is useful when you want receipts for a
  subset of tools.

The adapter never requires changes to existing agent code structure or tool
implementations.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic_ai import RunContext, WrapperToolset
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.toolsets import AbstractToolset, ToolsetTool

from .config import CCSConfig, ReceiptRecord
from .receipt_builder import ReceiptBuilder
from .signer import build_signer

__all__ = ["CCSToolset", "CCSCapability"]


def _extract_runtime_context(ctx: RunContext[Any]) -> dict[str, Any]:
    """Extract a JSON-serialisable snapshot of the run context for hashing."""
    snapshot: dict[str, Any] = {}
    for attr in (
        "run_id",
        "conversation_id",
        "run_step",
        "tool_name",
        "model_settings",
        "available_tool_names",
    ):
        try:
            value = getattr(ctx, attr, None)
        except Exception:  # noqa: BLE001 - defensive across pydantic-ai versions
            value = None
        if value is not None:
            snapshot[attr] = value
    return snapshot


class CCSToolset(WrapperToolset):  # type: ignore[misc]
    """A :class:`~pydantic_ai.WrapperToolset` that emits CCS receipts.

    Args:
        wrapped: The toolset whose tool calls to intercept and receipt.
        config: CCS configuration (deployment mode, signer, sink, ...).
        builder: Optional pre-built :class:`ReceiptBuilder` (used internally by
            :class:`CCSCapability` to share per-run state). If omitted, one is
            created from *config*.
    """

    def __init__(
        self,
        wrapped: AbstractToolset[Any],
        config: CCSConfig,
        *,
        builder: Optional[ReceiptBuilder] = None,
    ) -> None:
        super().__init__(wrapped)
        self.config = config
        if builder is None:
            builder = _build_builder(config)
        self._builder = builder

    async def for_run(self, ctx: RunContext[Any]) -> AbstractToolset[Any]:
        """Propagate per-run state instead of using dataclass replace()."""
        new_wrapped = await self.wrapped.for_run(ctx)
        if new_wrapped is self.wrapped:
            return self
        return CCSToolset(new_wrapped, self.config, builder=self._builder)

    async def call_tool(
        self,
        name: str,
        tool_args: dict[str, Any],
        ctx: RunContext[Any],
        tool: ToolsetTool[Any],
    ) -> Any:
        tool_call_id = getattr(ctx, "tool_call_id", None) or f"ccs-{uuid.uuid4().hex}"
        runtime_context = _extract_runtime_context(ctx)
        started_at = time.time()

        try:
            result = await super().call_tool(name, tool_args, ctx, tool)
        except BaseException as exc:  # includes ModelRetry, ToolFailed, etc.
            ended_at = time.time()
            self._emit(
                tool=name,
                tool_call_id=tool_call_id,
                args=tool_args,
                runtime_context=runtime_context,
                started_at=started_at,
                ended_at=ended_at,
                error=exc,
            )
            raise

        ended_at = time.time()
        self._emit(
            tool=name,
            tool_call_id=tool_call_id,
            args=tool_args,
            runtime_context=runtime_context,
            started_at=started_at,
            ended_at=ended_at,
            result=result,
        )
        return result

    # ------------------------------------------------------------------ #
    def _emit(
        self,
        *,
        tool: str,
        tool_call_id: str,
        args: dict[str, Any],
        runtime_context: dict[str, Any],
        started_at: float,
        ended_at: float,
        result: Any = None,
        error: Optional[BaseException] = None,
    ) -> None:
        try:
            built = self._builder.build(
                tool=tool,
                tool_call_id=tool_call_id,
                args=args,
                runtime_context=runtime_context,
                result=result,
                error=error,
                started_at=started_at,
                ended_at=ended_at,
            )
        except Exception as builder_exc:  # noqa: BLE001
            # Receipt generation must never break the agent run.
            # Log to stderr and continue.
            import sys

            print(
                f"[ccs-pydantic-ai] WARNING: failed to build receipt for "
                f"{tool!r}: {builder_exc}",
                file=sys.stderr,
                flush=True,
            )
            return

        record = ReceiptRecord(
            l1=built.l1,
            behavior=built.behavior,
            trace_id=built.l1["trace_id"],
            tool_call_id=tool_call_id,
            verdict=built.verdict,
        )
        try:
            self.config.sink(record)
        except Exception as sink_exc:  # noqa: BLE001
            import sys

            print(
                f"[ccs-pydantic-ai] WARNING: receipt sink raised: {sink_exc}",
                file=sys.stderr,
                flush=True,
            )


class CCSCapability(AbstractCapability[Any]):
    """Capability that wraps the agent's combined toolset with :class:`CCSToolset`.

    This is the recommended integration: it intercepts **all** tools (local
    function tools and MCP tools) uniformly. A fresh :class:`ReceiptBuilder`
    (and therefore a fresh sequence counter and per-run trace id when
    ``config.trace_id`` is unset) is created for each agent run via
    :meth:`for_run`, so receipt sequences never leak between runs.
    """

    def __init__(self, config: CCSConfig) -> None:
        self.config = config

    async def for_run(self, ctx: RunContext[Any]) -> "CCSCapability":
        trace_id = self.config.trace_id or f"ccs-run-{uuid.uuid4().hex}"
        builder = _build_builder(self.config, trace_id=trace_id)
        return _PerRunCCSCapability(self.config, builder)


@dataclass
class _PerRunCCSCapability(AbstractCapability[Any]):
    """Per-run instance holding a fresh receipt builder/sequence counter."""

    config: CCSConfig
    builder: ReceiptBuilder

    def get_wrapper_toolset(
        self, toolset: AbstractToolset[Any]
    ) -> AbstractToolset[Any]:
        return CCSToolset(toolset, self.config, builder=self.builder)


def _build_builder(config: CCSConfig, *, trace_id: Optional[str] = None) -> ReceiptBuilder:
    signer = build_signer(config)
    trace_id = trace_id or config.trace_id or f"ccs-{uuid.uuid4().hex}"
    return ReceiptBuilder(
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
    )
