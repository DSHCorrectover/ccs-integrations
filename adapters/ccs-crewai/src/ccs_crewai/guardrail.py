"""CrewAI guardrail integration for CCS runtime receipts.

CrewAI (as of early 2025) does not ship a formal ``GuardrailProvider`` base
class (see crewAIInc/crewAI#4877). The framework instead provides global
``before_tool_call`` / ``after_tool_call`` hooks:

* ``before_tool_call(context)`` — returning ``False`` (or raising) prevents the
  tool from executing.
* ``after_tool_call(context)``  — receives the tool result and may inspect or
  transform it.

:class:`CCSGuardrailProvider` implements both hook methods so it can be
registered via :func:`enable_guardrail` (which calls CrewAI's
``register_before_tool_call_hook`` / ``register_after_tool_call_hook``). It also
exposes :meth:`intercept_tool_call`, a framework-agnostic method that performs
the full pre-admission → execution → receipt cycle without CrewAI, making it
straightforward to unit-test and to embed in non-hook integrations.

Pre-admission (block) semantics
-------------------------------
Before a tool runs, the configured *policy* callable is invoked. If it returns
:attr:`PolicyDecision.BLOCK` (or a tuple whose first element is ``BLOCK``), the
tool call is blocked: a **block** L1 receipt (with behavior verdict
``observed_and_rejected``) is emitted to the sink, and the tool is **never
executed**. When *fail_closed* is ``True`` (the default), any exception in the
policy callable also blocks the call.

Post-execution (allow) semantics
--------------------------------
After the tool returns successfully (or raises), an **allow** or **block** L1
receipt is emitted together with the linked behavior evidence receipt.
"""

from __future__ import annotations

import time
import uuid
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .config import CCSConfig, PolicyDecision, ReceiptRecord
from .receipt_builder import ReceiptBuilder
from .signer import build_signer

__all__ = [
    "CCSGuardrailProvider",
    "GuardrailRequest",
    "GuardrailDecision",
    "ToolCallBlocked",
    "GuardedToolResult",
    "enable_guardrail",
]


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
@dataclass
class GuardrailRequest:
    """Normalised representation of an incoming tool call."""

    tool_name: str
    tool_args: dict[str, Any]
    tool_call_id: str
    runtime_context: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardrailDecision:
    """Result of a pre-admission policy evaluation."""

    allowed: bool
    reason: str = ""
    policy_decision: Optional[PolicyDecision] = None


class ToolCallBlocked(Exception):
    """Raised when a tool call is blocked by the CCS pre-admission policy."""

    def __init__(self, reason: str, receipt_record: Optional[ReceiptRecord] = None):
        self.reason = reason
        self.receipt_record = receipt_record
        super().__init__(reason)


@dataclass
class GuardedToolResult:
    """Wrapper holding the tool result and the emitted receipt record."""

    result: Any
    record: ReceiptRecord


# --------------------------------------------------------------------------- #
# Provider
# --------------------------------------------------------------------------- #
class CCSGuardrailProvider:
    """CCS guardrail provider for CrewAI agents.

    Register globally with CrewAI::

        provider = CCSGuardrailProvider(config)
        provider.enable_guardrail()

    Or use directly (framework-agnostic)::

        result = provider.intercept_tool_call(
            tool_name="search",
            tool_args={"q": "hello"},
            runner=lambda: search_tool(q="hello"),
        )
    """

    def __init__(self, config: CCSConfig) -> None:
        self.config = config
        self._signer = build_signer(config)
        self._builder = self._make_builder(config.trace_id)
        # Track before/after state keyed by CrewAI context objects so that
        # blocked calls (which already emitted a receipt in before_tool_call)
        # do not emit a duplicate in after_tool_call.
        self._hook_state: "weakref.WeakKeyDictionary[Any, dict[str, Any]]" = (
            weakref.WeakKeyDictionary()
        )

    # ------------------------------------------------------------------ #
    # Builder management
    # ------------------------------------------------------------------ #
    def _make_builder(self, trace_id: Optional[str] = None) -> ReceiptBuilder:
        trace_id = trace_id or self.config.trace_id or f"ccs-crew-{uuid.uuid4().hex}"
        return ReceiptBuilder(
            signer=self._signer,
            rule_version=self.config.rule_version,
            rule_summary=self.config.rule_summary,
            issuer=self.config.issuer,
            audience=self.config.audience,
            trace_id=trace_id,
            verifier_source_class=self.config.verifier_source_class,
            receipt_ttl_seconds=self.config.receipt_ttl_seconds,
            max_clock_skew=self.config.max_clock_skew,
            action_suffix=self.config.action_suffix,
            include_behavior=self.config.include_behavior_receipts,
        )

    def reset(self, trace_id: Optional[str] = None) -> None:
        """Reset the sequence counter and optionally set a new trace ID."""
        self._builder = self._make_builder(trace_id)

    # ------------------------------------------------------------------ #
    # Policy evaluation
    # ------------------------------------------------------------------ #
    def _evaluate_policy(
        self, request: GuardrailRequest
    ) -> GuardrailDecision:
        """Run the configured policy and normalise its return value."""
        try:
            raw = self.config.policy(
                request.tool_name,
                request.tool_args,
                request.runtime_context,
            )
        except Exception as exc:  # noqa: BLE001
            if self.config.fail_closed:
                return GuardrailDecision(
                    allowed=False,
                    reason=f"policy_error: {exc}",
                    policy_decision=PolicyDecision.BLOCK,
                )
            return GuardrailDecision(
                allowed=True,
                reason="policy_error_fail_open",
                policy_decision=PolicyDecision.ALLOW,
            )

        if isinstance(raw, tuple):
            decision, reason = raw
            if isinstance(decision, PolicyDecision):
                return GuardrailDecision(
                    allowed=decision.allowed,
                    reason=str(reason),
                    policy_decision=decision,
                )
            return GuardrailDecision(
                allowed=bool(decision),
                reason=str(reason),
                policy_decision=(
                    PolicyDecision.ALLOW if decision else PolicyDecision.BLOCK
                ),
            )

        if isinstance(raw, PolicyDecision):
            return GuardrailDecision(
                allowed=raw.allowed,
                reason=raw.reason,
                policy_decision=raw,
            )

        # Treat truthy as allow, falsy as block.
        return GuardrailDecision(
            allowed=bool(raw),
            policy_decision=(PolicyDecision.ALLOW if raw else PolicyDecision.BLOCK),
        )

    # ------------------------------------------------------------------ #
    # Receipt emission
    # ------------------------------------------------------------------ #
    def _emit(
        self,
        *,
        request: GuardrailRequest,
        result: Any = None,
        error: Optional[BaseException] = None,
        blocked: bool = False,
        block_reason: Optional[str] = None,
        started_at: Optional[float] = None,
        ended_at: Optional[float] = None,
    ) -> ReceiptRecord:
        built = self._builder.build(
            tool=request.tool_name,
            tool_call_id=request.tool_call_id,
            args=request.tool_args,
            runtime_context=request.runtime_context,
            result=result,
            error=error,
            blocked=blocked,
            block_reason=block_reason,
            started_at=started_at,
            ended_at=ended_at,
        )
        record = ReceiptRecord(
            l1=built.l1,
            behavior=built.behavior,
            trace_id=built.l1["trace_id"],
            tool_call_id=request.tool_call_id,
            verdict=built.verdict,
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
        return record

    # ------------------------------------------------------------------ #
    # Framework-agnostic direct interception
    # ------------------------------------------------------------------ #
    def intercept_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any],
        runner: Callable[[], Any],
        tool_call_id: Optional[str] = None,
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> GuardedToolResult:
        """Intercept a tool call: pre-admission → execute → receipt.

        Args:
            tool_name: Name of the tool being called.
            tool_args: Arguments passed to the tool.
            runner: Zero-argument callable that executes the actual tool.
            tool_call_id: Optional explicit call ID. Generated if omitted.
            runtime_context: Optional runtime metadata for hashing.

        Returns:
            A :class:`GuardedToolResult` with the tool result and receipt record.

        Raises:
            ToolCallBlocked: If the pre-admission policy blocks the call.
        """
        request = GuardrailRequest(
            tool_name=tool_name,
            tool_args=tool_args,
            tool_call_id=tool_call_id or f"ccs-{uuid.uuid4().hex}",
            runtime_context=runtime_context or {},
        )

        # Pre-admission
        decision = self._evaluate_policy(request)
        started_at = time.time()

        if not decision.allowed:
            ended_at = time.time()
            record = self._emit(
                request=request,
                blocked=True,
                block_reason=decision.reason or "blocked_by_policy",
                started_at=started_at,
                ended_at=ended_at,
            )
            raise ToolCallBlocked(decision.reason or "blocked_by_policy", record)

        # Execute
        try:
            result = runner()
        except BaseException as exc:
            ended_at = time.time()
            record = self._emit(
                request=request,
                error=exc,
                started_at=started_at,
                ended_at=ended_at,
            )
            raise

        # Post-execution receipt
        ended_at = time.time()
        record = self._emit(
            request=request,
            result=result,
            started_at=started_at,
            ended_at=ended_at,
        )
        return GuardedToolResult(result=result, record=record)

    # ------------------------------------------------------------------ #
    # CrewAI hook interface
    # ------------------------------------------------------------------ #
    def before_tool_call(self, context: Any) -> bool:
        """CrewAI ``before_tool_call`` hook.

        Returns ``False`` to block the tool call. A block receipt is emitted
        here; the corresponding :meth:`after_tool_call` will skip emission for
        the same context.
        """
        request = self._request_from_context(context)
        decision = self._evaluate_policy(request)

        state = {
            "request": request,
            "started_at": time.time(),
            "blocked": False,
        }

        if not decision.allowed:
            ended_at = time.time()
            record = self._emit(
                request=request,
                blocked=True,
                block_reason=decision.reason or "blocked_by_policy",
                started_at=state["started_at"],
                ended_at=ended_at,
            )
            state["blocked"] = True
            state["record"] = record
            self._hook_state[context] = state
            return False

        self._hook_state[context] = state
        return True

    def after_tool_call(self, context: Any) -> Any:
        """CrewAI ``after_tool_call`` hook.

        Emits the allow/error receipt for tool calls that were not blocked in
        :meth:`before_tool_call`. Returns the raw tool result unchanged.
        """
        state = self._hook_state.pop(context, None)

        # If we have no state the call was not seen by before_tool_call;
        # emit defensively.
        if state is None:
            return getattr(context, "raw_tool_result", None)

        # Blocked calls already got their receipt in before_tool_call.
        if state.get("blocked"):
            return getattr(context, "raw_tool_result", None)

        request: GuardrailRequest = state["request"]
        started_at: float = state["started_at"]
        ended_at = time.time()

        raw_result = getattr(context, "raw_tool_result", None)

        # CrewAI may store exceptions differently; check common attributes.
        error = getattr(context, "tool_error", None) or getattr(
            context, "error", None
        )

        if error is not None:
            self._emit(
                request=request,
                error=error,
                started_at=started_at,
                ended_at=ended_at,
            )
        else:
            self._emit(
                request=request,
                result=raw_result,
                started_at=started_at,
                ended_at=ended_at,
            )

        return raw_result

    # ------------------------------------------------------------------ #
    # CrewAI registration
    # ------------------------------------------------------------------ #
    def enable_guardrail(self) -> None:
        """Register this provider's hooks with CrewAI's global hook system."""
        try:
            from crewai import (  # type: ignore[import-not-found]
                register_after_tool_call_hook,
                register_before_tool_call_hook,
            )
        except ImportError as exc:
            raise ImportError(
                "crewai is required for enable_guardrail(). "
                "Install it with: pip install crewai"
            ) from exc

        register_before_tool_call_hook(self.before_tool_call)
        register_after_tool_call_hook(self.after_tool_call)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _request_from_context(context: Any) -> GuardrailRequest:
        """Extract a :class:`GuardrailRequest` from a CrewAI hook context."""
        tool_name = getattr(context, "tool_name", "unknown_tool") or "unknown_tool"
        tool_input = getattr(context, "tool_input", {}) or {}
        tool_call_id = (
            getattr(context, "tool_call_id", None)
            or getattr(context, "call_id", None)
            or f"ccs-{uuid.uuid4().hex}"
        )

        runtime: dict[str, Any] = {}
        for attr in ("agent", "task", "crew"):
            value = getattr(context, attr, None)
            if value is not None:
                name = getattr(value, "role", None) or getattr(
                    value, "name", None
                ) or type(value).__name__
                runtime[attr] = name

        return GuardrailRequest(
            tool_name=str(tool_name),
            tool_args=dict(tool_input) if isinstance(tool_input, dict) else {},
            tool_call_id=str(tool_call_id),
            runtime_context=runtime,
        )


# --------------------------------------------------------------------------- #
# Module-level convenience
# --------------------------------------------------------------------------- #
def enable_guardrail(config: CCSConfig) -> CCSGuardrailProvider:
    """Create a :class:`CCSGuardrailProvider` and register its CrewAI hooks.

    Returns the provider so callers can retain a reference and access emitted
    receipts or call :meth:`~CCSGuardrailProvider.intercept_tool_call` directly.
    """
    provider = CCSGuardrailProvider(config)
    provider.enable_guardrail()
    return provider
