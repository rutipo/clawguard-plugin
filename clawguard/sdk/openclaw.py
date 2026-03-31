"""OpenClaw integration - monitors real OpenClaw agents via the openclaw-sdk.

Two integration modes:

1. secure_execute() - wraps agent.execute(), captures tool_calls from result
2. secure_stream() - wraps agent.execute_stream(), captures events in real-time

Also provides a CallbackHandler for automatic monitoring of all executions.

Usage:
    from openclaw_sdk import OpenClawClient
    from clawguard.sdk.openclaw import secure_execute, secure_stream

    async with OpenClawClient.connect() as client:
        agent = client.get_agent("research-bot")

        # Option A: wrap a single execution
        result = await secure_execute(agent, "Summarize competitor pricing")

        # Option B: stream with real-time monitoring
        async for event in secure_stream(agent, "Summarize competitor pricing"):
            print(event)
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import structlog

from clawguard.sdk.config import ClawGuardConfig
from clawguard.sdk.logger import EventLogger
from clawguard.sdk.protocol import AgentProtocol
from clawguard.sdk.risk_engine import SessionRiskContext, inspect_event
from clawguard.sdk.sensitive import detect_sensitive_content

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Shared session helpers
# ---------------------------------------------------------------------------

def _create_session(
    config: ClawGuardConfig,
) -> tuple[str, SessionRiskContext, EventLogger]:
    """Create a new session with its risk context and event logger."""
    session_id = str(uuid.uuid4())
    risk_ctx = SessionRiskContext(session_id=session_id)
    event_logger = EventLogger(session_id=session_id, config=config)
    event_logger.start()
    return session_id, risk_ctx, event_logger


def _log_session_start(
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
    query: str,
    agent_id: str,
) -> None:
    """Log session_start and prompt events, emitting any prompt alerts."""
    event_logger.log_event("session_start", {
        "task": query,
        "agent_id": agent_id,
    })
    prompt_data = {
        "source_type": "user",
        "content": query,
        "content_preview": query[:200],
    }
    event_logger.log_event("prompt", prompt_data)
    alerts = inspect_event("prompt", prompt_data, risk_ctx)
    if alerts:
        event_logger.log_alerts(alerts)


def _log_session_end_error(
    event_logger: EventLogger, exc: BaseException,
) -> None:
    """Log a session_end event for an aborted session."""
    event_logger.log_event("session_end", {
        "status": "aborted",
        "error": str(exc)[:200],
    })


def _resolve_agent_id(agent: Any, override: str | None) -> str:
    """Resolve the display agent-id from an agent object or an override."""
    return override or getattr(agent, "agent_id", None) or "unknown"


# ---------------------------------------------------------------------------
# secure_execute helpers
# ---------------------------------------------------------------------------

def _log_tool_event(
    tc: Any,
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
) -> None:
    """Log tool_call and tool_output events for a single tool-call record."""
    tool_name = getattr(tc, "tool", "unknown")
    tool_input = getattr(tc, "input", "")
    tool_output = getattr(tc, "output", "") or ""
    duration_ms = getattr(tc, "duration_ms", None)

    call_data: dict[str, Any] = {
        "tool_name": tool_name,
        "input_summary": str(tool_input)[:200],
    }
    event_logger.log_event("tool_call", call_data)
    call_alerts = inspect_event("tool_call", call_data, risk_ctx)

    output_data: dict[str, Any] = {
        "tool_name": tool_name,
        "output_summary": str(tool_output)[:300],
        "output_size_bytes": len(str(tool_output)),
    }
    if duration_ms is not None:
        output_data["duration_ms"] = duration_ms

    sensitive = detect_sensitive_content(str(tool_output))
    if sensitive:
        output_data["sensitive"] = True
        output_data["sensitive_patterns"] = sensitive

    event_logger.log_event("tool_output", output_data)

    if call_alerts:
        event_logger.log_alerts(call_alerts)


def _process_execution_result(
    result: Any, event_logger: EventLogger,
) -> None:
    """Log thinking/reasoning and session_end from an execution result."""
    thinking = getattr(result, "thinking", None)
    if thinking:
        event_logger.log_event("decision", {
            "source": "thinking",
            "reasoning": str(thinking)[:2000],
        })

    success = getattr(result, "success", True)
    token_usage = getattr(result, "token_usage", None)

    end_data: dict[str, Any] = {
        "status": "completed" if success else "failed",
    }
    if token_usage:
        end_data["token_usage"] = {
            "input": getattr(token_usage, "input", 0),
            "output": getattr(token_usage, "output", 0),
            "total": getattr(token_usage, "total", 0),
        }
    event_logger.log_event("session_end", end_data)


# ---------------------------------------------------------------------------
# secure_stream helpers
# ---------------------------------------------------------------------------

def _get_payload_field(data: Any, field: str, default: str = "") -> str:
    """Safely extract a field from an event's data.payload dict."""
    if not isinstance(data, dict):
        return default
    return data.get("payload", {}).get(field, default)


def _process_stream_event(
    event_type: str | None,
    data: Any,
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
) -> None:
    """Dispatch a single stream event to the appropriate logging handler."""
    if event_type == "tool_call":
        _handle_stream_tool_call(data, event_logger, risk_ctx)
    elif event_type == "tool_result":
        _handle_stream_tool_result(data, event_logger)
    elif event_type == "thinking":
        _handle_stream_thinking(data, event_logger)
    elif event_type == "error":
        _handle_stream_error(data, event_logger)
    # "done" is intentionally ignored — handled by session_end after loop


def _handle_stream_tool_call(
    data: Any, event_logger: EventLogger, risk_ctx: SessionRiskContext,
) -> None:
    tool_name = _get_payload_field(data, "tool")
    tool_input = _get_payload_field(data, "input")
    call_data: dict[str, Any] = {
        "tool_name": tool_name,
        "input_summary": str(tool_input)[:200],
    }
    event_logger.log_event("tool_call", call_data)
    call_alerts = inspect_event("tool_call", call_data, risk_ctx)
    if call_alerts:
        event_logger.log_alerts(call_alerts)


def _handle_stream_tool_result(
    data: Any, event_logger: EventLogger,
) -> None:
    tool_name = _get_payload_field(data, "tool")
    tool_output = _get_payload_field(data, "output")
    output_data: dict[str, Any] = {
        "tool_name": tool_name,
        "output_summary": str(tool_output)[:300],
        "output_size_bytes": len(str(tool_output)),
    }
    sensitive = detect_sensitive_content(str(tool_output))
    if sensitive:
        output_data["sensitive"] = True
        output_data["sensitive_patterns"] = sensitive
    event_logger.log_event("tool_output", output_data)


def _handle_stream_thinking(
    data: Any, event_logger: EventLogger,
) -> None:
    thinking_text = _get_payload_field(data, "thinking")
    if thinking_text:
        event_logger.log_event("decision", {
            "source": "thinking",
            "reasoning": str(thinking_text)[:2000],
        })


def _handle_stream_error(
    data: Any, event_logger: EventLogger,
) -> None:
    error_msg = _get_payload_field(data, "message") or str(data)
    event_logger.log_event("session_end", {
        "status": "failed",
        "error": str(error_msg)[:200],
    })


# ---------------------------------------------------------------------------
# create_callback_handler helpers
# ---------------------------------------------------------------------------

def _process_callback_tool_calls(
    result: Any,
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext | None,
) -> None:
    """Log tool calls captured in a callback execution result."""
    tool_calls = getattr(result, "tool_calls", []) or []
    for tc in tool_calls:
        call_data: dict[str, Any] = {
            "tool_name": getattr(tc, "tool", "unknown"),
            "input_summary": str(getattr(tc, "input", ""))[:200],
        }
        event_logger.log_event("tool_call", call_data)
        if risk_ctx:
            call_alerts = inspect_event("tool_call", call_data, risk_ctx)
            if call_alerts:
                event_logger.log_alerts(call_alerts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def secure_execute(
    agent: AgentProtocol,
    query: str,
    config: ClawGuardConfig | None = None,
    agent_id: str | None = None,
) -> Any:
    """Execute an OpenClaw agent with ClawGuard monitoring.

    Wraps agent.execute() - captures the result including tool_calls,
    token usage, and files. Sends all events to the ClawGuard backend.

    Args:
        agent: An openclaw_sdk Agent instance (has .execute() method).
        query: The query/task to execute.
        config: Optional ClawGuard config. Reads from env if not provided.
        agent_id: Override agent identifier for display.

    Returns:
        The original ExecutionResult from OpenClaw.
    """
    if config is None:
        config = ClawGuardConfig()

    if not config.enabled:
        return await agent.execute(query)

    _sid, risk_ctx, event_logger = _create_session(config)
    resolved_agent_id = _resolve_agent_id(agent, agent_id)

    try:
        _log_session_start(event_logger, risk_ctx, query, resolved_agent_id)

        result = await agent.execute(query)

        for tc in getattr(result, "tool_calls", []) or []:
            _log_tool_event(tc, event_logger, risk_ctx)

        _process_execution_result(result, event_logger)
        return result

    except Exception as exc:
        _log_session_end_error(event_logger, exc)
        raise

    finally:
        event_logger.stop()


async def secure_stream(
    agent: AgentProtocol,
    query: str,
    config: ClawGuardConfig | None = None,
    agent_id: str | None = None,
) -> AsyncIterator[Any]:
    """Stream an OpenClaw agent execution with real-time ClawGuard monitoring.

    Wraps agent.execute_stream() - captures each event as it arrives and
    forwards it to the ClawGuard backend immediately. This is the preferred
    mode for long-running sessions.

    Args:
        agent: An openclaw_sdk Agent instance.
        query: The query/task to execute.
        config: Optional ClawGuard config.
        agent_id: Override agent identifier.

    Yields:
        Each StreamEvent from OpenClaw, unmodified.
    """
    if config is None:
        config = ClawGuardConfig()

    if not config.enabled:
        stream = await agent.execute_stream(query)
        async for event in stream:
            yield event
        return

    _sid, risk_ctx, event_logger = _create_session(config)
    resolved_agent_id = _resolve_agent_id(agent, agent_id)

    try:
        _log_session_start(event_logger, risk_ctx, query, resolved_agent_id)

        stream = await agent.execute_stream(query)
        async for event in stream:
            _process_stream_event(
                getattr(event, "event_type", None),
                getattr(event, "data", {}),
                event_logger,
                risk_ctx,
            )
            yield event

        event_logger.log_event("session_end", {"status": "completed"})

    except Exception as exc:
        _log_session_end_error(event_logger, exc)
        raise

    finally:
        event_logger.stop()


def create_callback_handler(
    config: ClawGuardConfig | None = None,
) -> Any:
    """Create an OpenClaw CallbackHandler that auto-monitors all executions.

    Usage:
        from openclaw_sdk import OpenClawClient
        from clawguard.sdk.openclaw import create_callback_handler

        handler = create_callback_handler()
        async with OpenClawClient.connect(callbacks=[handler]) as client:
            # All agent.execute() calls are automatically monitored
            result = await client.get_agent("bot").execute("hello")

    This is the simplest integration - just pass the handler at connect time.
    """
    if config is None:
        config = ClawGuardConfig()

    try:
        from openclaw_sdk.callbacks.handler import CallbackHandler
    except ImportError:
        raise ImportError(
            "openclaw-sdk is required for callback integration. "
            "Install it with: pip install openclaw-sdk"
        )

    class ClawGuardCallback(CallbackHandler):
        """Monitors all OpenClaw executions via the callback interface."""

        def __init__(self) -> None:
            self._loggers: dict[str, EventLogger] = {}
            self._risk_ctxs: dict[str, SessionRiskContext] = {}

        async def on_execution_start(self, agent_id: str, query: str) -> None:
            _sid, risk_ctx, event_logger = _create_session(config)
            key = f"{agent_id}:{hash(query)}"
            self._loggers[key] = event_logger
            self._risk_ctxs[key] = risk_ctx
            _log_session_start(event_logger, risk_ctx, query, agent_id)

        async def on_execution_end(self, agent_id: str, result: Any) -> None:
            matched_key = _find_callback_key(self._loggers, agent_id)
            if matched_key is None:
                return

            event_logger = self._loggers.pop(matched_key)
            risk_ctx = self._risk_ctxs.pop(matched_key, None)

            _process_callback_tool_calls(result, event_logger, risk_ctx)

            success = getattr(result, "success", True)
            event_logger.log_event("session_end", {
                "status": "completed" if success else "failed",
            })
            event_logger.stop()

    return ClawGuardCallback()


def _find_callback_key(
    loggers: dict[str, EventLogger], agent_id: str,
) -> str | None:
    """Find the first logger key matching the given agent_id prefix."""
    for key in list(loggers.keys()):
        if key.startswith(f"{agent_id}:"):
            return key
    return None
