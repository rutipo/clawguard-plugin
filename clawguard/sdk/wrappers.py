"""Tool wrapping for event capture in OpenClaw agents."""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable
from typing import Any

from clawguard.sdk.actions import classify_action, classify_source
from clawguard.sdk.config import ClawGuardConfig
from clawguard.sdk.logger import EventLogger
from clawguard.sdk.protocol import AgentProtocol
from clawguard.sdk.risk_engine import SessionRiskContext, inspect_event
from clawguard.sdk.sensitive import detect_sensitive_content
from clawguard.shared.utils import truncate


def _cap_text(text: str, max_bytes: int) -> str:
    """Cap text to max_bytes UTF-8 length."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace")


def _hash_content(text: str) -> str:
    """Short hash for data flow tracking."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _log_tool_call(
    tool_name: str,
    tool_category: str,
    input_str: str,
    correlation_id: str,
    kwargs: dict[str, Any],
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
    config: ClawGuardConfig,
) -> tuple[dict[str, Any], list[Any]]:
    """Build and log the tool_call event. Returns (call_data, alerts)."""
    call_data: dict[str, Any] = {
        "tool_name": tool_name,
        "tool_category": tool_category,
        "input_summary": truncate(input_str, 200),
        "input_sanitized": True,
        "correlation_id": correlation_id,
    }
    if config.capture_full_io:
        call_data["full_input"] = _cap_text(input_str, config.max_full_io_bytes)

    event_logger.log_event("tool_call", call_data)
    alerts = inspect_event("tool_call", call_data, risk_ctx)

    action = classify_action(tool_name, kwargs)
    if action:
        action["correlation_id"] = correlation_id
        event_logger.log_event("action", action)
        alerts.extend(inspect_event("action", action, risk_ctx))

    return call_data, alerts


def _log_tool_output(
    tool_name: str,
    result: Any,
    correlation_id: str,
    duration_ms: float | None,
    event_logger: EventLogger,
    config: ClawGuardConfig,
) -> tuple[str, list[str]]:
    """Log tool_output event. Returns (result_str, sensitive_patterns)."""
    result_str = str(result) if result else ""
    sensitive_patterns = detect_sensitive_content(result_str)

    output_data: dict[str, Any] = {
        "tool_name": tool_name,
        "output_summary": truncate(result_str, 300),
        "output_size_bytes": len(result_str.encode("utf-8", errors="replace")) if result else 0,
        "sensitive": bool(sensitive_patterns),
        "correlation_id": correlation_id,
    }
    if duration_ms is not None:
        output_data["duration_ms"] = round(duration_ms, 2)
    if sensitive_patterns:
        output_data["sensitive_patterns"] = sensitive_patterns
    if config.capture_full_io:
        output_data["full_output"] = _cap_text(result_str, config.max_full_io_bytes)

    event_logger.log_event("tool_output", output_data)
    return result_str, sensitive_patterns


def _check_exfiltration(
    action: dict[str, Any] | None,
    input_str: str,
    call_data: dict[str, Any],
    risk_ctx: SessionRiskContext,
) -> None:
    """Flag data-flow if an outbound action carries previously-seen sensitive data."""
    if not (action and action.get("direction") == "outbound" and risk_ctx.had_sensitive_access):
        return
    for _prev_corr_id, prev_output in risk_ctx.recent_outputs:
        if prev_output and len(prev_output) > 10 and prev_output[:50] in input_str:
            call_data["data_flow_detected"] = True
            break


def wrap_tool(
    tool_fn: Callable,
    tool_name: str,
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
    config: ClawGuardConfig | None = None,
) -> Callable:
    """Wrap a single tool function to capture events and run risk checks."""
    if config is None:
        config = ClawGuardConfig()

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        correlation_id = str(uuid.uuid4())
        tool_category = classify_source(tool_name)
        input_str = str(kwargs)

        call_data, alerts = _log_tool_call(
            tool_name, tool_category, input_str, correlation_id,
            kwargs, event_logger, risk_ctx, config,
        )

        action = classify_action(tool_name, kwargs)

        # Execute the actual tool with timing
        start_time = time.monotonic()
        result = tool_fn(*args, **kwargs)
        duration_ms = (time.monotonic() - start_time) * 1000 if config.capture_timing else None

        result_str, sensitive_patterns = _log_tool_output(
            tool_name, result, correlation_id, duration_ms,
            event_logger, config,
        )

        # Track data flow and event sequence
        if result_str:
            risk_ctx.recent_outputs.append((correlation_id, result_str[:200]))
            if len(risk_ctx.recent_outputs) > 20:
                risk_ctx.recent_outputs = risk_ctx.recent_outputs[-20:]

        risk_ctx.event_sequence.append({
            "tool_name": tool_name, "tool_category": tool_category,
            "correlation_id": correlation_id, "duration_ms": duration_ms,
            "sensitive": bool(sensitive_patterns), "action": action,
        })
        if len(risk_ctx.event_sequence) > 20:
            risk_ctx.event_sequence = risk_ctx.event_sequence[-20:]

        _check_exfiltration(action, input_str, call_data, risk_ctx)

        if alerts:
            event_logger.log_alerts(alerts)

        return result

    return wrapped


def wrap_agent_tools(
    agent: AgentProtocol,
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
    config: ClawGuardConfig | None = None,
) -> None:
    """Wrap all tools on an OpenClaw agent for event capture."""
    tools = getattr(agent, "tools", None)
    if not tools:
        return

    if isinstance(tools, dict):
        for name in list(tools.keys()):
            tools[name] = wrap_tool(tools[name], name, event_logger, risk_ctx, config)
    elif isinstance(tools, list):
        for i, tool in enumerate(tools):
            name = getattr(tool, "name", None) or getattr(tool, "__name__", f"tool_{i}")
            if callable(tool):
                tools[i] = wrap_tool(tool, name, event_logger, risk_ctx, config)
