"""secure_run() — main public API for ClawGuard SDK."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog

from clawguard.sdk.config import ClawGuardConfig
from clawguard.sdk.logger import EventLogger
from clawguard.sdk.protocol import AgentProtocol
from clawguard.sdk.risk_engine import SessionRiskContext, inspect_event
from clawguard.sdk.wrappers import wrap_agent_tools

logger = structlog.get_logger()

# Thread-local storage for the current event logger
_thread_local = threading.local()


def get_current_logger() -> EventLogger | None:
    """Get the event logger for the current thread, if any."""
    return getattr(_thread_local, "current_logger", None)


def capture_decision(reasoning: str, metadata: dict | None = None) -> None:
    """Manually log a decision event from within agent code."""
    event_logger = get_current_logger()
    if event_logger is None:
        return
    data: dict[str, Any] = {"reasoning": reasoning[:2000]}
    if metadata:
        data["metadata"] = metadata
    event_logger.log_event("decision", data)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _create_session(
    config: ClawGuardConfig,
) -> tuple[str, SessionRiskContext, EventLogger]:
    """Create a new monitoring session and start the event logger."""
    session_id = str(uuid.uuid4())
    risk_ctx = SessionRiskContext(session_id=session_id)
    event_logger = EventLogger(session_id=session_id, config=config)
    event_logger.start()
    _thread_local.current_logger = event_logger
    return session_id, risk_ctx, event_logger


def _teardown_session(event_logger: EventLogger) -> None:
    """Clean up thread-local state and stop the event logger."""
    _thread_local.current_logger = None
    event_logger.stop()


def _log_prompt(
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
    task: str,
) -> None:
    """Log a prompt event and emit any resulting alerts."""
    prompt_data: dict[str, Any] = {
        "source_type": "user",
        "content": task,
        "content_preview": task[:200],
    }
    event_logger.log_event("prompt", prompt_data)
    alerts = inspect_event("prompt", prompt_data, risk_ctx)
    if alerts:
        event_logger.log_alerts(alerts)


def _resolve_agent_id(agent: AgentProtocol) -> str:
    """Derive a display-friendly agent id from the agent object."""
    return getattr(agent, "id", None) or getattr(agent, "name", "unknown")


def _wrap_and_prepare(
    agent: AgentProtocol,
    task: str,
    event_logger: EventLogger,
    risk_ctx: SessionRiskContext,
    config: ClawGuardConfig,
) -> None:
    """Log session start, prompt, and wrap the agent's tools."""
    agent_id = _resolve_agent_id(agent)
    event_logger.log_event("session_start", {"task": task, "agent_id": agent_id})
    _log_prompt(event_logger, risk_ctx, task)
    wrap_agent_tools(agent, event_logger=event_logger, risk_ctx=risk_ctx, config=config)


def _log_agent_reasoning(agent: AgentProtocol, event_logger: EventLogger) -> None:
    """Log the first available reasoning attribute from the agent."""
    for attr in ("last_reasoning", "thinking", "messages"):
        reasoning = getattr(agent, attr, None)
        if reasoning:
            event_logger.log_event("decision", {
                "source": attr,
                "reasoning": str(reasoning)[:2000],
            })
            break


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def secure_run(
    agent: AgentProtocol,
    task: str,
    config: ClawGuardConfig | None = None,
) -> Any:
    """Wrap and execute an OpenClaw agent with security monitoring.

    Args:
        agent: The OpenClaw agent instance (must have a .run() method).
        task: The task string to execute.
        config: Optional SDK configuration. Reads from env if not provided.

    Returns:
        The agent's execution result.
    """
    if config is None:
        config = ClawGuardConfig()

    if not config.enabled:
        return agent.run(task)

    _sid, risk_ctx, event_logger = _create_session(config)

    try:
        _wrap_and_prepare(agent, task, event_logger, risk_ctx, config)
        result = agent.run(task)
        _log_agent_reasoning(agent, event_logger)
        event_logger.log_event("session_end", {"status": "completed"})
        return result

    except Exception as exc:
        event_logger.log_event("session_end", {"status": "aborted", "error": str(exc)[:200]})
        raise

    finally:
        _teardown_session(event_logger)


@contextmanager
def clawguard_context(
    agent: AgentProtocol, config: ClawGuardConfig | None = None,
) -> Iterator[_GuardProxy]:
    """Context manager API for ClawGuard.

    Usage:
        with clawguard_context(agent) as guard:
            result = guard.run("task")
    """
    if config is None:
        config = ClawGuardConfig()

    _sid, risk_ctx, event_logger = _create_session(config)

    if config.enabled:
        agent_id = _resolve_agent_id(agent)
        event_logger.log_event("session_start", {"agent_id": agent_id})
        wrap_agent_tools(agent, event_logger=event_logger, risk_ctx=risk_ctx, config=config)

    try:
        yield _GuardProxy(agent, event_logger, risk_ctx)
    finally:
        if config.enabled:
            event_logger.log_event("session_end", {"status": "completed"})
        _teardown_session(event_logger)


class _GuardProxy:
    """Thin proxy returned by clawguard_context; logs prompts and delegates to the agent."""

    def __init__(
        self,
        agent: AgentProtocol,
        event_logger: EventLogger,
        risk_ctx: SessionRiskContext,
    ) -> None:
        self._agent = agent
        self._event_logger = event_logger
        self._risk_ctx = risk_ctx

    def run(self, task: str) -> Any:
        """Log the prompt and execute the agent."""
        _log_prompt(self._event_logger, self._risk_ctx, task)
        return self._agent.run(task)
