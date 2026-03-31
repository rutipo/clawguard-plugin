"""Local risk detection engine — 6 MVP rules with session context."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from clawguard.shared.constants import AlertType, Severity
from clawguard.shared.schema import AlertData

PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "disregard system prompt",
    "reveal system prompt",
    "send data to",
    "exfiltrate",
    "override prior instructions",
    "ignore all prior",
    "forget your instructions",
    "you are now",
    "new instructions:",
]

SENSITIVE_PATH_PARTS = [
    ".env",
    "/secrets/",
    "/config/",
    "credentials",
    "private_key",
    "id_rsa",
    ".pem",
    "password",
    "/etc/shadow",
    "/etc/passwd",
    ".aws/",
    ".ssh/",
]

OUTBOUND_ACTION_TYPES = {
    "http_request", "email_send", "slack_send", "drive_write", "file_write",
    "db_write", "shell_exec",
}

SENSITIVE_TOOLS = {"shell", "database", "email", "slack"}

# Thresholds
EXFILTRATION_WINDOW_SECONDS = 60.0
COMM_SPIKE_WINDOW_SECONDS = 30.0
COMM_SPIKE_THRESHOLD = 5
CHAIN_ESCALATION_THRESHOLD = 3


@dataclass
class SessionRiskContext:
    """Tracks per-session state for stateful detection rules."""

    session_id: str = ""
    tools_seen: set[str] = field(default_factory=set)
    medium_risk_count: int = 0
    outbound_timestamps: list[float] = field(default_factory=list)
    had_sensitive_access: bool = False
    last_data_access_time: float = 0.0
    recent_outputs: list[tuple[str, str]] = field(default_factory=list)
    event_sequence: list[dict] = field(default_factory=list)


def inspect_event(
    event_type: str, event: dict, ctx: SessionRiskContext
) -> list[AlertData]:
    """Run all 6 detection rules against an event, return generated alerts."""
    alerts: list[AlertData] = []

    # Rule 1: Prompt injection
    if event_type == "prompt":
        alert = _check_prompt_injection(event, ctx)
        if alert:
            alerts.append(alert)

    # Rule 3: Sensitive source access
    if event_type in ("action", "data_access", "tool_call"):
        alert = _check_sensitive_access(event, ctx)
        if alert:
            alerts.append(alert)

    # Rule 4: Suspicious new tool use
    if event_type == "tool_call":
        alert = _check_new_tool(event, ctx)
        if alert:
            alerts.append(alert)

    # Rule 2: Exfiltration chain (sensitive access → outbound)
    if event_type == "action":
        alert = _check_exfiltration_chain(event, ctx)
        if alert:
            alerts.append(alert)

    # Rule 5: External communication spike
    if event_type == "action":
        alert = _check_comm_spike(event, ctx)
        if alert:
            alerts.append(alert)

    # Rule 6: Chain escalation (multiple medium risks → high)
    alert = _check_chain_escalation(alerts, ctx)
    if alert:
        alerts.append(alert)

    return alerts


def _check_prompt_injection(event: dict, ctx: SessionRiskContext) -> AlertData | None:
    text = (event.get("content") or event.get("content_preview") or "").lower()
    source_type = event.get("source_type", "external")

    if source_type in ("tool", "external") and any(p in text for p in PROMPT_INJECTION_PHRASES):
        return AlertData(
            session_id=ctx.session_id,
            severity=Severity.HIGH,
            alert_type=AlertType.PROMPT_INJECTION,
            title="Possible prompt injection detected",
            summary="External content contains instruction override language.",
            recommended_actions=[
                "Review the source content immediately",
                "Ask your agent to confirm the instruction",
                "Abort the active session if this was not intended",
            ],
        )
    return None


def _check_sensitive_access(event: dict, ctx: SessionRiskContext) -> AlertData | None:
    target = (
        event.get("target")
        or event.get("resource_path")
        or event.get("input_summary")
        or ""
    ).lower()

    if any(part in target for part in SENSITIVE_PATH_PARTS):
        ctx.had_sensitive_access = True
        ctx.last_data_access_time = time.time()
        return AlertData(
            session_id=ctx.session_id,
            severity=Severity.HIGH,
            alert_type=AlertType.SENSITIVE_ACCESS,
            title="Sensitive location accessed",
            summary=f"Agent accessed a sensitive resource: {target[:100]}",
            recommended_actions=[
                "Review this access immediately",
                "Ask your agent to explain why this resource was needed",
                "Abort the active session if this was not intended",
            ],
        )
    return None


def _check_new_tool(event: dict, ctx: SessionRiskContext) -> AlertData | None:
    tool_category = event.get("tool_category", "")
    tool_name = event.get("tool_name", "")

    is_sensitive_category = tool_category in SENSITIVE_TOOLS
    is_new = tool_name not in ctx.tools_seen

    ctx.tools_seen.add(tool_name)

    if is_sensitive_category and is_new:
        ctx.medium_risk_count += 1
        return AlertData(
            session_id=ctx.session_id,
            severity=Severity.MEDIUM,
            alert_type=AlertType.ANOMALY,
            title="Suspicious new tool use",
            summary=f"Sensitive tool '{tool_name}' ({tool_category}) used for the first time in this session.",
            recommended_actions=[
                "Verify the agent should be using this tool",
                "Check the tool call parameters",
                "Monitor subsequent actions",
            ],
        )
    return None


def _check_exfiltration_chain(event: dict, ctx: SessionRiskContext) -> AlertData | None:
    action_type = event.get("action_type", "")
    direction = event.get("direction", "")

    if direction == "outbound" or action_type in OUTBOUND_ACTION_TYPES:
        now = time.time()
        ctx.outbound_timestamps.append(now)

        if ctx.had_sensitive_access and (now - ctx.last_data_access_time) < EXFILTRATION_WINDOW_SECONDS:
            return AlertData(
                session_id=ctx.session_id,
                severity=Severity.HIGH,
                alert_type=AlertType.EXFILTRATION,
                title="Possible data exfiltration",
                summary=f"Outbound action ({action_type}) detected shortly after sensitive data access.",
                recommended_actions=[
                    "Review the outbound request target and payload",
                    "Confirm this action was intended",
                    "Abort the active session if this was not intended",
                    "Check the OpenClaw console for this session",
                ],
            )
    return None


def _check_comm_spike(event: dict, ctx: SessionRiskContext) -> AlertData | None:
    direction = event.get("direction", "")
    if direction != "outbound":
        return None

    now = time.time()
    # Prune old timestamps
    ctx.outbound_timestamps = [
        t for t in ctx.outbound_timestamps if now - t < COMM_SPIKE_WINDOW_SECONDS
    ]

    if len(ctx.outbound_timestamps) >= COMM_SPIKE_THRESHOLD:
        ctx.medium_risk_count += 1
        return AlertData(
            session_id=ctx.session_id,
            severity=Severity.MEDIUM,
            alert_type=AlertType.COMM_SPIKE,
            title="External communication spike",
            summary=f"{len(ctx.outbound_timestamps)} outbound requests in {COMM_SPIKE_WINDOW_SECONDS}s window.",
            recommended_actions=[
                "Check if the agent is making expected API calls",
                "Review the targets of outbound requests",
                "Consider rate-limiting the agent",
            ],
        )
    return None


def _check_chain_escalation(new_alerts: list[AlertData], ctx: SessionRiskContext) -> AlertData | None:
    # Count medium-severity alerts from this batch
    for alert in new_alerts:
        if alert.severity == Severity.MEDIUM:
            ctx.medium_risk_count += 1

    if ctx.medium_risk_count >= CHAIN_ESCALATION_THRESHOLD:
        # Reset to avoid re-triggering every event
        ctx.medium_risk_count = 0
        return AlertData(
            session_id=ctx.session_id,
            severity=Severity.HIGH,
            alert_type=AlertType.CHAIN_RISK,
            title="Risk chain escalation",
            summary="Multiple medium-risk events detected in session - escalating to high risk.",
            recommended_actions=[
                "Review the full session trace",
                "Consider aborting the session",
                "Check all recent tool calls and their outputs",
            ],
        )
    return None
