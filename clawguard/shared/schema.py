"""Pydantic v2 schemas for ClawGuard API and SDK."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from clawguard.shared.constants import (
    AlertStatus,
    AlertType,
    EventType,
    SessionStatus,
    Severity,
)


class EventPayload(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    agent_id: str = "unknown"
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict = Field(default_factory=dict)
    risk_flags: list[str] = Field(default_factory=list)


class BatchEventRequest(BaseModel):
    events: list[EventPayload]


class RegisterRequest(BaseModel):
    email: str


class RegisterResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    api_key: str
    message: str = "Account created. Save your API key - it will not be shown again."


class SessionStartRequest(BaseModel):
    agent_id: str = "unknown"
    task: str = ""


class SessionStartResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str


class SessionEndRequest(BaseModel):
    session_id: str
    status: SessionStatus = SessionStatus.COMPLETED


class EventResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str = "ok"
    event_id: str | None = None
    alerts_generated: int = 0


class AlertData(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    severity: Severity
    alert_type: AlertType
    title: str
    summary: str
    recommended_actions: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ConnectTelegramRequest(BaseModel):
    code: str


class ConnectTelegramStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    connected: bool


class IncidentLabelRequest(BaseModel):
    label: Literal["true_positive", "false_positive", "needs_review"]
    notes: str = ""


class SessionMetricsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str
    event_count: int = 0
    tool_call_count: int = 0
    alert_count: int = 0
    high_alert_count: int = 0
    duration_seconds: float | None = None
    risk_score: int = 0
    task_category: str = "unknown"
    tools_used: list[str] = Field(default_factory=list)
    targets_accessed: list[str] = Field(default_factory=list)
    sensitive_accesses: int = 0
    outbound_actions: int = 0
    risk_breakdown: dict = Field(default_factory=dict)
    narrative_summary: str = ""


class AgentProfileResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_id: str
    session_count: int = 0
    normal_tools: list[str] = Field(default_factory=list)
    normal_targets: list[str] = Field(default_factory=list)
    normal_task_categories: list[str] = Field(default_factory=list)
    avg_tool_calls_per_session: float = 0.0
    avg_session_duration_seconds: float = 0.0
    avg_risk_score: float = 0.0
    sensitive_access_rate: float = 0.0
    alert_rate: float = 0.0


class ActivityLogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    session_id: str
    event_id: str | None = None
    message_type: str
    content: str
    severity: str | None = None
    sent_to_telegram: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ActivityLogResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    entries: list[ActivityLogEntry] = Field(default_factory=list)


class ThreadSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    thread_id: str
    sequence_number: int = 1
    status: str = "active"
    inferred_goal: str = "unknown"
    goal_confidence: float = 0.0
    event_count: int = 0
    risk_score: int = 0
    tools_used: list[str] = Field(default_factory=list)
    targets_accessed: list[str] = Field(default_factory=list)
    sensitive_accesses: int = 0
    outbound_actions: int = 0
    started_at: datetime | None = None
    ended_at: datetime | None = None


class SessionThreadsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str
    threads: list[ThreadSummary] = Field(default_factory=list)
