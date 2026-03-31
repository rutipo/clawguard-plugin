"""Shared enumerations for ClawGuard."""

from enum import StrEnum


class EventType(StrEnum):
    PROMPT = "prompt"
    DECISION = "decision"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"
    DATA_ACCESS = "data_access"
    ACTION = "action"
    ALERT = "alert"
    SESSION_START = "session_start"
    SESSION_END = "session_end"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AlertType(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    EXFILTRATION = "exfiltration"
    SENSITIVE_ACCESS = "sensitive_access"
    ANOMALY = "anomaly"
    CHAIN_RISK = "chain_risk"
    COMM_SPIKE = "comm_spike"
    GOAL_DEVIATION = "goal_deviation"
    SOURCE_INFLUENCE_SHIFT = "source_influence_shift"
    CROSS_THREAD_ESCALATION = "cross_thread_escalation"


class SessionStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABORTED = "aborted"


class AlertStatus(StrEnum):
    NEW = "new"
    SENT = "sent"
    FAILED = "failed"


class SourceType(StrEnum):
    USER = "user"
    TOOL = "tool"
    SYSTEM = "system"
    EXTERNAL = "external"


class ActionDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class TaskCategory(StrEnum):
    DEPLOYMENT = "deployment"
    RESEARCH = "research"
    DATA_ANALYSIS = "data_analysis"
    COMMUNICATION = "communication"
    FILE_MANAGEMENT = "file_management"
    CODING = "coding"
    SYSTEM_ADMIN = "system_admin"
    UNKNOWN = "unknown"


class IncidentLabel(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class FlowType(StrEnum):
    TOOL_CHAIN = "tool_chain"
    OUTPUT_TO_INPUT = "output_to_input"
    SENSITIVE_PROPAGATION = "sensitive_propagation"


class ThreadStatus(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"


class ThreadGoalType(StrEnum):
    RESEARCH = "research"
    DATA_GATHERING = "data_gathering"
    DELIVERY = "delivery"
    FILE_ACCESS = "file_access"
    CONFIGURATION = "configuration"
    CREDENTIAL_ACCESS = "credential_access"
    PIPELINE = "pipeline"
    SYSTEM_OPERATION = "system_operation"
    UNKNOWN = "unknown"


class MessageType(StrEnum):
    ACTIVITY = "activity"
    INSIGHT = "insight"
    ALERT = "alert"
    MILESTONE = "milestone"
