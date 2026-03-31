"""Protocol definition for agents compatible with ClawGuard."""
from __future__ import annotations
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AgentProtocol(Protocol):
    """Minimal interface an agent must satisfy for ClawGuard wrapping."""
    def run(self, task: str) -> Any: ...
