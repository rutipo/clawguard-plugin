"""EventLogger — thread-safe queue + background flush to backend."""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

import structlog

from clawguard.sdk.config import ClawGuardConfig
from clawguard.shared.schema import AlertData, EventPayload

logger = structlog.get_logger()


class EventLogger:
    """Collects events and alerts in thread-safe deques, flushes to backend in a background thread."""

    def __init__(self, session_id: str, config: ClawGuardConfig) -> None:
        self.session_id = session_id
        self.config = config
        self._event_queue: deque[EventPayload] = deque()
        self._alert_queue: deque[AlertData] = deque()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the background flush thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the flush thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        # Final flush
        self._flush_sync()

    def log_event(self, event_type: str, data: dict) -> str:
        """Queue an event for sending. Returns the event_id."""
        event_id = str(uuid.uuid4())
        payload = EventPayload(
            event_id=event_id,
            session_id=self.session_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            data=data,
        )
        with self._lock:
            self._event_queue.append(payload)

        if self.config.log_to_stderr:
            logger.info("event_queued", event_type=event_type, event_id=event_id)

        return event_id

    def log_alerts(self, alerts: list[AlertData]) -> None:
        """Queue alerts for sending."""
        with self._lock:
            self._alert_queue.extend(alerts)

        for alert in alerts:
            if self.config.log_to_stderr:
                logger.warning(
                    "alert_queued",
                    severity=alert.severity,
                    alert_type=alert.alert_type,
                    title=alert.title,
                )

    def _run_loop(self) -> None:
        """Background thread: periodically flush queues to backend."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=self.config.flush_interval_seconds)
                loop.run_until_complete(self._flush())
        finally:
            loop.run_until_complete(self._flush())
            loop.close()

    async def _flush(self) -> None:
        """Send queued events and alerts to the backend."""
        events: list[EventPayload] = []
        alerts: list[AlertData] = []

        with self._lock:
            while self._event_queue:
                events.append(self._event_queue.popleft())
            while self._alert_queue:
                alerts.append(self._alert_queue.popleft())

        if not events and not alerts:
            return

        if not self.config.api_key or not self.config.backend_url:
            if self.config.log_to_stderr:
                logger.warning("backend_not_configured", events=len(events), alerts=len(alerts))
            return

        import httpx

        headers = {"X-API-Key": self.config.api_key}
        base_url = self.config.backend_url.rstrip("/")

        async with httpx.AsyncClient(timeout=10) as client:
            await self._flush_events(client, events, base_url, headers)
            await self._flush_alerts(client, alerts, base_url, headers)

    async def _flush_events(
        self,
        client: Any,
        events: list[EventPayload],
        base_url: str,
        headers: dict[str, str],
    ) -> None:
        """Send queued events to the backend in a single batch."""
        if not events:
            return
        try:
            resp = await client.post(
                f"{base_url}/v1/events/batch",
                json={"events": [e.model_dump(mode="json") for e in events]},
                headers=headers,
            )
            resp.raise_for_status()
        except Exception as exc:
            if self.config.log_to_stderr:
                logger.error("flush_events_failed", error=str(exc), count=len(events))
            with self._lock:
                self._event_queue.extendleft(reversed(events))

    async def _flush_alerts(
        self,
        client: Any,
        alerts: list[AlertData],
        base_url: str,
        headers: dict[str, str],
    ) -> None:
        """Send queued alerts to the backend one at a time."""
        for alert in alerts:
            try:
                resp = await client.post(
                    f"{base_url}/v1/events",
                    json=EventPayload(
                        session_id=alert.session_id,
                        event_type="alert",
                        data=alert.model_dump(mode="json"),
                        risk_flags=[alert.alert_type],
                    ).model_dump(mode="json"),
                    headers=headers,
                )
                resp.raise_for_status()
            except Exception as exc:
                if self.config.log_to_stderr:
                    logger.error("flush_alert_failed", error=str(exc), alert_type=alert.alert_type)

    def _flush_sync(self) -> None:
        """Synchronous final flush."""
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(self._flush())
        finally:
            loop.close()
