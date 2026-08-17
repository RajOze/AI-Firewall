"""Decoupled Asynchronous Event Dispatcher with backpressure guards and isolated fan-out."""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any, Sequence

from app.events.types import (
    AsyncEventHandler,
    DispatcherMetrics,
    DropPolicy,
    EventTopic,
    SubscriberProtocol,
    SubscriberTarget,
)
from app.schemas.events import EventType

logger = logging.getLogger(__name__)


class EventQueueFullError(Exception):
    """Raised when publishing to a full queue under DropPolicy.REJECT."""
    pass


class EventDispatcher:
    """High-throughput asynchronous event dispatcher with backpressure management.

    Attributes:
        max_capacity: Bounded capacity for the internal asyncio.Queue.
        drop_policy: Action to take on queue saturation (DROP_OLDEST, DROP_NEWEST, REJECT).
    """

    def __init__(
        self,
        max_capacity: int = 5000,
        drop_policy: DropPolicy = DropPolicy.DROP_OLDEST,
    ) -> None:
        self._max_capacity = max_capacity
        self._drop_policy = drop_policy
        self._queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=max_capacity)
        self._subscribers: dict[str, list[SubscriberTarget]] = {}
        self._worker_task: asyncio.Task[None] | None = None
        self._is_running = False
        self._metrics = DispatcherMetrics(max_capacity=max_capacity)

    @property
    def is_running(self) -> bool:
        """Return True if the dispatcher worker loop is active."""
        return self._is_running

    @property
    def metrics(self) -> DispatcherMetrics:
        """Return real-time dispatcher telemetry metrics."""
        self._metrics.queue_depth = self._queue.qsize()
        total_unique = set()
        for subs in self._subscribers.values():
            total_unique.update(subs)
        self._metrics.active_subscribers = len(total_unique)
        return self._metrics

    def subscribe(
        self,
        target: SubscriberTarget,
        topics: Sequence[str | EventTopic | EventType] | str | EventTopic | EventType | None = None,
    ) -> None:
        """Subscribe a callable or SubscriberProtocol instance to event topics."""
        if topics is None:
            topic_keys = [EventTopic.ALL.value]
        elif isinstance(topics, (str, EventTopic, EventType)):
            topic_keys = [self._resolve_topic_name(topics)]
        else:
            topic_keys = [self._resolve_topic_name(t) for t in topics]

        for topic in topic_keys:
            if topic not in self._subscribers:
                self._subscribers[topic] = []
            if target not in self._subscribers[topic]:
                self._subscribers[topic].append(target)
                logger.debug("Subscribed %s to topic '%s'", self._get_target_name(target), topic)

    def unsubscribe(
        self,
        target: SubscriberTarget,
        topics: Sequence[str | EventTopic | EventType] | str | EventTopic | EventType | None = None,
    ) -> None:
        """Unsubscribe a target from specific topics or all topics."""
        if topics is None:
            topic_keys = list(self._subscribers.keys())
        elif isinstance(topics, (str, EventTopic, EventType)):
            topic_keys = [self._resolve_topic_name(topics)]
        else:
            topic_keys = [self._resolve_topic_name(t) for t in topics]

        for topic in topic_keys:
            if topic in self._subscribers and target in self._subscribers[topic]:
                self._subscribers[topic].remove(target)
                logger.debug("Unsubscribed %s from topic '%s'", self._get_target_name(target), topic)

    def publish_nowait(
        self,
        event: Any,
        topic: str | EventTopic | EventType | None = None,
    ) -> bool:
        """Publish an event non-blockingly (< 1 ms latency).

        Applies configured DropPolicy if the bounded queue is saturated.
        """
        resolved_topic = self._resolve_event_topic(event, topic)
        item = (resolved_topic, event)

        if self._queue.full():
            if self._drop_policy == DropPolicy.DROP_OLDEST:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                    self._metrics.dropped_count += 1
                except (asyncio.QueueEmpty, ValueError):
                    pass
            elif self._drop_policy == DropPolicy.DROP_NEWEST:
                self._metrics.dropped_count += 1
                return False
            elif self._drop_policy == DropPolicy.REJECT:
                self._metrics.dropped_count += 1
                raise EventQueueFullError(
                    f"Dispatcher queue capacity reached ({self._max_capacity}). Event rejected."
                )

        try:
            self._queue.put_nowait(item)
            self._metrics.published_count += 1
            return True
        except asyncio.QueueFull:
            self._metrics.dropped_count += 1
            return False

    async def publish(
        self,
        event: Any,
        topic: str | EventTopic | EventType | None = None,
    ) -> None:
        """Publish an event, awaiting queue capacity if saturated under DropPolicy.REJECT."""
        if self._drop_policy == DropPolicy.REJECT and self._queue.full():
            resolved_topic = self._resolve_event_topic(event, topic)
            await self._queue.put((resolved_topic, event))
            self._metrics.published_count += 1
            return

        self.publish_nowait(event, topic)

    async def start(self) -> None:
        """Start the background consumer dispatch loop."""
        if self._is_running:
            return
        self._is_running = True
        self._worker_task = asyncio.create_task(self._worker_loop(), name="SentinelEventDispatcher")
        logger.info("EventDispatcher background worker started.")

    async def stop(self) -> None:
        """Gracefully stop dispatcher worker task."""
        if not self._is_running:
            return
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        logger.info("EventDispatcher worker stopped.")

    async def drain(self, timeout: float = 5.0) -> None:
        """Block until all queued events are dispatched or timeout occurs."""
        try:
            await asyncio.wait_for(self._queue.join(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("Dispatcher drain timed out after %.2f seconds (remaining: %d).", timeout, self._queue.qsize())

    async def _worker_loop(self) -> None:
        """Continuous consumer loop dispatching events to matching subscribers."""
        while self._is_running:
            try:
                topic, event = await self._queue.get()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Unexpected error in dispatcher queue get: %s", exc)
                continue

            try:
                await self._dispatch_to_subscribers(topic, event)
            finally:
                self._queue.task_done()

    async def _dispatch_to_subscribers(self, topic: str, event: Any) -> None:
        """Fan-out event to matching topic subscribers with complete error isolation."""
        targets: set[SubscriberTarget] = set()

        if topic in self._subscribers:
            targets.update(self._subscribers[topic])
        if EventTopic.ALL.value in self._subscribers:
            targets.update(self._subscribers[EventTopic.ALL.value])

        if not targets:
            return

        dispatch_coros = [self._safe_invoke(target, event) for target in targets]
        await asyncio.gather(*dispatch_coros, return_exceptions=True)

    async def _safe_invoke(self, target: SubscriberTarget, event: Any) -> None:
        """Invoke a subscriber safely, recording individual subscriber errors."""
        target_name = self._get_target_name(target)
        try:
            if isinstance(target, SubscriberProtocol) or hasattr(target, "handle_event"):
                await target.handle_event(event)
            elif inspect.iscoroutinefunction(target):
                await target(event)
            elif callable(target):
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, target, event)
            self._metrics.delivered_count += 1
        except Exception as exc:
            self._metrics.error_count += 1
            self._metrics.errors_by_subscriber[target_name] = (
                self._metrics.errors_by_subscriber.get(target_name, 0) + 1
            )
            logger.exception(
                "Subscriber '%s' raised an unhandled exception handling topic event: %s",
                target_name,
                exc,
            )

    def _resolve_topic_name(self, topic: str | EventTopic | EventType) -> str:
        if isinstance(topic, (EventTopic, EventType)):
            return topic.value
        return str(topic)

    def _resolve_event_topic(self, event: Any, explicit_topic: str | EventTopic | EventType | None) -> str:
        if explicit_topic is not None:
            return self._resolve_topic_name(explicit_topic)
        if hasattr(event, "event_type"):
            evt_type = getattr(event, "event_type")
            return self._resolve_topic_name(evt_type)
        if isinstance(event, dict) and "event_type" in event:
            return str(event["event_type"])
        return EventTopic.ALL.value

    @staticmethod
    def _get_target_name(target: Any) -> str:
        if hasattr(target, "__name__"):
            return target.__name__
        if hasattr(target, "__class__"):
            return target.__class__.__name__
        return str(target)
