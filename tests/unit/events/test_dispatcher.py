"""Unit tests for the Asynchronous Event Dispatcher."""

import asyncio
import time
import pytest

from app.events.dispatcher import EventDispatcher, EventQueueFullError
from app.events.subscribers.behavioral import BehavioralSubscriber
from app.events.subscribers.repository import RepositorySubscriber
from app.events.types import DropPolicy, EventTopic
from app.schemas.events import EventType, NetworkConnectionEvent, ProcessStartEvent
from backend.security.behavior import BehaviorEngine
from database.repositories.event_repository import EventRepository


def test_dispatcher_lifecycle_and_simple_publish():
    async def _test():
        dispatcher = EventDispatcher(max_capacity=100)
        received = []

        async def handler(event):
            received.append(event)

        dispatcher.subscribe(handler, EventTopic.PROCESS_START)
        await dispatcher.start()

        evt = ProcessStartEvent(process_id=1000, process_name="svchost.exe")
        dispatcher.publish_nowait(evt)

        await dispatcher.drain()
        await dispatcher.stop()

        assert len(received) == 1
        assert received[0].process_name == "svchost.exe"
        assert dispatcher.metrics.delivered_count == 1

    asyncio.run(_test())


def test_topic_filtering_and_wildcard_dispatch():
    async def _test():
        dispatcher = EventDispatcher()
        proc_events = []
        net_events = []
        all_events = []

        dispatcher.subscribe(lambda e: proc_events.append(e), EventType.PROCESS_START)
        dispatcher.subscribe(lambda e: net_events.append(e), EventType.NETWORK_CONNECTION)
        dispatcher.subscribe(lambda e: all_events.append(e), EventTopic.ALL)

        await dispatcher.start()

        proc_evt = ProcessStartEvent(process_id=101, process_name="powershell.exe")
        net_evt = NetworkConnectionEvent(
            protocol="TCP",
            local_address="127.0.0.1",
            local_port=5000,
            remote_address="8.8.8.8",
            remote_port=443,
            connection_state="ESTABLISHED",
            process_name="powershell.exe",
        )

        dispatcher.publish_nowait(proc_evt)
        dispatcher.publish_nowait(net_evt)

        await dispatcher.drain()
        await dispatcher.stop()

        assert len(proc_events) == 1
        assert len(net_events) == 1
        assert len(all_events) == 2

    asyncio.run(_test())


def test_error_isolation_between_subscribers():
    async def _test():
        dispatcher = EventDispatcher()
        received_healthy = []

        async def faulty_handler(event):
            raise RuntimeError("Database connection lost!")

        async def healthy_handler(event):
            received_healthy.append(event)

        dispatcher.subscribe(faulty_handler, EventTopic.ALL)
        dispatcher.subscribe(healthy_handler, EventTopic.ALL)

        await dispatcher.start()
        dispatcher.publish_nowait({"test": "data"}, topic=EventTopic.SECURITY_FINDING)

        await dispatcher.drain()
        await dispatcher.stop()

        assert len(received_healthy) == 1
        assert dispatcher.metrics.error_count == 1
        assert "faulty_handler" in dispatcher.metrics.errors_by_subscriber

    asyncio.run(_test())


def test_bounded_queue_drop_oldest_policy():
    async def _test():
        dispatcher = EventDispatcher(max_capacity=5, drop_policy=DropPolicy.DROP_OLDEST)
        received = []

        async def slow_handler(event):
            received.append(event)

        dispatcher.subscribe(slow_handler, EventTopic.ALL)

        for i in range(10):
            dispatcher.publish_nowait({"index": i}, topic=EventTopic.SYSTEM_METRIC)

        assert dispatcher.metrics.dropped_count == 5
        assert dispatcher.metrics.queue_depth == 5

        await dispatcher.start()
        await dispatcher.drain()
        await dispatcher.stop()

        assert len(received) == 5
        assert [r["index"] for r in received] == [5, 6, 7, 8, 9]

    asyncio.run(_test())


def test_bounded_queue_reject_policy():
    async def _test():
        dispatcher = EventDispatcher(max_capacity=3, drop_policy=DropPolicy.REJECT)

        for i in range(3):
            dispatcher.publish_nowait(i, topic=EventTopic.ALL)

        with pytest.raises(EventQueueFullError):
            dispatcher.publish_nowait(4, topic=EventTopic.ALL)

    asyncio.run(_test())


def test_ingestion_latency_sub_millisecond():
    async def _test():
        dispatcher = EventDispatcher(max_capacity=10000)
        event = ProcessStartEvent(process_id=2024, process_name="latency_test.exe")

        start_time = time.perf_counter()
        for _ in range(1000):
            dispatcher.publish_nowait(event)
        elapsed = time.perf_counter() - start_time

        avg_latency_ms = (elapsed / 1000.0) * 1000.0
        assert avg_latency_ms < 0.1, f"Average publish latency too high: {avg_latency_ms:.4f} ms"

    asyncio.run(_test())


def test_repository_and_behavioral_subscribers():
    async def _test():
        repo = EventRepository()
        engine = BehaviorEngine()
        repo_sub = RepositorySubscriber(repo)
        behav_sub = BehavioralSubscriber(engine)

        dispatcher = EventDispatcher()
        dispatcher.subscribe(repo_sub, EventTopic.ALL)
        dispatcher.subscribe(behav_sub, EventType.NETWORK_CONNECTION)

        await dispatcher.start()

        net_evt = NetworkConnectionEvent(
            protocol="TCP",
            local_address="192.168.1.100",
            local_port=54321,
            remote_address="93.184.216.34",
            remote_port=80,
            connection_state="ESTABLISHED",
            process_id=456,
            process_name="curl.exe",
        )
        dispatcher.publish_nowait(net_evt)

        await dispatcher.drain()
        await dispatcher.stop()

        # 1. Verify repository sink received the event
        events = repo.get_events()
        assert len(events) == 1
        assert events[0].process_name == "curl.exe"

        # 2. Verify behavioral engine processed the connection
        summary = engine.baseline_engine.get_summary()
        assert isinstance(summary, dict)
        assert dispatcher.metrics.delivered_count >= 2

    asyncio.run(_test())
