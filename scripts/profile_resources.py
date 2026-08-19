#!/usr/bin/env python3
"""
Resource profiling suite for Sentinel backend.
Simulates a sustained telemetry burst and measures resource usage.
"""

import asyncio
import gc
import sys
import time
import tracemalloc
from typing import List
import psutil
from datetime import datetime, timezone

# Add the backend directory to the Python path
sys.path.insert(0, 'backend')
# Also add current directory for relative imports
sys.path.insert(0, '.')

# Import Sentinel components
from app.events.dispatcher import EventDispatcher
from app.events.subscribers.repository import RepositorySubscriber
from database.repositories.event_repository import EventRepository
from app.schemas.events import (
    NetworkConnectionEvent,
    ConnectionDirection,
    EventType,
)


def get_system_process() -> psutil.Process:
    """Get the current system process for monitoring."""
    return psutil.Process()


def format_bytes(bytes_value: float) -> str:
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"


async def main():
    """
    Main profiling function.
    Simulates 5,000 network socket events over 10 seconds and measures resource usage.
    """
    print("=" * 60)
    print("Sentinel Backend Resource Profiling Suite")
    print("=" * 60)

    # Start tracking memory allocations
    tracemalloc.start()

    # Get the current process for monitoring
    process = get_system_process()

    # Force garbage collection to get a clean baseline
    gc.collect()
    # Take initial memory snapshot
    snapshot1 = tracemalloc.take_snapshot()

    # Initial resource measurements
    initial_rss = process.memory_info().rss
    initial_cpu_percent = process.cpu_percent(interval=0.1)

    print(f"Initial RSS: {format_bytes(initial_rss)}")
    print(f"Initial CPU %: {initial_cpu_percent:.2f}%")
    print()

    # Create components
    repository = EventRepository()
    dispatcher = EventDispatcher()

    # Add repository subscriber to dispatcher
    repo_subscriber = RepositorySubscriber(repository)
    dispatcher.subscribe(repo_subscriber, EventType.NETWORK_CONNECTION)

    # Start the dispatcher
    await dispatcher.start()

    # Generate 5,000 synthetic network events
    print("Generating 5,000 synthetic network events...")
    events: List[NetworkConnectionEvent] = []
    base_time = time.time()

    for i in range(5000):
        # Create varied events to simulate real traffic
        event_time = datetime.fromtimestamp(base_time + (i * 0.002), tz=timezone.utc).isoformat()
        event = NetworkConnectionEvent(
            protocol="TCP" if i % 2 == 0 else "UDP",
            local_address="127.0.0.1",
            local_port=8000 + (i % 1000),
            remote_address=f"10.0.{(i // 256) % 4}.{(i % 255) + 1}",
            remote_port=443 if i % 3 == 0 else 80,
            direction=ConnectionDirection.OUTBOUND if i % 2 == 0 else ConnectionDirection.INBOUND,
            connection_state="ESTABLISHED" if i % 5 != 0 else "TIME_WAIT",
            process_id=1000 + (i % 500),
            process_name=f"process_{(i % 20):02d}.exe",
            timestamp=event_time,  # ISO format string
        )
        events.append(event)

    print(f"Generated {len(events)} events")
    print("Starting telemetry burst simulation...")
    print("-" * 40)

    # Start timing for the burst
    burst_start_time = time.time()

    # Publish all events (this will go through the dispatcher to the repository subscriber)
    publish_tasks = []
    for event in events:
        # Use publish_nowait for non-blocking publishing
        dispatcher.publish_nowait(event)

    # Give time for events to be processed
    # We'll wait for the burst duration plus some processing time
    burst_duration = 10.0  # seconds
    await asyncio.sleep(burst_duration)

    burst_end_time = time.time()
    actual_burst_time = burst_end_time - burst_start_time

    print(f"Burst completed in {actual_burst_time:.2f} seconds")
    print(f"Effective rate: {len(events) / actual_burst_time:.1f} events/second")
    print()

    # Allow time for queue draining and final processing
    print("Draining queues and waiting for final processing...")
    await dispatcher.drain(timeout=5.0)

    # Small additional pause to let everything settle
    await asyncio.sleep(2.0)

    # Stop the dispatcher
    await dispatcher.stop()

    # Force garbage collection and take final memory snapshot
    gc.collect()
    snapshot2 = tracemalloc.take_snapshot()

    # Final resource measurements
    final_rss = process.memory_info().rss
    # Get CPU usage over a short interval
    final_cpu_percent = process.cpu_percent(interval=0.5)

    print(f"Final RSS: {format_bytes(final_rss)}")
    print(f"Final CPU %: {final_cpu_percent:.2f}%")
    print()

    # Calculate memory allocation differences
    top_stats = snapshot2.compare_to(snapshot1, 'lineno')
    print("Top 10 memory allocations:")
    print("-" * 40)
    for stat in top_stats[:10]:
        print(f"{stat.count:5d} blocks {format_bytes(stat.size_diff):>8} {stat.traceback}")

    # Calculate total memory growth
    total_increase = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
    total_decrease = sum(abs(stat.size_diff) for stat in top_stats if stat.size_diff < 0)
    net_change = total_increase - total_decrease

    print()
    print(f"Memory allocation increase: {format_bytes(total_increase)}")
    print(f"Memory allocation decrease: {format_bytes(total_decrease)}")
    print(f"Net memory change: {format_bytes(net_change)}")
    print()

    # Check repository stats
    stats = repository.get_stats()
    print("Repository Statistics:")
    print("-" * 40)
    print(f"Events stored in memory: {stats['total_stored_events']}")
    print(f"Total events ingested: {stats['total_ingested_events']}")
    print(f"Max capacity: {stats['max_capacity']}")
    print()

    # Resource assertions
    print("Resource Usage Assertions:")
    print("-" * 40)

    # RSS assertion (<= 400 MB)
    max_rss_mb = 400
    actual_rss_mb = final_rss / (1024 * 1024)
    rss_passed = actual_rss_mb <= max_rss_mb
    print(f"Peak RSS: {actual_rss_mb:.2f} MB <= {max_rss_mb} MB: {'PASS' if rss_passed else 'FAIL'}")

    # CPU assertion (<= 1.5%)
    max_cpu_percent = 1.5
    cpu_passed = final_cpu_percent <= max_cpu_percent
    print(f"Idle CPU: {final_cpu_percent:.2f}% <= {max_cpu_percent}%: {'PASS' if cpu_passed else 'FAIL'}")

    # Memory growth assertion (should be minimal/unbounded)
    # Allow for some small growth due to caching, interned strings, etc.
    max_memory_growth_mb = 10  # 10 MB allowance for normal Python/caching behavior
    memory_growth_mb = net_change / (1024 * 1024)
    memory_passed = memory_growth_mb <= max_memory_growth_mb
    print(f"Memory growth: {memory_growth_mb:.2f} MB <= {max_memory_growth_mb} MB: {'PASS' if memory_passed else 'FAIL'}")

    print()
    print("=" * 60)

    # Overall result
    all_passed = rss_passed and cpu_passed and memory_passed
    if all_passed:
        print("ALL RESOURCE ASSERTIONS PASSED")
        print("The Sentinel backend meets all resource requirements:")
        print(f"  - Memory usage: {actual_rss_mb:.2f} MB (<= 400 MB)")
        print(f"  - CPU usage: {final_cpu_percent:.2f}% (<= 1.5%)")
        print(f"  - Memory growth: {memory_growth_mb:.2f} MB (<= {max_memory_growth_mb} MB)")
    else:
        print("SOME RESOURCE ASSERTIONS FAILED")
        if not rss_passed:
            print(f"  • RSS too high: {actual_rss_mb:.2f} MB > {max_rss_mb} MB")
        if not cpu_passed:
            print(f"  • CPU usage too high: {final_cpu_percent:.2f}% > {max_cpu_percent}%")
        if not memory_passed:
            print(f"  • Memory growth too high: {memory_growth_mb:.2f} MB > {max_memory_growth_mb} MB")

    print("=" * 60)

    # Clean up
    await repository.close()

    return 0 if all_passed else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)