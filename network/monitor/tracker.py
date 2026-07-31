from __future__ import annotations

from datetime import datetime, timezone
import time

from network.monitor.connections import collect_connections


def _connection_key(connection):
    return (
        connection["pid"],
        connection["family"],
        connection["protocol"],
        connection["local_ip"],
        connection["local_port"],
        connection["remote_ip"],
        connection["remote_port"],
    )


def _snapshot():
    connections = collect_connections()

    return {
        _connection_key(connection): connection
        for connection in connections
    }


def _event(event_type, connection):
    return {
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "connection": connection,
    }


def compare_snapshots(previous, current):
    events = []

    previous_keys = set(previous)
    current_keys = set(current)

    for key in previous_keys & current_keys:
        previous_connection = previous[key]
        current_connection = current[key]

        if (
            current_connection["protocol"] == "TCP"
            and previous_connection["status"] != current_connection["status"]
        ):
            event = _event("CONNECTION_STATE_CHANGED", current_connection)
            event["previous_status"] = previous_connection["status"]
            event["current_status"] = current_connection["status"]
            events.append(event)

    for key in current_keys - previous_keys:
        connection = current[key]

        if (
            connection["protocol"] == "TCP"
            and connection["status"] == "LISTEN"
        ):
            event_type = "LISTENER_OPENED"
        else:
            event_type = "CONNECTION_APPEARED"

        events.append(_event(event_type, connection))

    for key in previous_keys - current_keys:
        connection = previous[key]

        if (
            connection["protocol"] == "TCP"
            and connection["status"] == "LISTEN"
        ):
            event_type = "LISTENER_CLOSED"
        else:
            event_type = "CONNECTION_DISAPPEARED"

        events.append(_event(event_type, connection))

    return events


def watch(interval=1.0):
    print("AI Firewall real-time network tracker")
    print(f"Polling interval: {interval} second(s)")
    print("Press Ctrl+C to stop.")

    previous = _snapshot()

    try:
        while True:
            time.sleep(interval)

            current = _snapshot()
            events = compare_snapshots(previous, current)

            for event in events:
                connection = event["connection"]

                print(
                    f'{event["event_timestamp"]} '
                    f'{event["event_type"]} '
                    f'pid={connection["pid"]} '
                    f'process={connection["process_name"]} '
                    f'{connection["protocol"]} '
                    f'{connection["local_ip"]}:{connection["local_port"]} '
                    f'-> '
                    f'{connection["remote_ip"]}:{connection["remote_port"]} '
                    f'status={connection["status"]}'
                )

            previous = current

    except KeyboardInterrupt:
        print("\nTracker stopped.")


if __name__ == "__main__":
    watch()
