"use client";

import { AlertTriangle, Plus, RefreshCw, Trash2, Check } from "lucide-react";

const events = [
  {
    icon: Plus,
    text: "Firewall rule added: Block Tor Network",
    time: "14:35",
    type: "rule",
  },
  {
    icon: RefreshCw,
    text: "AI model updated to v2.4.1",
    time: "14:32",
    type: "update",
  },
  {
    icon: AlertTriangle,
    text: "Threat blocked: Suspicious PowerShell activity",
    time: "14:30",
    type: "threat",
  },
  {
    icon: Trash2,
    text: "Connection terminated: 142.251.41.14:443",
    time: "14:28",
    type: "connection",
  },
  {
    icon: Check,
    text: "New process detected: svchost.exe - Approved",
    time: "14:25",
    type: "process",
  },
  {
    icon: Plus,
    text: "Network interface UP: Ethernet 2",
    time: "14:22",
    type: "network",
  },
  {
    icon: AlertTriangle,
    text: "High memory usage detected: 78%",
    time: "14:20",
    type: "warning",
  },
  {
    icon: RefreshCw,
    text: "Telemetry data synchronized",
    time: "14:18",
    type: "sync",
  },
];

function getEventColor(type: string) {
  switch (type) {
    case "threat":
      return "text-critical";
    case "warning":
      return "text-warning";
    case "update":
      return "text-primary";
    case "process":
      return "text-success";
    default:
      return "text-text-secondary";
  }
}

export function EventLog() {
  return (
    <div className="card-base">
      <div className="mb-4">
        <h3 className="text-sm font-semibold">Recent Events</h3>
        <p className="text-xs text-text-secondary mt-1">
          System and security event log
        </p>
      </div>

      <div className="space-y-2 max-h-64 overflow-y-auto">
        {events.map((event, idx) => (
          <div key={idx} className="flex items-start gap-3 p-2 hover:bg-card-dark rounded transition-colors">
            <event.icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${getEventColor(event.type)}`} />
            <div className="flex-1 min-w-0">
              <p className="text-xs text-foreground">{event.text}</p>
              <span className="text-xs text-text-secondary">{event.time}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
