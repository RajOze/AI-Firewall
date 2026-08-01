"use client";

import { Clock } from "lucide-react";
import { useState, useEffect } from "react";

export function StatusBar() {
  const [time, setTime] = useState("00:00:00");

  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      setTime(now.toLocaleTimeString("en-US", { hour12: false }));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const statusItems = [
    { label: "Windows Version", value: "Windows 11 Pro (23H2)" },
    { label: "AI Engine", value: "v2.4.1" },
    { label: "Telemetry", value: "Online" },
    { label: "Firewall", value: "Active" },
    { label: "Backend", value: "Connected" },
    { label: "WebSocket", value: "Connected" },
  ];

  return (
    <div className="h-10 bg-card border-t border-border px-4 flex items-center justify-between text-xs text-text-secondary">
      <div className="flex items-center gap-6">
        {statusItems.map((item, idx) => (
          <div key={idx} className="flex items-center gap-2">
            <span className="opacity-70">{item.label}:</span>
            <span className="text-foreground font-medium">{item.value}</span>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <Clock className="w-3.5 h-3.5" />
        <span className="font-mono">{time}</span>
      </div>
    </div>
  );
}
