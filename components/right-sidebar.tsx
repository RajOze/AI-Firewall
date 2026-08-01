"use client";

import { Search, RotateCcw, Pause, Download, Settings } from "lucide-react";

const actions = [
  { icon: Search, label: "Scan Now", color: "bg-primary hover:bg-primary-dark" },
  { icon: RotateCcw, label: "Refresh Telemetry", color: "bg-border hover:bg-border" },
  { icon: Pause, label: "Pause Protection", color: "bg-warning hover:bg-warning" },
  { icon: Download, label: "Export Logs", color: "bg-border hover:bg-border" },
  { icon: Settings, label: "Settings", color: "bg-border hover:bg-border" },
];

export function RightSidebar() {
  return (
    <aside className="w-56 bg-card-dark border-l border-border h-screen flex flex-col p-4">
      <div className="mb-4">
        <h3 className="text-sm font-semibold">Quick Actions</h3>
        <p className="text-xs text-text-secondary mt-1">Common operations</p>
      </div>

      <div className="space-y-2">
        {actions.map((action, idx) => (
          <button
            key={idx}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${action.color} text-foreground font-medium text-sm`}
          >
            <action.icon className="w-4 h-4" />
            <span>{action.label}</span>
          </button>
        ))}
      </div>

      {/* Status Info */}
      <div className="mt-auto pt-4 border-t border-border space-y-3">
        <div>
          <div className="text-xs text-text-secondary mb-1">Protection</div>
          <div className="inline-flex items-center gap-2">
            <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
            <span className="text-xs font-medium text-success">Active</span>
          </div>
        </div>

        <div>
          <div className="text-xs text-text-secondary mb-1">Backend</div>
          <div className="inline-flex items-center gap-2">
            <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
            <span className="text-xs font-medium text-success">Connected</span>
          </div>
        </div>

        <div>
          <div className="text-xs text-text-secondary mb-1">AI Engine</div>
          <div className="inline-flex items-center gap-2">
            <div className="w-2 h-2 bg-primary rounded-full animate-pulse"></div>
            <span className="text-xs font-medium text-primary">Running</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
