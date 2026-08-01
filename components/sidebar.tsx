"use client";

import {
  Shield,
  Wifi,
  Zap,
  Settings,
  BarChart3,
  Clock,
  Cpu,
  LayoutDashboard,
  AlertTriangle,
  GitBranch,
} from "lucide-react";

const sidebarItems = [
  { icon: LayoutDashboard, label: "Dashboard", active: true },
  { icon: Wifi, label: "Live Connections" },
  { icon: AlertTriangle, label: "AI Threat Detection" },
  { icon: GitBranch, label: "Firewall Rules" },
  { icon: Zap, label: "AI Decisions" },
  { icon: BarChart3, label: "Traffic Analytics" },
  { icon: Clock, label: "Event Timeline" },
  { icon: Cpu, label: "Processes" },
  { icon: Settings, label: "Settings" },
];

export function Sidebar() {
  return (
    <aside className="w-64 bg-card-dark border-r border-border h-screen flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-border flex items-center gap-3">
        <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="font-bold text-sm">SentinelAI</div>
          <div className="text-xs text-text-secondary">Firewall</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-4 space-y-2">
        {sidebarItems.map((item, idx) => (
          <button
            key={idx}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
              item.active
                ? "bg-primary/20 text-primary border border-primary/50"
                : "text-text-secondary hover:bg-border hover:text-foreground"
            }`}
          >
            <item.icon className="w-5 h-5" />
            <span className="text-sm font-medium">{item.label}</span>
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-border">
        <div className="text-xs text-text-secondary text-center">
          SentinelAI v2.4.1
        </div>
      </div>
    </aside>
  );
}
