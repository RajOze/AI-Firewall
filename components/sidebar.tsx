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
    <aside className="w-64 bg-[#0b1120] border-r border-[rgba(79,124,255,0.1)] h-screen flex flex-col backdrop-blur-xl">
      {/* Logo */}
      <div className="p-6 border-b border-[rgba(79,124,255,0.1)] flex items-center gap-3">
        <div className="w-10 h-10 bg-gradient-to-br from-[#4f7cff] to-[#7c3aed] rounded-xl flex items-center justify-center shadow-lg">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="font-bold text-sm gradient-text">SentinelAI</div>
          <div className="text-xs text-[#94a3b8]">Firewall</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-4 space-y-2">
        {sidebarItems.map((item, idx) => (
          <button
            key={idx}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 ${
              item.active
                ? "nav-item-active"
                : "text-[#94a3b8] hover:bg-[rgba(79,124,255,0.1)] hover:text-[#f1f5f9]"
            }`}
          >
            <item.icon className="w-5 h-5" />
            <span className="text-sm font-medium">{item.label}</span>
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-[rgba(79,124,255,0.1)]">
        <div className="text-xs text-[#94a3b8] text-center">
          SentinelAI v2.4.1
        </div>
      </div>
    </aside>
  );
}
