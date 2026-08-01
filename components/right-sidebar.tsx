"use client";

import { Search, RotateCcw, Pause, Download, Settings } from "lucide-react";

const actions = [
  { icon: Search, label: "Scan Now", bgGradient: "bg-gradient-to-r from-[#4f7cff] to-[#00e5ff]" },
  { icon: RotateCcw, label: "Refresh Telemetry", bgGradient: "bg-[rgba(79,124,255,0.2)] hover:bg-[rgba(79,124,255,0.3)]" },
  { icon: Pause, label: "Pause Protection", bgGradient: "bg-gradient-to-r from-[#f59e0b] to-[#ef4444]" },
  { icon: Download, label: "Export Logs", bgGradient: "bg-[rgba(79,124,255,0.2)] hover:bg-[rgba(79,124,255,0.3)]" },
  { icon: Settings, label: "Settings", bgGradient: "bg-[rgba(79,124,255,0.2)] hover:bg-[rgba(79,124,255,0.3)]" },
];

export function RightSidebar() {
  return (
    <aside className="w-56 bg-[#0b1120] border-l border-[rgba(79,124,255,0.1)] h-screen flex flex-col p-4 backdrop-blur-xl">
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-[#f1f5f9]">Quick Actions</h3>
        <p className="text-xs text-[#94a3b8] mt-1">Common operations</p>
      </div>

      <div className="space-y-2">
        {actions.map((action, idx) => (
          <button
            key={idx}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 ${action.bgGradient} text-[#f1f5f9] font-semibold text-sm hover:shadow-lg group`}
          >
            <action.icon className="w-4 h-4 group-hover:scale-110 transition-transform duration-200" />
            <span>{action.label}</span>
          </button>
        ))}
      </div>

      {/* Status Info */}
      <div className="mt-auto pt-4 border-t border-[rgba(79,124,255,0.1)] space-y-3">
        <div>
          <div className="text-xs text-[#94a3b8] mb-1 uppercase font-semibold tracking-wider">Protection</div>
          <div className="inline-flex items-center gap-2">
            <div className="w-2 h-2 bg-[#22c55e] rounded-full animate-pulse"></div>
            <span className="text-xs font-semibold text-[#22c55e]">Active</span>
          </div>
        </div>

        <div>
          <div className="text-xs text-[#94a3b8] mb-1 uppercase font-semibold tracking-wider">Backend</div>
          <div className="inline-flex items-center gap-2">
            <div className="w-2 h-2 bg-[#22c55e] rounded-full animate-pulse"></div>
            <span className="text-xs font-semibold text-[#22c55e]">Connected</span>
          </div>
        </div>

        <div>
          <div className="text-xs text-[#94a3b8] mb-1 uppercase font-semibold tracking-wider">AI Engine</div>
          <div className="inline-flex items-center gap-2">
            <div className="w-2 h-2 bg-[#4f7cff] rounded-full animate-pulse"></div>
            <span className="text-xs font-semibold text-[#4f7cff]">Running</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
