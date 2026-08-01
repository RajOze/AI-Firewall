"use client";

import { ShieldCheck, Zap, Wifi, AlertTriangle, GitBranch, Brain } from "lucide-react";

const cards = [
  {
    icon: ShieldCheck,
    label: "Protection Status",
    value: "Protected",
    valueClass: "text-[#22c55e]",
    accentColor: "from-[#22c55e]",
  },
  {
    icon: Brain,
    label: "AI Engine",
    value: "Running",
    valueClass: "text-[#00e5ff]",
    accentColor: "from-[#00e5ff]",
  },
  {
    icon: Wifi,
    label: "Active Connections",
    value: "127",
    valueClass: "text-[#f1f5f9]",
    accentColor: "from-[#4f7cff]",
  },
  {
    icon: AlertTriangle,
    label: "Blocked Threats",
    value: "12",
    valueClass: "text-[#ef4444]",
    accentColor: "from-[#ef4444]",
  },
  {
    icon: GitBranch,
    label: "Firewall Rules",
    value: "46 Active",
    valueClass: "text-[#f1f5f9]",
    accentColor: "from-[#4f7cff]",
  },
  {
    icon: Zap,
    label: "AI Confidence",
    value: "98.7%",
    valueClass: "text-[#22c55e]",
    accentColor: "from-[#22c55e]",
  },
];

export function SummaryCards() {
  return (
    <div className="grid grid-cols-6 gap-4 mb-6">
      {cards.map((card, idx) => (
        <div key={idx} className="group card-base relative overflow-hidden">
          <div className={`absolute inset-0 bg-gradient-to-br ${card.accentColor} to-transparent opacity-0 group-hover:opacity-20 transition-opacity duration-300`}></div>
          <div className="relative flex items-start justify-between">
            <div className="flex-1">
              <div className="text-xs text-[#94a3b8] font-semibold mb-2 uppercase tracking-wider">
                {card.label}
              </div>
              <div className={`text-2xl font-bold ${card.valueClass} transition-all duration-300`}>
                {card.value}
              </div>
            </div>
            <card.icon className="w-6 h-6 text-[#94a3b8] group-hover:text-[#4f7cff] transition-colors duration-300" />
          </div>
        </div>
      ))}
    </div>
  );
}
