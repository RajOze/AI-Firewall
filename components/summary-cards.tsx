"use client";

import { ShieldCheck, Zap, Wifi, AlertTriangle, GitBranch, Brain } from "lucide-react";

const cards = [
  {
    icon: ShieldCheck,
    label: "Protection Status",
    value: "Protected",
    valueClass: "text-success",
    bgClass: "bg-success/5",
  },
  {
    icon: Brain,
    label: "AI Engine",
    value: "Running",
    valueClass: "text-primary",
    bgClass: "bg-primary/5",
  },
  {
    icon: Wifi,
    label: "Active Connections",
    value: "127",
    valueClass: "text-foreground",
    bgClass: "bg-border",
  },
  {
    icon: AlertTriangle,
    label: "Blocked Threats",
    value: "12",
    valueClass: "text-critical",
    bgClass: "bg-critical/5",
  },
  {
    icon: GitBranch,
    label: "Firewall Rules",
    value: "46 Active",
    valueClass: "text-foreground",
    bgClass: "bg-border",
  },
  {
    icon: Zap,
    label: "AI Confidence",
    value: "98.7%",
    valueClass: "text-success",
    bgClass: "bg-success/5",
  },
];

export function SummaryCards() {
  return (
    <div className="grid grid-cols-6 gap-4 mb-6">
      {cards.map((card, idx) => (
        <div key={idx} className={`card-base ${card.bgClass}`}>
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="text-xs text-text-secondary font-medium mb-2">
                {card.label}
              </div>
              <div className={`text-2xl font-bold ${card.valueClass}`}>
                {card.value}
              </div>
            </div>
            <card.icon className="w-6 h-6 text-text-secondary" />
          </div>
        </div>
      ))}
    </div>
  );
}
