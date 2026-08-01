"use client";

import { Clock } from "lucide-react";

const decisions = [
  {
    time: "14:32",
    event: "AI detected abnormal outbound DNS traffic.",
    confidence: 96,
    decision: "Blocked",
    decisionClass: "text-[#ef4444]",
    borderColor: "border-[rgba(239,68,68,0.3)]",
  },
  {
    time: "14:31",
    event: "New executable detected in system32.",
    confidence: 88,
    decision: "Monitoring",
    decisionClass: "text-[#f59e0b]",
    borderColor: "border-[rgba(245,158,11,0.3)]",
  },
  {
    time: "14:29",
    event: "Chrome connection to googleapis.com approved.",
    confidence: 99,
    decision: "Allowed",
    decisionClass: "text-[#22c55e]",
    borderColor: "border-[rgba(34,197,94,0.3)]",
  },
  {
    time: "14:27",
    event: "Suspicious registry modification attempt blocked.",
    confidence: 94,
    decision: "Blocked",
    decisionClass: "text-[#ef4444]",
    borderColor: "border-[rgba(239,68,68,0.3)]",
  },
  {
    time: "14:25",
    event: "Legitimate Windows Update Service communication.",
    confidence: 99,
    decision: "Allowed",
    decisionClass: "text-[#22c55e]",
    borderColor: "border-[rgba(34,197,94,0.3)]",
  },
];

export function DecisionTimeline() {
  return (
    <div className="card-base">
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-[#f1f5f9]">AI Decision Log</h3>
        <p className="text-xs text-[#94a3b8] mt-1">
          Recent AI-driven security decisions
        </p>
      </div>

      <div className="space-y-1">
        {decisions.map((item, idx) => (
          <div key={idx} className={`py-3 px-3 border-l-2 ${item.borderColor} hover:bg-[rgba(79,124,255,0.08)] rounded-lg transition-all duration-150`}>
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <Clock className="w-3 h-3 text-[#94a3b8] flex-shrink-0" />
                  <span className="text-xs font-mono text-[#94a3b8]">
                    {item.time}
                  </span>
                </div>
                <p className="text-xs text-[#f1f5f9] mb-2 font-medium">{item.event}</p>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-[#94a3b8]">Confidence:</span>
                  <span className="text-[#4f7cff] font-semibold">{item.confidence}%</span>
                </div>
              </div>
              <span
                className={`status-badge flex-shrink-0 ${
                  item.decision === "Allowed"
                    ? "status-allowed"
                    : item.decision === "Blocked"
                      ? "status-blocked"
                      : "status-monitoring"
                }`}
              >
                {item.decision}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
