"use client";

import { AlertTriangle, Lock } from "lucide-react";

const threats = [
  {
    icon: AlertTriangle,
    title: "Suspicious PowerShell Activity",
    confidence: 97,
    severity: "High",
    action: "Blocked",
    reason: "Unexpected outbound encrypted connection.",
    severityClass: "text-[#ef4444]",
    actionClass: "status-blocked",
    borderColor: "border-[rgba(239,68,68,0.2)]",
  },
  {
    icon: Lock,
    title: "Unsigned Executable",
    confidence: 91,
    severity: "Medium",
    action: "Monitoring",
    reason: "Executable missing digital signature verification.",
    severityClass: "text-[#f59e0b]",
    actionClass: "status-monitoring",
    borderColor: "border-[rgba(245,158,11,0.2)]",
  },
  {
    icon: AlertTriangle,
    title: "Registry Modification Detected",
    confidence: 88,
    severity: "High",
    action: "Blocked",
    reason: "Suspicious registry changes to security policies.",
    severityClass: "text-[#ef4444]",
    actionClass: "status-blocked",
    borderColor: "border-[rgba(239,68,68,0.2)]",
  },
];

export function ThreatPanel() {
  return (
    <div className="card-base">
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-[#f1f5f9]">AI Threat Detection</h3>
        <p className="text-xs text-[#94a3b8] mt-1">
          Real-time AI-detected threats
        </p>
      </div>

      <div className="space-y-3">
        {threats.map((threat, idx) => (
          <div key={idx} className={`glass-card border ${threat.borderColor} rounded-xl p-4 transition-all duration-200 hover:shadow-lg`}>
            <div className="flex items-start gap-3">
              <threat.icon className="w-5 h-5 text-[#f59e0b] mt-0.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <h4 className="text-sm font-semibold mb-1 text-[#f1f5f9]">{threat.title}</h4>
                <p className="text-xs text-[#94a3b8] mb-3">{threat.reason}</p>

                <div className="flex items-center gap-3 flex-wrap">
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-[#94a3b8]">Confidence:</span>
                    <span className="text-xs font-semibold text-[#4f7cff]">
                      {threat.confidence}%
                    </span>
                  </div>
                  <div className="w-px h-4 bg-[rgba(79,124,255,0.1)]"></div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-[#94a3b8]">Severity:</span>
                    <span className={`text-xs font-semibold ${threat.severityClass}`}>
                      {threat.severity}
                    </span>
                  </div>
                  <div className="w-px h-4 bg-[rgba(79,124,255,0.1)]"></div>
                  <span className={`status-badge ${threat.actionClass}`}>
                    {threat.action}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
