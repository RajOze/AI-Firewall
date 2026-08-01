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
    severityClass: "text-critical",
    actionClass: "status-blocked",
  },
  {
    icon: Lock,
    title: "Unsigned Executable",
    confidence: 91,
    severity: "Medium",
    action: "Monitoring",
    reason: "Executable missing digital signature verification.",
    severityClass: "text-warning",
    actionClass: "status-monitoring",
  },
  {
    icon: AlertTriangle,
    title: "Registry Modification Detected",
    confidence: 88,
    severity: "High",
    action: "Blocked",
    reason: "Suspicious registry changes to security policies.",
    severityClass: "text-critical",
    actionClass: "status-blocked",
  },
];

export function ThreatPanel() {
  return (
    <div className="card-base">
      <div className="mb-4">
        <h3 className="text-sm font-semibold">AI Threat Detection</h3>
        <p className="text-xs text-text-secondary mt-1">
          Real-time AI-detected threats
        </p>
      </div>

      <div className="space-y-3">
        {threats.map((threat, idx) => (
          <div key={idx} className="bg-card-dark border border-border rounded-lg p-4">
            <div className="flex items-start gap-3">
              <threat.icon className="w-5 h-5 text-warning mt-0.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <h4 className="text-sm font-semibold mb-1">{threat.title}</h4>
                <p className="text-xs text-text-secondary mb-3">{threat.reason}</p>

                <div className="flex items-center gap-3 flex-wrap">
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-text-secondary">Confidence:</span>
                    <span className="text-xs font-semibold text-primary">
                      {threat.confidence}%
                    </span>
                  </div>
                  <div className="w-px h-4 bg-border"></div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-text-secondary">Severity:</span>
                    <span className={`text-xs font-semibold ${threat.severityClass}`}>
                      {threat.severity}
                    </span>
                  </div>
                  <div className="w-px h-4 bg-border"></div>
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
