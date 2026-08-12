import { useState } from "react";

interface Incident {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
  timestamp: string;
  sourceIp: string;
  targetService: string;
  details: string;
  status: "ACTIVE" | "MITIGATED" | "INVESTIGATING";
}

const mockIncidents: Incident[] = [
  {
    id: "INC-2026-8801",
    title: "SQL Injection Probe Attempt Detected",
    severity: "CRITICAL",
    timestamp: "2 mins ago (13:16:10)",
    sourceIp: "185.76.8.22",
    targetService: "Database API Gateway (:3306)",
    details: "Automated scanner attempted union-based payload injection on /api/v1/auth.",
    status: "ACTIVE",
  },
  {
    id: "INC-2026-8802",
    title: "Suspicious PowerShell Subprocess Execution",
    severity: "HIGH",
    timestamp: "12 mins ago (13:06:45)",
    sourceIp: "192.168.1.104",
    targetService: "Host Process Executable (PID: 5124)",
    details: "Encoded command execution flag (-EncodedCommand) detected from non-admin shell.",
    status: "INVESTIGATING",
  },
  {
    id: "INC-2026-8803",
    title: "Port Scan Burst Across Subnet 10.0.4.0/24",
    severity: "MEDIUM",
    timestamp: "28 mins ago (12:50:11)",
    sourceIp: "10.0.4.88",
    targetService: "Subnet Network Probe",
    details: "SYN packet sweep across ports 21, 22, 80, 443, 8080 within 500ms.",
    status: "MITIGATED",
  },
  {
    id: "INC-2026-8804",
    title: "TLS Certificate Expiration Warning",
    severity: "INFO",
    timestamp: "1 hour ago (12:15:00)",
    sourceIp: "192.168.1.1",
    targetService: "HTTPS Ingress Listener",
    details: "Public SSL certificate for ingress gateway expires in 14 days.",
    status: "MITIGATED",
  },
];

export default function AlertsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [incidents, setIncidents] = useState<Incident[]>(mockIncidents);

  const handleMitigate = (id: string) => {
    setIncidents((prev) =>
      prev.map((inc) => (inc.id === id ? { ...inc, status: "MITIGATED" } : inc))
    );
  };

  const filteredIncidents = incidents.filter(
    (inc) => severityFilter === "ALL" || inc.severity === severityFilter
  );

  return (
    <div className="flex flex-col w-full gap-gutter">
      {/* Header Banner */}
      <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex items-center justify-between">
        <div>
          <h1 className="font-headline-lg text-on-surface">Alerts & Threat Incidents</h1>
          <p className="font-body-sm text-outline mt-1">
            Real-time security event telemetry, automated incident triage, and response timeline.
          </p>
        </div>
        <div className="flex items-center gap-md">
          <span className="font-code-sm text-secondary">
            {incidents.filter((i) => i.status === "ACTIVE").length} Active Threat Alerts
          </span>
        </div>
      </div>

      {/* Severity Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-gutter">
        <div className="bg-surface-container p-lg rounded border border-outline-variant/30">
          <span className="font-label-caps text-error uppercase">Critical Incidents</span>
          <div className="font-headline-lg text-[36px] text-error mt-xs leading-none">
            {incidents.filter((i) => i.severity === "CRITICAL").length}
          </div>
        </div>
        <div className="bg-surface-container p-lg rounded border border-outline-variant/30">
          <span className="font-label-caps text-tertiary uppercase">High Severity</span>
          <div className="font-headline-lg text-[36px] text-tertiary mt-xs leading-none">
            {incidents.filter((i) => i.severity === "HIGH").length}
          </div>
        </div>
        <div className="bg-surface-container p-lg rounded border border-outline-variant/30">
          <span className="font-label-caps text-secondary uppercase">Mitigated Today</span>
          <div className="font-headline-lg text-[36px] text-secondary mt-xs leading-none">
            {incidents.filter((i) => i.status === "MITIGATED").length}
          </div>
        </div>
        <div className="bg-surface-container p-lg rounded border border-outline-variant/30">
          <span className="font-label-caps text-outline uppercase">Resolution Rate</span>
          <div className="font-headline-lg text-[36px] text-on-surface mt-xs leading-none">
            94.2%
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex items-center gap-sm border-b border-outline-variant/30 pb-sm">
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "INFO"].map((sev) => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={`px-md py-xs font-label-caps rounded transition-colors ${
              severityFilter === sev
                ? "bg-primary text-on-primary"
                : "bg-surface-container-high text-on-surface-variant hover:text-on-surface"
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Incident Stream Timeline */}
      <div className="flex flex-col gap-md">
        {filteredIncidents.map((inc) => (
          <div
            key={inc.id}
            className={`bg-surface-container p-lg rounded border transition-all flex flex-col gap-sm ${
              inc.severity === "CRITICAL"
                ? "border-error/50 border-l-4 border-l-error"
                : inc.severity === "HIGH"
                ? "border-tertiary/40 border-l-4 border-l-tertiary"
                : "border-outline-variant/30"
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-md">
                <span
                  className={`material-symbols-outlined text-[24px] ${
                    inc.severity === "CRITICAL"
                      ? "text-error animate-pulse"
                      : inc.severity === "HIGH"
                      ? "text-tertiary"
                      : "text-primary"
                  }`}
                >
                  {inc.severity === "CRITICAL" ? "warning" : "shield"}
                </span>
                <div>
                  <h3 className="font-headline-sm text-on-surface">{inc.title}</h3>
                  <div className="flex items-center gap-md font-code-sm text-[12px] text-outline mt-0.5">
                    <span>{inc.id}</span>
                    <span>•</span>
                    <span>{inc.timestamp}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-sm">
                <span
                  className={`px-xs py-[2px] rounded text-[10px] font-bold uppercase border ${
                    inc.severity === "CRITICAL"
                      ? "bg-error/10 text-error border-error/20"
                      : inc.severity === "HIGH"
                      ? "bg-tertiary/10 text-tertiary border-tertiary/20"
                      : "bg-primary/10 text-primary border-primary/20"
                  }`}
                >
                  {inc.severity}
                </span>
                <span
                  className={`px-xs py-[2px] rounded text-[10px] font-bold uppercase border ${
                    inc.status === "MITIGATED"
                      ? "bg-secondary/10 text-secondary border-secondary/20"
                      : "bg-surface-container-highest text-on-surface border-outline-variant"
                  }`}
                >
                  {inc.status}
                </span>
              </div>
            </div>

            <p className="font-body-md text-on-surface-variant bg-surface-container-low p-md rounded border border-outline-variant/20">
              {inc.details}
            </p>

            <div className="flex items-center justify-between font-code-sm text-[12px] pt-xs">
              <div className="flex gap-lg text-outline">
                <span>Source: <strong className="text-on-surface">{inc.sourceIp}</strong></span>
                <span>Target: <strong className="text-on-surface">{inc.targetService}</strong></span>
              </div>
              {inc.status !== "MITIGATED" && (
                <button
                  onClick={() => handleMitigate(inc.id)}
                  className="px-md py-xs bg-secondary/10 text-secondary border border-secondary/20 rounded hover:bg-secondary/20 transition-colors font-body-sm text-[12px]"
                >
                  Apply Automated Mitigation
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
