import { useState } from "react";
import { getConnections } from "../services/connectionService";
import { getThreats } from "../services/threatService";

export default function DashboardPage() {
  const [timeframe, setTimeframe] = useState<"1H" | "24H" | "7D">("24H");
  const connections = getConnections();
  const threats = getThreats();

  return (
    <div className="flex flex-col w-full gap-md">
      {/* Top Stats Row - Balanced for 1366x768 height */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-md">
        {/* Risk Score */}
        <div className="bg-surface-container p-md flex flex-col justify-between group hover:bg-surface-container-high transition-colors rounded border border-outline-variant/20">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-outline uppercase tracking-wider text-[11px]">
              Risk Score
            </span>
            <span className="material-symbols-outlined text-secondary text-[18px]">
              shield
            </span>
          </div>
          <div className="mt-md flex items-baseline justify-between">
            <div className="font-code-md text-[32px] font-bold text-secondary leading-none tracking-tight">
              0.04
            </div>
            <div className="font-body-sm text-secondary/90 text-[12px] flex items-center gap-xs bg-secondary/10 px-sm py-[2px] rounded border border-secondary/20">
              <span className="material-symbols-outlined text-[14px]">arrow_downward</span>
              Nominal
            </div>
          </div>
        </div>

        {/* Threats Blocked */}
        <div className="bg-surface-container p-md flex flex-col justify-between group hover:bg-surface-container-high transition-colors rounded border border-outline-variant/20">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-outline uppercase tracking-wider text-[11px]">
              Threats Blocked
            </span>
            <span className="material-symbols-outlined text-outline text-[18px]">
              block
            </span>
          </div>
          <div className="mt-md flex items-baseline justify-between">
            <div className="font-code-md text-[32px] font-bold text-on-surface leading-none tracking-tight tabular-nums">
              12,842
            </div>
            <span className="font-body-sm text-outline text-[12px]">Past 24 Hours</span>
          </div>
        </div>

        {/* Active Attacks */}
        <div className="bg-surface-container p-md flex flex-col justify-between border-l-2 border-error bg-error/5 group hover:bg-surface-container-high transition-colors rounded">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-error uppercase tracking-wider text-[11px]">
              Active Attacks
            </span>
            <span className="material-symbols-outlined text-error text-[18px] animate-pulse">
              warning
            </span>
          </div>
          <div className="mt-md flex items-baseline justify-between">
            <div className="font-code-md text-[32px] font-bold text-on-surface leading-none">
              03
            </div>
            <span className="font-body-sm text-error/90 text-[12px] bg-error/10 px-sm py-[2px] rounded border border-error/20 font-medium">
              DDoS Active
            </span>
          </div>
        </div>

        {/* System Health */}
        <div className="bg-surface-container p-md flex flex-col justify-between rounded border border-outline-variant/20">
          <div className="flex items-center justify-between mb-xs">
            <span className="font-label-caps text-outline uppercase tracking-wider text-[11px]">
              System Health
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-secondary animate-pulse" />
              <span className="font-code-sm text-[11px] text-secondary">Optimal</span>
            </span>
          </div>
          <div className="grid grid-cols-3 gap-xs text-center pt-xs">
            <div className="bg-surface-container-low p-xs rounded border border-outline-variant/20">
              <div className="font-label-caps text-[9px] text-outline truncate">Core</div>
              <div className="w-1.5 h-1.5 rounded-full bg-secondary mx-auto mt-1 shadow-[0_0_6px_rgba(78,222,163,0.6)]" />
            </div>
            <div className="bg-surface-container-low p-xs rounded border border-outline-variant/20">
              <div className="font-label-caps text-[9px] text-outline truncate">IPS</div>
              <div className="w-1.5 h-1.5 rounded-full bg-secondary mx-auto mt-1 shadow-[0_0_6px_rgba(78,222,163,0.6)]" />
            </div>
            <div className="bg-surface-container-low p-xs rounded border border-outline-variant/20">
              <div className="font-label-caps text-[9px] text-outline truncate">AI Engine</div>
              <div className="w-1.5 h-1.5 rounded-full bg-secondary mx-auto mt-1 shadow-[0_0_6px_rgba(78,222,163,0.6)]" />
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid - Balanced 7:5 ratio on desktop */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-md">
        {/* Left Column (7 cols): Telemetry & Active Sessions */}
        <div className="lg:col-span-7 flex flex-col gap-md">
          {/* Threat Frequency Timeline Chart */}
          <div className="bg-surface-container p-md rounded border border-outline-variant/30 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-md">
              <div className="flex flex-col">
                <span className="font-label-caps text-outline uppercase tracking-widest text-[11px]">
                  Threat Frequency
                </span>
                <span className="font-headline-sm text-on-surface text-[15px]">
                  24h Network Load Analysis
                </span>
              </div>
              <div className="flex gap-xs bg-surface-container-low p-1 rounded border border-outline-variant/30">
                {(["1H", "24H", "7D"] as const).map((tf) => (
                  <button
                    key={tf}
                    onClick={() => setTimeframe(tf)}
                    className={`px-sm py-0.5 font-label-caps text-[10px] rounded transition-colors ${
                      timeframe === tf
                        ? "bg-primary text-on-primary font-bold shadow-sm"
                        : "text-outline hover:text-on-surface hover:bg-surface-container-high"
                    }`}
                  >
                    {tf}
                  </button>
                ))}
              </div>
            </div>

            {/* Sparkline SVG Chart with Axis grid overlay */}
            <div className="relative w-full h-36 bg-surface-container-low/50 rounded border border-outline-variant/20 p-xs flex flex-col justify-between">
              {/* Background grid lines */}
              <div className="absolute inset-0 flex flex-col justify-between p-md pointer-events-none opacity-15">
                <div className="border-b border-dashed border-outline" />
                <div className="border-b border-dashed border-outline" />
                <div className="border-b border-dashed border-outline" />
              </div>

              <svg className="w-full h-full text-secondary relative z-10" preserveAspectRatio="none" viewBox="0 0 1000 100">
                <defs>
                  <linearGradient id="grad" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style={{ stopColor: "currentColor", stopOpacity: 0.35 }} />
                    <stop offset="100%" style={{ stopColor: "currentColor", stopOpacity: 0.0 }} />
                  </linearGradient>
                </defs>
                <path
                  className="opacity-30"
                  d="M0,80 Q50,75 100,85 T200,60 T300,70 T400,30 T500,45 T600,20 T700,40 T800,10 T900,35 T1000,25 V100 H0 Z"
                  fill="url(#grad)"
                />
                <path
                  d="M0,80 Q50,75 100,85 T200,60 T300,70 T400,30 T500,45 T600,20 T700,40 T800,10 T900,35 T1000,25"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                />
                <circle cx="400" cy="30" r="3.5" fill="currentColor" className="animate-ping opacity-75" />
                <circle cx="400" cy="30" r="3.5" fill="currentColor" />
                <circle cx="600" cy="20" r="3.5" fill="currentColor" />
                <circle cx="800" cy="10" r="3.5" fill="currentColor" />
              </svg>

              {/* Time ticks overlay */}
              <div className="flex justify-between px-xs pt-1 border-t border-outline-variant/20 font-code-sm text-[10px] text-outline">
                <span>00:00</span>
                <span>06:00</span>
                <span>12:00</span>
                <span>18:00</span>
                <span className="text-secondary font-medium">NOW</span>
              </div>
            </div>
          </div>

          {/* Active Network Sessions Table */}
          <div className="bg-surface-container overflow-hidden rounded border border-outline-variant/30 flex flex-col">
            <div className="px-md py-sm border-b border-outline-variant/30 flex items-center justify-between bg-surface-container-low">
              <div className="flex items-center gap-xs">
                <span className="material-symbols-outlined text-outline text-[18px]">device_hub</span>
                <span className="font-label-caps text-on-surface uppercase tracking-wider text-[11px]">
                  Active Network Sessions
                </span>
              </div>
              <div className="flex items-center gap-sm">
                <span className="font-body-sm text-outline text-[12px]">
                  <span className="text-secondary font-code-sm font-semibold">428</span> Live
                </span>
                <button className="flex items-center gap-1 text-[11px] text-outline hover:text-on-surface bg-surface-container-highest/40 hover:bg-surface-container-highest px-sm py-0.5 rounded transition-colors">
                  <span className="material-symbols-outlined text-[14px]">filter_list</span>
                  Filter
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-surface-container-highest/30 border-b border-outline-variant/20">
                    <th className="py-2.5 px-md font-label-caps text-outline text-[10px]">Process / App</th>
                    <th className="py-2.5 px-md font-label-caps text-outline text-[10px]">Source IP</th>
                    <th className="py-2.5 px-md font-label-caps text-outline text-[10px]">Protocol / Port</th>
                    <th className="py-2.5 px-md font-label-caps text-outline text-[10px]">Load</th>
                    <th className="py-2.5 px-md font-label-caps text-outline text-[10px] text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="font-code-sm text-[12px] divide-y divide-outline-variant/20">
                  {connections.map((conn, idx) => (
                    <tr
                      key={idx}
                      className="hover:bg-surface-container-high/60 transition-colors"
                    >
                      <td className="py-2 px-md text-on-surface font-medium whitespace-nowrap">
                        <div className="flex items-center gap-sm">
                          <span className="material-symbols-outlined text-[16px] text-outline">terminal</span>
                          {conn.process}
                        </div>
                      </td>
                      <td className="py-2 px-md text-on-surface-variant font-code-sm whitespace-nowrap">{conn.ip}</td>
                      <td className="py-2 px-md text-primary font-code-sm whitespace-nowrap">
                        {conn.protocol}/<span className="text-on-surface-variant">{conn.port}</span>
                      </td>
                      <td className="py-2 px-md">
                        <div className="w-20 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              conn.status === "Blocked"
                                ? "bg-error"
                                : conn.status === "Monitoring"
                                ? "bg-tertiary"
                                : "bg-secondary"
                            }`}
                            style={{ width: `${(idx + 1) * 20 + 25}%` }}
                          />
                        </div>
                      </td>
                      <td className="py-2 px-md text-right whitespace-nowrap">
                        <span
                          className={`px-xs py-[2px] border rounded-xs font-label-caps text-[9px] ${
                            conn.status === "Allowed"
                              ? "bg-secondary/10 text-secondary border-secondary/20"
                              : conn.status === "Monitoring"
                              ? "bg-tertiary/10 text-tertiary border-tertiary/20"
                              : "bg-error/10 text-error border-error/20"
                          }`}
                        >
                          {conn.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column (5 cols): Live Threat Stream & Shield Controls */}
        <div className="lg:col-span-5 flex flex-col gap-md">
          {/* Recent Security Threats Feed */}
          <div className="bg-surface-container p-md rounded border border-outline-variant/30 flex flex-col gap-sm">
            <div className="flex items-center justify-between border-b border-outline-variant/30 pb-xs">
              <div className="flex items-center gap-xs">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-error opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-error" />
                </span>
                <span className="font-label-caps text-outline uppercase tracking-wider text-[11px]">
                  Live Threat Stream
                </span>
              </div>
              <button className="font-body-sm text-[12px] text-primary hover:text-primary-container cursor-pointer transition-colors">
                View All
              </button>
            </div>

            <div className="space-y-xs pt-xs">
              {threats.map((threat) => (
                <div
                  key={threat.id}
                  className="p-sm bg-surface-container-low border border-outline-variant/30 hover:border-outline-variant/60 rounded flex items-center justify-between transition-colors"
                >
                  <div className="flex items-center gap-sm">
                    <div className={`p-xs rounded flex items-center justify-center ${
                      threat.severity === "High"
                        ? "bg-error/10 text-error"
                        : threat.severity === "Medium"
                        ? "bg-tertiary/10 text-tertiary"
                        : "bg-secondary/10 text-secondary"
                    }`}>
                      <span className="material-symbols-outlined text-[16px]">
                        {threat.severity === "High" ? "security_update_warning" : threat.severity === "Medium" ? "radar" : "check_circle"}
                      </span>
                    </div>
                    <div className="flex flex-col">
                      <span className="font-body-md text-[13px] font-medium text-on-surface">
                        {threat.name}
                      </span>
                      <span className="font-code-sm text-[11px] text-outline">
                        {threat.time}
                      </span>
                    </div>
                  </div>
                  <span
                    className={`px-sm py-[2px] rounded-xs font-label-caps text-[9px] border ${
                      threat.severity === "High"
                        ? "bg-error/10 text-error border-error/20"
                        : threat.severity === "Medium"
                        ? "bg-tertiary/10 text-tertiary border-tertiary/20"
                        : "bg-secondary/10 text-secondary border-secondary/20"
                    }`}
                  >
                    {threat.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Engine Controls */}
          <div className="bg-surface-container p-md rounded border border-outline-variant/30 flex flex-col gap-sm">
            <div className="flex items-center gap-xs border-b border-outline-variant/30 pb-xs">
              <span className="material-symbols-outlined text-outline text-[18px]">tune</span>
              <span className="font-label-caps text-outline uppercase tracking-wider text-[11px]">
                Shield Configuration
              </span>
            </div>
            <div className="space-y-xs pt-xs">
              <div className="flex items-center justify-between p-sm rounded bg-surface-container-low/60 border border-outline-variant/20">
                <div className="flex flex-col">
                  <span className="font-body-sm text-[13px] text-on-surface font-medium">Real-Time IPS Shield</span>
                  <span className="font-body-sm text-[11px] text-outline">Active Threat Prevention</span>
                </div>
                <span className="w-9 h-5 bg-secondary/20 border border-secondary/40 rounded-full flex items-center p-0.5 justify-end cursor-pointer transition-colors">
                  <span className="w-3.5 h-3.5 rounded-full bg-secondary shadow-xs"></span>
                </span>
              </div>

              <div className="flex items-center justify-between p-sm rounded bg-surface-container-low/60 border border-outline-variant/20">
                <div className="flex flex-col">
                  <span className="font-body-sm text-[13px] text-on-surface font-medium">AI Anomaly Detector</span>
                  <span className="font-body-sm text-[11px] text-outline">Behavioral Engine</span>
                </div>
                <span className="w-9 h-5 bg-secondary/20 border border-secondary/40 rounded-full flex items-center p-0.5 justify-end cursor-pointer transition-colors">
                  <span className="w-3.5 h-3.5 rounded-full bg-secondary shadow-xs"></span>
                </span>
              </div>

              <div className="flex items-center justify-between p-sm rounded bg-surface-container-low/60 border border-outline-variant/20">
                <div className="flex flex-col">
                  <span className="font-body-sm text-[13px] text-on-surface font-medium">Strict Egress Filtering</span>
                  <span className="font-body-sm text-[11px] text-outline">Outbound Packet Inspection</span>
                </div>
                <span className="w-9 h-5 bg-surface-container-highest border border-outline-variant rounded-full flex items-center p-0.5 justify-start cursor-pointer transition-colors">
                  <span className="w-3.5 h-3.5 rounded-full bg-outline shadow-xs"></span>
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

