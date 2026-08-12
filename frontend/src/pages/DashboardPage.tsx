import { useState } from "react";
import { getConnections } from "../services/connectionService";
import { getThreats } from "../services/threatService";

export default function DashboardPage() {
  const [timeframe, setTimeframe] = useState<"1H" | "24H" | "7D">("24H");
  const connections = getConnections();
  const threats = getThreats();

  return (
    <div className="flex flex-col w-full gap-gutter">
      {/* Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-gutter">
        {/* Risk Score */}
        <div className="bg-surface-container p-lg flex flex-col justify-between group hover:bg-surface-container-high transition-colors rounded">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-outline uppercase">Risk Score</span>
            <span className="material-symbols-outlined text-secondary text-[20px]">security</span>
          </div>
          <div className="mt-xl">
            <div className="font-headline-lg text-[48px] text-secondary leading-none">0.04</div>
            <div className="font-body-sm text-outline mt-xs flex items-center gap-xs">
              <span className="material-symbols-outlined text-[14px]">arrow_downward</span>
              System Nominal
            </div>
          </div>
        </div>

        {/* Threats Blocked */}
        <div className="bg-surface-container p-lg flex flex-col justify-between rounded">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-outline uppercase">Threats Blocked</span>
            <span className="material-symbols-outlined text-outline text-[20px]">block</span>
          </div>
          <div className="mt-xl">
            <div className="font-headline-lg text-[48px] text-on-surface leading-none tabular-nums">
              12,842
            </div>
            <div className="font-body-sm text-outline mt-xs">Past 24 Hours</div>
          </div>
        </div>

        {/* Active Attacks */}
        <div className="bg-surface-container p-lg flex flex-col justify-between border-l-2 border-error/50 rounded">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-error uppercase">Active Attacks</span>
            <span className="material-symbols-outlined text-error text-[20px] animate-pulse">
              warning
            </span>
          </div>
          <div className="mt-xl">
            <div className="font-headline-lg text-[48px] text-on-surface leading-none">03</div>
            <div className="font-body-sm text-outline mt-xs">DDoS Mitigation Active</div>
          </div>
        </div>

        {/* System Health */}
        <div className="bg-surface-container p-lg flex flex-col gap-md rounded">
          <span className="font-label-caps text-outline uppercase">System Health</span>
          <div className="space-y-sm">
            <div className="flex items-center justify-between">
              <span className="font-body-sm text-on-surface-variant">Firewall Core</span>
              <span className="w-2 h-2 rounded-full bg-secondary shadow-[0_0_8px_rgba(78,222,163,0.5)]"></span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-body-sm text-on-surface-variant">IPS Module</span>
              <span className="w-2 h-2 rounded-full bg-secondary shadow-[0_0_8px_rgba(78,222,163,0.5)]"></span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-body-sm text-on-surface-variant">AI Neural Engine</span>
              <span className="w-2 h-2 rounded-full bg-secondary shadow-[0_0_8px_rgba(78,222,163,0.5)]"></span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-12 gap-gutter">
        {/* Left Column (8 cols): Charts & Connection Sessions */}
        <div className="col-span-12 lg:col-span-8 flex flex-col gap-gutter">
          {/* Threat Frequency Timeline */}
          <div className="bg-surface-container p-lg relative overflow-hidden rounded border border-outline-variant/30">
            <div className="flex items-center justify-between mb-xl">
              <div className="flex flex-col">
                <span className="font-label-caps text-outline uppercase tracking-widest">
                  Threat Frequency
                </span>
                <span className="font-headline-sm text-on-surface">
                  24h Network Load Analysis
                </span>
              </div>
              <div className="flex gap-xs">
                {(["1H", "24H", "7D"] as const).map((tf) => (
                  <button
                    key={tf}
                    onClick={() => setTimeframe(tf)}
                    className={`px-sm py-xs font-label-caps text-[10px] rounded transition-colors ${
                      timeframe === tf
                        ? "bg-primary text-on-primary"
                        : "bg-surface-container-highest text-on-surface hover:bg-surface-container-high"
                    }`}
                  >
                    {tf}
                  </button>
                ))}
              </div>
            </div>

            {/* Sparkline SVG Chart */}
            <div className="h-48 w-full relative">
              <svg className="w-full h-full text-secondary" preserveAspectRatio="none" viewBox="0 0 1000 100">
                <defs>
                  <linearGradient id="grad" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style={{ stopColor: "currentColor", stopOpacity: 0.4 }} />
                    <stop offset="100%" style={{ stopColor: "currentColor", stopOpacity: 0.0 }} />
                  </linearGradient>
                </defs>
                <path
                  className="opacity-20"
                  d="M0,80 Q50,75 100,85 T200,60 T300,70 T400,30 T500,45 T600,20 T700,40 T800,10 T900,35 T1000,25 V100 H0 Z"
                  fill="url(#grad)"
                />
                <path
                  d="M0,80 Q50,75 100,85 T200,60 T300,70 T400,30 T500,45 T600,20 T700,40 T800,10 T900,35 T1000,25"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                />
                <circle cx="400" cy="30" r="4" fill="currentColor" />
                <circle cx="600" cy="20" r="4" fill="currentColor" />
                <circle cx="800" cy="10" r="4" fill="currentColor" />
              </svg>
            </div>
          </div>

          {/* Active Network Sessions Table */}
          <div className="bg-surface-container overflow-hidden rounded border border-outline-variant/30">
            <div className="p-lg border-b border-outline-variant flex items-center justify-between bg-surface-container-low">
              <span className="font-label-caps text-on-surface uppercase tracking-widest">
                Active Network Sessions
              </span>
              <div className="flex items-center gap-md">
                <span className="font-body-sm text-outline">
                  <span className="text-secondary">428</span> Live Sessions
                </span>
                <span className="material-symbols-outlined text-outline cursor-pointer hover:text-on-surface">
                  filter_list
                </span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-surface-container-highest/30">
                    <th className="p-md font-label-caps text-outline">Process / App</th>
                    <th className="p-md font-label-caps text-outline">Source IP</th>
                    <th className="p-md font-label-caps text-outline">Protocol / Port</th>
                    <th className="p-md font-label-caps text-outline">Load</th>
                    <th className="p-md font-label-caps text-outline text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="font-code-sm">
                  {connections.map((conn, idx) => (
                    <tr
                      key={idx}
                      className="border-b border-outline-variant/30 hover:bg-surface-container-high transition-colors"
                    >
                      <td className="p-md text-on-surface font-medium">{conn.process}</td>
                      <td className="p-md text-on-surface-variant">{conn.ip}</td>
                      <td className="p-md text-primary">
                        {conn.protocol}/{conn.port}
                      </td>
                      <td className="p-md">
                        <div className="w-24 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
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
                      <td className="p-md text-right">
                        <span
                          className={`px-xs py-[2px] border rounded-sm uppercase text-[10px] ${
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

        {/* Right Column (4 cols): Security Feed & Quick Controls */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-gutter">
          {/* Recent Security Threats Feed */}
          <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex flex-col gap-md">
            <div className="flex items-center justify-between border-b border-outline-variant/30 pb-sm">
              <span className="font-label-caps text-outline uppercase tracking-wider">
                Live Threat Stream
              </span>
              <span className="text-body-sm text-primary cursor-pointer hover:underline">
                View All
              </span>
            </div>

            <div className="space-y-sm">
              {threats.map((threat) => (
                <div
                  key={threat.id}
                  className="p-md bg-surface-container-low border border-outline-variant/40 rounded flex items-start justify-between"
                >
                  <div className="flex flex-col">
                    <span className="font-headline-sm text-[14px] text-on-surface">
                      {threat.name}
                    </span>
                    <span className="font-body-sm text-outline text-[12px]">
                      {threat.time}
                    </span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
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
          <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex flex-col gap-md">
            <span className="font-label-caps text-outline uppercase tracking-wider">
              Shield Configuration
            </span>
            <div className="space-y-md">
              <div className="flex items-center justify-between">
                <span className="font-body-md text-on-surface">Real-Time IPS Shield</span>
                <span className="w-10 h-6 bg-secondary/20 border border-secondary/40 rounded-full flex items-center p-1 justify-end cursor-pointer">
                  <span className="w-4 h-4 rounded-full bg-secondary"></span>
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="font-body-md text-on-surface">AI Anomaly Detector</span>
                <span className="w-10 h-6 bg-secondary/20 border border-secondary/40 rounded-full flex items-center p-1 justify-end cursor-pointer">
                  <span className="w-4 h-4 rounded-full bg-secondary"></span>
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="font-body-md text-on-surface">Strict Egress Filtering</span>
                <span className="w-10 h-6 bg-surface-container-highest border border-outline-variant rounded-full flex items-center p-1 justify-start cursor-pointer">
                  <span className="w-4 h-4 rounded-full bg-outline"></span>
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
