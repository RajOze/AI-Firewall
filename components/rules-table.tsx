"use client";

import { ScrollArea } from "./scroll-area";

const rulesData = [
  {
    rule: "Allow Chrome HTTPS",
    direction: "Outbound",
    protocol: "TCP",
    port: "443",
    application: "chrome.exe",
    action: "Allow",
    status: "Active",
  },
  {
    rule: "Block Powershell Outbound",
    direction: "Outbound",
    protocol: "TCP",
    port: "Any",
    application: "powershell.exe",
    action: "Block",
    status: "Active",
  },
  {
    rule: "Monitor RDP",
    direction: "Inbound",
    protocol: "TCP",
    port: "3389",
    application: "Any",
    action: "Monitor",
    status: "Active",
  },
  {
    rule: "Allow DNS",
    direction: "Outbound",
    protocol: "UDP",
    port: "53",
    application: "Any",
    action: "Allow",
    status: "Active",
  },
  {
    rule: "Block Tor Network",
    direction: "Outbound",
    protocol: "TCP",
    port: "9050-9051",
    application: "Any",
    action: "Block",
    status: "Active",
  },
  {
    rule: "Allow Windows Update",
    direction: "Outbound",
    protocol: "TCP",
    port: "80, 443",
    application: "svchost.exe",
    action: "Allow",
    status: "Active",
  },
];

function getActionColor(action: string) {
  switch (action) {
    case "Allow":
      return "bg-[rgba(34,197,94,0.15)] text-[#22c55e]";
    case "Block":
      return "bg-[rgba(239,68,68,0.15)] text-[#ef4444]";
    case "Monitor":
      return "bg-[rgba(245,158,11,0.15)] text-[#f59e0b]";
    default:
      return "bg-[rgba(79,124,255,0.1)] text-[#94a3b8]";
  }
}

export function RulesTable() {
  return (
    <div className="card-base">
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-[#f1f5f9]">Firewall Rules</h3>
        <p className="text-xs text-[#94a3b8] mt-1">
          Active firewall rules and policies
        </p>
      </div>

      <ScrollArea>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[rgba(79,124,255,0.1)]">
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Rule
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Direction
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Protocol
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Port
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Application
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Action
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {rulesData.map((row, idx) => (
                <tr key={idx} className="border-b border-[rgba(79,124,255,0.05)] hover:bg-[rgba(79,124,255,0.08)] transition-colors duration-150">
                  <td className="py-3 px-4 text-xs text-[#f1f5f9] font-medium">{row.rule}</td>
                  <td className="py-3 px-4 text-xs text-[#94a3b8]">
                    {row.direction}
                  </td>
                  <td className="py-3 px-4 text-xs font-semibold text-[#f1f5f9]">{row.protocol}</td>
                  <td className="py-3 px-4 text-xs font-mono text-[#f1f5f9]">{row.port}</td>
                  <td className="py-3 px-4 text-xs text-[#f1f5f9]">{row.application}</td>
                  <td className="py-3 px-4">
                    <span className={`status-badge ${getActionColor(row.action)}`}>
                      {row.action}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="inline-flex items-center gap-1.5">
                      <div className="w-2 h-2 bg-[#22c55e] rounded-full animate-pulse"></div>
                      <span className="text-xs text-[#22c55e] font-semibold">{row.status}</span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ScrollArea>
    </div>
  );
}
