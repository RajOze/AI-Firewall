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
      return "bg-success/10 text-success";
    case "Block":
      return "bg-critical/10 text-critical";
    case "Monitor":
      return "bg-warning/10 text-warning";
    default:
      return "bg-border text-text-secondary";
  }
}

export function RulesTable() {
  return (
    <div className="card-base">
      <div className="mb-4">
        <h3 className="text-sm font-semibold">Firewall Rules</h3>
        <p className="text-xs text-text-secondary mt-1">
          Active firewall rules and policies
        </p>
      </div>

      <ScrollArea>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Rule
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Direction
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Protocol
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Port
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Application
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Action
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {rulesData.map((row, idx) => (
                <tr key={idx} className="border-b border-border hover:bg-card-dark">
                  <td className="py-3 px-4 text-xs">{row.rule}</td>
                  <td className="py-3 px-4 text-xs text-text-secondary">
                    {row.direction}
                  </td>
                  <td className="py-3 px-4 text-xs font-medium">{row.protocol}</td>
                  <td className="py-3 px-4 text-xs font-mono">{row.port}</td>
                  <td className="py-3 px-4 text-xs">{row.application}</td>
                  <td className="py-3 px-4">
                    <span className={`status-badge ${getActionColor(row.action)}`}>
                      {row.action}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="inline-flex items-center gap-1.5">
                      <div className="w-2 h-2 bg-success rounded-full"></div>
                      <span className="text-xs text-success">{row.status}</span>
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
