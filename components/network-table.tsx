"use client";

import { ScrollArea } from "./scroll-area";

const networkData = [
  {
    process: "chrome.exe",
    pid: 5832,
    localIp: "192.168.1.100",
    remoteIp: "142.251.41.14",
    port: 443,
    protocol: "TCP",
    country: "US",
    riskLevel: "low",
    status: "Allowed",
  },
  {
    process: "explorer.exe",
    pid: 1024,
    localIp: "192.168.1.100",
    remoteIp: "8.8.8.8",
    port: 53,
    protocol: "UDP",
    country: "US",
    riskLevel: "low",
    status: "Allowed",
  },
  {
    process: "powershell.exe",
    pid: 7392,
    localIp: "192.168.1.100",
    remoteIp: "13.107.42.14",
    port: 443,
    protocol: "TCP",
    country: "US",
    riskLevel: "high",
    status: "Blocked",
  },
  {
    process: "svchost.exe",
    pid: 2856,
    localIp: "192.168.1.100",
    remoteIp: "1.1.1.1",
    port: 443,
    protocol: "TCP",
    country: "US",
    riskLevel: "low",
    status: "Allowed",
  },
  {
    process: "outlook.exe",
    pid: 6124,
    localIp: "192.168.1.100",
    remoteIp: "outlook.office365.com",
    port: 993,
    protocol: "TCP",
    country: "US",
    riskLevel: "medium",
    status: "Monitoring",
  },
];

function getRiskColor(level: string) {
  switch (level) {
    case "low":
      return "text-success";
    case "medium":
      return "text-warning";
    case "high":
      return "text-critical";
    default:
      return "text-text-secondary";
  }
}

function getStatusBadgeClass(status: string) {
  switch (status) {
    case "Allowed":
      return "status-allowed";
    case "Monitoring":
      return "status-monitoring";
    case "Blocked":
      return "status-blocked";
    default:
      return "";
  }
}

export function NetworkTable() {
  return (
    <div className="card-base">
      <div className="mb-4">
        <h3 className="text-sm font-semibold">Live Network Panel</h3>
        <p className="text-xs text-text-secondary mt-1">
          Active network connections and traffic
        </p>
      </div>

      <ScrollArea>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Process
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  PID
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Local IP
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Remote IP
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Port
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Protocol
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Country
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Risk
                </th>
                <th className="text-left py-3 px-4 font-medium text-text-secondary">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {networkData.map((row, idx) => (
                <tr key={idx} className="border-b border-border hover:bg-card-dark">
                  <td className="py-3 px-4 font-mono text-xs">{row.process}</td>
                  <td className="py-3 px-4 text-xs text-text-secondary">
                    {row.pid}
                  </td>
                  <td className="py-3 px-4 text-xs font-mono">{row.localIp}</td>
                  <td className="py-3 px-4 text-xs font-mono">{row.remoteIp}</td>
                  <td className="py-3 px-4 text-xs">{row.port}</td>
                  <td className="py-3 px-4 text-xs font-medium">{row.protocol}</td>
                  <td className="py-3 px-4 text-xs">{row.country}</td>
                  <td className={`py-3 px-4 text-xs font-medium ${getRiskColor(row.riskLevel)} capitalize`}>
                    {row.riskLevel}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`status-badge ${getStatusBadgeClass(row.status)}`}>
                      {row.status}
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
