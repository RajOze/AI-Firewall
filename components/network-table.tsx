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
      return "text-[#22c55e]";
    case "medium":
      return "text-[#f59e0b]";
    case "high":
      return "text-[#ef4444]";
    default:
      return "text-[#94a3b8]";
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
        <h3 className="text-sm font-semibold text-[#f1f5f9]">Live Network Panel</h3>
        <p className="text-xs text-[#94a3b8] mt-1">
          Active network connections and traffic
        </p>
      </div>

      <ScrollArea>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[rgba(79,124,255,0.1)]">
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Process
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  PID
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Local IP
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Remote IP
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Port
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Protocol
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Country
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Risk
                </th>
                <th className="text-left py-3 px-4 font-semibold text-[#94a3b8] uppercase text-xs tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {networkData.map((row, idx) => (
                <tr key={idx} className="border-b border-[rgba(79,124,255,0.05)] hover:bg-[rgba(79,124,255,0.08)] transition-colors duration-150">
                  <td className="py-3 px-4 font-mono text-xs text-[#f1f5f9]">{row.process}</td>
                  <td className="py-3 px-4 text-xs text-[#94a3b8]">
                    {row.pid}
                  </td>
                  <td className="py-3 px-4 text-xs font-mono text-[#f1f5f9]">{row.localIp}</td>
                  <td className="py-3 px-4 text-xs font-mono text-[#f1f5f9]">{row.remoteIp}</td>
                  <td className="py-3 px-4 text-xs text-[#f1f5f9]">{row.port}</td>
                  <td className="py-3 px-4 text-xs font-medium text-[#f1f5f9]">{row.protocol}</td>
                  <td className="py-3 px-4 text-xs text-[#f1f5f9]">{row.country}</td>
                  <td className={`py-3 px-4 text-xs font-semibold ${getRiskColor(row.riskLevel)} capitalize`}>
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
