import type { Connection } from "../types/Connection";

export function getConnections(): Connection[] {
  return [
    {
      process: "chrome.exe",
      ip: "142.250.183.14",
      port: 443,
      protocol: "HTTPS",
      status: "Allowed",
    },
    {
      process: "discord.exe",
      ip: "162.159.137.232",
      port: 443,
      protocol: "HTTPS",
      status: "Allowed",
    },
    {
      process: "powershell.exe",
      ip: "10.10.25.6",
      port: 4444,
      protocol: "TCP",
      status: "Monitoring",
    },
    {
      process: "unknown.exe",
      ip: "185.76.8.22",
      port: 8080,
      protocol: "TCP",
      status: "Blocked",
    },
  ];
}