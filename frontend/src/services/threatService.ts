import type { Threat } from "../types/Threat";

export function getThreats(): Threat[] {
  return [
    {
      id: 1,
      name: "Trojan.Win32",
      severity: "High",
      time: "2 min ago",
    },
    {
      id: 2,
      name: "Suspicious PowerShell",
      severity: "Medium",
      time: "8 min ago",
    },
    {
      id: 3,
      name: "Chrome.exe",
      severity: "Safe",
      time: "12 min ago",
    },
  ];
}