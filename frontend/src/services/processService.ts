import  type { Process } from "../types/Process";

export function getProcesses(): Process[] {
  return [
    {
      name: "chrome.exe",
      pid: 4312,
      cpu: "5%",
      memory: "240 MB",
      risk: "Safe",
    },
    {
      name: "explorer.exe",
      pid: 1180,
      cpu: "1%",
      memory: "95 MB",
      risk: "Safe",
    },
    {
      name: "powershell.exe",
      pid: 5124,
      cpu: "9%",
      memory: "62 MB",
      risk: "Medium",
    },
    {
      name: "unknown.exe",
      pid: 8231,
      cpu: "18%",
      memory: "140 MB",
      risk: "High",
    },
  ];
}