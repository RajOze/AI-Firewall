"use client";

import { Cpu, HardDrive, BarChart3, Zap } from "lucide-react";

const healthMetrics = [
  { icon: Cpu, label: "CPU Usage", value: 24, unit: "%", color: "bg-[#4f7cff]" },
  { icon: HardDrive, label: "RAM Usage", value: 58, unit: "%", color: "bg-[#f59e0b]" },
  { icon: BarChart3, label: "Disk Usage", value: 42, unit: "%", color: "bg-[#7c3aed]" },
  { icon: Zap, label: "GPU Usage", value: 15, unit: "%", color: "bg-[#22c55e]" },
];

export function SystemHealth() {
  return (
    <div className="grid grid-cols-4 gap-4">
      {healthMetrics.map((metric, idx) => (
        <div key={idx} className="card-base group">
          <div className="flex items-start justify-between mb-3">
            <div>
              <div className="text-xs text-[#94a3b8] font-semibold mb-1 uppercase tracking-wider">
                {metric.label}
              </div>
              <div className="text-2xl font-bold text-[#f1f5f9]">
                {metric.value}
                <span className="text-sm text-[#94a3b8]">{metric.unit}</span>
              </div>
            </div>
            <metric.icon className="w-5 h-5 text-[#94a3b8] group-hover:text-[#4f7cff] transition-colors duration-300" />
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-[rgba(79,124,255,0.1)] rounded-full h-2">
            <div
              className={`h-2 rounded-full ${metric.color} transition-all duration-300`}
              style={{ width: `${metric.value}%` }}
            ></div>
          </div>
        </div>
      ))}
    </div>
  );
}
