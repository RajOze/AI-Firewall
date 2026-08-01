"use client";

import { Cpu, HardDrive, BarChart3, Zap } from "lucide-react";

const healthMetrics = [
  { icon: Cpu, label: "CPU Usage", value: 24, unit: "%", color: "bg-primary" },
  { icon: HardDrive, label: "RAM Usage", value: 58, unit: "%", color: "bg-warning" },
  { icon: BarChart3, label: "Disk Usage", value: 42, unit: "%", color: "bg-primary" },
  { icon: Zap, label: "GPU Usage", value: 15, unit: "%", color: "bg-success" },
];

export function SystemHealth() {
  return (
    <div className="grid grid-cols-4 gap-4">
      {healthMetrics.map((metric, idx) => (
        <div key={idx} className="card-base">
          <div className="flex items-start justify-between mb-3">
            <div>
              <div className="text-xs text-text-secondary font-medium mb-1">
                {metric.label}
              </div>
              <div className="text-2xl font-bold">
                {metric.value}
                <span className="text-sm text-text-secondary">{metric.unit}</span>
              </div>
            </div>
            <metric.icon className="w-5 h-5 text-text-secondary" />
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-card-dark rounded-full h-1.5">
            <div
              className={`h-1.5 rounded-full ${metric.color}`}
              style={{ width: `${metric.value}%` }}
            ></div>
          </div>
        </div>
      ))}
    </div>
  );
}
