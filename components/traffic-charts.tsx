"use client";

import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";

const uploadData = [
  { time: "00:00", value: 240 },
  { time: "04:00", value: 221 },
  { time: "08:00", value: 229 },
  { time: "12:00", value: 200 },
  { time: "16:00", value: 250 },
  { time: "20:00", value: 228 },
  { time: "24:00", value: 240 },
];

const downloadData = [
  { time: "00:00", value: 400 },
  { time: "04:00", value: 380 },
  { time: "08:00", value: 420 },
  { time: "12:00", value: 390 },
  { time: "16:00", value: 440 },
  { time: "20:00", value: 410 },
  { time: "24:00", value: 400 },
];

const connectionData = [
  { time: "00:00", value: 45 },
  { time: "04:00", value: 52 },
  { time: "08:00", value: 48 },
  { time: "12:00", value: 71 },
  { time: "16:00", value: 58 },
  { time: "20:00", value: 61 },
  { time: "24:00", value: 55 },
];

const blockedData = [
  { time: "00:00", value: 2 },
  { time: "04:00", value: 1 },
  { time: "08:00", value: 3 },
  { time: "12:00", value: 2 },
  { time: "16:00", value: 5 },
  { time: "20:00", value: 4 },
  { time: "24:00", value: 0 },
];

const tooltipStyle = {
  backgroundColor: "rgba(5, 8, 22, 0.9)",
  border: "1px solid rgba(79, 124, 255, 0.3)",
  borderRadius: "12px",
  boxShadow: "0 0 20px rgba(79, 124, 255, 0.2)",
};

const gridColor = "rgba(79, 124, 255, 0.05)";
const axisColor = "#94a3b8";

export function TrafficCharts() {
  return (
    <div className="grid grid-cols-2 gap-4 mb-6">
      {/* Network Upload */}
      <div className="card-base group">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-[#f1f5f9]">Network Upload</h3>
          <div className="w-2 h-2 bg-[#4f7cff] rounded-full group-hover:animate-pulse"></div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={uploadData}>
            <defs>
              <linearGradient id="colorUpload" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#4f7cff" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#4f7cff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke={axisColor} />
            <YAxis tick={{ fontSize: 12 }} stroke={axisColor} />
            <Tooltip contentStyle={tooltipStyle} />
            <Area
              type="monotone"
              dataKey="value"
              stroke="#4f7cff"
              fillOpacity={1}
              fill="url(#colorUpload)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Network Download */}
      <div className="card-base group">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-[#f1f5f9]">Network Download</h3>
          <div className="w-2 h-2 bg-[#22c55e] rounded-full group-hover:animate-pulse"></div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={downloadData}>
            <defs>
              <linearGradient id="colorDownload" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke={axisColor} />
            <YAxis tick={{ fontSize: 12 }} stroke={axisColor} />
            <Tooltip contentStyle={tooltipStyle} />
            <Area
              type="monotone"
              dataKey="value"
              stroke="#22c55e"
              fillOpacity={1}
              fill="url(#colorDownload)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Connection Count */}
      <div className="card-base group">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-[#f1f5f9]">Connection Count</h3>
          <div className="w-2 h-2 bg-[#f59e0b] rounded-full group-hover:animate-pulse"></div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={connectionData}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke={axisColor} />
            <YAxis tick={{ fontSize: 12 }} stroke={axisColor} />
            <Tooltip contentStyle={tooltipStyle} />
            <Line
              type="monotone"
              dataKey="value"
              stroke="#f59e0b"
              dot={false}
              strokeWidth={2.5}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Blocked Events */}
      <div className="card-base group">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-[#f1f5f9]">Blocked Events</h3>
          <div className="w-2 h-2 bg-[#ef4444] rounded-full group-hover:animate-pulse"></div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={blockedData}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke={axisColor} />
            <YAxis tick={{ fontSize: 12 }} stroke={axisColor} />
            <Tooltip contentStyle={tooltipStyle} />
            <Bar dataKey="value" fill="#ef4444" radius={[8, 8, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
