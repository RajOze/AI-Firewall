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

export function TrafficCharts() {
  return (
    <div className="grid grid-cols-2 gap-4 mb-6">
      {/* Network Upload */}
      <div className="card-base">
        <h3 className="text-sm font-semibold mb-4">Network Upload</h3>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={uploadData}>
            <defs>
              <linearGradient id="colorUpload" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <YAxis tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1a1a1a",
                border: "1px solid #2a2a2a",
                borderRadius: "8px",
              }}
            />
            <Area
              type="monotone"
              dataKey="value"
              stroke="#3b82f6"
              fillOpacity={1}
              fill="url(#colorUpload)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Network Download */}
      <div className="card-base">
        <h3 className="text-sm font-semibold mb-4">Network Download</h3>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={downloadData}>
            <defs>
              <linearGradient id="colorDownload" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <YAxis tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1a1a1a",
                border: "1px solid #2a2a2a",
                borderRadius: "8px",
              }}
            />
            <Area
              type="monotone"
              dataKey="value"
              stroke="#10b981"
              fillOpacity={1}
              fill="url(#colorDownload)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Connection Count */}
      <div className="card-base">
        <h3 className="text-sm font-semibold mb-4">Connection Count</h3>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={connectionData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <YAxis tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1a1a1a",
                border: "1px solid #2a2a2a",
                borderRadius: "8px",
              }}
            />
            <Line
              type="monotone"
              dataKey="value"
              stroke="#f59e0b"
              dot={false}
              strokeWidth={2}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Blocked Events */}
      <div className="card-base">
        <h3 className="text-sm font-semibold mb-4">Blocked Events</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={blockedData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <YAxis tick={{ fontSize: 12 }} stroke="#9ca3af" />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1a1a1a",
                border: "1px solid #2a2a2a",
                borderRadius: "8px",
              }}
            />
            <Bar dataKey="value" fill="#ef4444" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
