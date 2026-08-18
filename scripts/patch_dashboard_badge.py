from pathlib import Path

dashboard_code = '''import React from 'react';
import { useWebSocketStream } from '../hooks/useWebSocketStream';
import { useTelemetryStore } from '../stores/useTelemetryStore';
import { Shield, Activity, Radio, CheckCircle, ShieldAlert, Cpu } from 'lucide-react';

export default function DashboardPage() {
  // Initialize stream listener
  useWebSocketStream();

  // Read all reactive state directly from Zustand store
  const { 
    isConnected,
    activeConnectionsCount, 
    overallRiskScore, 
    threatsCount, 
    recentEvents, 
    liveSessions 
  } = useTelemetryStore();

  const riskPercentage = Math.round(overallRiskScore * 100);

  return (
    <div className="flex flex-col w-full gap-6 p-6 text-on-surface">
      {/* Real-time Status Banner */}
      <div className="bg-surface-container p-4 rounded-lg border border-outline-variant/30 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-primary" />
          <div>
            <h1 className="text-xl font-bold font-headline-lg">Sentinel AI Real-Time SOC Dashboard</h1>
            <p className="text-xs text-outline">Continuous kernel packet inspection & autonomous ML threat mitigation</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-3 h-3 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
          <span className={`text-xs font-mono font-semibold ${isConnected ? 'text-emerald-400' : 'text-red-400'}`}>
            {isConnected ? 'STREAM CONNECTED (WS LIVE)' : 'STREAM DISCONNECTED'}
          </span>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-surface-container p-4 rounded-lg border border-outline-variant/20 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-outline">Active Sockets</span>
            <div className="text-2xl font-bold mt-1">{activeConnectionsCount}</div>
          </div>
          <Activity className="w-8 h-8 text-primary opacity-80" />
        </div>

        <div className="bg-surface-container p-4 rounded-lg border border-outline-variant/20 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-outline">Behavioral Threat Score</span>
            <div className={`text-2xl font-bold mt-1 ${riskPercentage > 60 ? 'text-red-500' : riskPercentage > 30 ? 'text-amber-500' : 'text-emerald-500'}`}>
              {riskPercentage}%
            </div>
          </div>
          <Radio className="w-8 h-8 text-secondary opacity-80" />
        </div>

        <div className="bg-surface-container p-4 rounded-lg border border-outline-variant/20 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-outline">Autonomous Actions</span>
            <div className="text-2xl font-bold mt-1 text-red-400">{threatsCount}</div>
          </div>
          <ShieldAlert className="w-8 h-8 text-red-400 opacity-80" />
        </div>

        <div className="bg-surface-container p-4 rounded-lg border border-outline-variant/20 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-outline">Engine Health</span>
            <div className="text-sm font-bold text-emerald-400 mt-1 flex items-center gap-1">
              <CheckCircle className="w-4 h-4" /> Operational
            </div>
          </div>
          <Cpu className="w-8 h-8 text-emerald-400 opacity-80" />
        </div>
      </div>

      {/* Live Connection Sessions & Event Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Telemetry Table */}
        <div className="lg:col-span-2 bg-surface-container p-5 rounded-lg border border-outline-variant/20">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider font-mono">Live Network Sockets</h2>
            <span className="text-xs text-outline">{liveSessions.length} active sessions</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-surface-container-low border-b border-outline-variant/30 text-outline">
                <tr>
                  <th className="py-2 px-3">Process</th>
                  <th className="py-2 px-3">Remote Target</th>
                  <th className="py-2 px-3">Proto</th>
                  <th className="py-2 px-3">Risk</th>
                  <th className="py-2 px-3">Policy Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/10 font-mono">
                {liveSessions.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center py-8 text-outline">
                      Listening on WebSocket feed... Waiting for network events.
                    </td>
                  </tr>
                ) : (
                  liveSessions.map((session, idx) => (
                    <tr key={idx} className="hover:bg-surface-container-high/40 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-on-surface">{session.process}</td>
                      <td className="py-2.5 px-3">{session.ip}:{session.port}</td>
                      <td className="py-2.5 px-3">{session.protocol}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                          session.riskScore > 0.7 ? 'bg-red-950 text-red-400 border border-red-800' :
                          session.riskScore > 0.4 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                          'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}>
                          {(session.riskScore * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`font-semibold ${
                          session.status === 'Blocked' ? 'text-red-400' :
                          session.status === 'Monitoring' ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {session.status}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Real-time Event Feed */}
        <div className="bg-surface-container p-5 rounded-lg border border-outline-variant/20 flex flex-col">
          <h2 className="text-sm font-semibold uppercase tracking-wider font-mono mb-4">Event Dispatch Feed</h2>
          <div className="flex-1 overflow-y-auto max-h-[400px] space-y-2">
            {recentEvents.length === 0 ? (
              <p className="text-xs text-outline text-center py-10 font-mono">No incoming events received yet</p>
            ) : (
              recentEvents.map((evt, idx) => (
                <div key={idx} className="p-2.5 bg-surface-container-low rounded border border-outline-variant/10 text-xs">
                  <div className="flex items-center justify-between text-outline text-[10px]">
                    <span className="font-mono text-primary font-semibold">{evt.topic}</span>
                    <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <pre className="text-[11px] mt-1 text-on-surface-variant font-mono truncate">
                    {JSON.stringify(evt.data)}
                  </pre>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
'''

Path("frontend/src/pages/DashboardPage.tsx").write_text(dashboard_code, encoding="utf-8")
print("Successfully patched DashboardPage.tsx")
