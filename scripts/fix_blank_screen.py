from pathlib import Path

files = {}

# 1. frontend/src/main.tsx - Clean Root Mount
files['frontend/src/main.tsx'] = '''import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
'''

# 2. frontend/src/App.tsx - Robust Router + Navigation + Error Boundary
files['frontend/src/App.tsx'] = '''import React, { Component, ErrorInfo, ReactNode } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import DashboardPage from './pages/DashboardPage';
import FirewallPage from './pages/FirewallPage';
import { Shield, LayoutDashboard, ShieldCheck, AlertOctagon, Terminal } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public state: ErrorBoundaryState = { hasError: false, error: null };

  public static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[Sentinel ErrorBoundary Caught]:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#090d16] text-red-400 p-8 flex flex-col items-center justify-center font-mono">
          <AlertOctagon className="w-12 h-12 text-red-500 mb-4 animate-pulse" />
          <h1 className="text-xl font-bold mb-2">Sentinel UI Runtime Exception</h1>
          <p className="text-xs text-slate-400 max-w-lg text-center mb-4">
            {this.state.error?.message || 'An unexpected rendering error occurred.'}
          </p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs transition-colors"
          >
            Reload Dashboard
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Firewall', path: '/firewall', icon: ShieldCheck },
  ];

  return (
    <div className="flex min-h-screen bg-[#0b0f19] text-slate-100 font-sans antialiased">
      {/* Left Sidebar */}
      <aside className="w-64 border-r border-slate-800/80 bg-[#111625] flex flex-col justify-between p-4 shrink-0 shadow-xl">
        <div>
          {/* Logo & Brand */}
          <div className="flex items-center gap-3 px-3 py-4 mb-6">
            <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-bold text-base tracking-wide text-white font-mono">Sentinel AI</h1>
              <p className="text-[10px] text-slate-400 font-mono">Autonomous Host Defense</p>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="space-y-1">
            <span className="px-3 text-[10px] font-mono uppercase text-slate-500 font-semibold tracking-wider">
              System Console
            </span>
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-semibold font-mono transition-all ${
                    active
                      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-inner'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.name}
                </Link>
              );
            })}
          </div>
        </div>

        {/* Footer Status */}
        <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl text-xs font-mono text-slate-400">
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-blue-400" /> ENGINE
            </span>
            <span className="text-emerald-400 font-bold">OPERATIONAL</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1 truncate">SENTINEL-X1-MAIN</p>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-x-hidden bg-[#0b0f19]">
        {children}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/firewall" element={<FirewallPage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
'''

# 3. frontend/src/pages/DashboardPage.tsx - Hardened & Null-Safe
files['frontend/src/pages/DashboardPage.tsx'] = '''import React, { useState } from 'react';
import { useWebSocketStream } from '../hooks/useWebSocketStream';
import { useTelemetryStore, LiveSession } from '../stores/useTelemetryStore';
import { ThreatInspectorModal } from '../components/ThreatInspectorModal';
import { Shield, Activity, Radio, CheckCircle, ShieldAlert, Cpu, Eye } from 'lucide-react';

export default function DashboardPage() {
  useWebSocketStream();

  const isConnected = useTelemetryStore((s) => s.isConnected);
  const activeConnectionsCount = useTelemetryStore((s) => s.activeConnectionsCount);
  const overallRiskScore = useTelemetryStore((s) => s.overallRiskScore ?? 0.04);
  const threatsCount = useTelemetryStore((s) => s.threatsCount ?? 0);
  const recentEvents = useTelemetryStore((s) => s.recentEvents ?? []);
  const liveSessions = useTelemetryStore((s) => s.liveSessions ?? []);

  const [selectedSession, setSelectedSession] = useState<LiveSession | null>(null);
  const riskPercentage = Math.round(overallRiskScore * 100);

  return (
    <div className="flex flex-col w-full gap-6 p-6 text-slate-100">
      {/* Real-time Status Banner */}
      <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-blue-400" />
          <div>
            <h1 className="text-lg font-bold font-mono tracking-tight">Sentinel AI Real-Time SOC Dashboard</h1>
            <p className="text-xs text-slate-400 font-mono">Continuous kernel packet inspection & autonomous ML threat mitigation</p>
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
        <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400">Active Sockets</span>
            <div className="text-2xl font-bold font-mono mt-1">{activeConnectionsCount}</div>
          </div>
          <Activity className="w-7 h-7 text-blue-400 opacity-80" />
        </div>

        <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400">Threat Score</span>
            <div className={`text-2xl font-bold font-mono mt-1 ${riskPercentage > 60 ? 'text-red-400' : riskPercentage > 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
              {riskPercentage}%
            </div>
          </div>
          <Radio className="w-7 h-7 text-indigo-400 opacity-80" />
        </div>

        <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400">Threat Actions</span>
            <div className="text-2xl font-bold font-mono mt-1 text-red-400">{threatsCount}</div>
          </div>
          <ShieldAlert className="w-7 h-7 text-red-400 opacity-80" />
        </div>

        <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400">Engine Health</span>
            <div className="text-xs font-bold font-mono text-emerald-400 mt-1 flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" /> Operational
            </div>
          </div>
          <Cpu className="w-7 h-7 text-emerald-400 opacity-80" />
        </div>
      </div>

      {/* Live Sockets & Event Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Telemetry Table */}
        <div className="lg:col-span-2 bg-[#111625] p-5 rounded-xl border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-300">Live Network Sockets</h2>
            <span className="text-xs text-slate-400 font-mono">{liveSessions.length} active sessions</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#161c2e] border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2.5 px-3">Process</th>
                  <th className="py-2.5 px-3">Remote Target</th>
                  <th className="py-2.5 px-3">Proto</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {liveSessions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-10 text-slate-500">
                      Listening for OS network sockets...
                    </td>
                  </tr>
                ) : (
                  liveSessions.map((session, idx) => (
                    <tr
                      key={idx}
                      onClick={() => setSelectedSession(session)}
                      className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                    >
                      <td className="py-2.5 px-3 font-semibold text-slate-200 group-hover:text-blue-400 transition-colors">
                        {session.process}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{session.ip}:{session.port}</td>
                      <td className="py-2.5 px-3 text-slate-400">{session.protocol}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          session.riskScore > 0.7 ? 'bg-red-950/80 text-red-400 border border-red-800' :
                          session.riskScore > 0.4 ? 'bg-amber-950/80 text-amber-400 border border-amber-800' :
                          'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
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
                      <td className="py-2.5 px-3 text-right">
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 group-hover:text-blue-400 border border-slate-700 inline-flex items-center gap-1 transition-all">
                          <Eye className="w-3 h-3" /> Inspect
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
        <div className="bg-[#111625] p-5 rounded-xl border border-slate-800 shadow-sm flex flex-col">
          <h2 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-300 mb-4">Event Dispatch Feed</h2>
          <div className="flex-1 overflow-y-auto max-h-[420px] space-y-2 font-mono">
            {recentEvents.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-12">Waiting for telemetry stream...</p>
            ) : (
              recentEvents.map((evt, idx) => (
                <div key={idx} className="p-2.5 bg-[#161c2e] rounded-lg border border-slate-800 text-xs">
                  <div className="flex items-center justify-between text-slate-400 text-[10px]">
                    <span className="text-blue-400 font-bold">{evt.topic}</span>
                    <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <pre className="text-[11px] mt-1 text-slate-300 truncate">
                    {JSON.stringify(evt.data)}
                  </pre>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Threat Inspector Modal Drawer */}
      <ThreatInspectorModal
        session={selectedSession}
        onClose={() => setSelectedSession(null)}
      />
    </div>
  );
}
'''

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully updated: {rel_path}')
