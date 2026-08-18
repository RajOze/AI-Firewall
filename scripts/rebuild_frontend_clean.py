from pathlib import Path

files = {}

# 1. frontend/index.html
files['frontend/index.html'] = '''<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Sentinel AI Real-Time SOC</title>
  </head>
  <body class="bg-[#0b0f19] text-slate-100 antialiased selection:bg-blue-500 selection:text-white">
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
'''

# 2. frontend/src/main.tsx
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

# 3. frontend/src/services/api.ts
files['frontend/src/services/api.ts'] = '''export interface ThreatEvaluationRequest {
  process_name: string;
  process_id?: number | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol?: string;
  fusion_risk_score?: number;
  max_z_score?: number;
  anomaly_score?: number;
  reputation_score?: number;
  behavior_findings?: string[];
  extra_context?: Record<string, any>;
}

export interface MITRETechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  reference_url?: string;
}

export interface ThreatEvidence {
  source: string;
  metric_name: string;
  observed_value: any;
  threshold_or_baseline?: any;
  anomaly_contribution: number;
}

export interface ThreatAdvisory {
  advisory_id: string;
  timestamp: string;
  process_name: string;
  process_id?: number | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol: string;
  severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence_score: number;
  recommended_action: 'ALLOW' | 'MONITOR' | 'ALERT' | 'BLOCK_RECOMMENDED' | 'QUARANTINE_RECOMMENDED';
  summary: string;
  detailed_reasoning: string;
  mitre_mappings: MITRETechnique[];
  evidence: ThreatEvidence[];
  provider_name: string;
  inference_latency_ms: number;
  is_fallback: boolean;
  is_advisory_only: boolean;
}

export interface PolicyDecision {
  decision_id: string;
  timestamp: string;
  process_name: string;
  process_id?: number | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  action: 'ENFORCE_BLOCK' | 'QUEUE_FOR_APPROVAL' | 'MONITOR_ONLY' | 'IGNORE_WHITELISTED' | 'RATE_LIMITED';
  reason: string;
  is_blocked: boolean;
  mutation_rule_name?: string | null;
}

export interface FirewallRuleSummary {
  name: string;
  display_name?: string;
  direction?: 'inbound' | 'outbound';
  action?: 'allow' | 'block';
  enabled?: boolean;
  profile?: string;
  remote_address?: string;
  remote_port?: string;
}

const API_BASE = 'http://127.0.0.1:8000';

export const api = {
  evaluateThreat: async (req: ThreatEvaluationRequest, forceFallback = false): Promise<ThreatAdvisory> => {
    const res = await fetch(`${API_BASE}/api/v1/ai/advisory/evaluate?force_fallback=${forceFallback}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`Evaluation error: ${res.statusText}`);
    return res.json();
  },

  enforcePolicy: async (advisory: ThreatAdvisory): Promise<PolicyDecision> => {
    const res = await fetch(`${API_BASE}/api/v1/policy/evaluate-and-enforce`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(advisory),
    });
    if (!res.ok) throw new Error(`Enforcement error: ${res.statusText}`);
    return res.json();
  },

  getFirewallRules: async (limit = 100): Promise<{ rules: FirewallRuleSummary[]; count: number }> => {
    const res = await fetch(`${API_BASE}/firewall/rules?limit=${limit}`);
    if (!res.ok) throw new Error(`Rule fetch failed: ${res.statusText}`);
    return res.json();
  },
};
'''

# 4. frontend/src/stores/useTelemetryStore.ts
files['frontend/src/stores/useTelemetryStore.ts'] = '''import { create } from 'zustand';

export interface TelemetryEvent {
  topic: string;
  timestamp: string;
  data: Record<string, any>;
}

export interface LiveSession {
  process: string;
  ip: string;
  protocol: string;
  port: number | string;
  status: 'Allowed' | 'Monitoring' | 'Blocked';
  riskScore: number;
}

export interface TelemetryState {
  isConnected: boolean;
  activeConnectionsCount: number;
  overallRiskScore: number;
  threatsCount: number;
  recentEvents: TelemetryEvent[];
  liveSessions: LiveSession[];

  setConnected: (status: boolean) => void;
  ingestStreamEvent: (topic: string, data: Record<string, any>) => void;
  clearEvents: () => void;
}

export const useTelemetryStore = create<TelemetryState>((set) => ({
  isConnected: false,
  activeConnectionsCount: 0,
  overallRiskScore: 0.04,
  threatsCount: 0,
  recentEvents: [],
  liveSessions: [],

  setConnected: (status) => set({ isConnected: status }),

  ingestStreamEvent: (topic, data) =>
    set((state) => {
      const newEvent: TelemetryEvent = {
        topic: topic || 'TELEMETRY',
        timestamp: new Date().toISOString(),
        data: typeof data === 'object' && data !== null ? data : { payload: data },
      };
      const updatedEvents = [newEvent, ...state.recentEvents].slice(0, 100);

      let newLiveSessions = state.liveSessions;
      let newThreatCount = state.threatsCount;
      let newRiskScore = state.overallRiskScore;

      if (topic === 'NETWORK_CONNECTION' || topic === 'PROCESS_START') {
        const session: LiveSession = {
          process: data?.process_name || data?.process || 'system.exe',
          ip: data?.remote_address || data?.ip || '127.0.0.1',
          protocol: data?.protocol || 'TCP',
          port: data?.remote_port || data?.port || 0,
          status: (data?.risk_score ?? 0) > 0.7 ? 'Blocked' : (data?.risk_score ?? 0) > 0.4 ? 'Monitoring' : 'Allowed',
          riskScore: data?.risk_score ?? 0.0,
        };
        newLiveSessions = [session, ...state.liveSessions].slice(0, 50);
      }

      if (topic === 'AI_ADVISORY' || topic === 'POLICY_VIOLATION') {
        newThreatCount += 1;
        if (data?.severity === 'CRITICAL' || data?.severity === 'HIGH') {
          newRiskScore = Math.min(1.0, newRiskScore + 0.15);
        }
      }

      return {
        isConnected: true,
        recentEvents: updatedEvents,
        liveSessions: newLiveSessions,
        threatsCount: newThreatCount,
        overallRiskScore: newRiskScore,
        activeConnectionsCount: newLiveSessions.length,
      };
    }),

  clearEvents: () => set({ recentEvents: [], liveSessions: [] }),
}));
'''

# 5. frontend/src/hooks/useWebSocketStream.ts
files['frontend/src/hooks/useWebSocketStream.ts'] = '''import { useEffect, useRef } from 'react';
import { useTelemetryStore } from '../stores/useTelemetryStore';

export function useWebSocketStream() {
  const ingestStreamEvent = useTelemetryStore((s) => s.ingestStreamEvent);
  const setConnected = useTelemetryStore((s) => s.setConnected);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<any>(null);

  useEffect(() => {
    let isMounted = true;

    function connect() {
      if (!isMounted) return;
      const wsUrl = 'ws://127.0.0.1:8000/api/v1/stream/ws?topics=*';

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isMounted) {
            setConnected(true);
            console.log('[Sentinel WS] Telemetry stream online');
          }
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const parsed = JSON.parse(event.data);
            const topic = parsed.topic || parsed.event_type || 'NETWORK_CONNECTION';
            const data = parsed.data || parsed.payload || parsed;
            ingestStreamEvent(topic, data);
          } catch (err) {
            console.warn('[Sentinel WS] Frame parse error:', err);
          }
        };

        ws.onerror = (err) => {
          console.warn('[Sentinel WS] Socket error:', err);
        };

        ws.onclose = () => {
          if (isMounted) {
            setConnected(false);
            reconnectTimerRef.current = setTimeout(connect, 3000);
          }
        };
      } catch (err) {
        if (isMounted) {
          reconnectTimerRef.current = setTimeout(connect, 3000);
        }
      }
    }

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [ingestStreamEvent, setConnected]);
}
'''

# 6. frontend/src/components/ThreatInspectorModal.tsx
files['frontend/src/components/ThreatInspectorModal.tsx'] = '''import React, { useState, useEffect } from 'react';
import { ThreatAdvisory, PolicyDecision, api } from '../services/api';
import { LiveSession } from '../stores/useTelemetryStore';
import { 
  ShieldAlert, 
  Cpu, 
  ExternalLink, 
  CheckCircle, 
  X, 
  Lock, 
  Loader2,
  AlertTriangle 
} from 'lucide-react';

interface ThreatInspectorModalProps {
  session: LiveSession | null;
  onClose: () => void;
}

export const ThreatInspectorModal: React.FC<ThreatInspectorModalProps> = ({ session, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [advisory, setAdvisory] = useState<ThreatAdvisory | null>(null);
  const [enforcing, setEnforcing] = useState(false);
  const [decision, setDecision] = useState<PolicyDecision | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!session) return;
    setAdvisory(null);
    setDecision(null);
    setError(null);
    setLoading(true);

    const rawPort = typeof session.port === 'number' ? session.port : parseInt(String(session.port) || '0', 10);
    const validPort = rawPort >= 1 && rawPort <= 65535 ? rawPort : null;
    const cleanIp = session.ip && session.ip !== '*' && session.ip !== '*:0' ? session.ip : null;

    api.evaluateThreat({
      process_name: session.process,
      destination_ip: cleanIp,
      destination_port: validPort,
      protocol: session.protocol,
      fusion_risk_score: session.riskScore * 100,
      anomaly_score: session.riskScore,
      max_z_score: session.riskScore > 0.6 ? 4.5 : 1.2,
      behavior_findings: session.riskScore > 0.6 ? ['ELEVATED_OUTBOUND_FREQUENCY'] : [],
    })
      .then((res) => setAdvisory(res))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [session]);

  const handleEnforceBlock = async () => {
    if (!advisory) return;
    setEnforcing(true);
    setError(null);
    try {
      const dec = await api.enforcePolicy(advisory);
      setDecision(dec);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setEnforcing(false);
    }
  };

  if (!session) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#111625] border border-slate-800 w-full max-w-2xl rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-[#161c2e]">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider">AI Threat Inspector & Advisory</h2>
              <span className="text-xs text-slate-400 font-mono">{session.process} ({session.ip}:{session.port})</span>
            </div>
          </div>
          <button 
            onClick={onClose} 
            className="p-1.5 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto max-h-[70vh] space-y-5">
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 space-y-3">
              <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
              <p className="text-xs font-mono text-slate-400">Evaluating Telemetry via AIRouter...</p>
            </div>
          )}

          {error && (
            <div className="p-4 bg-red-950/50 border border-red-800/60 rounded-xl text-red-400 text-xs font-mono flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Analysis Notice</p>
                <p className="opacity-90">{error}</p>
              </div>
            </div>
          )}

          {advisory && !loading && (
            <>
              {/* Executive Assessment Card */}
              <div className="p-4 bg-[#161c2e] rounded-xl border border-slate-800 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                      advisory.severity === 'CRITICAL' || advisory.severity === 'HIGH' ? 'bg-red-950 text-red-400 border border-red-800' :
                      advisory.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                      'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      {advisory.severity} SEVERITY
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      Confidence: {(advisory.confidence_score * 100).toFixed(0)}%
                    </span>
                    {advisory.is_fallback && (
                      <span className="text-[10px] px-2 py-0.5 bg-slate-800 text-slate-400 rounded font-mono">
                        Local Heuristics
                      </span>
                    )}
                  </div>
                  <p className="text-xs font-semibold text-slate-100 mt-2">{advisory.summary}</p>
                </div>
                <Cpu className="w-6 h-6 text-blue-400 opacity-80 shrink-0 mt-1" />
              </div>

              {/* Analytical Reasoning */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-mono uppercase text-slate-400 font-semibold">Detailed AI Reasoning</h3>
                <div className="p-3.5 bg-[#161c2e] rounded-xl border border-slate-800 text-xs leading-relaxed text-slate-300 font-mono">
                  {advisory.detailed_reasoning}
                </div>
              </div>

              {/* MITRE ATT&CK Mappings */}
              {advisory.mitre_mappings && advisory.mitre_mappings.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-mono uppercase text-slate-400 font-semibold">MITRE ATT&CK Techniques</h3>
                  <div className="flex flex-wrap gap-2">
                    {advisory.mitre_mappings.map((m, i) => (
                      <a 
                        key={i} 
                        href={m.reference_url || '#'} 
                        target="_blank" 
                        rel="noreferrer"
                        className="flex items-center gap-1.5 px-3 py-1 bg-[#161c2e] rounded-lg border border-slate-800 text-xs font-mono hover:border-blue-500 transition-colors text-blue-400"
                      >
                        <span className="font-bold">{m.technique_id}</span>: {m.technique_name}
                        <ExternalLink className="w-3 h-3 ml-0.5 opacity-60" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Evidence Metrics */}
              {advisory.evidence && advisory.evidence.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-mono uppercase text-slate-400 font-semibold">Observed Telemetry Evidence</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {advisory.evidence.map((ev, i) => (
                      <div key={i} className="p-3 bg-[#161c2e] rounded-xl border border-slate-800 text-xs font-mono">
                        <div className="text-[10px] text-slate-400 uppercase">{ev.source}</div>
                        <div className="text-xs font-semibold text-slate-200 mt-0.5">{ev.metric_name} = {String(ev.observed_value)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Enforcement Result */}
              {decision && (
                <div className={`p-4 rounded-xl border text-xs font-mono ${
                  decision.is_blocked ? 'bg-red-950/40 border-red-800 text-red-300' : 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                }`}>
                  <div className="font-bold uppercase flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" /> Action: {decision.action}
                  </div>
                  <p className="mt-1 text-[11px] opacity-90">{decision.reason}</p>
                  {decision.mutation_rule_name && (
                    <p className="mt-1 font-bold text-[10px] text-blue-400">Enforced Rule: {decision.mutation_rule_name}</p>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-slate-800 flex items-center justify-between bg-[#161c2e]">
          <span className="text-[11px] font-mono text-slate-500">Deterministic Policy Shield v0.1.0</span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono transition-colors text-slate-300"
            >
              Close
            </button>
            <button
              onClick={handleEnforceBlock}
              disabled={loading || enforcing || decision?.is_blocked}
              className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
            >
              {enforcing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
              {decision?.is_blocked ? 'Rule Enforced' : 'Enforce Policy Block'}
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
'''

# 7. frontend/src/pages/DashboardPage.tsx
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
            <h1 className="text-lg font-bold font-mono tracking-tight text-white">Sentinel AI Real-Time SOC Dashboard</h1>
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
            <div className="text-2xl font-bold font-mono mt-1 text-white">{activeConnectionsCount}</div>
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

# 8. frontend/src/pages/FirewallPage.tsx
files['frontend/src/pages/FirewallPage.tsx'] = '''import React, { useState, useEffect } from 'react';
import { api, FirewallRuleSummary } from '../services/api';
import { Shield, Search, RefreshCw, AlertCircle, CheckCircle2, ArrowUpRight, ArrowDownLeft } from 'lucide-react';

export default function FirewallPage() {
  const [rules, setRules] = useState<FirewallRuleSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState<'all' | 'block' | 'allow'>('all');
  const [filterDirection, setFilterDirection] = useState<'all' | 'inbound' | 'outbound'>('all');
  const [error, setError] = useState<string | null>(null);

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getFirewallRules(200);
      setRules(data.rules || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load firewall rules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const filteredRules = rules.filter((r) => {
    const nameMatch = (r.name || '').toLowerCase().includes(search.toLowerCase()) || 
                      (r.display_name || '').toLowerCase().includes(search.toLowerCase());
    const actionMatch = filterAction === 'all' || (r.action || '').toLowerCase() === filterAction;
    const directionMatch = filterDirection === 'all' || (r.direction || '').toLowerCase() === filterDirection;
    return nameMatch && actionMatch && directionMatch;
  });

  return (
    <div className="flex flex-col w-full gap-6 p-6 text-slate-100 font-mono">
      {/* Top Banner */}
      <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-blue-400" />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">Windows Firewall Management</h1>
            <p className="text-xs text-slate-400">Real-time NetSecurity rule inventory & policy synchronization</p>
          </div>
        </div>
        <button 
          onClick={fetchRules}
          disabled={loading}
          className="px-3.5 py-1.5 bg-[#161c2e] hover:bg-slate-800 rounded-lg border border-slate-700 text-xs font-semibold flex items-center gap-2 transition-colors disabled:opacity-50 text-slate-200"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Sync Rules
        </button>
      </div>

      {error && (
        <div className="p-4 bg-red-950/50 border border-red-800/60 rounded-xl text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input 
            type="text"
            placeholder="Search rules by name or display tag..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#161c2e] border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Action:</span>
          {(['all', 'block', 'allow'] as const).map((act) => (
            <button
              key={act}
              onClick={() => setFilterAction(act)}
              className={`px-2.5 py-1 rounded uppercase text-[10px] font-bold transition-colors ${
                filterAction === act 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-[#161c2e] text-slate-400 hover:text-white'
              }`}
            >
              {act}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Direction:</span>
          {(['all', 'inbound', 'outbound'] as const).map((dir) => (
            <button
              key={dir}
              onClick={() => setFilterDirection(dir)}
              className={`px-2.5 py-1 rounded uppercase text-[10px] font-bold transition-colors ${
                filterDirection === dir 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-[#161c2e] text-slate-400 hover:text-white'
              }`}
            >
              {dir}
            </button>
          ))}
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-[#111625] p-5 rounded-xl border border-slate-800 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-300">Host Firewall Rule Inventory</h2>
          <span className="text-xs text-slate-400">
            Showing {filteredRules.length} of {rules.length} loaded rules
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#161c2e] border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2.5 px-3">Rule Name / Display Tag</th>
                <th className="py-2.5 px-3">Direction</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Target Address</th>
                <th className="py-2.5 px-3">Target Port</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-slate-500">
                    {loading ? 'Querying Windows NetSecurity Provider...' : 'No matching rules found.'}
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule, idx) => {
                  const isSentinelRule = (rule.name || '').startsWith('AI-Firewall');
                  const isBlock = (rule.action || '').toLowerCase() === 'block';

                  return (
                    <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                          {isSentinelRule && (
                            <span className="px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-400 text-[9px] uppercase font-bold">
                              Sentinel
                            </span>
                          )}
                          <span className="truncate max-w-[280px]">{rule.display_name || rule.name}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 truncate block max-w-[320px]">{rule.name}</span>
                      </td>

                      <td className="py-2.5 px-3">
                        <span className="flex items-center gap-1 text-[11px]">
                          {(rule.direction || '').toLowerCase() === 'outbound' ? (
                            <><ArrowUpRight className="w-3.5 h-3.5 text-blue-400" /> Outbound</>
                          ) : (
                            <><ArrowDownLeft className="w-3.5 h-3.5 text-emerald-400" /> Inbound</>
                          )}
                        </span>
                      </td>

                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          isBlock ? 'bg-red-950/80 text-red-400 border border-red-800' : 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                        }`}>
                          {rule.action || 'ALLOW'}
                        </span>
                      </td>

                      <td className="py-2.5 px-3 text-slate-300">
                        {rule.remote_address || 'Any'}
                      </td>

                      <td className="py-2.5 px-3 text-slate-300">
                        {rule.remote_port || 'Any'}
                      </td>

                      <td className="py-2.5 px-3 text-right">
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold text-[11px]">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Active
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
'''

# 9. frontend/src/App.tsx
files['frontend/src/App.tsx'] = '''import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import DashboardPage from './pages/DashboardPage';
import FirewallPage from './pages/FirewallPage';
import { Shield, LayoutDashboard, ShieldCheck, Terminal } from 'lucide-react';

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
  );
}
'''

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully built: {rel_path}')
