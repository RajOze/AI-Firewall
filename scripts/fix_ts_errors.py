from pathlib import Path

files = {}

# 1. frontend/src/services/api.ts
files['frontend/src/services/api.ts'] = '''/**
 * Sentinel AI Firewall - Complete REST API Client & Types
 */

const API_BASE = `http://${typeof window !== 'undefined' && window.location.hostname === 'localhost' ? '127.0.0.1' : (typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1') || '127.0.0.1'}:8000`;

export interface AnalyzeRequest {
  text: string;
}

export interface AnalyzeResponse {
  decision: string;
  confidence: number;
  reason: string;
}

export interface ThreatEvaluationRequest {
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

export interface FirewallRuleResponse {
  name: string;
  display_name: string;
  enabled: boolean;
  direction: string;
  action: string;
  profile: string;
}

export interface FirewallRuleStatusResponse {
  rule_name: string;
  exists: boolean;
}

export async function fetchHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function analyzePrompt(text: string): Promise<AnalyzeResponse> {
  const res = await fetch(`${API_BASE}/api/v1/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) throw new Error(`Analyze prompt failed: ${res.statusText}`);
  return res.json();
}

export async function fetchFirewallRules(): Promise<FirewallRuleResponse[]> {
  const res = await fetch(`${API_BASE}/firewall/rules`);
  if (!res.ok) throw new Error(`Fetch rules failed: ${res.statusText}`);
  const data = await res.json();
  return Array.isArray(data) ? data : data.rules || [];
}

export async function checkFirewallRule(ruleName: string): Promise<FirewallRuleStatusResponse> {
  const res = await fetch(`${API_BASE}/firewall/rules/${encodeURIComponent(ruleName)}`);
  if (!res.ok) throw new Error(`Check rule failed: ${res.statusText}`);
  return res.json();
}

export const api = {
  evaluateThreat: async (req: ThreatEvaluationRequest, forceFallback = false): Promise<ThreatAdvisory> => {
    const res = await fetch(`${API_BASE}/api/v1/ai/advisory/evaluate?force_fallback=${forceFallback}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`Threat evaluation failed: ${res.statusText}`);
    return res.json();
  },

  enforcePolicy: async (advisory: ThreatAdvisory): Promise<PolicyDecision> => {
    const res = await fetch(`${API_BASE}/api/v1/policy/evaluate-and-enforce`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(advisory),
    });
    if (!res.ok) throw new Error(`Policy enforcement failed: ${res.statusText}`);
    return res.json();
  },

  getFirewallRules: async (limit = 100): Promise<{ rules: FirewallRuleSummary[]; count: number }> => {
    const res = await fetch(`${API_BASE}/firewall/rules?limit=${limit}`);
    if (!res.ok) throw new Error(`Rule query failed: ${res.statusText}`);
    return res.json();
  },

  inspectRule: async (ruleName: string): Promise<FirewallRuleStatusResponse> => {
    return checkFirewallRule(ruleName);
  },
};
'''

# 2. frontend/src/components/ThreatInspectorModal.tsx
files['frontend/src/components/ThreatInspectorModal.tsx'] = '''import { useState, useEffect } from 'react';
import type { ThreatAdvisory, PolicyDecision } from '../services/api';
import { api } from '../services/api';
import type { LiveSession } from '../stores/useTelemetryStore';
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

export function ThreatInspectorModal({ session, onClose }: ThreatInspectorModalProps) {
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
}
'''

# 3. frontend/src/pages/DashboardPage.tsx
files['frontend/src/pages/DashboardPage.tsx'] = '''import { useState } from 'react';
import { useWebSocketStream } from '../hooks/useWebSocketStream';
import { useTelemetryStore } from '../stores/useTelemetryStore';
import type { LiveSession } from '../stores/useTelemetryStore';
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

# 4. frontend/src/pages/FirewallPage.tsx
files['frontend/src/pages/FirewallPage.tsx'] = '''import { useState, useEffect } from 'react';
import type { FirewallRuleSummary } from '../services/api';
import { api } from '../services/api';
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

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully updated: {rel_path}')
