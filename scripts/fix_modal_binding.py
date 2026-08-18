from pathlib import Path

files = {}

# 1. frontend/src/components/ThreatInspectorModal.tsx
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
  AlertTriangle,
  FileCode
} from 'lucide-react';

interface ThreatInspectorModalProps {
  session: LiveSession | null;
  onClose: () => void;
  onBlockEnforced?: (ruleName: string) => void;
}

export const ThreatInspectorModal: React.FC<ThreatInspectorModalProps> = ({ session, onClose, onBlockEnforced }) => {
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

    // Sanitize destination IP and port (handles *:0 and UDP listening sockets)
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
      .then(res => setAdvisory(res))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [session]);

  const handleEnforceBlock = async () => {
    if (!advisory) return;
    setEnforcing(true);
    setError(null);
    try {
      const dec = await api.enforcePolicy(advisory);
      setDecision(dec);
      if (dec.is_blocked && dec.mutation_rule_name && onBlockEnforced) {
        onBlockEnforced(dec.mutation_rule_name);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setEnforcing(false);
    }
  };

  if (!session) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-[#161a23] border border-outline-variant/30 w-full max-w-2xl rounded-2xl shadow-2xl flex flex-col overflow-hidden text-on-surface animate-in fade-in zoom-in-95 duration-150">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-outline-variant/20 flex items-center justify-between bg-surface-container-high/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
              <ShieldAlert className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider">AI Threat Inspector & Advisory</h2>
              <span className="text-xs text-outline font-mono">{session.process} ({session.ip}:{session.port})</span>
            </div>
          </div>
          <button 
            onClick={onClose} 
            className="p-1.5 hover:bg-surface-container-highest rounded-lg text-outline hover:text-on-surface transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto max-h-[70vh] space-y-5">
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 space-y-3">
              <Loader2 className="w-8 h-8 text-primary animate-spin" />
              <p className="text-xs font-mono text-outline">Querying AIRouter & Neural Threat Engine...</p>
            </div>
          )}

          {error && (
            <div className="p-4 bg-red-950/50 border border-red-800/60 rounded-xl text-red-400 text-xs font-mono flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Analysis Failed</p>
                <p className="opacity-90">{error}</p>
              </div>
            </div>
          )}

          {advisory && !loading && (
            <>
              {/* Executive Assessment Card */}
              <div className="p-4 bg-surface-container-low rounded-xl border border-outline-variant/20 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                      advisory.severity === 'CRITICAL' || advisory.severity === 'HIGH' ? 'bg-red-950 text-red-400 border border-red-800' :
                      advisory.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                      'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      {advisory.severity} SEVERITY
                    </span>
                    <span className="text-xs text-outline font-mono">
                      Confidence: {(advisory.confidence_score * 100).toFixed(0)}%
                    </span>
                    {advisory.is_fallback && (
                      <span className="text-[10px] px-2 py-0.5 bg-surface-container-highest text-outline rounded font-mono">
                        Local Heuristic Engine
                      </span>
                    )}
                  </div>
                  <p className="text-xs font-semibold text-on-surface mt-2">{advisory.summary}</p>
                </div>
                <Cpu className="w-6 h-6 text-primary opacity-80 shrink-0 mt-1" />
              </div>

              {/* Analytical Reasoning */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-mono uppercase text-outline font-semibold">Detailed AI Reasoning</h3>
                <div className="p-3.5 bg-surface-container-low rounded-xl border border-outline-variant/10 text-xs leading-relaxed text-on-surface-variant font-mono">
                  {advisory.detailed_reasoning}
                </div>
              </div>

              {/* MITRE ATT&CK Mappings */}
              {advisory.mitre_mappings.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-mono uppercase text-outline font-semibold">MITRE ATT&CK Techniques</h3>
                  <div className="flex flex-wrap gap-2">
                    {advisory.mitre_mappings.map((m, i) => (
                      <a 
                        key={i} 
                        href={m.reference_url || '#'} 
                        target="_blank" 
                        rel="noreferrer"
                        className="flex items-center gap-1.5 px-3 py-1 bg-surface-container-high rounded-lg border border-outline-variant/30 text-xs font-mono hover:border-primary transition-colors text-primary"
                      >
                        <span className="font-bold">{m.technique_id}</span>: {m.technique_name}
                        <ExternalLink className="w-3 h-3 ml-0.5 opacity-60" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Evidence Metrics */}
              {advisory.evidence.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-mono uppercase text-outline font-semibold">Observed Telemetry Evidence</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {advisory.evidence.map((ev, i) => (
                      <div key={i} className="p-3 bg-surface-container-low rounded-xl border border-outline-variant/10 text-xs font-mono">
                        <div className="text-[10px] text-outline uppercase">{ev.source}</div>
                        <div className="text-xs font-semibold text-on-surface mt-0.5">{ev.metric_name} = {String(ev.observed_value)}</div>
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
                    <p className="mt-1 font-bold text-[10px] text-primary">Enforced Rule: {decision.mutation_rule_name}</p>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-outline-variant/20 flex items-center justify-between bg-surface-container-high/40">
          <span className="text-[11px] font-mono text-outline">Deterministic Policy Shield v0.1.0</span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-surface-container-highest hover:bg-surface-container-low text-xs font-mono transition-colors"
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

# 2. frontend/src/pages/DashboardPage.tsx
files['frontend/src/pages/DashboardPage.tsx'] = '''import React, { useState } from 'react';
import { useWebSocketStream } from '../hooks/useWebSocketStream';
import { useTelemetryStore, LiveSession } from '../stores/useTelemetryStore';
import { ThreatInspectorModal } from '../components/ThreatInspectorModal';
import { Shield, Activity, Radio, CheckCircle, ShieldAlert, Cpu, Eye } from 'lucide-react';

export default function DashboardPage() {
  useWebSocketStream();

  const { 
    isConnected,
    activeConnectionsCount, 
    overallRiskScore, 
    threatsCount, 
    recentEvents, 
    liveSessions 
  } = useTelemetryStore();

  const [selectedSession, setSelectedSession] = useState<LiveSession | null>(null);
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
            <span className="text-xs text-outline">{liveSessions.length} active sessions (Click any row to inspect)</span>
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
                  <th className="py-2 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/10 font-mono">
                {liveSessions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-outline">
                      Listening on WebSocket feed... Waiting for network events.
                    </td>
                  </tr>
                ) : (
                  liveSessions.map((session, idx) => (
                    <tr 
                      key={idx} 
                      onClick={() => setSelectedSession(session)}
                      className="hover:bg-surface-container-high/60 cursor-pointer transition-colors group"
                    >
                      <td className="py-2.5 px-3 font-semibold text-on-surface group-hover:text-primary transition-colors">
                        {session.process}
                      </td>
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
                      <td className="py-2.5 px-3 text-right">
                        <span className="text-[11px] px-2 py-0.5 rounded bg-surface-container-highest text-outline group-hover:text-primary group-hover:border-primary/40 border border-outline-variant/20 inline-flex items-center gap-1 transition-all">
                          <Eye className="w-3.5 h-3.5" /> Inspect
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
    print(f'Successfully wrote: {rel_path}')
