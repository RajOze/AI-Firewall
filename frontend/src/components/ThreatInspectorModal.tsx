import { useState, useEffect } from 'react';
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
