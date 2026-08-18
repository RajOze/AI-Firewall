from pathlib import Path

files = {}

# 1. frontend/postcss.config.js
files['frontend/postcss.config.js'] = '''export default {
  plugins: {
    tailwindcss: {},
  },
};
'''

# 2. frontend/src/services/api.ts
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
  safe?: boolean;
  score?: number;
  category?: string;
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
  const data = await res.json();
  return {
    decision: data.decision || (data.safe ? 'ALLOW' : 'BLOCK'),
    confidence: data.confidence ?? data.score ?? 0.9,
    reason: data.reason || 'Heuristic evaluation complete',
    safe: data.safe ?? (data.decision !== 'BLOCK'),
    score: data.score ?? data.confidence ?? 0.05,
    category: data.category || 'General Network Payload',
  };
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

# 3. frontend/src/pages/AIAssistantPage.tsx
files['frontend/src/pages/AIAssistantPage.tsx'] = '''import { useState } from 'react';
import { analyzePrompt } from '../services/api';
import type { AnalyzeResponse } from '../services/api';
import { Bot, Send, ShieldAlert, CheckCircle, Loader2 } from 'lucide-react';

interface Message {
  sender: 'user' | 'assistant';
  text: string;
  analysis?: AnalyzeResponse;
}

export default function AIAssistantPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'assistant',
      text: 'Hello! I am Sentinel AI Assistant. Enter any network payload, suspicious command, or log line to evaluate threat risk.',
    },
  ]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    const textToSend = input;
    setInput('');
    setMessages((prev) => [...prev, { sender: 'user', text: textToSend }]);
    setLoading(true);

    try {
      const response = await analyzePrompt(textToSend);
      const isSafe = response.safe ?? (response.decision !== 'BLOCK');
      const score = response.score ?? response.confidence ?? 0.0;
      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: `Analysis complete. Result: ${isSafe ? 'SAFE' : 'POTENTIAL THREAT'} (Score: ${score.toFixed(2)})`,
          analysis: response,
        },
      ]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: `Analysis failed: ${err.message || 'Unknown error occurred'}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col w-full h-[calc(100vh-2rem)] gap-4 p-6 text-slate-100 font-mono">
      <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">Sentinel AI Copilot</h1>
            <p className="text-xs text-slate-400">Interactive threat triage & security reasoning assistant</p>
          </div>
        </div>
      </div>

      <div className="flex-1 bg-[#111625] rounded-xl border border-slate-800 p-4 overflow-y-auto space-y-4">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`max-w-xl p-3.5 rounded-xl text-xs ${
                msg.sender === 'user'
                  ? 'bg-blue-600 text-white rounded-br-none'
                  : 'bg-[#161c2e] border border-slate-800 text-slate-200 rounded-bl-none'
              }`}
            >
              <p>{msg.text}</p>
              {msg.analysis && (
                <div className="mt-2.5 pt-2.5 border-t border-slate-700/60 text-[11px] space-y-1">
                  <div className="flex items-center gap-1.5 font-bold">
                    {msg.analysis.safe ? (
                      <span className="text-emerald-400 flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5" /> ✓ SAFE</span>
                    ) : (
                      <span className="text-red-400 flex items-center gap-1"><ShieldAlert className="w-3.5 h-3.5" /> ⚠ THREAT DETECTED</span>
                    )}
                  </div>
                  <p className="text-slate-400">Decision: <span className="text-slate-200">{msg.analysis.decision}</span></p>
                  <p className="text-slate-400">Reason: <span className="text-slate-300">{msg.analysis.reason}</span></p>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="bg-[#111625] p-3 rounded-xl border border-slate-800 flex items-center gap-3">
        <input
          type="text"
          placeholder="Type a PowerShell command, suspicious IP, or payload to analyze..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          className="flex-1 bg-[#161c2e] border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={handleSend}
          disabled={loading || !input.trim()}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-colors"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          Analyze
        </button>
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
