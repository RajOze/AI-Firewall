/**
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
