const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export interface AnalyzeRequest {
  text: string;
}

export interface AnalyzeResponse {
  safe: boolean;
  score: number;
  category: string;
  reason: string;
}

export interface FirewallRuleStatusResponse {
  rule_name: string;
  exists: boolean;
}

export interface FirewallRuleResponse {
  name: string;
  display_name: string;
  enabled: boolean;
  direction: string;
  action: string;
  profile: string;
}

export async function fetchHealth(): Promise<{ status: string }> {
  const response = await fetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error(`Health check failed with status: ${response.status}`);
  }

  return response.json();
}

export async function analyzePrompt(
  text: string,
): Promise<AnalyzeResponse> {
  const response = await fetch(`${API_BASE_URL}/analyze/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text }),
  });

  if (!response.ok) {
    throw new Error(`Analysis failed with status: ${response.status}`);
  }

  return response.json();
}

export async function fetchFirewallRules(): Promise<FirewallRuleResponse[]> {
  const response = await fetch(`${API_BASE_URL}/firewall/rules`);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));

    throw new Error(
      errorData.detail ||
        `Firewall rules query failed with status: ${response.status}`,
    );
  }

  return response.json();
}

export async function checkFirewallRule(
  ruleName: string,
): Promise<FirewallRuleStatusResponse> {
  const response = await fetch(
    `${API_BASE_URL}/firewall/rules/${encodeURIComponent(ruleName)}`,
  );

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));

    throw new Error(
      errorData.detail ||
        `Firewall query failed with status: ${response.status}`,
    );
  }

  return response.json();
}
