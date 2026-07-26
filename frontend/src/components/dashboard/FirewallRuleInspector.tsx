import { useState } from "react";
import { checkFirewallRule, FirewallRuleResponse } from "../../services/api";

function FirewallRuleInspector() {
  const [ruleName, setRuleName] = useState("AI-Firewall-block-inbound-sample");
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<FirewallRuleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleName.trim()) return;
    setChecking(true);
    setError(null);
    try {
      const res = await checkFirewallRule(ruleName.trim());
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Rule lookup failed.");
      setResult(null);
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="panel firewall-inspector">
      <h3>🛡️ Firewall Rule Inspector (Read-Only)</h3>
      <p style={{ color: "#9ca3af", fontSize: "0.875rem", marginBottom: "12px" }}>
        Query host firewall rule status via GET /firewall/rules/&#123;rule_name&#125;. No mutations allowed.
      </p>

      <form onSubmit={handleCheck} style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
        <input
          type="text"
          value={ruleName}
          onChange={(e) => setRuleName(e.target.value)}
          placeholder="Rule Name (e.g. AI-Firewall-test)"
          style={{
            flex: 1,
            padding: "8px 12px",
            borderRadius: "6px",
            border: "1px solid #374151",
            backgroundColor: "#1f2937",
            color: "#f9fafb",
          }}
        />
        <button
          type="submit"
          disabled={checking || !ruleName.trim()}
          className="block-btn"
          style={{ cursor: checking ? "not-allowed" : "pointer" }}
        >
          {checking ? "Querying..." : "Query Status"}
        </button>
      </form>

      {result && (
        <div style={{ padding: "10px", borderRadius: "6px", backgroundColor: "#1f2937", border: "1px solid #374151" }}>
          <p><strong>Rule Name:</strong> {result.rule_name}</p>
          <p><strong>Status:</strong> {result.exists ? "Active (Exists)" : "Not Found (Absent)"}</p>
        </div>
      )}

      {error && (
        <div style={{ color: "#ef4444", padding: "8px", borderRadius: "6px", backgroundColor: "rgba(239, 68, 68, 0.1)" }}>
          <small>{error}</small>
        </div>
      )}
    </div>
  );
}

export default FirewallRuleInspector;
