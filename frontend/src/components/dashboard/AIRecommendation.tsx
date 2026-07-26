import { useState } from "react";
import { analyzePrompt } from "../../services/api";
import type { AnalyzeResponse } from "../../services/api";

function AIRecommendation() {
  const [inputText, setInputText] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    setAnalyzing(true);
    setError(null);
    try {
      const res = await analyzePrompt(inputText);
      setResult(res);
    } catch (err) {
      setError((err as Error).message || "Analysis request failed.");
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="panel ai-panel">
      <h3>🤖 AI Security & Detector Engine</h3>

      <div className="ai-alert">
        <h4>Live Prompt Injection Analyzer</h4>

        <form onSubmit={handleAnalyze} style={{ marginTop: "10px", marginBottom: "15px" }}>
          <input
            type="text"
            placeholder="Type prompt to analyze (e.g. Ignore previous instructions...)"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            style={{
              width: "100%",
              padding: "8px 12px",
              borderRadius: "6px",
              border: "1px solid #374151",
              backgroundColor: "#1f2937",
              color: "#f9fafb",
              marginBottom: "10px",
              boxSizing: "border-box",
            }}
          />
          <button
            type="submit"
            disabled={analyzing || !inputText.trim()}
            className="block-btn"
            style={{ cursor: analyzing ? "not-allowed" : "pointer" }}
          >
            {analyzing ? "Analyzing..." : "Analyze Prompt"}
          </button>
        </form>

        {result && (
          <div
            style={{
              padding: "10px",
              borderRadius: "6px",
              backgroundColor: result.safe ? "rgba(34, 197, 94, 0.1)" : "rgba(239, 68, 68, 0.1)",
              border: `1px solid ${result.safe ? "#22c55e" : "#ef4444"}`,
              marginBottom: "10px",
            }}
          >
            <p><strong>Result:</strong> {result.safe ? "✅ Safe" : "🚨 Threat Detected"}</p>
            <p><strong>Category:</strong> {result.category}</p>
            <p><strong>Score:</strong> {result.score}</p>
            <p><strong>Reason:</strong> {result.reason}</p>
          </div>
        )}

        {error && (
          <div style={{ color: "#ef4444", marginBottom: "10px" }}>
            <small>{error}</small>
          </div>
        )}

        <hr style={{ borderColor: "#374151", margin: "15px 0" }} />

        <h4>Suspicious Activity Recommendation</h4>
        <p>
          powershell.exe attempted an outbound TCP connection to
          <strong> 10.10.25.6:4444</strong>.
        </p>
        <p>
          AI Confidence: <span className="confidence">94%</span>
        </p>
        <p>
          Recommendation: Block this connection and continue monitoring the process.
        </p>
      </div>
    </div>
  );
}

export default AIRecommendation;