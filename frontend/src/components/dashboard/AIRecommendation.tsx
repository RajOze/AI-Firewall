function AIRecommendation() {
  return (
    <div className="panel ai-panel">
      <h3>🤖 AI Security Recommendation</h3>

      <div className="ai-alert">
        <h4>Suspicious Activity Detected</h4>

        <p>
          powershell.exe attempted an outbound TCP connection to
          <strong> 10.10.25.6:4444</strong>.
        </p>

        <p>
          AI Confidence:
          <span className="confidence"> 94%</span>
        </p>

        <p>
          Recommendation:
          Block this connection and continue monitoring the process.
        </p>

        <div className="ai-buttons">
          <button className="block-btn">Block</button>
          <button className="ignore-btn">Ignore</button>
        </div>
      </div>
    </div>
  );
}

export default AIRecommendation;