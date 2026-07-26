function ThreatAnalytics() {
  const threats = [
    { label: "High", count: 3, color: "#ef4444" },
    { label: "Medium", count: 7, color: "#f59e0b" },
    { label: "Low", count: 15, color: "#22c55e" },
  ];

  const max = Math.max(...threats.map((t) => t.count));

  return (
    <div className="panel">
      <h3>📊 Threat Analytics</h3>

      {threats.map((threat) => (
        <div key={threat.label} className="threat-chart-row">
          <span>{threat.label}</span>

          <div className="threat-chart-track">
            <div
              className="threat-chart-fill"
              style={{
                width: `${(threat.count / max) * 100}%`,
                background: threat.color,
              }}
            ></div>
          </div>

          <strong>{threat.count}</strong>
        </div>
      ))}
    </div>
  );
}

export default ThreatAnalytics;