function ThreatList() {
  const threats = [
    {
      id: 1,
      name: "Trojan.Win32",
      severity: "High",
      time: "2 min ago",
    },
    {
      id: 2,
      name: "Suspicious PowerShell",
      severity: "Medium",
      time: "8 min ago",
    },
    {
      id: 3,
      name: "Chrome.exe",
      severity: "Safe",
      time: "12 min ago",
    },
  ];

  const getColor = (severity: string) => {
    switch (severity) {
      case "High":
        return "#ef4444";
      case "Medium":
        return "#f59e0b";
      default:
        return "#22c55e";
    }
  };

  return (
    <div className="panel">
      <h3>Recent Threats</h3>

      {threats.map((threat) => (
        <div key={threat.id} className="threat-item">
          <div>
            <strong>{threat.name}</strong>

            <p>{threat.time}</p>
          </div>

          <span
            className="severity-badge"
            style={{ background: getColor(threat.severity) }}
          >
            {threat.severity}
          </span>
        </div>
      ))}
    </div>
  );
}

export default ThreatList;