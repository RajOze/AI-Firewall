function ThreatList() {
  const threats = [
    {
      name: "Trojan.Win32",
      severity: "High",
      status: "Blocked",
    },
    {
      name: "Suspicious PowerShell",
      severity: "Medium",
      status: "Monitoring",
    },
    {
      name: "Unknown Connection",
      severity: "Low",
      status: "Investigating",
    },
  ];

  return (
    <div className="panel">
      <h2>Recent Threats</h2>

      <ul className="threat-list">
        {threats.map((threat, index) => (
          <li key={index}>
            <div>
              <strong>{threat.name}</strong>
              <p>{threat.severity} Risk</p>
            </div>

            <span>{threat.status}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default ThreatList;