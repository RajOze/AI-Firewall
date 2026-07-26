import { getThreats } from "../../services/threatService";
function ThreatList() {
  const threats = getThreats();
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