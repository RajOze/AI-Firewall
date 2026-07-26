function ProcessTable() {
  const processes = [
    {
      name: "chrome.exe",
      pid: 4312,
      cpu: "5%",
      memory: "240 MB",
      risk: "Safe",
    },
    {
      name: "explorer.exe",
      pid: 1180,
      cpu: "1%",
      memory: "95 MB",
      risk: "Safe",
    },
    {
      name: "powershell.exe",
      pid: 5124,
      cpu: "9%",
      memory: "62 MB",
      risk: "Medium",
    },
    {
      name: "unknown.exe",
      pid: 8231,
      cpu: "18%",
      memory: "140 MB",
      risk: "High",
    },
  ];

  const getRiskColor = (risk: string) => {
    switch (risk) {
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
      <h3>Running Processes</h3>

      <table>
        <thead>
          <tr>
            <th>Process</th>
            <th>PID</th>
            <th>CPU</th>
            <th>Memory</th>
            <th>Risk</th>
          </tr>
        </thead>

        <tbody>
          {processes.map((process) => (
            <tr key={process.pid}>
              <td>{process.name}</td>
              <td>{process.pid}</td>
              <td>{process.cpu}</td>
              <td>{process.memory}</td>
              <td>
                <span
                  className="risk-badge"
                  style={{ background: getRiskColor(process.risk) }}
                >
                  {process.risk}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ProcessTable;