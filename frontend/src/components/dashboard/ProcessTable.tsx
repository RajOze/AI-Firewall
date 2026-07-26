import { getProcesses } from "../../services/processService";

function ProcessTable() {
  const processes = getProcesses();

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