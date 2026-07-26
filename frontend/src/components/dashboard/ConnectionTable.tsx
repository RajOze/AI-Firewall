import { getConnections } from "../../services/connectionService";
function ConnectionTable() {
  const connections = getConnections();

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Blocked":
        return "#ef4444";
      case "Monitoring":
        return "#f59e0b";
      default:
        return "#22c55e";
    }
  };

  return (
    <div className="panel">
      <h3>Network Connections</h3>

      <table>
        <thead>
          <tr>
            <th>Process</th>
            <th>Remote IP</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {connections.map((connection, index) => (
            <tr key={index}>
              <td>{connection.process}</td>
              <td>{connection.ip}</td>
              <td>{connection.port}</td>
              <td>{connection.protocol}</td>
              <td>
                <span
                  className="status-badge"
                  style={{
                    background: getStatusColor(connection.status),
                  }}
                >
                  {connection.status}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ConnectionTable;