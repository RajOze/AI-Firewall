function ConnectionTable() {
  const connections = [
    {
      process: "chrome.exe",
      destination: "google.com",
      port: 443,
      status: "Allowed",
    },
    {
      process: "discord.exe",
      destination: "discord.com",
      port: 443,
      status: "Allowed",
    },
    {
      process: "unknown.exe",
      destination: "185.44.76.21",
      port: 8080,
      status: "Blocked",
    },
  ];

  return (
    <div className="panel">
      <h2>Network Connections</h2>

      <table className="process-table">
        <thead>
          <tr>
            <th>Process</th>
            <th>Destination</th>
            <th>Port</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {connections.map((connection, index) => (
            <tr key={index}>
              <td>{connection.process}</td>
              <td>{connection.destination}</td>
              <td>{connection.port}</td>
              <td>{connection.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ConnectionTable;