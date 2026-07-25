function ProcessTable() {
  const processes = [
    {
      name: "chrome.exe",
      cpu: "12%",
      memory: "350 MB",
    },
    {
      name: "explorer.exe",
      cpu: "3%",
      memory: "95 MB",
    },
    {
      name: "python.exe",
      cpu: "25%",
      memory: "180 MB",
    },
  ];

  return (
    <div className="panel">
      <h2>Active Processes</h2>

      <table className="process-table">
        <thead>
          <tr>
            <th>Process</th>
            <th>CPU</th>
            <th>Memory</th>
          </tr>
        </thead>

        <tbody>
          {processes.map((process, index) => (
            <tr key={index}>
              <td>{process.name}</td>
              <td>{process.cpu}</td>
              <td>{process.memory}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ProcessTable;