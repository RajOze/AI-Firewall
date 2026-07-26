function LiveActivity() {
  const activities = [
    {
      time: "12:31",
      title: "Chrome.exe",
      description: "Connected to 142.250.183.14",
      color: "#22c55e",
    },
    {
      time: "12:32",
      title: "PowerShell",
      description: "Outbound TCP connection detected",
      color: "#f59e0b",
    },
    {
      time: "12:33",
      title: "Firewall",
      description: "Blocked Unknown.exe",
      color: "#ef4444",
    },
    {
      time: "12:35",
      title: "AI Engine",
      description: "Classified Malware.exe as High Risk",
      color: "#8b5cf6",
    },
  ];

  return (
    <div className="panel live-activity">
      <h3>📡 Live Activity</h3>

      {activities.map((item, index) => (
        <div key={index} className="activity-item">
          <div
            className="activity-dot"
            style={{ background: item.color }}
          />

          <div className="activity-content">
            <small>{item.time}</small>

            <strong>{item.title}</strong>

            <p>{item.description}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default LiveActivity;