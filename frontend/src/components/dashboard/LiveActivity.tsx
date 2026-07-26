function LiveActivity() {
  const activities = [
    {
      time: "12:31",
      event: "Chrome.exe connected to 142.250.183.14",
      type: "info",
    },
    {
      time: "12:32",
      event: "PowerShell opened outbound TCP connection",
      type: "warning",
    },
    {
      time: "12:33",
      event: "Firewall blocked Unknown.exe",
      type: "danger",
    },
    {
      time: "12:35",
      event: "AI classified Malware.exe as High Risk",
      type: "danger",
    },
  ];

  const getColor = (type: string) => {
    switch (type) {
      case "danger":
        return "#ef4444";
      case "warning":
        return "#f59e0b";
      default:
        return "#22c55e";
    }
  };

  return (
    <div className="panel live-activity">
      <h3>📡 Live Activity</h3>

      {activities.map((activity, index) => (
        <div key={index} className="activity-item">
          <div
            className="activity-dot"
            style={{ background: getColor(activity.type) }}
          ></div>

          <div className="activity-content">
            <small>{activity.time}</small>
            <p>{activity.event}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default LiveActivity;