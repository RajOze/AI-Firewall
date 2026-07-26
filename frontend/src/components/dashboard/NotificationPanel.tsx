function NotificationPanel() {
  const notifications = [
    {
      title: "New Threat Detected",
      time: "2 min ago",
      color: "#ef4444",
    },
    {
      title: "System Scan Completed",
      time: "10 min ago",
      color: "#22c55e",
    },
    {
      title: "Firewall Rules Updated",
      time: "25 min ago",
      color: "#3b82f6",
    },
    {
      title: "6 New Connections",
      time: "40 min ago",
      color: "#f59e0b",
    },
  ];

  return (
    <div className="panel">
      <h3>🔔 Notifications</h3>

      {notifications.map((note, index) => (
        <div key={index} className="notification-item">
          <div
            className="notification-dot"
            style={{ background: note.color }}
          />

          <div>
            <strong>{note.title}</strong>
            <p>{note.time}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default NotificationPanel;