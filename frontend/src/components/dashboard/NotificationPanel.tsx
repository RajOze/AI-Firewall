import { getNotifications } from "../../services/notificationService";
function NotificationPanel() {
  const notifications = getNotifications();
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