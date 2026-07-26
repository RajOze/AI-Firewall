function Sidebar() {
  return (
    <aside className="sidebar">
      <div>
        <h2>🛡 AI Firewall</h2>

        <ul>
          <li className="active">🏠 Dashboard</li>
          <li>💻 Processes</li>
          <li>🌐 Connections</li>
          <li>⚠ Threats</li>
          <li>🛡 Firewall Rules</li>
          <li>📜 Logs</li>
          <li>⚙ Settings</li>
        </ul>
      </div>

      <div className="sidebar-footer">
        Version 0.2.0
      </div>
    </aside>
  );
}

export default Sidebar;