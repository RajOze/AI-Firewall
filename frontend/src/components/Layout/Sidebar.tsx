function Sidebar() {
  return (
    <aside className="sidebar">
      <h2>🛡 AI Firewall</h2>

      <nav>
        <ul>
          <li className="active">🏠 Dashboard</li>
          <li>💻 Processes</li>
          <li>🌐 Connections</li>
          <li>⚠ Threats</li>
          <li>🛡 Firewall Rules</li>
          <li>📜 Logs</li>
          <li>⚙ Settings</li>
        </ul>
      </nav>

      <div className="sidebar-footer">
        <p>Version 0.1.0</p>
      </div>
    </aside>
  );
}

export default Sidebar;