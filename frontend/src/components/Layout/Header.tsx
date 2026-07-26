function Header() {
  return (
    <header className="header">
      <div>
        <h1>🛡 AI Firewall</h1>
        <p>Real-Time Intelligent Network Protection</p>
      </div>

      <div className="header-actions">
        <span className="status">🟢 Protected</span>

        <button>🔔 Alerts</button>

        <button>⚙ Settings</button>

        <div className="profile">
          👤 Admin
        </div>
      </div>
    </header>
  );
}

export default Header;