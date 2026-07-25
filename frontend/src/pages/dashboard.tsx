function Dashboard() {
  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🛡️ AI Firewall</h1>
        <p>Real-Time Intelligent Network Protection</p>
      </header>

      <section className="dashboard-content">
        <h2>Dashboard</h2>

        <div className="dashboard-cards">
          <div className="card">
            <h3>Active Processes</h3>
            <p>0</p>
          </div>

          <div className="card">
            <h3>Network Connections</h3>
            <p>0</p>
          </div>

          <div className="card">
            <h3>Threat Alerts</h3>
            <p>0</p>
          </div>

          <div className="card">
            <h3>Firewall Status</h3>
            <p>Protected ✅</p>
          </div>
        </div>
      </section>
    </div>
  );
}

export default Dashboard;