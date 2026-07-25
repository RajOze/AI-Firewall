import Header from "../components/layout/Header";
import Sidebar from "../components/layout/Sidebar";
import StatCard from "../components/dashboard/StatCard";

function Dashboard() {
  return (
    <div className="dashboard-layout">
      <Sidebar />

      <main className="dashboard-main">
        <Header />

        <section className="dashboard-content">
          <h2>Dashboard Overview</h2>

          <div className="dashboard-grid">
            <StatCard
              title="Active Processes"
              value={0}
            />

            <StatCard
              title="Network Connections"
              value={0}
            />

            <StatCard
              title="Threat Alerts"
              value={0}
              color="#ef4444"
            />

            <StatCard
              title="Firewall Status"
              value="Protected"
              color="#22c55e"
            />
          </div>
        </section>
      </main>
    </div>
  );
}

export default Dashboard;