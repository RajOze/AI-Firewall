import Header from "../components/layout/Header";
import Sidebar from "../components/layout/Sidebar";
import StatCard from "../components/dashboard/StatCard";
import ThreatList from "../components/dashboard/ThreatList";
import ProcessTable from "../components/dashboard/ProcessTable";
import ConnectionTable from "../components/dashboard/ConnectionTable";
import AIRecommendation from "../components/dashboard/AIRecommendation";
import SystemStatus from "../components/dashboard/SystemStatus";
import LiveActivity from "../components/dashboard/LiveActivity";
import NotificationPanel from "../components/dashboard/NotificationPanel";

function Dashboard() {
  return (
    <div className="dashboard-layout">
      <Sidebar />

      <main className="dashboard-main">
        <Header />

        <SystemStatus />

        <section className="dashboard-content">
          <h2>Dashboard Overview</h2>

          <div className="dashboard-grid">
            <StatCard
              title="Active Processes"
              value={152}
              subtitle="+8 since last scan"
              icon="💻"
            />

            <StatCard
              title="Network Connections"
              value={42}
              subtitle="12 Active"
              icon="🌐"
            />

            <StatCard
              title="Threat Alerts"
              value={2}
              subtitle="High Risk"
              icon="⚠"
              color="#ef4444"
            />

            <StatCard
              title="Firewall Status"
              value="Protected"
              subtitle="Real-Time Protection ON"
              icon="🛡"
              color="#22c55e"
            />
          </div>

          <div className="dashboard-panels">
  <ThreatList />
  <ProcessTable />
</div>

<LiveActivity />

          <div className="dashboard-network">
            <ConnectionTable />
          </div>

          <AIRecommendation />

          <NotificationPanel />
        </section>
      </main>
    </div>
  );
}

export default Dashboard;