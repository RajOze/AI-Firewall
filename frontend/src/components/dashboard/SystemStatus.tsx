import { useState, useEffect } from "react";
import { fetchHealth } from "../../services/api";

function SystemStatus() {
  const [backendStatus, setBackendStatus] = useState<string>("Checking...");

  useEffect(() => {
    fetchHealth()
      .then((data) => setBackendStatus(data.status === "healthy" ? "Healthy (API Connected)" : "Degraded"))
      .catch(() => setBackendStatus("Offline"));
  }, []);

  const stats = [
    { title: "CPU", value: "18%" },
    { title: "RAM", value: "1.7 / 4 GB" },
    { title: "Network", value: "26 Mbps" },
    { title: "Backend API", value: backendStatus },
    { title: "Uptime", value: "4h 21m" },
  ];

  return (
    <section className="system-status">
      <div className="system-health">
        <span className="health-dot"></span>
        <span>System {backendStatus}</span>
      </div>

      <div className="status-grid">
        {stats.map((item) => (
          <div key={item.title} className="status-card">
            <p>{item.title}</p>
            <h3>{item.value}</h3>
          </div>
        ))}
      </div>
    </section>
  );
}

export default SystemStatus;