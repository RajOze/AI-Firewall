function SystemStatus() {
  const stats = [
    { title: "CPU", value: "18%" },
    { title: "RAM", value: "1.7 / 4 GB" },
    { title: "Network", value: "26 Mbps" },
    { title: "Last Scan", value: "2 min ago" },
    { title: "Uptime", value: "4h 21m" },
  ];

  return (
    <section className="system-status">
      <div className="system-health">
        <span className="health-dot"></span>
        <span>System Healthy</span>
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