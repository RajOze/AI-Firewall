function NetworkTraffic() {
  const traffic = [
    { time: "10:00", value: 18 },
    { time: "10:05", value: 24 },
    { time: "10:10", value: 16 },
    { time: "10:15", value: 32 },
    { time: "10:20", value: 26 },
    { time: "10:25", value: 38 },
    { time: "10:30", value: 30 },
  ];

  const max = Math.max(...traffic.map((t) => t.value));

  return (
    <div className="panel">
      <h3>📈 Network Traffic</h3>

      <div className="traffic-chart">
        {traffic.map((point) => (
          <div key={point.time} className="traffic-bar-container">
            <div
              className="traffic-bar"
              style={{
                height: `${(point.value / max) * 160}px`,
              }}
            ></div>

            <small>{point.time}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

export default NetworkTraffic;