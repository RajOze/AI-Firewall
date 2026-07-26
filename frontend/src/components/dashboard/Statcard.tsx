type StatCardProps = {
  title: string;
  value: string | number;
  subtitle: string;
  icon: string;
  color?: string;
};

function StatCard({
  title,
  value,
  subtitle,
  icon,
  color = "#38bdf8",
}: StatCardProps) {
  return (
    <div className="stat-card">
      <div className="stat-header">
        <span className="stat-icon">{icon}</span>
        <h3>{title}</h3>
      </div>

      <h1 style={{ color }}>{value}</h1>

      <p className="stat-subtitle">{subtitle}</p>
    </div>
  );
}

export default StatCard;