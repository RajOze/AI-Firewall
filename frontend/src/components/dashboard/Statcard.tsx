type StatCardProps = {
  title: string;
  value: string | number;
  color?: string;
};

function StatCard({
  title,
  value,
  color = "#38bdf8",
}: StatCardProps) {
  return (
    <div className="stat-card">
      <h3>{title}</h3>

      <h1 style={{ color }}>{value}</h1>
    </div>
  );
}

export default StatCard;