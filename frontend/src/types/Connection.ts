export interface Connection {
  process: string;
  ip: string;
  port: number;
  protocol: string;
  status: "Allowed" | "Monitoring" | "Blocked";
}