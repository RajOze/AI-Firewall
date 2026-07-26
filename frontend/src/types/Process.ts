export interface Process {
  name: string;
  pid: number;
  cpu: string;
  memory: string;
  risk: "Safe" | "Medium" | "High";
}