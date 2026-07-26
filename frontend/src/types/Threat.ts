export interface Threat {
  id: number;
  name: string;
  severity: "Safe" | "Medium" | "High";
  time: string;
}