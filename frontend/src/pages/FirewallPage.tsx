import { useState } from "react";
import { checkFirewallRule } from "../services/api";
import type { FirewallRuleResponse } from "../services/api";


interface Rule {
  id: string;
  name: string;
  action: "ALLOW" | "BLOCK" | "REJECT";
  protocol: "TCP" | "UDP" | "ANY";
  source: string;
  destination: string;
  port: string;
  enabled: boolean;
}

const mockRules: Rule[] = [
  {
    id: "RULE-101",
    name: "Block-Malicious-Inbound-SSH",
    action: "BLOCK",
    protocol: "TCP",
    source: "0.0.0.0/0",
    destination: "192.168.1.100",
    port: "22",
    enabled: true,
  },
  {
    id: "RULE-102",
    name: "Allow-HTTPS-Web-Traffic",
    action: "ALLOW",
    protocol: "TCP",
    source: "192.168.1.0/24",
    destination: "ANY",
    port: "443",
    enabled: true,
  },
  {
    id: "RULE-103",
    name: "Block-Known-Botnet-C2-IPs",
    action: "BLOCK",
    protocol: "ANY",
    source: "185.76.8.0/24",
    destination: "ANY",
    port: "*",
    enabled: true,
  },
  {
    id: "RULE-104",
    name: "Allow-Internal-DNS-Queries",
    action: "ALLOW",
    protocol: "UDP",
    source: "10.0.0.0/16",
    destination: "8.8.8.8",
    port: "53",
    enabled: true,
  },
];

export default function FirewallPage() {
  const [queryRuleName, setQueryRuleName] = useState<string>("Block-Malicious-Inbound-SSH");
  const [queryResult, setQueryResult] = useState<FirewallRuleResponse | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const handleInspectRule = async () => {
    if (!queryRuleName.trim()) return;
    setLoading(true);
    setQueryError(null);
    setQueryResult(null);

    try {
      const res = await checkFirewallRule(queryRuleName);
      setQueryResult(res);
    } catch (err: any) {
      setQueryError(err.message || "Failed to inspect firewall rule");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col w-full gap-gutter">
      {/* Header Banner */}
      <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex items-center justify-between">
        <div>
          <h1 className="font-headline-lg text-on-surface">Firewall Management & Rule Inspector</h1>
          <p className="font-body-sm text-outline mt-1">
            Configure packet filtering rules, inspect OS firewall state, and manage port ACLs.
          </p>
        </div>
        <button className="px-md py-sm bg-primary text-on-primary font-body-sm rounded hover:bg-primary-container transition-colors flex items-center gap-xs">
          <span className="material-symbols-outlined text-[18px]">add</span>
          Create New Rule
        </button>
      </div>

      {/* Backend Firewall Rule Inspector Widget (Preserving API Integration) */}
      <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex flex-col gap-md">
        <div className="flex items-center gap-sm">
          <span className="material-symbols-outlined text-primary text-[24px]">verified_user</span>
          <div>
            <h2 className="font-headline-sm text-on-surface">Live OS Rule Inspector (FastAPI Backend)</h2>
            <p className="font-body-sm text-outline text-[12px]">
              Queries the local Windows Firewall service to verify rule existence.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-md max-w-xl">
          <input
            type="text"
            value={queryRuleName}
            onChange={(e) => setQueryRuleName(e.target.value)}
            placeholder="Enter rule name (e.g., Core Networking - Dynamic Host Configuration Protocol (DHCP-In))"
            className="flex-1 bg-surface-container-low border border-outline-variant rounded px-md py-sm text-body-sm font-code-sm text-on-surface focus:outline-none focus:border-primary"
          />
          <button
            onClick={handleInspectRule}
            disabled={loading}
            className="px-lg py-sm bg-secondary text-on-secondary font-body-sm font-medium rounded hover:bg-secondary-container transition-colors disabled:opacity-50"
          >
            {loading ? "Checking..." : "Inspect Rule"}
          </button>
        </div>

        {queryResult && (
          <div className="p-md bg-secondary/10 border border-secondary/20 rounded font-code-sm text-[13px] text-secondary flex items-center gap-md">
            <span className="material-symbols-outlined text-[20px]">check_circle</span>
            <span>
              Rule <strong>"{queryResult.rule_name}"</strong>:{" "}
              {queryResult.exists ? "Active & Configured in OS" : "Not Found"}
            </span>
          </div>
        )}

        {queryError && (
          <div className="p-md bg-error/10 border border-error/20 rounded font-code-sm text-[13px] text-error flex items-center gap-md">
            <span className="material-symbols-outlined text-[20px]">error</span>
            <span>{queryError}</span>
          </div>
        )}
      </div>

      {/* Rules Table */}
      <div className="bg-surface-container rounded border border-outline-variant/30 overflow-hidden">
        <div className="p-lg border-b border-outline-variant flex items-center justify-between bg-surface-container-low">
          <span className="font-label-caps text-on-surface uppercase tracking-widest">
            Active Filter Policies (4 Rules)
          </span>
          <span className="font-body-sm text-outline">Default Action: <strong className="text-error">BLOCK INBOUND</strong></span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-surface-container-highest/30">
                <th className="p-md font-label-caps text-outline">Rule Name</th>
                <th className="p-md font-label-caps text-outline">Action</th>
                <th className="p-md font-label-caps text-outline">Protocol</th>
                <th className="p-md font-label-caps text-outline">Source</th>
                <th className="p-md font-label-caps text-outline">Port</th>
                <th className="p-md font-label-caps text-outline text-right">Status</th>
              </tr>
            </thead>
            <tbody className="font-code-sm">
              {mockRules.map((rule) => (
                <tr
                  key={rule.id}
                  className="border-b border-outline-variant/30 hover:bg-surface-container-high transition-colors"
                >
                  <td className="p-md text-on-surface font-medium">
                    <div className="flex flex-col">
                      <span>{rule.name}</span>
                      <span className="text-[11px] text-outline">{rule.id}</span>
                    </div>
                  </td>
                  <td className="p-md">
                    <span
                      className={`px-xs py-[2px] rounded text-[10px] font-bold border uppercase ${
                        rule.action === "ALLOW"
                          ? "bg-secondary/10 text-secondary border-secondary/20"
                          : "bg-error/10 text-error border-error/20"
                      }`}
                    >
                      {rule.action}
                    </span>
                  </td>
                  <td className="p-md text-primary">{rule.protocol}</td>
                  <td className="p-md text-on-surface-variant">{rule.source}</td>
                  <td className="p-md text-on-surface-variant">{rule.port}</td>
                  <td className="p-md text-right">
                    <span className="w-8 h-4 bg-secondary/20 border border-secondary/40 rounded-full inline-flex items-center p-0.5 justify-end">
                      <span className="w-3 h-3 rounded-full bg-secondary"></span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
