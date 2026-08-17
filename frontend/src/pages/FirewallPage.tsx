import { useEffect, useState } from "react";
import {
  checkFirewallRule,
  fetchFirewallRules,
} from "../services/api";
import type {
  FirewallRuleResponse,
  FirewallRuleStatusResponse,
} from "../services/api";

export default function FirewallPage() {
  const [rules, setRules] = useState<FirewallRuleResponse[]>([]);
  const [rulesLoading, setRulesLoading] = useState(true);
  const [rulesError, setRulesError] = useState<string | null>(null);

  const [queryRuleName, setQueryRuleName] = useState("");
  const [queryResult, setQueryResult] =
    useState<FirewallRuleStatusResponse | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [queryLoading, setQueryLoading] = useState(false);

  useEffect(() => {
    const loadFirewallRules = async () => {
      setRulesLoading(true);
      setRulesError(null);

      try {
        const data = await fetchFirewallRules();

        setRules(data);

        if (data.length > 0) {
          setQueryRuleName(data[0].name);
        }
      } catch (err: unknown) {
        setRulesError(
          err instanceof Error
            ? err.message
            : "Failed to load Windows Firewall rules",
        );
      } finally {
        setRulesLoading(false);
      }
    };

    loadFirewallRules();
  }, []);

  const handleInspectRule = async () => {
    if (!queryRuleName.trim()) return;

    setQueryLoading(true);
    setQueryError(null);
    setQueryResult(null);

    try {
      const result = await checkFirewallRule(queryRuleName);
      setQueryResult(result);
    } catch (err: unknown) {
      setQueryError(
        err instanceof Error
          ? err.message
          : "Failed to inspect firewall rule",
      );
    } finally {
      setQueryLoading(false);
    }
  };

  return (
    <div className="flex flex-col w-full gap-gutter">
      <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex items-center justify-between">
        <div>
          <h1 className="font-headline-lg text-on-surface">
            Firewall Management & Rule Inspector
          </h1>

          <p className="font-body-sm text-outline mt-1">
            Inspect and manage the live Windows Firewall configuration.
          </p>
        </div>

        <button className="px-md py-sm bg-primary text-on-primary font-body-sm rounded hover:bg-primary-container transition-colors flex items-center gap-xs">
          <span className="material-symbols-outlined text-[18px]">
            add
          </span>
          Create New Rule
        </button>
      </div>

      <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex flex-col gap-md">
        <div className="flex items-center gap-sm">
          <span className="material-symbols-outlined text-primary text-[24px]">
            verified_user
          </span>

          <div>
            <h2 className="font-headline-sm text-on-surface">
              Live OS Rule Inspector (FastAPI Backend)
            </h2>

            <p className="font-body-sm text-outline text-[12px]">
              Queries the local Windows Firewall service to verify rule
              existence.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-md max-w-xl">
          <input
            type="text"
            value={queryRuleName}
            onChange={(e) => setQueryRuleName(e.target.value)}
            placeholder="Enter an actual Windows Firewall rule name"
            className="flex-1 bg-surface-container-low border border-outline-variant rounded px-md py-sm text-body-sm font-code-sm text-on-surface focus:outline-none focus:border-primary"
          />

          <button
            onClick={handleInspectRule}
            disabled={queryLoading || !queryRuleName.trim()}
            className="px-lg py-sm bg-secondary text-on-secondary font-body-sm font-medium rounded hover:bg-secondary-container transition-colors disabled:opacity-50"
          >
            {queryLoading ? "Checking..." : "Inspect Rule"}
          </button>
        </div>

        {queryResult && (
          <div className="p-md bg-secondary/10 border border-secondary/20 rounded font-code-sm text-[13px] text-secondary flex items-center gap-md">
            <span className="material-symbols-outlined text-[20px]">
              check_circle
            </span>

            <span>
              Rule <strong>"{queryResult.rule_name}"</strong>:{" "}
              {queryResult.exists
                ? "Active & Configured in OS"
                : "Not Found"}
            </span>
          </div>
        )}

        {queryError && (
          <div className="p-md bg-error/10 border border-error/20 rounded font-code-sm text-[13px] text-error flex items-center gap-md">
            <span className="material-symbols-outlined text-[20px]">
              error
            </span>

            <span>{queryError}</span>
          </div>
        )}
      </div>

      <div className="bg-surface-container rounded border border-outline-variant/30 overflow-hidden">
        <div className="p-lg border-b border-outline-variant flex items-center justify-between bg-surface-container-low">
          <span className="font-label-caps text-on-surface uppercase tracking-widest">
            Windows Firewall Rules ({rules.length})
          </span>

          <span className="font-body-sm text-outline">
            Source:{" "}
            <strong className="text-secondary">LIVE WINDOWS</strong>
          </span>
        </div>

        {rulesLoading && (
          <div className="p-xl text-center text-outline">
            Loading Windows Firewall rules...
          </div>
        )}

        {rulesError && (
          <div className="m-lg p-md bg-error/10 border border-error/20 rounded text-error">
            <strong>Unable to load firewall rules:</strong>{" "}
            {rulesError}
          </div>
        )}

        {!rulesLoading && !rulesError && rules.length === 0 && (
          <div className="p-xl text-center text-outline">
            No Windows Firewall rules were returned.
          </div>
        )}

        {!rulesLoading && !rulesError && rules.length > 0 && (
          <div className="overflow-x-auto max-h-[650px] overflow-y-auto">
            <table className="w-full text-left">
              <thead className="sticky top-0 z-10 bg-surface-container-highest">
                <tr>
                  <th className="p-md font-label-caps text-outline">
                    Rule Name
                  </th>
                  <th className="p-md font-label-caps text-outline">
                    Action
                  </th>
                  <th className="p-md font-label-caps text-outline">
                    Direction
                  </th>
                  <th className="p-md font-label-caps text-outline">
                    Profile
                  </th>
                  <th className="p-md font-label-caps text-outline text-right">
                    Status
                  </th>
                </tr>
              </thead>

              <tbody className="font-code-sm">
                {rules.map((rule) => {
                  const action = rule.action.toUpperCase();

                  return (
                    <tr
                      key={rule.name}
                      className="border-b border-outline-variant/30 hover:bg-surface-container-high transition-colors"
                    >
                      <td className="p-md text-on-surface font-medium">
                        <div className="flex flex-col">
                          <span>{rule.display_name}</span>
                          <span className="text-[11px] text-outline">
                            {rule.name}
                          </span>
                        </div>
                      </td>

                      <td className="p-md">
                        <span
                          className={`px-xs py-[2px] rounded text-[10px] font-bold border uppercase ${
                            action === "ALLOW"
                              ? "bg-secondary/10 text-secondary border-secondary/20"
                              : action === "BLOCK"
                                ? "bg-error/10 text-error border-error/20"
                                : "bg-surface-container-high text-outline border-outline-variant"
                          }`}
                        >
                          {action}
                        </span>
                      </td>

                      <td className="p-md text-primary uppercase">
                        {rule.direction}
                      </td>

                      <td className="p-md text-on-surface-variant uppercase">
                        {rule.profile}
                      </td>

                      <td className="p-md text-right">
                        <span
                          className={`inline-flex items-center gap-xs px-sm py-[2px] rounded text-[10px] font-bold border ${
                            rule.enabled
                              ? "bg-secondary/10 text-secondary border-secondary/20"
                              : "bg-error/10 text-error border-error/20"
                          }`}
                        >
                          <span
                            className={`w-2 h-2 rounded-full ${
                              rule.enabled
                                ? "bg-secondary"
                                : "bg-error"
                            }`}
                          />

                          {rule.enabled ? "ENABLED" : "DISABLED"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
