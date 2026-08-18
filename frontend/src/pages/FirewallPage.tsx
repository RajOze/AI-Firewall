import { useState, useEffect } from 'react';
import type { FirewallRuleSummary } from '../services/api';
import { api } from '../services/api';
import { Shield, Search, RefreshCw, AlertCircle, CheckCircle2, ArrowUpRight, ArrowDownLeft } from 'lucide-react';

export default function FirewallPage() {
  const [rules, setRules] = useState<FirewallRuleSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState<'all' | 'block' | 'allow'>('all');
  const [filterDirection, setFilterDirection] = useState<'all' | 'inbound' | 'outbound'>('all');
  const [error, setError] = useState<string | null>(null);

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getFirewallRules(200);
      setRules(data.rules || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load firewall rules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const filteredRules = rules.filter((r) => {
    const nameMatch = (r.name || '').toLowerCase().includes(search.toLowerCase()) || 
                      (r.display_name || '').toLowerCase().includes(search.toLowerCase());
    const actionMatch = filterAction === 'all' || (r.action || '').toLowerCase() === filterAction;
    const directionMatch = filterDirection === 'all' || (r.direction || '').toLowerCase() === filterDirection;
    return nameMatch && actionMatch && directionMatch;
  });

  return (
    <div className="flex flex-col w-full gap-6 p-6 text-slate-100 font-mono">
      {/* Top Banner */}
      <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-blue-400" />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">Windows Firewall Management</h1>
            <p className="text-xs text-slate-400">Real-time NetSecurity rule inventory & policy synchronization</p>
          </div>
        </div>
        <button 
          onClick={fetchRules}
          disabled={loading}
          className="px-3.5 py-1.5 bg-[#161c2e] hover:bg-slate-800 rounded-lg border border-slate-700 text-xs font-semibold flex items-center gap-2 transition-colors disabled:opacity-50 text-slate-200"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Sync Rules
        </button>
      </div>

      {error && (
        <div className="p-4 bg-red-950/50 border border-red-800/60 rounded-xl text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input 
            type="text"
            placeholder="Search rules by name or display tag..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#161c2e] border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Action:</span>
          {(['all', 'block', 'allow'] as const).map((act) => (
            <button
              key={act}
              onClick={() => setFilterAction(act)}
              className={`px-2.5 py-1 rounded uppercase text-[10px] font-bold transition-colors ${
                filterAction === act 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-[#161c2e] text-slate-400 hover:text-white'
              }`}
            >
              {act}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Direction:</span>
          {(['all', 'inbound', 'outbound'] as const).map((dir) => (
            <button
              key={dir}
              onClick={() => setFilterDirection(dir)}
              className={`px-2.5 py-1 rounded uppercase text-[10px] font-bold transition-colors ${
                filterDirection === dir 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-[#161c2e] text-slate-400 hover:text-white'
              }`}
            >
              {dir}
            </button>
          ))}
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-[#111625] p-5 rounded-xl border border-slate-800 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-300">Host Firewall Rule Inventory</h2>
          <span className="text-xs text-slate-400">
            Showing {filteredRules.length} of {rules.length} loaded rules
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#161c2e] border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2.5 px-3">Rule Name / Display Tag</th>
                <th className="py-2.5 px-3">Direction</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Target Address</th>
                <th className="py-2.5 px-3">Target Port</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-slate-500">
                    {loading ? 'Querying Windows NetSecurity Provider...' : 'No matching rules found.'}
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule, idx) => {
                  const isSentinelRule = (rule.name || '').startsWith('AI-Firewall');
                  const isBlock = (rule.action || '').toLowerCase() === 'block';

                  return (
                    <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                          {isSentinelRule && (
                            <span className="px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-400 text-[9px] uppercase font-bold">
                              Sentinel
                            </span>
                          )}
                          <span className="truncate max-w-[280px]">{rule.display_name || rule.name}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 truncate block max-w-[320px]">{rule.name}</span>
                      </td>

                      <td className="py-2.5 px-3">
                        <span className="flex items-center gap-1 text-[11px]">
                          {(rule.direction || '').toLowerCase() === 'outbound' ? (
                            <><ArrowUpRight className="w-3.5 h-3.5 text-blue-400" /> Outbound</>
                          ) : (
                            <><ArrowDownLeft className="w-3.5 h-3.5 text-emerald-400" /> Inbound</>
                          )}
                        </span>
                      </td>

                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          isBlock ? 'bg-red-950/80 text-red-400 border border-red-800' : 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                        }`}>
                          {rule.action || 'ALLOW'}
                        </span>
                      </td>

                      <td className="py-2.5 px-3 text-slate-300">
                        {rule.remote_address || 'Any'}
                      </td>

                      <td className="py-2.5 px-3 text-slate-300">
                        {rule.remote_port || 'Any'}
                      </td>

                      <td className="py-2.5 px-3 text-right">
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold text-[11px]">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Active
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
