from pathlib import Path

# 1. Update frontend/src/stores/useTelemetryStore.ts to auto-mark connected on incoming packets
store_code = '''import { create } from 'zustand';

export interface TelemetryEvent {
  topic: string;
  timestamp: string;
  data: Record<string, any>;
}

export interface LiveSession {
  process: string;
  ip: string;
  protocol: string;
  port: number | string;
  status: 'Allowed' | 'Monitoring' | 'Blocked';
  riskScore: number;
}

export interface TelemetryState {
  isConnected: boolean;
  activeConnectionsCount: number;
  overallRiskScore: number;
  threatsCount: number;
  recentEvents: TelemetryEvent[];
  liveSessions: LiveSession[];

  // Actions
  setConnected: (status: boolean) => void;
  ingestStreamEvent: (topic: string, data: Record<string, any>) => void;
  clearEvents: () => void;
}

export const useTelemetryStore = create<TelemetryState>((set) => ({
  isConnected: false,
  activeConnectionsCount: 0,
  overallRiskScore: 0.04,
  threatsCount: 0,
  recentEvents: [],
  liveSessions: [],

  setConnected: (status) => set({ isConnected: status }),

  ingestStreamEvent: (topic, data) =>
    set((state) => {
      const newEvent: TelemetryEvent = {
        topic,
        timestamp: new Date().toISOString(),
        data,
      };
      const updatedEvents = [newEvent, ...state.recentEvents].slice(0, 100);

      let newLiveSessions = state.liveSessions;
      let newThreatCount = state.threatsCount;
      let newRiskScore = state.overallRiskScore;

      if (topic === 'NETWORK_CONNECTION' || topic === 'PROCESS_START') {
        const session: LiveSession = {
          process: data.process_name || data.process || 'system.exe',
          ip: data.remote_address || data.ip || '127.0.0.1',
          protocol: data.protocol || 'TCP',
          port: data.remote_port || data.port || 0,
          status: data.risk_score > 0.7 ? 'Blocked' : data.risk_score > 0.4 ? 'Monitoring' : 'Allowed',
          riskScore: data.risk_score || 0.0,
        };
        newLiveSessions = [session, ...state.liveSessions].slice(0, 50);
      }

      if (topic === 'AI_ADVISORY' || topic === 'POLICY_VIOLATION') {
        newThreatCount += 1;
        if (data.severity === 'CRITICAL' || data.severity === 'HIGH') {
          newRiskScore = Math.min(1.0, newRiskScore + 0.15);
        }
      }

      return {
        isConnected: true, // Auto-mark connected when streaming packets arrive
        recentEvents: updatedEvents,
        liveSessions: newLiveSessions,
        threatsCount: newThreatCount,
        overallRiskScore: newRiskScore,
        activeConnectionsCount: newLiveSessions.length,
      };
    }),

  clearEvents: () => set({ recentEvents: [], liveSessions: [] }),
}));
'''

Path("frontend/src/stores/useTelemetryStore.ts").write_text(store_code, encoding="utf-8")
print("Successfully patched useTelemetryStore.ts")
