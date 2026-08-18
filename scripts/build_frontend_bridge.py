from pathlib import Path

files = {}

# 1. frontend/src/stores/useTelemetryStore.ts
files['frontend/src/stores/useTelemetryStore.ts'] = '''import { create } from 'zustand';

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
      // 1. Append to bounded event buffer (capped at 100 to prevent memory growth)
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

# 2. frontend/src/hooks/useWebSocketStream.ts
files['frontend/src/hooks/useWebSocketStream.ts'] = '''import { useEffect, useRef, useCallback } from 'react';
import { useTelemetryStore } from '../stores/useTelemetryStore';

interface UseWebSocketOptions {
  url?: string;
  topics?: string[];
  reconnectInterval?: number;
}

export function useWebSocketStream(options: UseWebSocketOptions = {}) {
  const {
    url = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.hostname || '127.0.0.1'}:8000/api/v1/stream/ws`,
    topics = ['*'],
    reconnectInterval = 3000,
  } = options;

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const { setConnected, ingestStreamEvent } = useTelemetryStore();

  const connect = useCallback(() => {
    try {
      const topicParam = encodeURIComponent(topics.join(','));
      const wsUrl = `${url}?topics=${topicParam}`;
      const socket = new WebSocket(wsUrl);

      socket.onopen = () => {
        setConnected(true);
        const pingInterval = window.setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send('ping');
          }
        }, 15000);
        (socket as any)._pingInterval = pingInterval;
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'pong') return;
          if (payload.topic && payload.data) {
            ingestStreamEvent(payload.topic, payload.data);
          }
        } catch {
          // Ignore raw heartbeat or unparseable payloads
        }
      };

      socket.onclose = () => {
        setConnected(false);
        if ((socket as any)._pingInterval) {
          clearInterval((socket as any)._pingInterval);
        }
        reconnectTimeoutRef.current = window.setTimeout(connect, reconnectInterval);
      };

      socket.onerror = () => {
        socket.close();
      };

      wsRef.current = socket;
    } catch {
      reconnectTimeoutRef.current = window.setTimeout(connect, reconnectInterval);
    }
  }, [url, topics, reconnectInterval, setConnected, ingestStreamEvent]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        if ((wsRef.current as any)._pingInterval) {
          clearInterval((wsRef.current as any)._pingInterval);
        }
        wsRef.current.close();
      }
    };
  }, [connect]);

  return { isConnected: wsRef.current?.readyState === WebSocket.OPEN };
}
'''

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully created: {rel_path}')
