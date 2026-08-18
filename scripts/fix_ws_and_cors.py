from pathlib import Path

# 1. Update frontend/src/hooks/useWebSocketStream.ts
ws_hook_code = '''import { useEffect, useRef, useCallback } from 'react';
import { useTelemetryStore } from '../stores/useTelemetryStore';

interface UseWebSocketOptions {
  url?: string;
  topics?: string[];
  reconnectInterval?: number;
}

export function useWebSocketStream(options: UseWebSocketOptions = {}) {
  // Explicitly target IPv4 127.0.0.1 to avoid Windows IPv6 [::1] connection rejection
  const defaultWsHost = window.location.hostname === 'localhost' ? '127.0.0.1' : (window.location.hostname || '127.0.0.1');
  const {
    url = `ws://${defaultWsHost}:8000/api/v1/stream/ws`,
    topics = ['*'],
    reconnectInterval = 2000,
  } = options;

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const { setConnected, ingestStreamEvent } = useTelemetryStore();

  const connect = useCallback(() => {
    try {
      const topicParam = encodeURIComponent(topics.join(','));
      const wsUrl = `${url}?topics=${topicParam}`;
      console.log('[Sentinel WS] Connecting to:', wsUrl);
      const socket = new WebSocket(wsUrl);

      socket.onopen = () => {
        console.log('[Sentinel WS] Connection established successfully.');
        setConnected(true);
        const pingInterval = window.setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send('ping');
          }
        }, 10000);
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
          // Ignore heartbeat/ping frame parse errors
        }
      };

      socket.onclose = (ev) => {
        console.warn('[Sentinel WS] Socket closed (code: ' + ev.code + '). Reconnecting in ' + reconnectInterval + 'ms...');
        setConnected(false);
        if ((socket as any)._pingInterval) {
          clearInterval((socket as any)._pingInterval);
        }
        reconnectTimeoutRef.current = window.setTimeout(connect, reconnectInterval);
      };

      socket.onerror = (err) => {
        console.error('[Sentinel WS] Socket error:', err);
        socket.close();
      };

      wsRef.current = socket;
    } catch (err) {
      console.error('[Sentinel WS] Init error:', err);
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
Path("frontend/src/hooks/useWebSocketStream.ts").write_text(ws_hook_code, encoding="utf-8")
print("Successfully updated frontend/src/hooks/useWebSocketStream.ts")

# 2. Ensure CORS in backend/app/main.py allows all origins for local dev
main_py_path = Path("backend/app/main.py")
if main_py_path.exists():
    main_code = main_py_path.read_text(encoding="utf-8-sig").replace("\ufeff", "")
    if "CORSMiddleware" not in main_code:
        cors_snippet = """from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
"""
        # Insert CORS right after app initialization
        if "app = FastAPI(" in main_code:
            parts = main_code.split("app = FastAPI(", 1)
            rest_of_code = parts[1].split(")", 1)
            main_code = parts[0] + "app = FastAPI(" + rest_of_code[0] + ")\n\n" + cors_snippet + rest_of_code[1]
            main_py_path.write_text(main_code, encoding="utf-8")
            print("Successfully injected CORS middleware into backend/app/main.py")
