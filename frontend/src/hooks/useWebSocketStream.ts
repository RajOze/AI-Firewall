import { useEffect, useRef } from 'react';
import { useTelemetryStore } from '../stores/useTelemetryStore';

export function useWebSocketStream() {
  const ingestStreamEvent = useTelemetryStore((s) => s.ingestStreamEvent);
  const setConnected = useTelemetryStore((s) => s.setConnected);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<any>(null);

  useEffect(() => {
    let isMounted = true;

    function connect() {
      if (!isMounted) return;
      const wsUrl = 'ws://127.0.0.1:8000/api/v1/stream/ws?topics=*';

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isMounted) {
            setConnected(true);
            console.log('[Sentinel WS] Telemetry stream online');
          }
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const parsed = JSON.parse(event.data);
            const topic = parsed.topic || parsed.event_type || 'NETWORK_CONNECTION';
            const data = parsed.data || parsed.payload || parsed;
            ingestStreamEvent(topic, data);
          } catch (err) {
            console.warn('[Sentinel WS] Frame parse error:', err);
          }
        };

        ws.onerror = (err) => {
          console.warn('[Sentinel WS] Socket error:', err);
        };

        ws.onclose = () => {
          if (isMounted) {
            setConnected(false);
            reconnectTimerRef.current = setTimeout(connect, 3000);
          }
        };
      } catch (err) {
        if (isMounted) {
          reconnectTimerRef.current = setTimeout(connect, 3000);
        }
      }
    }

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [ingestStreamEvent, setConnected]);
}
