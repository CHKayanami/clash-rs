import { useEffect, useEffectEvent, useState } from 'react';

export type ReadyState = 'CONNECTING' | 'OPEN' | 'CLOSED';

export function useWebSocket<T>(url: string | null, onMessage: (message: T) => void): ReadyState {
  const initialState = url ? 'CONNECTING' : 'CLOSED';
  const [connection, setConnection] = useState<{ url: string | null; readyState: ReadyState }>({
    url,
    readyState: initialState,
  });
  if (connection.url !== url) {
    setConnection({ url, readyState: initialState });
  }

  const receiveMessage = useEffectEvent(onMessage);

  useEffect(() => {
    if (!url) return;

    let socket: WebSocket | undefined;
    let retryTimeout: ReturnType<typeof setTimeout> | undefined;
    let retryCount = 0;
    let active = true;

    function connect(address: string) {
      const ws = new WebSocket(address);
      socket = ws;

      ws.onopen = () => {
        if (!active) return;
        setConnection({ url: address, readyState: 'OPEN' });
        retryCount = 0;
      };

      ws.onmessage = (event) => {
        if (!active) return;
        let message: T;
        try {
          message = JSON.parse(event.data) as T;
        } catch {
          return;
        }
        receiveMessage(message);
      };

      ws.onclose = () => {
        if (!active) return;
        setConnection({ url: address, readyState: 'CLOSED' });
        socket = undefined;

        const delay = Math.min(1000 * 2 ** retryCount, 30000);
        retryCount += 1;
        retryTimeout = setTimeout(() => {
          setConnection({ url: address, readyState: 'CONNECTING' });
          connect(address);
        }, delay);
      };

      ws.onerror = () => ws.close();
    }

    connect(url);
    return () => {
      active = false;
      clearTimeout(retryTimeout);
      socket?.close();
    };
  }, [url]);

  return connection.url === url ? connection.readyState : initialState;
}
