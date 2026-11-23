import { useState } from 'react';
import { useWebSocket } from './useWebSocket';
import { getWsUrl, type TrafficData } from '../lib/api';

const HISTORY_LENGTH = 60;

interface TrafficHistory {
  up: number[];
  down: number[];
  timestamps: number[];
}

interface UseTrafficReturn {
  history: TrafficHistory;
  current: TrafficData;
}

export function useTraffic(): UseTrafficReturn {
  const [traffic, setTraffic] = useState<UseTrafficReturn>(() => {
    const now = Date.now() / 1000;
    return {
      history: {
        up: new Array(HISTORY_LENGTH).fill(0),
        down: new Array(HISTORY_LENGTH).fill(0),
        timestamps: Array.from({ length: HISTORY_LENGTH }, (_, i) => now - (HISTORY_LENGTH - 1 - i)),
      },
      current: { up: 0, down: 0 },
    };
  });

  useWebSocket<TrafficData>(getWsUrl('/ws/traffic'), (sample) => {
    if (!sample) return;
    const now = Date.now() / 1000;
    setTraffic(({ history }) => ({
      current: sample,
      history: {
        up: [...history.up.slice(1), sample.up],
        down: [...history.down.slice(1), sample.down],
        timestamps: [...history.timestamps.slice(1), now],
      },
    }));
  });

  return traffic;
}
