import { useState } from 'react';
import { useWebSocket, type ReadyState } from './useWebSocket';
import { getWsUrl } from '../lib/api';

export interface FlowRecord {
  dstHost: string;
  dstPort: number;
  protocol: string;
  srcIps: string[];
  connCount: number;
  activeCount: number;
  closedCount: number;
  uploadTotal: number;
  downloadTotal: number;
  bytesTotal: number;
  rule: string;
  rulePayload: string;
  chains: string[];
  asn: string | null;
  country: string | null;
  lastSeen: string;
}

interface UseFlowsReturn {
  flows: FlowRecord[];
  readyState: ReadyState;
}

export function useFlows(includeClosed = true): UseFlowsReturn {
  const url = getWsUrl(`/ws/flows?interval=5&top=50&include_closed=${includeClosed}`);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const readyState = useWebSocket<FlowRecord[]>(url, (message) => {
    if (message) setFlows(message);
  });

  return { flows, readyState };
}
