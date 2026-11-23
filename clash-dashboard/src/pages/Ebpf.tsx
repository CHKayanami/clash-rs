import { useRef, useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  getEbpfStatus,
  queryEbpfDomain,
  queryEbpfIp,
  type EbpfDomainQueryResponse,
  type EbpfIpQueryResponse,
} from '../lib/api';
import {
  AlertCircle,
  CheckCircle2,
  Cpu,
  Globe,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';

interface StatusBadgeMeta {
  label: string;
  background: string;
  color: string;
}

function getOffloadStatusBadge(status: string): StatusBadgeMeta {
  switch (status) {
    case 'applied':
      return {
        label: 'Applied (Kernel Direct)',
        background: 'rgba(52,199,89,0.12)',
        color: '#34c759',
      };
    case 'static_bypass':
      return {
        label: 'Static Bypass',
        background: 'rgba(0,113,227,0.12)',
        color: '#0071e3',
      };
    case 'pending_sync':
      return {
        label: 'Pending Sync',
        background: 'rgba(255,149,0,0.12)',
        color: '#ff9500',
      };
    case 'paused_global':
      return {
        label: 'Paused (Global Mode)',
        background: 'rgba(255,149,0,0.12)',
        color: '#ff9500',
      };
    case 'vetoed':
      return {
        label: 'Vetoed (Shared Proxy IP)',
        background: 'rgba(255,59,48,0.12)',
        color: '#ff3b30',
      };
    case 'proxy':
    case 'static_proxy':
      return {
        label: status === 'static_proxy' ? 'Static Proxy' : 'Proxy',
        background: 'rgba(175,82,222,0.12)',
        color: '#af52de',
      };
    case 'reserved':
      return {
        label: 'Reserved IP',
        background: 'var(--color-fill-medium)',
        color: 'var(--color-text-secondary)',
      };
    case 'fake_ip':
      return {
        label: 'Fake-IP',
        background: 'rgba(255,45,85,0.12)',
        color: '#ff2d55',
      };
    default:
      return {
        label: 'Not Tracked',
        background: 'var(--color-fill-medium)',
        color: 'var(--color-text-secondary)',
      };
  }
}

function getActionBadge(action: string): StatusBadgeMeta {
  if (action === 'direct') {
    return {
      label: 'DIRECT',
      background: 'rgba(52,199,89,0.12)',
      color: '#34c759',
    };
  }
  return {
    label: 'PROXY',
    background: 'rgba(255,149,0,0.12)',
    color: '#ff9500',
  };
}

function BoolPill({ value, trueLabel = 'Yes', falseLabel = 'No' }: { value: boolean; trueLabel?: string; falseLabel?: string }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium"
      style={
        value
          ? { background: 'rgba(52,199,89,0.12)', color: '#34c759' }
          : { background: 'var(--color-fill-medium)', color: 'var(--color-text-secondary)' }
      }
    >
      {value ? trueLabel : falseLabel}
    </span>
  );
}

export function Ebpf() {
  const {
    data: status,
    isLoading: statusLoading,
    isFetching: statusFetching,
    error: statusError,
    refetch: refetchStatus,
  } = useQuery({
    queryKey: ['ebpf-status'],
    queryFn: getEbpfStatus,
    refetchInterval: 10000,
    retry: 0,
  });

  // Manual refresh spin feedback (API replies in ~1ms, too fast for a single frame)
  const [manualRefreshing, setManualRefreshing] = useState(false);

  async function handleRefreshStatus() {
    if (manualRefreshing || statusFetching) return;
    setManualRefreshing(true);
    try {
      await Promise.all([
        refetchStatus(),
        new Promise((resolve) => window.setTimeout(resolve, 350)),
      ]);
    } finally {
      setManualRefreshing(false);
    }
  }

  // Domain exact lookup state
  const [domainInput, setDomainInput] = useState('');
  const [domainResult, setDomainResult] = useState<EbpfDomainQueryResponse | null>(null);
  const [domainError, setDomainError] = useState<string | null>(null);
  const [domainLoading, setDomainLoading] = useState(false);
  const domainSeqRef = useRef(0);

  // IP exact lookup state
  const [ipInput, setIpInput] = useState('');
  const [ipResult, setIpResult] = useState<EbpfIpQueryResponse | null>(null);
  const [ipError, setIpError] = useState<string | null>(null);
  const [ipLoading, setIpLoading] = useState(false);
  const ipSeqRef = useRef(0);

  async function runDomainLookup(raw: string) {
    const trimmed = raw.trim();
    if (!trimmed) return;
    const seq = ++domainSeqRef.current;
    setDomainLoading(true);
    setDomainError(null);
    try {
      const res = await queryEbpfDomain(trimmed);
      if (seq !== domainSeqRef.current) return;
      setDomainResult(res);
    } catch (e) {
      if (seq !== domainSeqRef.current) return;
      setDomainResult(null);
      setDomainError(e instanceof Error ? e.message : 'Domain lookup failed');
    } finally {
      if (seq === domainSeqRef.current) {
        setDomainLoading(false);
      }
    }
  }

  async function runIpLookup(raw: string) {
    const trimmed = raw.trim();
    if (!trimmed) return;
    const seq = ++ipSeqRef.current;
    setIpLoading(true);
    setIpError(null);
    try {
      const res = await queryEbpfIp(trimmed);
      if (seq !== ipSeqRef.current) return;
      setIpResult(res);
    } catch (e) {
      if (seq !== ipSeqRef.current) return;
      setIpResult(null);
      setIpError(e instanceof Error ? e.message : 'IP lookup failed');
    } finally {
      if (seq === ipSeqRef.current) {
        setIpLoading(false);
      }
    }
  }

  function handleDomainSubmit(e: FormEvent) {
    e.preventDefault();
    void runDomainLookup(domainInput);
  }

  function handleIpSubmit(e: FormEvent) {
    e.preventDefault();
    void runIpLookup(ipInput);
  }

  function handleInspectIpFromDomain(ip: string) {
    setIpInput(ip);
    void runIpLookup(ip);
  }

  const canQuery = Boolean(status?.enabled && status?.auto_direct_offload && status?.ready);
  const counts = status?.counts;

  return (
    <div className="p-4 sm:p-6 space-y-5">
      {/* Header & Summary Card */}
      <div className="glass-card p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center"
              style={{ background: 'rgba(0,113,227,0.12)', color: '#0071e3' }}
            >
              <Cpu size={18} />
            </div>
            <div>
              <h1 className="text-[17px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>
                eBPF Direct Offload
              </h1>
              <p className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
                Inspect domain owners and kernel dynamic bypass status
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {status && (
              <>
                <span
                  className="px-2.5 py-1 rounded-full text-[12px] font-medium"
                  style={
                    status.enabled
                      ? { background: 'rgba(52,199,89,0.12)', color: '#34c759' }
                      : { background: 'var(--color-fill-medium)', color: 'var(--color-text-secondary)' }
                  }
                >
                  {status.enabled ? 'eBPF Enabled' : 'eBPF Disabled'}
                </span>
                {status.enabled && (
                  <span
                    className="px-2.5 py-1 rounded-full text-[12px] font-medium"
                    style={
                      status.auto_direct_offload
                        ? { background: 'rgba(0,113,227,0.12)', color: '#0071e3' }
                        : { background: 'rgba(255,149,0,0.12)', color: '#ff9500' }
                    }
                  >
                    {status.auto_direct_offload ? 'Auto Offload On' : 'Auto Offload Off'}
                  </span>
                )}
                {status.active_mode && (
                  <span
                    className="px-2.5 py-1 rounded-full text-[12px] font-medium uppercase"
                    style={{ background: 'var(--color-fill-medium)', color: 'var(--color-text-primary)' }}
                  >
                    Mode: {status.active_mode}
                  </span>
                )}
              </>
            )}
            <button
              type="button"
              onClick={() => void handleRefreshStatus()}
              disabled={manualRefreshing || statusFetching}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium cursor-pointer transition-all hover:brightness-95 active:scale-[0.96] disabled:opacity-60 disabled:cursor-not-allowed"
              style={{
                background: 'rgba(0,113,227,0.1)',
                color: '#0071e3',
              }}
            >
              <RefreshCw size={13} className={manualRefreshing || statusFetching ? 'animate-spin' : ''} />
              {manualRefreshing || statusFetching ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </div>

        {statusError && (
          <div
            className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-[13px]"
            style={{ background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }}
          >
            <AlertCircle size={15} />
            <span>{statusError instanceof Error ? statusError.message : 'Failed to load eBPF status'}</span>
          </div>
        )}

        {!statusLoading && status && !status.enabled && (
          <div
            className="flex items-center gap-2 px-3.5 py-3 rounded-xl text-[13px]"
            style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}
          >
            <ShieldAlert size={16} />
            <span>eBPF datapath is currently disabled on this instance.</span>
          </div>
        )}

        {!statusLoading && status?.enabled && !status.auto_direct_offload && (
          <div
            className="flex items-center gap-2 px-3.5 py-3 rounded-xl text-[13px]"
            style={{ background: 'rgba(255,149,0,0.1)', color: '#ff9500' }}
          >
            <AlertCircle size={16} />
            <span>
              Auto direct offload is disabled (<code>ebpf.auto-direct-offload: false</code>). Enable it to track and inspect dynamic direct bypasses.
            </span>
          </div>
        )}

        {!statusLoading && status?.enabled && status.auto_direct_offload && !status.ready && (
          <div
            className="flex items-center gap-2 px-3.5 py-3 rounded-xl text-[13px]"
            style={{ background: 'rgba(255,149,0,0.1)', color: '#ff9500' }}
          >
            <AlertCircle size={16} />
            <span>eBPF offloader is initializing or unavailable.</span>
          </div>
        )}

        {counts && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
            <div className="rounded-xl p-3.5" style={{ background: 'var(--color-fill-subtle)' }}>
              <div className="text-[11px] font-medium" style={{ color: 'var(--color-text-secondary)' }}>
                Domains
              </div>
              <div className="mt-1 text-[18px] font-semibold tabular-nums" style={{ color: 'var(--color-text-primary)' }}>
                {counts.domain_owners.toLocaleString()}
                <span className="text-[12px] font-normal ml-1" style={{ color: 'var(--color-text-secondary)' }}>
                  / {counts.max_domain_owners.toLocaleString()}
                </span>
              </div>
            </div>

            <div className="rounded-xl p-3.5" style={{ background: 'var(--color-fill-subtle)' }}>
              <div className="text-[11px] font-medium" style={{ color: 'var(--color-text-secondary)' }}>
                Direct IP Owners
              </div>
              <div className="mt-1 text-[18px] font-semibold tabular-nums" style={{ color: 'var(--color-text-primary)' }}>
                {counts.direct_ip_owners.toLocaleString()}
                <span className="text-[12px] font-normal ml-1" style={{ color: 'var(--color-text-secondary)' }}>
                  / {counts.max_direct_ip_owners.toLocaleString()}
                </span>
              </div>
            </div>

            <div className="rounded-xl p-3.5" style={{ background: 'var(--color-fill-subtle)' }}>
              <div className="text-[11px] font-medium" style={{ color: 'var(--color-text-secondary)' }}>
                Tracked IPs (v4 / v6)
              </div>
              <div className="mt-1 text-[18px] font-semibold tabular-nums" style={{ color: 'var(--color-text-primary)' }}>
                {counts.tracked_v4.toLocaleString()}
                <span className="text-[13px] font-normal mx-1" style={{ color: 'var(--color-text-secondary)' }}>
                  /
                </span>
                {counts.tracked_v6.toLocaleString()}
              </div>
              <div className="text-[11px] tabular-nums" style={{ color: 'var(--color-text-secondary)' }}>
                Limit: {counts.max_v4_ips.toLocaleString()} each
              </div>
            </div>

            <div className="rounded-xl p-3.5" style={{ background: 'var(--color-fill-subtle)' }}>
              <div className="text-[11px] font-medium" style={{ color: 'var(--color-text-secondary)' }}>
                Kernel Applied / Desired
              </div>
              <div className="mt-1 text-[18px] font-semibold tabular-nums" style={{ color: '#34c759' }}>
                {counts.applied.toLocaleString()}
                <span className="text-[13px] font-normal mx-1" style={{ color: 'var(--color-text-secondary)' }}>
                  / {counts.desired.toLocaleString()}
                </span>
              </div>
              <div className="text-[11px] tabular-nums" style={{ color: counts.dirty > 0 ? '#ff9500' : 'var(--color-text-secondary)' }}>
                Dirty pending: {counts.dirty.toLocaleString()}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 1. Domain Exact Lookup */}
      <div className="glass-card p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Globe size={16} style={{ color: '#0071e3' }} />
          <h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>
            Domain Owner Lookup
          </h2>
          <span className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
            Exact match in domain_owners
          </span>
        </div>

        <form onSubmit={handleDomainSubmit} className="flex flex-col sm:flex-row gap-2.5">
          <div className="relative flex-1">
            <Search
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              style={{ color: 'var(--color-text-secondary)' }}
            />
            <input
              type="text"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="Enter exact domain, e.g. example.com"
              disabled={!canQuery || domainLoading}
              className="w-full pl-9 pr-3 py-2 rounded-xl text-[13px] outline-none transition-all disabled:opacity-50"
              style={{
                background: 'var(--color-fill-subtle)',
                color: 'var(--color-text-primary)',
                border: '1px solid var(--color-separator)',
              }}
            />
          </div>
          <button
            type="submit"
            disabled={!canQuery || domainLoading || !domainInput.trim()}
            className="px-4 py-2 rounded-xl text-[13px] font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
            style={{ background: '#0071e3' }}
          >
            {domainLoading ? 'Querying...' : 'Query Domain'}
          </button>
        </form>

        {domainError && (
          <div
            className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-[13px]"
            style={{ background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }}
          >
            <AlertCircle size={15} />
            <span>{domainError}</span>
          </div>
        )}

        {domainResult && !domainResult.found && (
          <div
            className="px-4 py-3 rounded-xl text-[13px]"
            style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}
          >
            Domain <span className="font-mono font-medium" style={{ color: 'var(--color-text-primary)' }}>{domainResult.normalized}</span> is not in <code>domain_owners</code>.
          </div>
        )}

        {domainResult?.found && domainResult.owner && (
          <div className="space-y-3">
            <div
              className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-xl text-[13px]"
              style={{ background: 'var(--color-fill-subtle)' }}
            >
              <div>
                <span className="text-[11px] block" style={{ color: 'var(--color-text-secondary)' }}>Domain</span>
                <span className="font-mono font-semibold" style={{ color: 'var(--color-text-primary)' }}>
                  {domainResult.normalized}
                </span>
              </div>
              <div>
                <span className="text-[11px] block" style={{ color: 'var(--color-text-secondary)' }}>Action</span>
                <span
                  className="inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold"
                  style={getActionBadge(domainResult.owner.action)}
                >
                  {getActionBadge(domainResult.owner.action).label}
                </span>
              </div>
              <div>
                <span className="text-[11px] block" style={{ color: 'var(--color-text-secondary)' }}>Outbound</span>
                <span className="font-medium" style={{ color: 'var(--color-text-primary)' }}>
                  {domainResult.owner.outbound ?? '-'}
                </span>
              </div>
              <div>
                <span className="text-[11px] block" style={{ color: 'var(--color-text-secondary)' }}>Rule Offloadable</span>
                <BoolPill value={domainResult.owner.rule_offloadable} />
              </div>
              <div>
                <span className="text-[11px] block" style={{ color: 'var(--color-text-secondary)' }}>Last Seen Seq</span>
                <span className="font-mono tabular-nums" style={{ color: 'var(--color-text-primary)' }}>
                  #{domainResult.owner.last_seen}
                </span>
              </div>
            </div>

            {domainResult.owner.ips.length === 0 ? (
              <div
                className="px-4 py-3 rounded-xl text-[13px]"
                style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}
              >
                No IPs currently associated with this domain owner.
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl" style={{ border: '1px solid var(--color-separator)' }}>
                <table className="w-full text-left border-collapse text-[12px]">
                  <thead>
                    <tr style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}>
                      <th className="py-2.5 px-3 font-medium">IP Address</th>
                      <th className="py-2.5 px-3 font-medium">Family</th>
                      <th className="py-2.5 px-3 font-medium">Counts (Direct / Proxy)</th>
                      <th className="py-2.5 px-3 font-medium">Desired</th>
                      <th className="py-2.5 px-3 font-medium">Kernel Applied</th>
                      <th className="py-2.5 px-3 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {domainResult.owner.ips.map((item) => {
                      const badge = getOffloadStatusBadge(item.status);
                      return (
                        <tr
                          key={item.ip}
                          className="transition-colors hover:bg-black/[0.02] dark:hover:bg-white/[0.03]"
                          style={{ borderTop: '1px solid var(--color-separator)' }}
                        >
                          <td className="py-2.5 px-3">
                            <button
                              type="button"
                              disabled={!canQuery || ipLoading}
                              onClick={() => handleInspectIpFromDomain(item.ip)}
                              title="Click to inspect this IP"
                              className="font-mono font-medium hover:underline text-left disabled:opacity-50 disabled:cursor-not-allowed disabled:no-underline"
                              style={{ color: '#0071e3' }}
                            >
                              {item.ip}
                            </button>
                          </td>
                          <td className="py-2.5 px-3 uppercase" style={{ color: 'var(--color-text-secondary)' }}>
                            {item.family}
                          </td>
                          <td className="py-2.5 px-3 font-mono tabular-nums" style={{ color: 'var(--color-text-primary)' }}>
                            <span style={{ color: '#34c759' }}>{item.direct_count}</span>
                            {' / '}
                            <span style={{ color: item.proxy_count > 0 ? '#ff3b30' : 'var(--color-text-secondary)' }}>
                              {item.proxy_count}
                            </span>
                          </td>
                          <td className="py-2.5 px-3">
                            <BoolPill value={item.desired} />
                          </td>
                          <td className="py-2.5 px-3">
                            <BoolPill value={item.applied} trueLabel="Applied" falseLabel="No" />
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium"
                              style={{ background: badge.background, color: badge.color }}
                            >
                              {badge.label}
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
        )}
      </div>

      {/* 2. IP Exact Lookup */}
      <div className="glass-card p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Network size={16} style={{ color: '#34c759' }} />
          <h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>
            IP Direct Offload Lookup
          </h2>
          <span className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
            Exact lookup across static rules & dynamic offload state
          </span>
        </div>

        <form onSubmit={handleIpSubmit} className="flex flex-col sm:flex-row gap-2.5">
          <div className="relative flex-1">
            <Search
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              style={{ color: 'var(--color-text-secondary)' }}
            />
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="Enter IPv4 or IPv6 address, e.g. 1.1.1.1"
              disabled={!canQuery || ipLoading}
              className="w-full pl-9 pr-3 py-2 rounded-xl text-[13px] font-mono outline-none transition-all disabled:opacity-50"
              style={{
                background: 'var(--color-fill-subtle)',
                color: 'var(--color-text-primary)',
                border: '1px solid var(--color-separator)',
              }}
            />
          </div>
          <button
            type="submit"
            disabled={!canQuery || ipLoading || !ipInput.trim()}
            className="px-4 py-2 rounded-xl text-[13px] font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
            style={{ background: '#34c759' }}
          >
            {ipLoading ? 'Querying...' : 'Query IP'}
          </button>
        </form>

        {ipError && (
          <div
            className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-[13px]"
            style={{ background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }}
          >
            <AlertCircle size={15} />
            <span>{ipError}</span>
          </div>
        )}

        {ipResult && (() => {
          const effectiveBadge = getOffloadStatusBadge(ipResult.effective_status);
          const isDirectOffloaded =
            ipResult.effective_status === 'applied' || ipResult.effective_status === 'static_bypass';
          return (
            <div className="space-y-3">
              {/* Effective Verdict Banner */}
              <div
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 rounded-xl"
                style={{ background: effectiveBadge.background, color: effectiveBadge.color }}
              >
                <div className="flex items-center gap-2">
                  {isDirectOffloaded ? <ShieldCheck size={17} /> : <CheckCircle2 size={17} />}
                  <span className="font-mono font-semibold text-[14px]">{ipResult.ip}</span>
                  <span className="text-[11px] uppercase opacity-80">({ipResult.family})</span>
                </div>
                <span className="text-[13px] font-semibold">{effectiveBadge.label}</span>
              </div>

              {/* Detail Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
                <div className="rounded-xl p-3" style={{ background: 'var(--color-fill-subtle)' }}>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>Static Match</div>
                  <div className="mt-1 text-[13px] font-medium font-mono" style={{ color: 'var(--color-text-primary)' }}>
                    {ipResult.static_match}
                  </div>
                </div>
                <div className="rounded-xl p-3" style={{ background: 'var(--color-fill-subtle)' }}>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>Desired</div>
                  <div className="mt-1"><BoolPill value={ipResult.desired} /></div>
                </div>
                <div className="rounded-xl p-3" style={{ background: 'var(--color-fill-subtle)' }}>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>Kernel Applied</div>
                  <div className="mt-1"><BoolPill value={ipResult.applied} trueLabel="Applied" falseLabel="No" /></div>
                </div>
                <div className="rounded-xl p-3" style={{ background: 'var(--color-fill-subtle)' }}>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>Dirty Pending</div>
                  <div className="mt-1"><BoolPill value={ipResult.dirty} /></div>
                </div>
                <div className="rounded-xl p-3" style={{ background: 'var(--color-fill-subtle)' }}>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>Counts (Direct / Proxy)</div>
                  <div className="mt-1 text-[14px] font-mono font-semibold tabular-nums" style={{ color: 'var(--color-text-primary)' }}>
                    <span style={{ color: '#34c759' }}>{ipResult.counts.direct}</span>
                    {' / '}
                    <span style={{ color: ipResult.counts.proxy > 0 ? '#ff3b30' : 'var(--color-text-secondary)' }}>
                      {ipResult.counts.proxy}
                    </span>
                  </div>
                </div>
                <div className="rounded-xl p-3" style={{ background: 'var(--color-fill-subtle)' }}>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>Domains</div>
                  <div className="mt-1 text-[14px] font-mono font-semibold tabular-nums" style={{ color: 'var(--color-text-primary)' }}>
                    {ipResult.domain_owner_count}
                  </div>
                </div>
              </div>

              {/* Direct IP Owner Record (if any) */}
              {ipResult.direct_ip_owner && (
                <div
                  className="flex flex-wrap items-center gap-4 px-4 py-3 rounded-xl text-[12px]"
                  style={{ background: 'var(--color-fill-subtle)' }}
                >
                  <span className="font-semibold" style={{ color: 'var(--color-text-primary)' }}>
                    Direct IP Owner Record:
                  </span>
                  <span
                    className="inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold"
                    style={getActionBadge(ipResult.direct_ip_owner.action)}
                  >
                    {getActionBadge(ipResult.direct_ip_owner.action).label}
                  </span>
                  <span style={{ color: 'var(--color-text-secondary)' }}>
                    Outbound: <strong style={{ color: 'var(--color-text-primary)' }}>{ipResult.direct_ip_owner.outbound ?? '-'}</strong>
                  </span>
                  <span className="flex items-center gap-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                    Rule Offloadable: <BoolPill value={ipResult.direct_ip_owner.rule_offloadable} />
                  </span>
                  <span className="font-mono tabular-nums" style={{ color: 'var(--color-text-secondary)' }}>
                    Last Seen: #{ipResult.direct_ip_owner.last_seen}
                  </span>
                </div>
              )}
            </div>
          );
        })()}
      </div>
    </div>
  );
}
