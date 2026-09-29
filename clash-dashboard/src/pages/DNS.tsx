import { useState, useEffect } from 'react';
import {
  queryDNS,
  getDnsUpstreams,
  getDnsCache,
  deleteDnsCache,
  type DNSQueryResult,
  type DnsUpstreamInfo,
  type DnsCacheUpstreamStat,
} from '../lib/api';
import {
  Search,
  Trash2,
  Database,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Server,
} from 'lucide-react';
import { ConfirmDialog } from '../components/ui/confirm-dialog';

const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'];

const DNS_TYPE_NAMES: Record<number, string> = {
  1: 'A',
  28: 'AAAA',
  5: 'CNAME',
  15: 'MX',
  16: 'TXT',
  2: 'NS',
  6: 'SOA',
};

function getTypeBadgeStyle(typeNumOrStr: number | string): {
  background: string;
  color: string;
} {
  const type =
    typeof typeNumOrStr === 'number'
      ? (DNS_TYPE_NAMES[typeNumOrStr] ?? '')
      : typeNumOrStr;
  if (type === 'A')
    return { background: 'rgba(52,199,89,0.12)', color: '#34c759' };
  if (type === 'AAAA')
    return { background: 'rgba(0,113,227,0.12)', color: '#0071e3' };
  if (type === 'CNAME')
    return { background: 'rgba(255,149,0,0.12)', color: '#ff9500' };
  if (type === 'TXT')
    return { background: 'rgba(175,82,222,0.12)', color: '#af52de' };
  return {
    background: 'var(--color-fill-medium)',
    color: 'var(--color-text-secondary)',
  };
}

function getUpstreamTypeBadge(type?: string): {
  background: string;
  color: string;
  label: string;
} {
  switch (type?.toLowerCase()) {
    case 'fakeip':
      return {
        background: 'rgba(255,45,85,0.12)',
        color: '#ff2d55',
        label: 'FakeIP',
      };
    case 'remote':
      return {
        background: 'rgba(0,113,227,0.12)',
        color: '#0071e3',
        label: 'Remote',
      };
    case 'local':
      return {
        background: 'rgba(52,199,89,0.12)',
        color: '#34c759',
        label: 'Local',
      };
    default:
      return {
        background: 'rgba(94,92,230,0.12)',
        color: '#5e5ce6',
        label: type ? type.toUpperCase() : 'DNS',
      };
  }
}

export function DNS() {
  // DNS Lookup state
  const [hostname, setHostname] = useState('');
  const [type, setType] = useState('A');
  const [result, setResult] = useState<DNSQueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // DNS Cache Management state
  const [upstreams, setUpstreams] = useState<DnsUpstreamInfo[]>([]);
  const [selectedUpstream, setSelectedUpstream] = useState<string>('');
  const [wildcard, setWildcard] = useState('');
  const [cacheResult, setCacheResult] = useState<DnsCacheUpstreamStat | null>(null);
  const [cacheLoading, setCacheLoading] = useState(false);
  const [cacheError, setCacheError] = useState<string | null>(null);
  const [cacheSuccessMsg, setCacheSuccessMsg] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteConfirmTarget, setDeleteConfirmTarget] = useState<{
    upstream: string;
    pattern: string;
    isSpecificDomain: boolean;
    count?: number;
  } | null>(null);

  async function fetchUpstreams() {
    try {
      const res = await getDnsUpstreams();
      if (res.upstreams && res.upstreams.length > 0) {
        setUpstreams(res.upstreams);
        setSelectedUpstream(res.upstreams[0].tag);
      }
    } catch (e) {
      console.error('Failed to load DNS upstreams', e);
    }
  }

  // Fetch available upstreams on mount
  useEffect(() => {
    void fetchUpstreams();
  }, []);

  // Lookup handler
  async function handleQuery() {
    const normalizedHostname = hostname.trim();
    if (!normalizedHostname || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await queryDNS(normalizedHostname, type);
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Query failed');
    } finally {
      setLoading(false);
    }
  }

  // Cache Query handler
  async function handleCacheQuery(overridePattern?: string, overrideUpstream?: string) {
    const targetUpstream = overrideUpstream !== undefined ? overrideUpstream : selectedUpstream;
    const p = (overridePattern !== undefined ? overridePattern : wildcard).trim();

    if (!targetUpstream) {
      setCacheError('查询条件必须指定上游');
      return;
    }
    if (!p) {
      setCacheError('请输入域名通配符进行查询');
      return;
    }

    setCacheLoading(true);
    setCacheError(null);
    setCacheSuccessMsg(null);
    try {
      const res = await getDnsCache(targetUpstream, p);
      setCacheResult(res.upstream);
    } catch (e) {
      setCacheError(e instanceof Error ? e.message : '查询 DNS 缓存失败');
    } finally {
      setCacheLoading(false);
    }
  }

  // Cache Delete handlers
  function requestDeleteCache(specificDomain?: string) {
    if (!selectedUpstream) {
      setCacheError('必须指定上游才能删除缓存');
      return;
    }
    const p = specificDomain || wildcard.trim() || '*';
    setDeleteConfirmTarget({
      upstream: selectedUpstream,
      pattern: p,
      isSpecificDomain: Boolean(specificDomain),
      count: specificDomain ? 1 : cacheResult?.count,
    });
  }

  async function handleConfirmDeleteCache() {
    if (!deleteConfirmTarget) return;
    const { upstream, pattern } = deleteConfirmTarget;

    setIsDeleting(true);
    setCacheError(null);
    setCacheSuccessMsg(null);
    try {
      const res = await deleteDnsCache(upstream, pattern);
      setCacheSuccessMsg(`成功从上游 "${upstream}" 中删除 ${res.deleted} 条缓存记录`);
      setDeleteConfirmTarget(null);
      // Refresh cache
      const updated = await getDnsCache(upstream, wildcard.trim() || '*');
      setCacheResult(updated.upstream);
    } catch (e) {
      setCacheError(e instanceof Error ? e.message : '删除 DNS 缓存失败');
    } finally {
      setIsDeleting(false);
    }
  }

  const QUICK_WILDCARDS = ['*', '*.com', '*.org', '*google*', '*baidu*', '*apple*'];

  return (
    <div className="p-6 space-y-8 max-w-7xl mx-auto">
      {/* ─── Module 1: DNS Cache Management ─────────────────────────────── */}
      <section className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2
              className="text-xl font-bold tracking-tight flex items-center gap-2"
              style={{ color: 'var(--color-text-primary)' }}
            >
              <Database size={20} className="text-[#0071e3]" />
              DNS 缓存管理
            </h2>
            <p
              className="text-[13px] mt-0.5"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              按指定上游与域名通配符检索 DNS 缓存条数并清理（传统 DNS 区分默认上游与 FakeIP，DNS2 按 upstream tag 区分）
            </p>
          </div>

          {cacheResult && cacheResult.count > 0 && (
            <button
              onClick={() => requestDeleteCache()}
              disabled={isDeleting || cacheLoading}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-[13px] font-medium transition-all shadow-sm hover:brightness-105 active:scale-[0.98] disabled:opacity-50 self-start sm:self-auto cursor-pointer"
              style={{
                background: 'rgba(255,59,48,0.12)',
                color: '#ff3b30',
                border: '1px solid rgba(255,59,48,0.25)',
              }}
            >
              <Trash2 size={14} />
              {isDeleting ? '正在清理…' : `删除当前上游匹配缓存 (${cacheResult.count})`}
            </button>
          )}
        </div>

        {/* Upstream & Wildcard Search Controls */}
        <div className="space-y-3 p-4 rounded-2xl border" style={{ background: 'var(--color-fill-subtle)', borderColor: 'var(--color-border)' }}>
          {/* Row 1: Upstream Selector (Required) */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-[13px] font-medium" style={{ color: 'var(--color-text-primary)' }}>
              <Server size={15} className="text-[#0071e3]" />
              <span>选择上游 (必选)</span>
            </div>

            {upstreams.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {upstreams.map((u) => {
                  const badge = getUpstreamTypeBadge(u.type);
                  const isSelected = selectedUpstream === u.tag;

                  return (
                    <button
                      key={u.tag}
                      type="button"
                      onClick={() => {
                        setSelectedUpstream(u.tag);
                        setCacheResult(null);
                        setCacheError(null);
                        setCacheSuccessMsg(null);
                      }}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-[13px] font-mono transition-all border cursor-pointer"
                      style={{
                        background: isSelected ? 'var(--color-input-focus-bg)' : 'var(--color-fill-medium)',
                        borderColor: isSelected ? '#0071e3' : 'transparent',
                        boxShadow: isSelected ? '0 0 0 1px #0071e3, 0 1px 3px rgba(0,0,0,0.08)' : 'none',
                        color: isSelected ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
                      }}
                    >
                      <span className="font-semibold">{u.tag}</span>
                      <span
                        className="text-[10px] font-bold px-1.5 py-0.2 rounded-full uppercase"
                        style={{ background: badge.background, color: badge.color }}
                      >
                        {badge.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            ) : (
              <div className="text-[12px]" style={{ color: 'var(--color-text-tertiary)' }}>
                正在加载可用上游列表…
              </div>
            )}
          </div>

          {/* Row 2: Wildcard input + Search button */}
          <div className="flex flex-col sm:flex-row gap-2 pt-1">
            <div className="flex-1 relative">
              <Search
                size={16}
                className="absolute left-3.5 top-1/2 -translate-y-1/2"
                style={{ color: 'var(--color-text-tertiary)' }}
              />
              <input
                type="text"
                placeholder="域名通配符 (例如 *.google.com, *baidu*, 或 * 查询全部)"
                value={wildcard}
                onChange={(e) => setWildcard(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    if (wildcard.trim() && selectedUpstream && !cacheLoading) {
                      void handleCacheQuery();
                    }
                  }
                }}
                className="w-full pl-10 pr-4 py-2.5 rounded-xl text-[14px] focus:outline-none transition-shadow"
                style={{
                  background: 'var(--color-input-bg)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-text-primary)',
                }}
              />
            </div>
            <button
              onClick={() => void handleCacheQuery()}
              disabled={cacheLoading || !selectedUpstream || !wildcard.trim()}
              className="flex items-center justify-center gap-1.5 px-5 py-2.5 rounded-xl text-[14px] font-medium transition-all shadow-sm hover:brightness-105 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              style={{ background: '#0071e3', color: 'white' }}
            >
              {cacheLoading ? (
                <>
                  <RefreshCw size={15} className="animate-spin" />
                  查询中…
                </>
              ) : (
                <>
                  <Search size={15} />
                  查询缓存
                </>
              )}
            </button>
          </div>

          {/* Row 3: Quick Chips */}
          <div className="flex flex-wrap items-center gap-1.5 text-[12px] pt-0.5">
            <span style={{ color: 'var(--color-text-tertiary)' }}>常用通配符:</span>
            {QUICK_WILDCARDS.map((w) => (
              <button
                key={w}
                onClick={() => {
                  setWildcard(w);
                  void handleCacheQuery(w);
                }}
                className="px-2.5 py-1 rounded-lg font-mono transition-colors hover:bg-[var(--color-fill-strong)] cursor-pointer"
                style={{
                  background: wildcard === w ? '#0071e3' : 'var(--color-fill-medium)',
                  color: wildcard === w ? '#ffffff' : 'var(--color-text-secondary)',
                }}
              >
                {w}
              </button>
            ))}
          </div>
        </div>

        {/* Cache Success Notification */}
        {cacheSuccessMsg && (
          <div
            className="flex items-center gap-2 rounded-xl p-3 text-[13px] transition-all"
            style={{
              background: 'rgba(52,199,89,0.1)',
              border: '1px solid rgba(52,199,89,0.25)',
              color: '#34c759',
            }}
          >
            <CheckCircle2 size={16} />
            <span>{cacheSuccessMsg}</span>
          </div>
        )}

        {/* Cache Error Notification */}
        {cacheError && (
          <div
            className="flex items-center gap-2 rounded-xl p-3 text-[13px]"
            style={{
              background: 'rgba(255,59,48,0.08)',
              border: '1px solid rgba(255,59,48,0.25)',
              color: '#ff3b30',
            }}
          >
            <AlertCircle size={16} />
            <span>{cacheError}</span>
          </div>
        )}

        {/* Cache Results */}
        {cacheResult && (
          <div className="space-y-4">
            {/* Header info */}
            <div
              className="flex flex-wrap items-center justify-between px-4 py-3 rounded-2xl"
              style={{
                background: 'var(--color-fill-subtle)',
                border: '1px solid var(--color-separator)',
              }}
            >
              <div className="flex items-center gap-3">
                <span className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
                  当前检索上游:
                </span>
                <span className="font-mono font-bold text-[14px]" style={{ color: 'var(--color-text-primary)' }}>
                  {cacheResult.name}
                </span>
                {cacheResult.type && (
                  <span
                    className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase"
                    style={getUpstreamTypeBadge(cacheResult.type)}
                  >
                    {cacheResult.type}
                  </span>
                )}
                <span className="text-[12px] font-mono px-2 py-0.5 rounded bg-[var(--color-fill-medium)] text-[var(--color-text-secondary)]">
                  通配符: {wildcard.trim() || '*'}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
                  缓存条数:
                </span>
                <span
                  className="font-mono text-[13px] font-bold px-3 py-0.5 rounded-full"
                  style={{
                    background:
                      cacheResult.count > 0
                        ? 'rgba(52,199,89,0.12)'
                        : 'var(--color-fill-medium)',
                    color:
                      cacheResult.count > 0
                        ? '#34c759'
                        : 'var(--color-text-tertiary)',
                  }}
                >
                  {cacheResult.count} 条缓存
                </span>
              </div>
            </div>

            {/* Records List */}
            {cacheResult.items && cacheResult.items.length > 0 ? (
              <div
                className="liquid-glass-card rounded-2xl overflow-hidden shadow-sm"
                style={{ border: '1px solid var(--color-border)' }}
              >
                <div
                  className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-[0.06em] flex items-center justify-between border-b"
                  style={{
                    color: 'var(--color-text-secondary)',
                    borderColor: 'var(--color-separator)',
                    background: 'var(--color-fill-subtle)',
                  }}
                >
                  <span>缓存条目明细</span>
                  <span>操作</span>
                </div>

                <div className="divide-y divide-[var(--color-separator)]">
                  {cacheResult.items.map((item, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between px-4 py-3 text-[13px] gap-3 hover:bg-[var(--color-fill-subtle)] transition-colors"
                    >
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        <span
                          className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-md flex-shrink-0"
                          style={getTypeBadgeStyle(item.qtype)}
                        >
                          {item.qtype}
                        </span>
                        <span
                          className="font-mono truncate font-medium"
                          style={{ color: 'var(--color-text-primary)' }}
                        >
                          {item.domain}
                        </span>
                        {item.is_stale && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded font-medium bg-[rgba(255,149,0,0.12)] text-[#ff9500]">
                            Stale
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-4 flex-shrink-0 font-mono text-[12px]">
                        {item.ip && (
                          <span className="text-[#0071e3] font-medium">{item.ip}</span>
                        )}
                        {item.ttl !== undefined && (
                          <span style={{ color: 'var(--color-text-tertiary)' }}>
                            {item.ttl}s TTL
                          </span>
                        )}
                        <button
                          onClick={() => requestDeleteCache(item.domain)}
                          disabled={isDeleting}
                          className="p-1 rounded text-[#ff3b30] hover:bg-[rgba(255,59,48,0.1)] transition-colors cursor-pointer disabled:opacity-50"
                          title={`删除 ${item.domain} 的缓存`}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
                {cacheResult.count > cacheResult.items.length && (
                  <div
                    className="px-4 py-2.5 text-center text-[12px] border-t"
                    style={{
                      background: 'var(--color-fill-subtle)',
                      borderColor: 'var(--color-separator)',
                      color: 'var(--color-text-secondary)',
                    }}
                  >
                    已展示前 50 条匹配明细（该上游实际共匹配 {cacheResult.count} 条记录）。如需查看更具体的条目，请指定更精确的域名通配符。
                  </div>
                )}
              </div>
            ) : (
              <div
                className="rounded-2xl p-8 text-center"
                style={{
                  background: 'var(--color-fill-subtle)',
                  border: '1px dashed var(--color-border)',
                }}
              >
                <Database
                  size={32}
                  className="mx-auto mb-2 opacity-30 text-[var(--color-text-secondary)]"
                />
                <div
                  className="text-[14px] font-medium"
                  style={{ color: 'var(--color-text-primary)' }}
                >
                  上游 "{cacheResult.name}" 中未查到匹配 "{wildcard.trim() || '*'}" 的缓存记录
                </div>
                <div
                  className="text-[12px] mt-1"
                  style={{ color: 'var(--color-text-secondary)' }}
                >
                  请尝试更改通配符规则或切换其他上游重试
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ─── Divider ────────────────────────────────────────────────────── */}
      <div style={{ height: 1, background: 'var(--color-separator)' }} />

      {/* ─── Module 2: DNS Lookup ───────────────────────────────────────── */}
      <section className="space-y-4">
        <div>
          <h2
            className="text-xl font-bold tracking-tight"
            style={{ color: 'var(--color-text-primary)' }}
          >
            DNS Lookup
          </h2>
          <p
            className="text-[13px] mt-0.5"
            style={{ color: 'var(--color-text-secondary)' }}
          >
            实时解析域名并返回 DNS 应答记录
          </p>
        </div>

        {/* Query form */}
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search
              size={15}
              className="absolute left-3.5 top-1/2 -translate-y-1/2"
              style={{ color: 'var(--color-text-tertiary)' }}
            />
            <input
              type="text"
              placeholder="Hostname (e.g. example.com)"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  void handleQuery();
                }
              }}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl text-[15px] focus:outline-none transition-shadow"
              style={{
                background: 'var(--color-input-bg)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-primary)',
              }}
            />
          </div>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="px-3 py-2.5 rounded-xl text-[15px] focus:outline-none cursor-pointer"
            style={{
              background: 'var(--color-input-focus-bg)',
              border: '1px solid var(--color-border)',
              color: 'var(--color-text-primary)',
            }}
          >
            {DNS_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <button
            onClick={handleQuery}
            disabled={loading || !hostname.trim()}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-[15px] font-medium transition-colors disabled:opacity-50 cursor-pointer"
            style={{ background: '#0071e3', color: 'white' }}
          >
            {loading ? 'Querying…' : 'Query'}
          </button>
        </div>

        {/* Error */}
        {error && (
          <div
            className="rounded-xl p-4"
            style={{
              background: 'rgba(255,59,48,0.08)',
              border: '1px solid rgba(255,59,48,0.2)',
            }}
          >
            <div
              className="text-[13px] font-semibold mb-0.5"
              style={{ color: '#ff3b30' }}
            >
              Query failed
            </div>
            <div className="text-[13px]" style={{ color: '#ff3b30' }}>
              {error}
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-4">
            {result.Answer && result.Answer.length > 0 ? (
              <div>
                <div
                  className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-2 px-1"
                  style={{ color: 'var(--color-text-secondary)' }}
                >
                  Answer
                </div>
                <div
                  className="liquid-glass-card rounded-xl overflow-hidden"
                  style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
                >
                  {result.Answer.map((a, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-3 px-4"
                      style={{
                        minHeight: 52,
                        borderBottom:
                          i < result.Answer!.length - 1
                            ? '1px solid var(--color-separator)'
                            : 'none',
                      }}
                    >
                      <div className="flex-1 min-w-0">
                        <div
                          className="font-mono text-[13px] truncate"
                          style={{ color: 'var(--color-text-primary)' }}
                        >
                          {a.name}
                        </div>
                        <div
                          className="font-mono text-[11px]"
                          style={{ color: 'var(--color-text-tertiary)' }}
                        >
                          {a.TTL}s TTL
                        </div>
                      </div>
                      <span
                        className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                        style={getTypeBadgeStyle(a.type)}
                      >
                        {DNS_TYPE_NAMES[a.type] ?? String(a.type)}
                      </span>
                      <div
                        className="font-mono text-[13px] text-right"
                        style={{ color: '#34c759' }}
                      >
                        {a.data}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div
                className="rounded-xl p-4 text-[13px]"
                style={{
                  background: 'rgba(255,149,0,0.08)',
                  border: '1px solid rgba(255,149,0,0.2)',
                  color: '#ff9500',
                }}
              >
                No answer records returned.
              </div>
            )}

            <div
              className="rounded-xl p-3 text-[11px] font-mono"
              style={{
                background: 'var(--color-input-focus-bg)',
                border: '1px solid var(--color-separator)',
                color: 'var(--color-text-tertiary)',
                boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
              }}
            >
              Status: {result.Status} · TC: {String(result.TC)} · RD:{' '}
              {String(result.RD)} · RA: {String(result.RA)} · AD:{' '}
              {String(result.AD)}
            </div>
          </div>
        )}
      </section>

      {/* ─── Cache Delete Confirmation Modal ─────────────────────────────── */}
      <ConfirmDialog
        open={Boolean(deleteConfirmTarget)}
        onClose={() => !isDeleting && setDeleteConfirmTarget(null)}
        onConfirm={() => void handleConfirmDeleteCache()}
        title={
          deleteConfirmTarget?.isSpecificDomain
            ? '确认删除域名缓存'
            : '确认清理匹配缓存'
        }
        description="此操作将从目标 DNS 上游缓存中移除该条目或匹配规则下的解析记录，此操作无法恢复。"
        confirmText="确认删除"
        cancelText="取消"
        variant="destructive"
        icon="none"
        isLoading={isDeleting}
      >
        {deleteConfirmTarget && (
          <div
            className="p-3.5 rounded-xl border text-[13px] space-y-2.5"
            style={{
              background: 'var(--color-fill-subtle)',
              borderColor: 'var(--color-border)',
            }}
          >
            <div className="flex items-center justify-between gap-4">
              <span className="shrink-0" style={{ color: 'var(--color-text-secondary)' }}>
                目标上游
              </span>
              <span
                className="font-mono font-medium text-[12px] px-2 py-0.5 rounded-md truncate max-w-[220px]"
                style={{
                  background: 'var(--color-fill-medium)',
                  color: 'var(--color-text-primary)',
                }}
                title={deleteConfirmTarget.upstream}
              >
                {deleteConfirmTarget.upstream}
              </span>
            </div>

            <div className="flex items-center justify-between gap-4">
              <span className="shrink-0" style={{ color: 'var(--color-text-secondary)' }}>
                {deleteConfirmTarget.isSpecificDomain ? '域名' : '匹配通配符'}
              </span>
              <span
                className="font-mono font-semibold text-[12px] px-2 py-0.5 rounded-md truncate max-w-[220px]"
                style={{
                  background: deleteConfirmTarget.isSpecificDomain
                    ? 'rgba(0,113,227,0.1)'
                    : 'rgba(255,149,0,0.1)',
                  color: deleteConfirmTarget.isSpecificDomain ? '#0071e3' : '#ff9500',
                }}
                title={deleteConfirmTarget.pattern}
              >
                {deleteConfirmTarget.pattern}
              </span>
            </div>

            {deleteConfirmTarget.count !== undefined && !deleteConfirmTarget.isSpecificDomain && (
              <div
                className="flex items-center justify-between pt-2 border-t"
                style={{ borderColor: 'var(--color-separator)' }}
              >
                <span style={{ color: 'var(--color-text-secondary)' }}>当前匹配总数</span>
                <span className="font-semibold text-[#ff3b30] text-[12px]">
                  共 {deleteConfirmTarget.count} 条记录
                </span>
              </div>
            )}
          </div>
        )}
      </ConfirmDialog>
    </div>
  );
}
