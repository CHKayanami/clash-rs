export const getApiUrl = () => localStorage.getItem('clash-api-url') || window.location.origin;

export const getSecret = () => {
  const persisted = localStorage.getItem('clash-api-secret');
  if (persisted !== null) {
    return persisted;
  }

  const legacySessionSecret = sessionStorage.getItem('clash-api-secret');
  if (legacySessionSecret !== null) {
    // lgtm[js/clear-text-storage-of-sensitive-data]
    // Intentional: persist LAN dashboard credentials across browser restarts.
    // This secret stays on the current device and should only be used on trusted hosts.
    localStorage.setItem('clash-api-secret', legacySessionSecret);
    return legacySessionSecret;
  }

  return '';
};

export const setApiUrl = (url: string) => localStorage.setItem('clash-api-url', url);

export const setSecret = (s: string) => {
  // lgtm[js/clear-text-storage-of-sensitive-data]
  // Intentional: persist LAN dashboard credentials across browser restarts.
  // This secret stays on the current device and should only be used on trusted hosts.
  localStorage.setItem('clash-api-secret', s);
  sessionStorage.removeItem('clash-api-secret');
};

/**
 * Automatically read connection and authentication parameters from the URL
 * and persist them in localStorage.
 *
 * Supported parameters:
 * - `secret` or `token`: API secret for authentication
 * - `host` or `hostname`: API host / IP
 * - `port`: API port
 * - `url`, `apiUrl`, `api_url`, `server`: Direct full API URL
 * - `protocol` or `proto`: Connection protocol (http / https)
 */
export function initSettingsFromUrl(): { apiUrl?: string; secret?: string } {
  if (typeof window === 'undefined') return {};

  const params = new URLSearchParams(window.location.search);

  // Support query parameters in hash (e.g. /ui/#/?host=... or /ui/#/settings?host=...)
  if (window.location.hash.includes('?')) {
    const hashQuery = window.location.hash.slice(window.location.hash.indexOf('?') + 1);
    const hashParams = new URLSearchParams(hashQuery);
    hashParams.forEach((value, key) => {
      if (!params.has(key)) {
        params.set(key, value);
      }
    });
  }

  const result: { apiUrl?: string; secret?: string } = {};

  // Secret / token
  const secretParam = params.get('secret') ?? params.get('token');
  if (secretParam !== null) {
    setSecret(secretParam);
    result.secret = secretParam;
  }

  // API URL / host / port
  const directUrl =
    params.get('url') ?? params.get('apiUrl') ?? params.get('api_url') ?? params.get('server');
  const hostParam = params.get('host') ?? params.get('hostname');
  const portParam = params.get('port');
  const protocolParam = (params.get('protocol') ?? params.get('proto') ?? '').replace(/:$/, '');

  let determinedUrl: string | null = null;

  if (directUrl) {
    let u = directUrl.trim();
    if (!/^https?:\/\//i.test(u)) {
      const proto =
        protocolParam ||
        (window.location.protocol.startsWith('http')
          ? window.location.protocol.replace(':', '')
          : 'http');
      u = `${proto}://${u}`;
    }
    determinedUrl = u.replace(/\/+$/, '');
  } else if (hostParam || portParam) {
    let host = (hostParam ?? window.location.hostname ?? '127.0.0.1').trim();
    let proto = protocolParam;
    let port = portParam ? portParam.trim() : '';

    if (/^https?:\/\//i.test(host)) {
      try {
        const parsed = new URL(host);
        proto = proto || parsed.protocol.replace(':', '');
        host = parsed.hostname;
        if (!port && parsed.port) {
          port = parsed.port;
        }
      } catch {
        // fallback
      }
    }

    // Extract port from host if host contains :port and portParam was not given
    if (!port) {
      if (host.startsWith('[') && host.includes(']:')) {
        const match = host.match(/^(\[[a-fA-F0-9:]+\]):(\d+)$/);
        if (match) {
          host = match[1];
          port = match[2];
        }
      } else if (!host.startsWith('[') && host.includes(':')) {
        const parts = host.split(':');
        if (parts.length === 2 && /^\d+$/.test(parts[1])) {
          host = parts[0];
          port = parts[1];
        }
      }
    }

    if (!proto) {
      proto = window.location.protocol.startsWith('http')
        ? window.location.protocol.replace(':', '')
        : 'http';
    }

    determinedUrl = `${proto}://${host}${port ? `:${port}` : ''}`;
  }

  if (determinedUrl) {
    setApiUrl(determinedUrl);
    result.apiUrl = determinedUrl;
  }

  return result;
}

// Automatically initialize settings from URL parameters on load
initSettingsFromUrl();

