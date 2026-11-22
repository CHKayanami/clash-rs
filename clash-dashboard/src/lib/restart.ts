import type { RestartResponse, Version } from './api';

export interface RestartOptions {
  triggerRestart: (signal: AbortSignal) => Promise<RestartResponse>;
  fetchVersion: (signal: AbortSignal) => Promise<Version>;
  signal?: AbortSignal;
  timeoutMs?: number;
  initialDelayMs?: number;
  pollIntervalMs?: number;
  probeTimeoutMs?: number;
  minSpinMs?: number;
}

export type RestartResult =
  | { status: 'restarted' }
  | { status: 'aborted' }
  | { status: 'error'; message: string };

class AbortSignalError extends Error {
  constructor() {
    super('Aborted');
    this.name = 'AbortError';
  }
}

function getHttpStatus(err: unknown): number | undefined {
  if (typeof err === 'object' && err !== null && 'status' in err) {
    const status = (err as { status?: unknown }).status;
    return typeof status === 'number' ? status : undefined;
  }
  return undefined;
}

function createLinkedSignal(
  parents: Array<AbortSignal | undefined>,
  timeoutMs?: number,
): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController();
  const cleanups: Array<() => void> = [];

  const abort = () => {
    if (!controller.signal.aborted) {
      controller.abort();
    }
  };

  for (const parent of parents) {
    if (!parent) continue;
    if (parent.aborted) {
      abort();
      break;
    }
    parent.addEventListener('abort', abort, { once: true });
    cleanups.push(() => parent.removeEventListener('abort', abort));
  }

  if (timeoutMs !== undefined && !controller.signal.aborted) {
    const timer = setTimeout(abort, Math.max(0, timeoutMs));
    cleanups.push(() => clearTimeout(timer));
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      for (const fn of cleanups) fn();
    },
  };
}

function runWithAbort<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(new AbortSignalError());
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new AbortSignalError());
    signal.addEventListener('abort', onAbort, { once: true });
    fn(signal).then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (err) => {
        signal.removeEventListener('abort', onAbort);
        reject(err);
      },
    );
  });
}

function sleepAbortable(ms: number, signal: AbortSignal): Promise<void> {
  if (ms <= 0 || signal.aborted) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export async function performRestart(options: RestartOptions): Promise<RestartResult> {
  const {
    triggerRestart,
    fetchVersion,
    signal: externalSignal,
    timeoutMs = 15_000,
    initialDelayMs = 500,
    pollIntervalMs = 400,
    probeTimeoutMs = 2_500,
    minSpinMs = 800,
  } = options;

  if (externalSignal?.aborted) {
    return { status: 'aborted' };
  }

  const startedAt = Date.now();
  const deadline = createLinkedSignal([externalSignal], timeoutMs);

  try {
    let previousInstanceId: string;
    try {
      const response = await runWithAbort(triggerRestart, deadline.signal);
      if (typeof response?.instance_id !== 'string' || !response.instance_id) {
        return { status: 'error', message: 'Restart response is missing the instance ID' };
      }
      previousInstanceId = response.instance_id;
    } catch (err: unknown) {
      if (externalSignal?.aborted) {
        return { status: 'aborted' };
      }
      if (deadline.signal.aborted) {
        return { status: 'error', message: 'Restart request timed out' };
      }
      return {
        status: 'error',
        message: err instanceof Error ? err.message : 'Failed to restart',
      };
    }

    await sleepAbortable(initialDelayMs, deadline.signal);
    if (externalSignal?.aborted) {
      return { status: 'aborted' };
    }

    let recovered = false;

    while (!deadline.signal.aborted) {
      const probe = createLinkedSignal([deadline.signal], probeTimeoutMs);
      try {
        const version = await runWithAbort(fetchVersion, probe.signal);
        const currentInstanceId = version?.instance_id;
        if (typeof currentInstanceId === 'string' && currentInstanceId && currentInstanceId !== previousInstanceId) {
          recovered = true;
          break;
        }
      } catch (err: unknown) {
        if (externalSignal?.aborted) {
          return { status: 'aborted' };
        }
        if (deadline.signal.aborted) {
          break;
        }
        if (getHttpStatus(err) === 401) {
          return {
            status: 'error',
            message: err instanceof Error ? err.message : 'Unauthorized',
          };
        }
      } finally {
        probe.cleanup();
      }

      if (!deadline.signal.aborted) {
        await sleepAbortable(pollIntervalMs, deadline.signal);
      }
    }

    if (externalSignal?.aborted) {
      return { status: 'aborted' };
    }

    if (!recovered) {
      return { status: 'error', message: 'Server did not come back in time' };
    }

    const remainingSpin = minSpinMs - (Date.now() - startedAt);
    if (remainingSpin > 0) {
      const spinSignal = createLinkedSignal([externalSignal]);
      try {
        await sleepAbortable(remainingSpin, spinSignal.signal);
      } finally {
        spinSignal.cleanup();
      }
      if (externalSignal?.aborted) {
        return { status: 'aborted' };
      }
    }

    return { status: 'restarted' };
  } finally {
    deadline.cleanup();
  }
}
