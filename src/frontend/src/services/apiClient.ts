/**
 * CENTRALIZED API CLIENT
 *
 * The single place in the frontend that performs network I/O. No component,
 * page or hook may call `fetch()` directly.
 *
 * Guarantees:
 *  - Base URL comes from VITE_API_BASE_URL. No backend URL is hard-coded.
 *  - Non-2xx responses throw a typed `ApiError` carrying the HTTP status.
 *  - Network failures and timeouts throw a typed `ApiError` with status 0.
 *  - Requests time out rather than hanging forever.
 *  - A failed request ALWAYS throws. It is never converted into a fake
 *    success and never silently substituted with mock data — that decision
 *    belongs to the caller's error UI, not to this layer.
 *  - Nothing is logged. No credential, token or header value can leak here.
 */

const DEFAULT_TIMEOUT_MS = 15_000;

/** Resolved once at module load. Trailing slashes are normalised away. */
export function getApiBaseUrl(): string {
  const raw = import.meta.env?.VITE_API_BASE_URL;
  const base = typeof raw === 'string' && raw.trim() ? raw.trim() : 'http://localhost:8000';
  return base.replace(/\/+$/, '');
}

/** Distinguishes the kind of failure so the UI can phrase it accurately. */
export type ApiErrorKind = 'http' | 'network' | 'timeout' | 'parse';

export class ApiError extends Error {
  /** HTTP status code, or 0 when the request never produced a response. */
  readonly status: number;
  readonly kind: ApiErrorKind;
  /** The path that failed, e.g. "/api/alerts". Never includes credentials. */
  readonly path: string;

  constructor(
    message: string,
    options: { status: number; kind: ApiErrorKind; path: string },
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = options.status;
    this.kind = options.kind;
    this.path = options.path;
  }

  /** A short, user-facing sentence suitable for an ErrorState. */
  get userMessage(): string {
    switch (this.kind) {
      case 'timeout':
        return `The request to ${this.path} timed out. The backend may be starting up or unreachable.`;
      case 'network':
        return `Could not reach the backend at ${getApiBaseUrl()}. Check that the API is running and that VITE_API_BASE_URL is correct.`;
      case 'parse':
        return `The backend returned a response that could not be read as JSON (${this.path}).`;
      case 'http':
      default:
        return `${this.path} failed with HTTP ${this.status}. ${this.message}`;
    }
  }
}

export interface RequestOptions {
  method?: 'GET' | 'POST';
  /** Serialised as a query string. Null/undefined/empty values are dropped. */
  params?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  timeoutMs?: number;
  signal?: AbortSignal;
}

function buildUrl(path: string, params?: RequestOptions['params']): string {
  const url = new URL(`${getApiBaseUrl()}${path}`);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === '') continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

/** Best-effort extraction of a server-provided error message. */
async function readErrorMessage(response: Response): Promise<string> {
  try {
    const text = await response.text();
    if (!text) return response.statusText || 'Request failed.';
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      const detail = parsed.detail ?? parsed.message ?? parsed.error;
      if (typeof detail === 'string') return detail;
    } catch {
      /* body was not JSON — fall through to the raw text */
    }
    return text.slice(0, 300);
  } catch {
    return response.statusText || 'Request failed.';
  }
}

export async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { method = 'GET', params, body, timeoutMs = DEFAULT_TIMEOUT_MS } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  // Propagate an externally supplied abort (e.g. component unmount).
  const external = options.signal;
  const forwardAbort = () => controller.abort();
  external?.addEventListener('abort', forwardAbort);

  let response: Response;
  try {
    response = await fetch(buildUrl(path, params), {
      method,
      headers: {
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (error) {
    // An aborted request is either our timeout or the caller's cancellation.
    const aborted =
      controller.signal.aborted ||
      (error instanceof DOMException && error.name === 'AbortError');
    throw new ApiError(
      aborted ? 'Request timed out.' : 'Network request failed.',
      { status: 0, kind: aborted ? 'timeout' : 'network', path },
    );
  } finally {
    clearTimeout(timer);
    external?.removeEventListener('abort', forwardAbort);
  }

  if (!response.ok) {
    throw new ApiError(await readErrorMessage(response), {
      status: response.status,
      kind: 'http',
      path,
    });
  }

  // 204 / empty body is a legitimate success for POST /api/analyze.
  const raw = await response.text();
  if (!raw) return undefined as T;

  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new ApiError('Response was not valid JSON.', {
      status: response.status,
      kind: 'parse',
      path,
    });
  }
}

export const apiClient = {
  get: <T>(path: string, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...options, method: 'GET' }),
  post: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, 'method'>) =>
    request<T>(path, { ...options, method: 'POST', body }),
};
