/**
 * Shared async-resource primitive.
 *
 * Every page's four required states derive from this single hook, so no page
 * grows its own one-off loading/error handling:
 *   status === 'loading'                     -> LoadingSkeleton
 *   status === 'error'                       -> ErrorState (reload = retry)
 *   status === 'success' && data is empty    -> EmptyState
 *   status === 'success' && data has content -> the real UI
 *
 * `reload()` re-runs the ORIGINAL request, which is what a Retry button must do.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from '../services/apiClient';

export type ResourceStatus = 'loading' | 'success' | 'error';

export interface AsyncResource<T> {
  data: T | null;
  status: ResourceStatus;
  error: ApiError | null;
  /** Re-runs the request. Bound to every ErrorState Retry button. */
  reload: () => void;
  /** True while a reload is in flight over already-loaded data. */
  isRefreshing: boolean;
}

function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError(
    error instanceof Error ? error.message : 'An unexpected error occurred.',
    { status: 0, kind: 'network', path: '' },
  );
}

export function useAsyncResource<T>(
  loader: () => Promise<T>,
  deps: readonly unknown[] = [],
): AsyncResource<T> {
  const [data, setData] = useState<T | null>(null);
  const [status, setStatus] = useState<ResourceStatus>('loading');
  const [error, setError] = useState<ApiError | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [nonce, setNonce] = useState(0);

  // Keeps the latest loader without making it a dependency of the effect.
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const hasLoadedRef = useRef(false);

  useEffect(() => {
    let cancelled = false;

    if (hasLoadedRef.current) {
      setIsRefreshing(true);
    } else {
      setStatus('loading');
    }

    loaderRef
      .current()
      .then((result) => {
        if (cancelled) return;
        hasLoadedRef.current = true;
        setData(result);
        setError(null);
        setStatus('success');
      })
      .catch((caught: unknown) => {
        if (cancelled) return;
        setError(toApiError(caught));
        setStatus('error');
      })
      .finally(() => {
        if (!cancelled) setIsRefreshing(false);
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  return { data, status, error, reload, isRefreshing };
}
