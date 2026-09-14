import { useCallback } from 'react';
import { getAlerts } from '../services/alertsService';
import { useAsyncResource } from './useAsyncResource';
import type { Alert, AlertQueryParams } from '../types/alert';
import type { AsyncResource } from './useAsyncResource';

/** Loads GET /api/alerts. Filtering is applied client-side by the page. */
export function useAlerts(params?: AlertQueryParams): AsyncResource<Alert[]> {
  const key = JSON.stringify(params ?? {});
  const loader = useCallback(() => getAlerts(params), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return useAsyncResource<Alert[]>(loader, [key]);
}
