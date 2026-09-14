import { useCallback } from 'react';
import { getDashboardStats } from '../services/dashboardService';
import { useAsyncResource } from './useAsyncResource';
import type { DashboardStats } from '../types/dashboard';
import type { AsyncResource } from './useAsyncResource';

/** Loads GET /api/dashboard/stats. Response shape is PROVISIONAL. */
export function useDashboardStats(): AsyncResource<DashboardStats> {
  const loader = useCallback(() => getDashboardStats(), []);
  return useAsyncResource<DashboardStats>(loader, []);
}
