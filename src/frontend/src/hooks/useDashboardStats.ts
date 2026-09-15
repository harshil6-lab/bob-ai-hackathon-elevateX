import { useCallback } from 'react';
import { getDashboardStats } from '../services/dashboardService';
import { useAsyncResource } from './useAsyncResource';
import type { DashboardStats } from '../types/dashboard';
import type { AsyncResource } from './useAsyncResource';

/** Loads GET /api/dashboard/stats and maps it to the dashboard view model. */
export function useDashboardStats(): AsyncResource<DashboardStats> {
  const loader = useCallback(() => getDashboardStats(), []);
  return useAsyncResource<DashboardStats>(loader, []);
}
