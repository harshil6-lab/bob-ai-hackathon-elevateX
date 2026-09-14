import { useCallback } from 'react';
import { getIncidents } from '../services/incidentsService';
import { useAsyncResource } from './useAsyncResource';
import type { Incident, IncidentQueryParams } from '../types/incident';
import type { AsyncResource } from './useAsyncResource';

/** Loads GET /api/incidents. */
export function useIncidents(params?: IncidentQueryParams): AsyncResource<Incident[]> {
  const key = JSON.stringify(params ?? {});
  const loader = useCallback(() => getIncidents(params), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return useAsyncResource<Incident[]>(loader, [key]);
}
