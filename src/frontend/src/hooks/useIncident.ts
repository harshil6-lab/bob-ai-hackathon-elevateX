import { useCallback } from 'react';
import { getIncidentById } from '../services/incidentsService';
import { useAsyncResource } from './useAsyncResource';
import type { Incident } from '../types/incident';
import type { AsyncResource } from './useAsyncResource';

/** Loads GET /api/incidents/{id}. A 404 surfaces as a not-found ErrorState. */
export function useIncident(id: string | undefined): AsyncResource<Incident> {
  const loader = useCallback(() => {
    if (!id) return Promise.reject(new Error('No incident id was provided.'));
    return getIncidentById(id);
  }, [id]);
  return useAsyncResource<Incident>(loader, [id]);
}
