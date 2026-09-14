/**
 * Drives the Analyze workflow's explicit lifecycle:
 *   idle -> analyzing -> success
 *   idle -> analyzing -> failure
 *
 * No state is skipped, and `success` is only ever reached when
 * `triggerAnalysis()` reported a genuine 2xx (or an explicitly-labelled demo
 * run). A failure is never rewritten as a success.
 */

import { useCallback, useRef, useState } from 'react';
import { triggerAnalysis } from '../services/analyzeService';
import type { ApiError } from '../services/apiClient';
import type { AnalyzeResult, AnalyzeStatus } from '../types/dashboard';

export interface UseAnalyze {
  status: AnalyzeStatus;
  result: AnalyzeResult | null;
  error: ApiError | null;
  /** True when the completed run was a demo simulation, not a backend call. */
  simulated: boolean;
  /** Starts a run. Ignored while one is already in flight. */
  run: () => Promise<void>;
  /** Returns to `idle`, clearing the previous outcome. */
  reset: () => void;
}

export function useAnalyze(onSuccess?: () => void): UseAnalyze {
  const [status, setStatus] = useState<AnalyzeStatus>('idle');
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [simulated, setSimulated] = useState(false);

  const inFlight = useRef(false);
  const onSuccessRef = useRef(onSuccess);
  onSuccessRef.current = onSuccess;

  const run = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;

    setStatus('analyzing');
    setError(null);
    setResult(null);

    try {
      const outcome = await triggerAnalysis();

      if (outcome.status === 'success') {
        setResult(outcome.result);
        setSimulated(outcome.simulated);
        setStatus('success');
        // Refresh dependent views only after a real success.
        onSuccessRef.current?.();
      } else {
        setError(outcome.error);
        setSimulated(false);
        setStatus('failure');
      }
    } finally {
      inFlight.current = false;
    }
  }, []);

  const reset = useCallback(() => {
    setStatus('idle');
    setResult(null);
    setError(null);
    setSimulated(false);
  }, []);

  return { status, result, error, simulated, run, reset };
}
