import { useCallback, useEffect, useRef, useState } from 'react';

import { ApiError, isAbort, toApiError } from '../api/client';

export interface Resource<T> {
  /** Data for the current key, once loaded. */
  data: T | undefined;
  /** Data from the previous key, kept while the next one loads. */
  previous: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
}

interface State<T> {
  key: string | null;
  data?: T;
  error?: ApiError;
}

/**
 * Loads data for `key` and reloads whenever the key changes. Requests for
 * an old key are aborted, so a slow response can never replace a newer one.
 */
export function useResource<T>(
  key: string,
  load: (signal: AbortSignal) => Promise<T>,
): Resource<T> {
  const [reloads, setReloads] = useState(0);
  const [state, setState] = useState<State<T>>({ key: null });
  const loadRef = useRef(load);
  useEffect(() => {
    loadRef.current = load;
  });
  const current = `${key}#${reloads}`;
  useEffect(() => {
    const controller = new AbortController();
    loadRef.current(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setState({ key: current, data });
      },
      (error: unknown) => {
        if (!controller.signal.aborted && !isAbort(error)) {
          setState((previous) => ({ key: current, data: previous.data, error: toApiError(error) }));
        }
      },
    );
    return () => controller.abort();
  }, [current]);
  const reload = useCallback(() => setReloads((n) => n + 1), []);
  const fresh = state.key === current;
  return {
    data: fresh && !state.error ? state.data : undefined,
    previous: state.data,
    error: fresh ? state.error : undefined,
    loading: !fresh,
    reload,
  };
}
