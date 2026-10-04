import { useCallback } from 'react';
import { useSearchParams } from 'react-router';

/**
 * List state (page, sort, filter...) kept in the URL, so views can be
 * bookmarked and shared and the back button works.
 */
export function useSearchState() {
  const [params, setParams] = useSearchParams();

  const text = useCallback((name: string, fallback = '') => params.get(name) ?? fallback, [params]);

  const number = useCallback(
    (name: string, fallback: number) => {
      const value = Number.parseInt(params.get(name) ?? '', 10);
      return Number.isSafeInteger(value) && value > 0 ? value : fallback;
    },
    [params],
  );

  /** Sets values (empty ones are removed); any change but `page` resets to page 1. */
  const update = useCallback(
    (values: Record<string, string | number | null | undefined>) => {
      setParams((current) => {
        const next = new URLSearchParams(current);
        for (const [name, value] of Object.entries(values)) {
          if (value === null || value === undefined || value === '') next.delete(name);
          else next.set(name, String(value));
        }
        if (!('page' in values)) next.delete('page');
        return next;
      });
    },
    [setParams],
  );

  return { text, number, update };
}

/** A positive integer route parameter, or null. */
export function idParam(value: string | undefined): number | null {
  if (!value || !/^\d{1,15}$/.test(value)) return null;
  const id = Number(value);
  return id > 0 ? id : null;
}
