import type { ReactNode } from 'react';

import type { ApiError } from '../api/client';

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <p className="state state-loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </p>
  );
}

export function ErrorState({
  error,
  onRetry,
  title = 'Could not load this page',
}: {
  error: ApiError;
  onRetry?: () => void;
  title?: string;
}) {
  return (
    <div className="state state-error" role="alert">
      <p className="state-title">{title}</p>
      <p>
        {error.message}
        {error.code !== 'http_error' && (
          <>
            {' '}
            <code>{error.code}</code>
          </>
        )}
      </p>
      {onRetry && (
        <button type="button" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state state-empty">
      <p className="state-title">{title}</p>
      {children}
    </div>
  );
}

/** Shown wherever alerts appear. */
export function HeuristicNotice() {
  return (
    <p className="notice">
      Alerts are <strong>heuristic indicators</strong>: observed patterns that deserve review, not
      proof of compromise. Each one lists its evidence, its uncertainty and benign activity that
      looks the same.
    </p>
  );
}
