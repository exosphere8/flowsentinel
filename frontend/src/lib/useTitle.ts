import { useEffect } from 'react';

/** Sets the document title, so each page is announced and bookmarked by name. */
export function useTitle(title: string): void {
  useEffect(() => {
    document.title = title ? `${title} · FlowSentinel` : 'FlowSentinel';
  }, [title]);
}
