import { formatNumber } from '../lib/format';

export function Pagination({
  page,
  perPage,
  total,
  onPage,
  label,
}: {
  page: number;
  perPage: number;
  total: number;
  onPage: (page: number) => void;
  label: string;
}) {
  const pages = Math.max(1, Math.ceil(total / perPage));
  const first = total === 0 ? 0 : (page - 1) * perPage + 1;
  const last = Math.min(total, page * perPage);
  return (
    <nav className="pagination" aria-label={`${label} pages`}>
      <p className="pagination-range">
        {total === 0
          ? 'No results'
          : `${formatNumber(first)}–${formatNumber(last)} of ${formatNumber(total)}`}
      </p>
      <div className="pagination-buttons">
        <button type="button" onClick={() => onPage(1)} disabled={page <= 1}>
          First
        </button>
        <button type="button" onClick={() => onPage(page - 1)} disabled={page <= 1}>
          Previous
        </button>
        <span aria-current="page">
          Page {formatNumber(Math.min(page, pages))} of {formatNumber(pages)}
        </span>
        <button type="button" onClick={() => onPage(page + 1)} disabled={page >= pages}>
          Next
        </button>
        <button type="button" onClick={() => onPage(pages)} disabled={page >= pages}>
          Last
        </button>
      </div>
    </nav>
  );
}
