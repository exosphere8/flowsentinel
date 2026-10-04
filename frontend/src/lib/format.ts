// Display formatting. Every function accepts missing values and returns
// a dash for them.

const DASH = '–';
const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

export function formatNumber(value: number | null | undefined): string {
  return value === null || value === undefined || !Number.isFinite(value)
    ? DASH
    : integer.format(value);
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return DASH;
  let size = value;
  let unit = 0;
  // Compare the value as it will be shown, so 1023.96 KiB becomes 1.0 MiB.
  const shown = () => (unit === 0 ? size : Number(size.toFixed(1)));
  while (shown() >= 1024 && unit < UNITS.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${size} B` : `${size.toFixed(1)} ${UNITS[unit]}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return DASH;
  }
  // Each unit is chosen by the rounded value, so 0.99996 s is not "1000.0 ms".
  if (Number((seconds * 1000).toFixed(1)) < 1000) return `${(seconds * 1000).toFixed(1)} ms`;
  if (Number(seconds.toFixed(3)) < 120) return `${seconds.toFixed(3)} s`;
  const total = Math.round(seconds);
  const minutes = Math.floor(total / 60);
  if (minutes < 120) return `${minutes} min ${total - minutes * 60} s`;
  const hours = Math.floor(minutes / 60);
  return `${hours} h ${minutes - hours * 60} min`;
}

/** RFC 3339 times from the API are UTC; they are shown as UTC, unchanged. */
export function formatTime(value: string | null | undefined): string {
  return value ? value.replace('T', ' ').replace(/Z$/, ' UTC') : DASH;
}

export function formatEndpoint(ip: string | null | undefined, port?: number | null): string {
  if (!ip) return DASH;
  if (port === null || port === undefined || port === 0) return ip;
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/** Turns `false_positive` into `false positive`. */
export function humanize(value: string | null | undefined): string {
  return value ? value.replace(/_/g, ' ') : DASH;
}

/**
 * Converts a UTF-8 byte range (as reported by the API for filter errors)
 * into string indexes, clamped to the text.
 */
export function byteRangeToIndexes(text: string, start: number, end: number): [number, number] {
  const encoder = new TextEncoder();
  let bytes = 0;
  let index = 0;
  let from: number | null = null;
  let to: number | null = null;
  for (const char of text) {
    if (from === null && bytes >= start) from = index;
    if (to === null && bytes >= end) to = index;
    bytes += encoder.encode(char).length;
    index += char.length;
  }
  const first = from ?? text.length;
  const last = to ?? text.length;
  return [Math.min(first, last), Math.max(first, last)];
}
