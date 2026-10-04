import { describe, expect, it } from 'vitest';

import {
  byteRangeToIndexes,
  formatBytes,
  formatDuration,
  formatEndpoint,
  formatNumber,
  formatTime,
  humanize,
} from './format';

describe('format', () => {
  it('formats numbers, sizes and durations, with a dash for missing values', () => {
    expect(formatNumber(1234567)).toBe('1,234,567');
    expect(formatNumber(null)).toBe('–');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(-1)).toBe('–');
    expect(formatDuration(0.0042)).toBe('4.2 ms');
    expect(formatDuration(61)).toBe('61.000 s');
    expect(formatDuration(7200)).toBe('2 h 0 min');
  });

  it('chooses units by the rounded value', () => {
    expect(formatBytes(1048575)).toBe('1.0 MiB');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatBytes(1024)).toBe('1.0 KiB');
    expect(formatDuration(0.99996)).toBe('1.000 s');
    expect(formatDuration(0.9994)).toBe('999.4 ms');
    expect(formatDuration(119.9996)).toBe('2 min 0 s');
    expect(formatDuration(179.6)).toBe('3 min 0 s');
    expect(formatDuration(7199.6)).toBe('2 h 0 min');
  });

  it('formats endpoints, times and names', () => {
    expect(formatEndpoint('192.0.2.1', 443)).toBe('192.0.2.1:443');
    expect(formatEndpoint('2001:db8::1', 53)).toBe('[2001:db8::1]:53');
    expect(formatEndpoint('192.0.2.1', 0)).toBe('192.0.2.1');
    expect(formatTime('2026-01-01T00:00:01.5Z')).toBe('2026-01-01 00:00:01.5 UTC');
    expect(humanize('false_positive')).toBe('false positive');
  });

  it('maps UTF-8 byte ranges onto string indexes', () => {
    expect(byteRangeToIndexes('tcp and é', 8, 10)).toEqual([8, 9]);
    expect(byteRangeToIndexes('nosuch == 1', 0, 6)).toEqual([0, 6]);
    // An empty range at the end of the text.
    expect(byteRangeToIndexes('tcp and', 7, 7)).toEqual([7, 7]);
    expect(byteRangeToIndexes('é x', 3, 4)).toEqual([2, 3]);
  });
});
