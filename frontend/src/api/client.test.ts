import { describe, expect, it } from 'vitest';

import { mockApi } from '../test/api';
import { api, ApiError, buildQuery } from './client';

describe('buildQuery', () => {
  it('leaves out empty values and encodes the rest', () => {
    expect(buildQuery({ page: 2, filter: 'tcp.port == 443', sort: undefined, x: '' })).toBe(
      '?page=2&filter=tcp.port+%3D%3D+443',
    );
    expect(buildQuery({})).toBe('');
  });
});

describe('request', () => {
  it('turns error bodies into ApiError with code and position', async () => {
    mockApi([
      [
        'GET',
        /\/filters\/validate/,
        () => ({
          status: 400,
          body: { error: { code: 'unknown_field', message: 'unknown field', position: { start: 0, end: 6 } } },
        }),
      ],
    ]);
    const error = await api.validateFilter('packets', 'nosuch == 1').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 400, code: 'unknown_field', position: { start: 0, end: 6 } });
  });

  it('reports unreachable servers and unexpected bodies', async () => {
    const { fetch } = mockApi([]);
    fetch.mockRejectedValueOnce(new TypeError('network down'));
    await expect(api.overview()).rejects.toMatchObject({ code: 'network_error' });
    fetch.mockResolvedValueOnce(new Response('<html>', { status: 200 }));
    await expect(api.overview()).rejects.toMatchObject({ code: 'invalid_response' });
    fetch.mockResolvedValueOnce(new Response('oops', { status: 502 }));
    await expect(api.overview()).rejects.toMatchObject({ code: 'http_error', status: 502 });
  });

  it('sends uploads as the raw body with the capture media type', async () => {
    const { calls, fetch } = mockApi([['POST', /\/captures\?file_name=lab\.pcap$/, () => ({ status: 201, body: { id: 1 } })]]);
    const file = new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'lab.pcap');
    await api.importCapture(file);
    expect(calls[0]?.url).toBe('/api/v1/captures?file_name=lab.pcap');
    const init = fetch.mock.calls[0]?.[1];
    expect(new Headers(init?.headers).get('Content-Type')).toBe('application/vnd.tcpdump.pcap');
    expect(init?.body).toBe(file);
  });

  it('sends triage changes as JSON', async () => {
    const { calls } = mockApi([['PATCH', /\/captures\/7\/alerts\/2$/, () => ({ body: { status: 'resolved' } })]]);
    await api.setAlertStatus(7, 2, 'resolved');
    expect(calls[0]).toMatchObject({ method: 'PATCH', body: { status: 'resolved' } });
  });
});
