// A fake `fetch` for tests: routes match on method and path (with query),
// and every call is recorded.
import { vi } from 'vitest';

export interface Call {
  method: string;
  url: string;
  body: unknown;
  /** The X-CSRF-Token header, if sent. */
  csrf: string | null;
}

type Handler = (call: Call) => { status?: number; body?: unknown } | Promise<{ status?: number; body?: unknown }>;

/** The session the page tests sign in with, unless a test says otherwise. */
export function sessionAs(role: 'viewer' | 'analyst' | 'admin', username: string = role) {
  return {
    user: { id: role === 'admin' ? 1 : role === 'analyst' ? 2 : 3, username, role },
    csrf_token: 'c'.repeat(64),
    expires_at: '2026-10-04T22:00:00Z',
    idle_timeout_seconds: 1800,
  };
}

/**
 * Stubs `fetch`. Unless `routes` answers `GET /auth/session` itself, the
 * dashboard is signed in as an admin.
 */
export function mockApi(routes: [string, RegExp, Handler][]) {
  const signedIn: [string, RegExp, Handler] = ['GET', /\/auth\/session$/, () => ({ body: sessionAs('admin') })];
  routes = [...routes, signedIn];
  // Calls the tests look at; the default session check is left out.
  const calls: Call[] = [];
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    let body: unknown = init?.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch {
        // Left as text.
      }
    }
    const headers = new Headers(init?.headers);
    const call = { method, url, body, csrf: headers.get('X-CSRF-Token') };
    const route = routes.find(([m, pattern]) => m === method && pattern.test(url));
    if (route !== signedIn) calls.push(call);
    if (!route) {
      return new Response(JSON.stringify({ error: { code: 'not_found', message: 'no such endpoint' } }), {
        status: 404,
      });
    }
    const { status = 200, body: reply } = await route[2](call);
    return new Response(reply === undefined ? null : JSON.stringify(reply), { status });
  });
  vi.stubGlobal('fetch', fetch);
  return { calls, fetch };
}

export const session = {
  id: 7,
  file_name: 'detect-mixed.pcap',
  file_size_bytes: 11416,
  sha256: 'a'.repeat(64),
  source: 'upload',
  completion_state: 'complete',
  pcap_version: '2.4',
  endianness: 'little',
  timestamp_resolution: 'microsecond',
  link_type: 1,
  link_type_name: 'ETHERNET',
  snap_length: 65535,
  packets_processed: 138,
  packets_stored: 138,
  captured_bytes_total: 9000,
  original_bytes_total: 9000,
  first_packet_ns: 1767225600000000000,
  first_packet_time: '2026-01-01T00:00:00.000000000Z',
  last_packet_ns: 1767225980000000000,
  last_packet_time: '2026-01-01T00:06:20.000000000Z',
  flows_total: 47,
  flows_stored: 47,
  alerts_total: 5,
  created_at: '2026-10-04T10:00:00Z',
  expires_at: '2026-11-03T10:00:00Z',
};

export const sessionDetail = {
  ...session,
  capture_warnings: [],
  decode_summary: { packets_decoded: 138, status_counts: { complete: 138 }, protocol_counts: { ethernet: 138, tcp: 122, dns: 14 } },
  flow_summary: { end_reasons: { tcp_finished: 33, idle_timeout: 13, capture_end: 1 } },
  detection_summary: {
    alerts_total: 5,
    alerts_by_rule: { 'FS-BEACON': 1, 'FS-SCAN-SYN': 1 },
    alerts_by_severity: { high: 2, medium: 2, low: 1 },
  },
};

export const packet = {
  packet_index: 3,
  ts_ns: 1767225600100000000,
  time: '2026-01-01T00:00:00.100000000Z',
  captured_length: 74,
  original_length: 74,
  decode_status: 'complete',
  top_protocol: 'TCP',
  source: '192.0.2.10',
  destination: '198.51.100.80',
  src_port: 41000,
  dst_port: 443,
  flow_id: 2,
  info: '41000 → 443 [SYN]',
};

export const packetDetail = {
  ...packet,
  layers: [
    { layer: 'ethernet', source: '02:00:00:00:00:01', destination: '02:00:00:00:00:02', vlan_tags: [] },
    { layer: 'ipv4', source: '192.0.2.10', destination: '198.51.100.80', ttl: 64, payload_length: 40 },
    { layer: 'tcp', source_port: 41000, destination_port: 443, flags: { bits: 2, names: ['SYN'] } },
  ],
  warnings: [],
};

export const alert = {
  alert_id: 2,
  rule_id: 'FS-BEACON',
  rule_name: 'Regular repeated connections',
  severity: 'medium',
  confidence: 'medium',
  status: 'open',
  nature: 'heuristic indicator: an observed pattern that deserves review, not proof of compromise',
  first_seen_ns: 1767225620000000000,
  first_seen: '2026-01-01T00:00:20.000000000Z',
  last_seen_ns: 1767225980000000000,
  last_seen: '2026-01-01T00:06:20.007000000Z',
  source: '192.0.2.10',
  destination: '203.0.113.80',
  destination_port: 8443,
  related_flow_ids: [41, 42],
  related_packet_indexes: [],
  evidence: [
    { name: 'connections', value: '7' },
    { name: 'mean_interval_seconds', value: '60.000' },
  ],
  explanation: '192.0.2.10 connected to 203.0.113.80 port 8443 7 times at intervals of 60.0 s.',
  uncertainty: 'Regularity alone is common.',
  likely_false_positives: ['software update and licence checks'],
  mitre_attack: ['T1071 Application Layer Protocol'],
  status_changed_at: null,
};

export const flow = {
  flow_id: 41,
  protocol: 6,
  protocol_name: 'TCP',
  ip_version: 4,
  initiator_ip: '192.0.2.10',
  initiator_port: 41000,
  responder_ip: '203.0.113.80',
  responder_port: 8443,
  first_seen_ns: 1767225620000000000,
  first_seen: '2026-01-01T00:00:20.000000000Z',
  last_seen_ns: 1767225620200000000,
  packets_total: 9,
  bytes_total: 1017,
  duration_seconds: 0.2,
  tcp_state: 'closed',
  end_reason: 'tcp_finished',
  dominant_endpoint: 'responder',
  alert_count: 1,
  max_alert_severity: 'medium',
};

export const flowDetail = {
  ...flow,
  record: {
    initiator_basis: 'tcp_syn',
    initiator_to_responder: { packets: 5, bytes: 420, payload_bytes: 120 },
    responder_to_initiator: { packets: 4, bytes: 597, payload_bytes: 300 },
    tcp: { state: 'closed', flags_initiator: ['SYN', 'ACK', 'FIN'], flags_responder: ['SYN', 'ACK', 'FIN'], syn_packets: 2, fin_packets: 2, rst_packets: 0, duplicate_segments: 0 },
    application: { protocols: ['tls'], tls_server_names: ['www.example.com'], tls_alpn: ['h2'], payload: 'FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER' },
    alert_ids: [2],
  },
};

export function paged<T>(items: T[], page = 1, perPage = 50, total = items.length) {
  return { items, page, per_page: perPage, total };
}
