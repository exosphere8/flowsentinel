// Typed client for the FlowSentinel API (`/api/v1`). Every response is
// metadata; no endpoint returns packet payloads.
import type {
  AlertRow,
  ErrorResponse,
  FilterCheck,
  FilterField,
  FlowDetail,
  FlowSummaryRow,
  Overview,
  PacketDetail,
  PacketSummary,
  Paged,
  Position,
  RetentionSettings,
  RuleInfo,
  Session,
  SessionDetail,
} from './schema';

export type * from './schema';

export const API_BASE = '/api/v1';

export type Severity = 'low' | 'medium' | 'high';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive';
export type FilterTarget = 'packets' | 'flows';

export const SEVERITIES: readonly Severity[] = ['high', 'medium', 'low'];
export const ALERT_STATUSES: readonly AlertStatus[] = [
  'open',
  'acknowledged',
  'resolved',
  'false_positive',
];

/** A failed request, with the server's stable error code. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly position: Position | null;

  constructor(status: number, code: string, message: string, position: Position | null = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.position = position;
  }
}

export function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

/** Converts anything thrown by a request into an `ApiError`. */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError(0, 'client_error', 'Something went wrong in the dashboard.');
}

type QueryValue = string | number | undefined | null;

/** Builds a query string, leaving out empty values. */
export function buildQuery(query: Record<string, QueryValue>): string {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    params.set(name, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : '';
}

function errorBody(body: unknown): ErrorResponse['error'] | null {
  if (typeof body !== 'object' || body === null || !('error' in body)) return null;
  const error = (body as { error: unknown }).error;
  if (typeof error !== 'object' || error === null) return null;
  const { code, message, position } = error as Record<string, unknown>;
  if (typeof code !== 'string' || typeof message !== 'string') return null;
  const valid =
    typeof position === 'object' &&
    position !== null &&
    typeof (position as Position).start === 'number' &&
    typeof (position as Position).end === 'number';
  return { code, message, position: valid ? (position as Position) : null };
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      credentials: 'same-origin',
      headers: { Accept: 'application/json', ...init.headers },
    });
  } catch (error) {
    if (isAbort(error)) throw error;
    throw new ApiError(0, 'network_error', 'The API server could not be reached.');
  }
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!response.ok) {
    const error = errorBody(body);
    throw new ApiError(
      response.status,
      error?.code ?? 'http_error',
      error?.message ?? `The request failed with status ${response.status}.`,
      error?.position ?? null,
    );
  }
  if (body === null) {
    throw new ApiError(response.status, 'invalid_response', 'The API returned an unexpected response.');
  }
  return body as T;
}

function json(method: string, value: unknown, signal?: AbortSignal): RequestInit {
  return {
    method,
    signal,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
  };
}

export interface PageQuery {
  page?: number;
  per_page?: number;
  sort?: string;
}

export interface PacketQuery extends PageQuery {
  filter?: string;
  flow_id?: number;
}

export interface FlowQuery extends PageQuery {
  filter?: string;
}

export interface AlertQuery extends PageQuery {
  severity?: Severity;
  status?: AlertStatus;
  rule?: string;
}

const enc = encodeURIComponent;

export const api = {
  overview: (signal?: AbortSignal) => request<Overview>('/overview', { signal }),

  listCaptures: (query: PageQuery, signal?: AbortSignal) =>
    request<Paged<Session>>(`/captures${buildQuery({ ...query })}`, { signal }),

  getCapture: (id: number, signal?: AbortSignal) =>
    request<SessionDetail>(`/captures/${id}`, { signal }),

  deleteCapture: (id: number) => request<undefined>(`/captures/${id}`, { method: 'DELETE' }),

  /** Uploads a classic `.pcap` file as the raw request body. */
  importCapture: (file: File, signal?: AbortSignal) =>
    request<SessionDetail>(`/captures${buildQuery({ file_name: file.name })}`, {
      method: 'POST',
      signal,
      headers: { 'Content-Type': 'application/vnd.tcpdump.pcap' },
      body: file,
    }),

  listPackets: (id: number, query: PacketQuery, signal?: AbortSignal) =>
    request<Paged<PacketSummary>>(`/captures/${id}/packets${buildQuery({ ...query })}`, {
      signal,
    }),

  getPacket: (id: number, index: number, signal?: AbortSignal) =>
    request<PacketDetail>(`/captures/${id}/packets/${index}`, { signal }),

  listFlows: (id: number, query: FlowQuery, signal?: AbortSignal) =>
    request<Paged<FlowSummaryRow>>(`/captures/${id}/flows${buildQuery({ ...query })}`, {
      signal,
    }),

  getFlow: (id: number, flowId: number, signal?: AbortSignal) =>
    request<FlowDetail>(`/captures/${id}/flows/${flowId}`, { signal }),

  listAlerts: (id: number, query: AlertQuery, signal?: AbortSignal) =>
    request<Paged<AlertRow>>(`/captures/${id}/alerts${buildQuery({ ...query })}`, { signal }),

  getAlert: (id: number, alertId: number, signal?: AbortSignal) =>
    request<AlertRow>(`/captures/${id}/alerts/${alertId}`, { signal }),

  setAlertStatus: (id: number, alertId: number, status: AlertStatus) =>
    request<AlertRow>(`/captures/${id}/alerts/${alertId}`, json('PATCH', { status })),

  rules: (signal?: AbortSignal) => request<RuleInfo[]>('/rules', { signal }),

  validateFilter: (target: FilterTarget, filter: string, signal?: AbortSignal) =>
    request<FilterCheck>(`/filters/validate?target=${target}&filter=${enc(filter)}`, { signal }),

  filterFields: (target: FilterTarget, signal?: AbortSignal) =>
    request<FilterField[]>(`/filters/fields?target=${target}`, { signal }),

  retention: (signal?: AbortSignal) => request<RetentionSettings>('/settings/retention', { signal }),

  setRetention: (settings: RetentionSettings) =>
    request<RetentionSettings>('/settings/retention', json('PUT', settings)),
};
