// Generated from docs/openapi.json by scripts/gen-api-types.mjs. Do not edit;
// run `npm run gen:api` after changing the API.

/** A page of results. */
export interface Paged<T> {
  items: T[];
  page: number;
  per_page: number;
  total: number;
}

/**
 * One stored alert: a heuristic indicator with its evidence. Never proof
 * of compromise.
 */
export type AlertRow = {
  alert_id: number;
  /**
   * `low`, `medium` or `high`.
   */
  confidence: string;
  destination?: string | null;
  destination_port?: number | null;
  /**
   * `[{"name": ..., "value": ...}]`: the measured facts behind the alert.
   */
  evidence: Record<string, unknown>[];
  explanation: string;
  first_seen?: string | null;
  first_seen_ns?: number | null;
  last_seen?: string | null;
  last_seen_ns?: number | null;
  likely_false_positives: string[];
  /**
   * MITRE ATT&CK techniques as context only; not a claim that a technique
   * was used.
   */
  mitre_attack: string[];
  /**
   * Always the same statement that alerts are heuristic indicators.
   */
  nature: string;
  related_flow_ids: number[];
  related_packet_indexes: number[];
  rule_id: string;
  rule_name: string;
  /**
   * `low`, `medium` or `high`.
   */
  severity: string;
  source?: string | null;
  /**
   * `open`, `acknowledged`, `resolved` or `false_positive`.
   */
  status: string;
  /**
   * RFC 3339, UTC: when an analyst last changed the status.
   */
  status_changed_at?: string | null;
  uncertainty: string;
};

/**
 * A triage status change.
 */
export type AlertUpdate = {
  /**
   * `open`, `acknowledged`, `resolved` or `false_positive`.
   */
  status: string;
};

/**
 * The applied limits of a capture.
 */
export type AppliedLiveLimits = {
  max_bytes: number;
  max_packets: number;
  max_seconds: number;
  snaplen: number;
};

/**
 * A stored audit event.
 */
export type AuditEvent = {
  action: string;
  actor?: string | null;
  actor_id?: number | null;
  /**
   * RFC 3339 UTC.
   */
  at: string;
  client_ip?: string | null;
  details: Record<string, unknown>;
  id: number;
  outcome: AuditOutcome;
  target_id?: string | null;
  target_type?: string | null;
};

/**
 * How an audited action ended.
 */
export type AuditOutcome = "success" | "failure" | "denied";

export type DnsEvent = {
  answer_count: number;
  answers: Record<string, unknown>[];
  flow_id?: number | null;
  is_response: boolean;
  packet_index: number;
  query_name?: string | null;
  query_type?: string | null;
  response_code?: string | null;
  time?: string | null;
  transaction_id: number;
  ts_ns?: number | null;
};

export type ErrorBody = {
  /**
   * Stable machine-readable code, for example `not_found`.
   */
  code: string;
  /**
   * Human-readable explanation.
   */
  message: string;
  position?: null | Position;
};

export type ErrorResponse = {
  error: ErrorBody;
};

/**
 * A valid filter.
 */
export type FilterCheck = {
  /**
   * The filter in canonical form (keywords lowercased, values quoted).
   */
  normalized: string;
  /**
   * Values bound as query parameters.
   */
  parameters: number;
  target: string;
  valid: boolean;
};

/**
 * One filterable field.
 */
export type FilterField = {
  description: string;
  /**
   * Largest allowed value, for integer fields.
   */
  max?: number | null;
  name: string;
  /**
   * Operators the field accepts.
   */
  operators: string[];
  /**
   * `ip address or cidr`, `unsigned integer`, `number`, `text`,
   * `keyword` or `boolean`.
   */
  type: string;
  /**
   * Allowed values, for keyword fields.
   */
  values?: string[] | null;
};

/**
 * A flow with its full record (statistics, TCP, application metadata).
 */
export type FlowDetail = FlowSummaryRow & {
  record: Record<string, unknown>;
};

/**
 * One flow's indexed metadata.
 */
export type FlowSummaryRow = {
  /**
   * Alerts that cite this flow (at most 16 are linked).
   */
  alert_count: number;
  bytes_total: number;
  dominant_endpoint: string;
  duration_seconds: number;
  end_reason: string;
  first_seen?: string | null;
  first_seen_ns?: number | null;
  flow_id: number;
  initiator_ip: string;
  initiator_port: number;
  ip_version: number;
  last_seen_ns?: number | null;
  /**
   * `low`, `medium` or `high`: the most severe linked alert.
   */
  max_alert_severity?: string | null;
  packets_total: number;
  protocol: number;
  protocol_name?: string | null;
  responder_ip: string;
  responder_port: number;
  tcp_state?: string | null;
};

export type HttpEvent = {
  content_type?: string | null;
  flow_id?: number | null;
  host?: string | null;
  kind: string;
  method?: string | null;
  packet_index: number;
  path?: string | null;
  /**
   * Credentials, cookies or a query string were present and removed.
   */
  redacted: boolean;
  status_code?: number | null;
  time?: string | null;
  ts_ns?: number | null;
};

/**
 * A network interface.
 */
export type Interface = {
  addresses: string[];
  description?: string | null;
  loopback: boolean;
  name: string;
  up: boolean;
};

/**
 * Body of `POST /live/captures`. Limits left out take the defaults
 * (60 s, 100,000 packets, 100 MiB, 65,535-byte snapshots) within the
 * server's maximums.
 */
export type LiveStart = {
  /**
   * Must be `true`: you confirm that you own this network or are
   * authorized to capture its traffic.
   */
  authorized: boolean;
  /**
   * Optional BPF capture filter, for example `tcp port 443`.
   */
  filter?: string;
  /**
   * An interface name from `GET /live/interfaces`.
   */
  interface: string;
  max_bytes?: number | null;
  max_packets?: number | null;
  max_seconds?: number | null;
  /**
   * Capture traffic not addressed to this host. Off by default.
   */
  promiscuous?: boolean;
  snaplen?: number | null;
};

/**
 * The current or most recent live capture.
 */
export type LiveStatus = {
  bytes_written: number;
  /**
   * The stored capture, once imported.
   */
  capture_id?: number | null;
  /**
   * Dropped because the file writer fell behind.
   */
  dropped_backpressure: number;
  /**
   * Dropped by the kernel or the interface, as the system reports them.
   */
  dropped_by_system: number;
  elapsed_seconds: number;
  error?: null | ErrorBody;
  filter?: string | null;
  interface?: string | null;
  limits?: null | AppliedLiveLimits;
  packets_seen: number;
  packets_written: number;
  promiscuous: boolean;
  /**
   * RFC 3339 UTC.
   */
  started_at?: string | null;
  started_by?: string | null;
  /**
   * `idle` (none yet), `capturing`, `importing`, `finished` or `failed`.
   */
  state: string;
  /**
   * `requested`, `packet_limit_reached`, `byte_limit_reached`,
   * `time_limit_reached` or `source_ended`.
   */
  stop_reason?: string | null;
};

/**
 * Credentials for `POST /auth/login`. `Debug` never shows the password.
 */
export type LoginRequest = {
  password: string;
  username: string;
};

/**
 * Body of `POST /users`.
 */
export type NewUser = {
  /**
   * 12 to 256 characters, not containing the username.
   */
  password: string;
  role: Role;
  /**
   * 1 to 64 letters, digits, `.`, `_` or `-`; stored lowercase.
   */
  username: string;
};

/**
 * Totals across every stored capture, for the dashboard's overview.
 */
export type Overview = {
  /**
   * Alerts by severity (`low`, `medium`, `high`), any status.
   */
  alerts_by_severity: Record<string, number>;
  /**
   * Alerts by triage status.
   */
  alerts_by_status: Record<string, number>;
  /**
   * Alerts are heuristic indicators, not proof of compromise.
   */
  alerts_total: number;
  captures: number;
  flows_total: number;
  /**
   * Open alerts by severity.
   */
  open_alerts_by_severity: Record<string, number>;
  packets_processed: number;
  /**
   * The five most recent imports, newest first.
   */
  recent_captures: Session[];
};

/**
 * A packet with its full decoded protocol tree.
 */
export type PacketDetail = PacketSummary & {
  /**
   * Decoded layers as produced by the decoder (metadata only).
   */
  layers: Record<string, unknown>[];
  warnings: Record<string, unknown>[];
};

/**
 * One packet's indexed metadata.
 */
export type PacketSummary = {
  captured_length: number;
  decode_status: string;
  destination?: string | null;
  dst_port?: number | null;
  flow_id?: number | null;
  info: string;
  original_length: number;
  packet_index: number;
  source?: string | null;
  src_port?: number | null;
  time?: string | null;
  top_protocol?: string | null;
  ts_ns?: number | null;
};

export type Paged_AlertRow = Paged<AlertRow>;

export type Paged_AuditEvent = Paged<AuditEvent>;

export type Paged_DnsEvent = Paged<DnsEvent>;

export type Paged_FlowSummaryRow = Paged<FlowSummaryRow>;

export type Paged_HttpEvent = Paged<HttpEvent>;

export type Paged_PacketSummary = Paged<PacketSummary>;

export type Paged_Session = Paged<Session>;

export type Paged_TlsEvent = Paged<TlsEvent>;

export type Paged_User = Paged<User>;

/**
 * Body of `PUT /auth/password`.
 */
export type PasswordChange = {
  current_password: string;
  /**
   * 12 to 256 characters, not containing the username.
   */
  new_password: string;
};

export type PcapFile = string;

/**
 * A byte range in a request value.
 */
export type Position = {
  end: number;
  start: number;
};

/**
 * How long imported data is kept.
 */
export type RetentionSettings = {
  /**
   * Packets whose metadata is stored per session (0-1000000). Flows and
   * summaries always cover the whole capture.
   */
  max_packets_stored: number;
  /**
   * Sessions are deleted this many days after import (1-3650).
   */
  session_ttl_days: number;
};

/**
 * What an account may do. Each role includes everything the roles below it
 * may do: `viewer` < `analyst` < `admin`.
 */
export type Role = "viewer" | "analyst" | "admin";

/**
 * One detection rule.
 */
export type RuleInfo = {
  description: string;
  /**
   * Stable identifier, for example `FS-SCAN-SYN`.
   */
  id: string;
  likely_false_positives: string[];
  /**
   * MITRE ATT&CK techniques the pattern can relate to, as context only.
   */
  mitre_attack: string[];
  name: string;
  /**
   * Every alert is a heuristic indicator, not proof of compromise.
   */
  nature: string;
  /**
   * `low`, `medium` or `high`.
   */
  severity: string;
  /**
   * Why an alert from this rule may be wrong.
   */
  uncertainty: string;
};

/**
 * A stored capture session.
 */
export type Session = {
  /**
   * Alerts raised by the detection rules (heuristic indicators).
   */
  alerts_total: number;
  captured_bytes_total: number;
  completion_state: string;
  /**
   * RFC 3339, UTC.
   */
  created_at: string;
  endianness: string;
  /**
   * RFC 3339, UTC. The session and everything stored for it are deleted
   * after this time.
   */
  expires_at: string;
  file_name: string;
  file_size_bytes: number;
  first_packet_ns?: number | null;
  first_packet_time?: string | null;
  /**
   * Flows with stored records (may be fewer than the total when the flow
   * engine's retention limit was reached).
   */
  flows_stored: number;
  flows_total: number;
  id: number;
  last_packet_ns?: number | null;
  last_packet_time?: string | null;
  link_type: number;
  link_type_name?: string | null;
  original_bytes_total: number;
  packets_processed: number;
  /**
   * Packets with stored metadata (may be fewer than processed, see
   * retention settings).
   */
  packets_stored: number;
  pcap_version: string;
  /**
   * SHA-256 of the uploaded file, for identifying duplicates.
   */
  sha256: string;
  snap_length: number;
  source: string;
  timestamp_resolution: string;
};

/**
 * The signed-in account, as the dashboard sees it.
 */
export type SessionAccount = {
  id: number;
  role: Role;
  username: string;
};

/**
 * A session with its stored summaries.
 */
export type SessionDetail = Session & {
  capture_warnings: Record<string, unknown>[];
  decode_summary: Record<string, unknown>;
  /**
   * Alert counts by rule and severity, and what the rules evaluated.
   */
  detection_summary: Record<string, unknown>;
  flow_summary: Record<string, unknown>;
};

/**
 * A signed-in session.
 */
export type SessionInfo = {
  /**
   * Send this in the `X-CSRF-Token` header with every `POST`, `PUT`,
   * `PATCH` and `DELETE` request.
   */
  csrf_token: string;
  /**
   * When the session ends at the latest (RFC 3339 UTC).
   */
  expires_at: string;
  /**
   * The session also ends after this many seconds without a request.
   */
  idle_timeout_seconds: number;
  user: SessionAccount;
};

export type TlsEvent = {
  alpn: string[];
  cipher_suite_count: number;
  flow_id?: number | null;
  handshake_type: string;
  negotiated_version?: string | null;
  packet_index: number;
  server_name?: string | null;
  time?: string | null;
  ts_ns?: number | null;
  /**
   * Always "visible handshake metadata only; nothing is decrypted".
   */
  visibility: string;
};

/**
 * An account, without its password hash.
 */
export type User = {
  created_at: string;
  /**
   * A disabled account cannot sign in, and its sessions end.
   */
  disabled: boolean;
  id: number;
  last_login_at?: string | null;
  password_changed_at: string;
  role: Role;
  updated_at: string;
  username: string;
};

/**
 * Body of `PATCH /users/{id}`. Changing the role, the enabled state or the
 * password ends the account's sessions.
 */
export type UserPatch = {
  disabled?: boolean | null;
  /**
   * A new password, set by an admin.
   */
  password?: string | null;
  role?: null | Role;
};
