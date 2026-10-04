//! Writes one analyzed capture in a single transaction.
//!
//! The session row and flows come from the first analysis pass; packets
//! arrive afterwards in batches from the second pass. Nothing is visible to
//! readers until [`ImportTransaction::commit`]; dropping the transaction
//! instead rolls everything back.

use std::collections::HashMap;
use std::net::IpAddr;

use analysis::{Analysis, AnalyzedPacket};
use decoder::{DecodedPacket, Layer};
use detection_engine::{Alert, Severity};
use flow_engine::FlowRecord;
use sqlx::{Postgres, QueryBuilder, Transaction};

use crate::{SessionDetail, Storage, StorageError};

/// Rows per multi-row INSERT. Postgres allows 65,535 bind parameters per
/// statement; the widest insert here binds 26 columns per row.
const BATCH_ROWS: usize = 1_000;

/// Where a capture came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureSource {
    /// A file uploaded through the API.
    Upload,
    /// Recorded live from a network interface.
    Live,
}

impl CaptureSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Live => "live",
        }
    }
}

/// Facts about the imported file that the analysis does not contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportMeta {
    /// Sanitized display name of the uploaded file (1-160 characters).
    pub file_name: String,
    /// Where the capture came from.
    pub source: CaptureSource,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    /// Days until the session expires (1-3650).
    pub ttl_days: i32,
}

fn nanos(ts: Option<capture::Timestamp>) -> Option<i64> {
    ts.and_then(|t| i64::try_from(t.as_unix_nanos()).ok())
}

fn clamp_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn clamp_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, StorageError> {
    serde_json::to_value(value).map_err(|_| StorageError::Corrupt("metadata failed to serialize"))
}

fn to_json_text<T: serde::Serialize>(value: &T) -> Result<String, StorageError> {
    serde_json::to_string(value).map_err(|_| StorageError::Corrupt("metadata failed to serialize"))
}

/// Serialized name of a unit enum variant (for example `"tcp_finished"`).
fn variant_name<T: serde::Serialize>(value: &T) -> Result<String, StorageError> {
    to_json(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or(StorageError::Corrupt("expected a named value"))
}

/// Application-layer event extracted from a packet.
#[derive(Debug, Clone, PartialEq)]
enum Event {
    Dns {
        transaction_id: i32,
        is_response: bool,
        query_name: Option<String>,
        query_type: Option<&'static str>,
        response_code: Option<&'static str>,
        answer_count: i32,
        answers: serde_json::Value,
    },
    Http {
        kind: &'static str,
        method: Option<&'static str>,
        host: Option<String>,
        path: Option<String>,
        status_code: Option<i32>,
        content_type: Option<String>,
        redacted: bool,
    },
    Tls {
        handshake_type: &'static str,
        server_name: Option<String>,
        alpn: Vec<String>,
        negotiated_version: Option<&'static str>,
        cipher_suite_count: i32,
    },
}

/// One packet's row, prepared without touching the database so the work can
/// run on a blocking thread.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketRow {
    packet_index: i64,
    ts_ns: Option<i64>,
    captured_length: i32,
    original_length: i32,
    decode_status: &'static str,
    top_protocol: Option<&'static str>,
    source: Option<String>,
    destination: Option<String>,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    ip_protocol: Option<i16>,
    tcp_flags: Option<i32>,
    flow_id: Option<i64>,
    protocols: Vec<String>,
    dns_query: Option<String>,
    http_host: Option<String>,
    tls_sni: Option<String>,
    info: String,
    /// Serialized JSON text: much smaller in memory than a parsed value,
    /// and cast to `jsonb` by the database.
    layers: String,
    warnings: String,
    event: Option<Event>,
}

impl PacketRow {
    /// Extracts the indexed columns and serializes the metadata of `packet`.
    pub fn from_analyzed(packet: &AnalyzedPacket) -> Result<Self, StorageError> {
        let decoded = &packet.decoded;
        let (source, destination) = decoded.endpoints().unzip();
        let mut row = Self {
            packet_index: clamp_i64(packet.record.index),
            ts_ns: nanos(packet.record.timestamp),
            captured_length: clamp_i32(packet.record.captured_length),
            original_length: clamp_i32(packet.record.original_length),
            decode_status: decoded.status.as_str(),
            top_protocol: decoded.top_protocol().map(|p| p.as_str()),
            source,
            destination,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            ip_protocol: None,
            tcp_flags: None,
            flow_id: packet.flow_id.map(clamp_i64),
            protocols: Vec::with_capacity(decoded.layers.len()),
            dns_query: None,
            http_host: None,
            tls_sni: None,
            info: decoded.info(),
            layers: to_json_text(&decoded.layers)?,
            warnings: to_json_text(&decoded.warnings)?,
            event: None,
        };
        row.extract(decoded)?;
        Ok(row)
    }

    fn extract(&mut self, decoded: &DecodedPacket) -> Result<(), StorageError> {
        for layer in &decoded.layers {
            let name = layer.protocol().as_str().to_ascii_lowercase();
            if !self.protocols.contains(&name) {
                self.protocols.push(name);
            }
            match layer {
                Layer::Ipv4(h) => {
                    self.src_ip = Some(IpAddr::V4(h.source));
                    self.dst_ip = Some(IpAddr::V4(h.destination));
                    self.ip_protocol = Some(i16::from(h.protocol));
                }
                Layer::Ipv6(h) => {
                    self.src_ip = Some(IpAddr::V6(h.source));
                    self.dst_ip = Some(IpAddr::V6(h.destination));
                    self.ip_protocol =
                        Some(i16::from(h.upper_layer_protocol.unwrap_or(h.next_header)));
                }
                Layer::Tcp(h) => {
                    self.src_port = Some(i32::from(h.source_port));
                    self.dst_port = Some(i32::from(h.destination_port));
                    self.tcp_flags = Some(i32::from(h.flags.0));
                }
                Layer::Udp(h) => {
                    self.src_port = Some(i32::from(h.source_port));
                    self.dst_port = Some(i32::from(h.destination_port));
                }
                Layer::Dns(m) => {
                    let question = m.questions.first();
                    self.dns_query = question.map(|q| q.name.clone());
                    self.event = Some(Event::Dns {
                        transaction_id: i32::from(m.transaction_id),
                        is_response: m.is_response,
                        query_name: question.map(|q| q.name.clone()),
                        query_type: question.and_then(|q| q.type_name),
                        response_code: m.is_response.then_some(m.response_code_name).flatten(),
                        answer_count: i32::from(m.answer_count),
                        answers: to_json(&m.answers)?,
                    });
                }
                Layer::Http(m) => {
                    self.http_host = m.host.clone();
                    self.event = Some(Event::Http {
                        kind: if m.status_code.is_some() {
                            "response"
                        } else {
                            "request"
                        },
                        method: m.method,
                        host: m.host.clone(),
                        path: m.path.clone(),
                        status_code: m.status_code.map(i32::from),
                        content_type: m.content_type.clone(),
                        redacted: m.query_redacted
                            || m.userinfo_redacted
                            || m.path_segments_redacted > 0
                            || m.target_withheld
                            || !m.redacted_headers.is_empty(),
                    });
                }
                Layer::Tls(m) => {
                    self.tls_sni = m.server_name.clone();
                    self.event = Some(Event::Tls {
                        handshake_type: m.handshake_type_name,
                        server_name: m.server_name.clone(),
                        alpn: m.alpn.clone(),
                        negotiated_version: m.negotiated_version_name,
                        cipher_suite_count: i32::from(m.cipher_suite_count),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// An import in progress. Dropping it without [`commit`](Self::commit)
/// rolls back everything written so far.
#[derive(Debug)]
pub struct ImportTransaction {
    tx: Transaction<'static, Postgres>,
    session_id: i64,
    packets_stored: i64,
}

impl Storage {
    /// Starts an import: writes the session row and every retained flow from
    /// the first analysis pass. Packets follow with
    /// [`ImportTransaction::add_packets`].
    pub async fn begin_import(
        &self,
        analysis: &Analysis,
        meta: &ImportMeta,
    ) -> Result<ImportTransaction, StorageError> {
        let mut tx = self.pool.begin().await?;
        let session_id = insert_session(&mut tx, analysis, meta).await?;
        let alerts: &[Alert] = analysis
            .detection
            .as_ref()
            .map_or(&[], |d| d.alerts.as_slice());
        let severities: HashMap<u64, Severity> =
            alerts.iter().map(|a| (a.alert_id, a.severity)).collect();
        for chunk in analysis.flows.flows.chunks(BATCH_ROWS) {
            insert_flows(&mut tx, session_id, chunk, &severities).await?;
        }
        for chunk in alerts.chunks(BATCH_ROWS) {
            insert_alerts(&mut tx, session_id, chunk).await?;
        }
        Ok(ImportTransaction {
            tx,
            session_id,
            packets_stored: 0,
        })
    }
}

impl ImportTransaction {
    pub fn session_id(&self) -> i64 {
        self.session_id
    }

    /// Writes a batch of packets and their DNS, HTTP and TLS events.
    /// Inserts a batch of packets and their DNS/HTTP/TLS events. The rows
    /// are consumed, so their metadata is never copied.
    pub async fn add_packets(&mut self, mut rows: Vec<PacketRow>) -> Result<(), StorageError> {
        while !rows.is_empty() {
            let rest = rows.split_off(rows.len().min(BATCH_ROWS));
            let added = i64::try_from(rows.len()).unwrap_or(i64::MAX);
            insert_events(&mut self.tx, self.session_id, &rows).await?;
            insert_packets(&mut self.tx, self.session_id, rows).await?;
            self.packets_stored = self.packets_stored.saturating_add(added);
            rows = rest;
        }
        Ok(())
    }

    /// Records the stored packet count and makes the import visible.
    pub async fn commit(mut self, storage: &Storage) -> Result<SessionDetail, StorageError> {
        sqlx::query("UPDATE capture_sessions SET packets_stored = $1 WHERE id = $2")
            .bind(self.packets_stored)
            .bind(self.session_id)
            .execute(&mut *self.tx)
            .await?;
        self.tx.commit().await?;
        storage
            .get_session(self.session_id)
            .await?
            .ok_or(StorageError::Corrupt("imported session disappeared"))
    }
}

async fn insert_session(
    tx: &mut Transaction<'static, Postgres>,
    analysis: &Analysis,
    meta: &ImportMeta,
) -> Result<i64, StorageError> {
    let s = &analysis.report.summary;
    let h = &s.header;
    let flows_stored = analysis.flows.flows.len();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO capture_sessions (file_name, file_size_bytes, sha256, source, \
         completion_state, pcap_version, endianness, timestamp_resolution, link_type, \
         link_type_name, snap_length, packets_processed, packets_stored, captured_bytes_total, \
         original_bytes_total, first_packet_ns, last_packet_ns, flows_total, flows_stored, \
         capture_warnings, decode_summary, flow_summary, alerts_total, detection_summary, \
         expires_at) \
         VALUES ($1, $2, $3, $24, $4, $5, $6, $7, $8, $9, $10, $11, 0, $12, $13, $14, $15, \
         $16, $17, $18, $19, $20, $21, $22, now() + make_interval(days => $23)) RETURNING id",
    )
    .bind(&meta.file_name)
    .bind(clamp_i64(s.file_size_bytes))
    .bind(&meta.sha256)
    .bind(analysis.report.completion_state.code())
    .bind(format!("{}.{}", h.version.major, h.version.minor))
    .bind(h.endianness.as_str())
    .bind(h.timestamp_resolution.as_str())
    .bind(i32::from(h.link_type.0))
    .bind(h.link_type_name)
    .bind(i64::from(h.snap_length))
    .bind(clamp_i64(s.packets_processed))
    .bind(clamp_i64(s.captured_bytes_total))
    .bind(clamp_i64(s.original_bytes_total))
    .bind(nanos(s.earliest_timestamp))
    .bind(nanos(s.latest_timestamp))
    .bind(clamp_i64(analysis.flows.summary.flows_total))
    .bind(i64::try_from(flows_stored).unwrap_or(i64::MAX))
    .bind(to_json(&analysis.report.warnings)?)
    .bind(to_json(&analysis.decode_summary)?)
    .bind(to_json(&analysis.flows.summary)?)
    .bind(
        analysis
            .detection
            .as_ref()
            .map_or(0, |d| clamp_i64(d.summary.alerts_total)),
    )
    .bind(match &analysis.detection {
        Some(d) => to_json(&d.summary)?,
        None => serde_json::json!({}),
    })
    .bind(meta.ttl_days)
    .bind(meta.source.as_str())
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Lowercase application protocol names of a flow.
fn application_protocols(flow: &FlowRecord) -> Vec<String> {
    flow.application
        .protocols
        .iter()
        .map(|p| p.as_str().to_ascii_lowercase())
        .collect()
}

async fn insert_flows(
    tx: &mut Transaction<'static, Postgres>,
    session_id: i64,
    flows: &[FlowRecord],
    severities: &HashMap<u64, Severity>,
) -> Result<(), StorageError> {
    let mut rows = Vec::with_capacity(flows.len());
    for flow in flows {
        let highest = flow
            .alert_ids
            .iter()
            .filter_map(|id| severities.get(id))
            .max()
            .map(|s| s.as_str());
        rows.push((
            flow,
            to_json(flow)?,
            variant_name(&flow.dominant_endpoint)?,
            highest,
        ));
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO flows (session_id, flow_id, ip_version, protocol, protocol_name, \
         initiator_ip, initiator_port, responder_ip, responder_port, first_seen_ns, \
         last_seen_ns, duration_seconds, packets_total, bytes_total, packets_initiator, \
         packets_responder, bytes_initiator, bytes_responder, tcp_state, end_reason, \
         dominant_endpoint, application_protocols, dns_query, http_host, tls_sni, record, \
         alert_count, max_alert_severity) ",
    );
    builder.push_values(rows, |mut b, (f, record, dominant, highest)| {
        let app = &f.application;
        b.push_bind(session_id)
            .push_bind(clamp_i64(f.flow_id))
            .push_bind(i16::from(f.ip_version))
            .push_bind(i16::from(f.protocol))
            .push_bind(f.protocol_name)
            .push_bind(f.initiator.ip)
            .push_bind(i32::from(f.initiator.port))
            .push_bind(f.responder.ip)
            .push_bind(i32::from(f.responder.port))
            .push_bind(nanos(f.first_seen))
            .push_bind(nanos(f.last_seen))
            .push_bind(f.duration_seconds)
            .push_bind(clamp_i64(f.packets_total))
            .push_bind(clamp_i64(f.bytes_total))
            .push_bind(clamp_i64(f.initiator_to_responder.packets))
            .push_bind(clamp_i64(f.responder_to_initiator.packets))
            .push_bind(clamp_i64(f.initiator_to_responder.bytes))
            .push_bind(clamp_i64(f.responder_to_initiator.bytes))
            .push_bind(f.tcp.as_ref().map(|t| t.state.as_str()))
            .push_bind(f.end_reason.as_str())
            .push_bind(dominant)
            .push_bind(application_protocols(f))
            .push_bind(app.dns_queries.first().cloned())
            .push_bind(app.http_hosts.first().cloned())
            .push_bind(app.tls_server_names.first().cloned())
            .push_bind(record)
            .push_bind(i32::try_from(f.alert_ids.len()).unwrap_or(i32::MAX))
            .push_bind(highest);
    });
    builder.build().execute(&mut **tx).await?;
    Ok(())
}

fn severity_rank(severity: Severity) -> i16 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
    }
}

async fn insert_alerts(
    tx: &mut Transaction<'static, Postgres>,
    session_id: i64,
    alerts: &[Alert],
) -> Result<(), StorageError> {
    if alerts.is_empty() {
        return Ok(());
    }
    let mut rows = Vec::with_capacity(alerts.len());
    for alert in alerts {
        rows.push((alert, to_json(&alert.evidence)?));
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO alerts (session_id, alert_id, rule_id, rule_name, severity, severity_rank, \
         confidence, status, first_seen_ns, last_seen_ns, source, destination, destination_port, \
         related_flow_ids, related_packet_indexes, evidence, explanation, uncertainty, \
         likely_false_positives, mitre_attack) ",
    );
    builder.push_values(rows, |mut b, (a, evidence)| {
        b.push_bind(session_id)
            .push_bind(clamp_i64(a.alert_id))
            .push_bind(a.rule_id)
            .push_bind(a.rule_name)
            .push_bind(a.severity.as_str())
            .push_bind(severity_rank(a.severity))
            .push_bind(a.confidence.as_str())
            .push_bind(a.status.as_str())
            .push_bind(nanos(a.first_seen))
            .push_bind(nanos(a.last_seen))
            .push_bind(a.source)
            .push_bind(a.destination)
            .push_bind(a.destination_port.map(i32::from))
            .push_bind(
                a.related_flow_ids
                    .iter()
                    .map(|&id| clamp_i64(id))
                    .collect::<Vec<_>>(),
            )
            .push_bind(
                a.related_packet_indexes
                    .iter()
                    .map(|&id| clamp_i64(id))
                    .collect::<Vec<_>>(),
            )
            .push_bind(evidence)
            .push_bind(a.explanation.clone())
            .push_bind(a.uncertainty)
            .push_bind(a.likely_false_positives.to_vec())
            .push_bind(a.mitre_attack.to_vec());
    });
    builder.build().execute(&mut **tx).await?;
    Ok(())
}

async fn insert_packets(
    tx: &mut Transaction<'static, Postgres>,
    session_id: i64,
    rows: Vec<PacketRow>,
) -> Result<(), StorageError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO packets (session_id, packet_index, ts_ns, captured_length, \
         original_length, decode_status, top_protocol, source, destination, src_ip, dst_ip, \
         src_port, dst_port, ip_protocol, tcp_flags, flow_id, protocols, dns_query, http_host, \
         tls_sni, info, layers, warnings) ",
    );
    builder.push_values(rows, |mut b, p| {
        b.push_bind(session_id)
            .push_bind(p.packet_index)
            .push_bind(p.ts_ns)
            .push_bind(p.captured_length)
            .push_bind(p.original_length)
            .push_bind(p.decode_status)
            .push_bind(p.top_protocol)
            .push_bind(p.source)
            .push_bind(p.destination)
            .push_bind(p.src_ip)
            .push_bind(p.dst_ip)
            .push_bind(p.src_port)
            .push_bind(p.dst_port)
            .push_bind(p.ip_protocol)
            .push_bind(p.tcp_flags)
            .push_bind(p.flow_id)
            .push_bind(p.protocols)
            .push_bind(p.dns_query)
            .push_bind(p.http_host)
            .push_bind(p.tls_sni)
            .push_bind(p.info)
            .push_bind(p.layers)
            .push_unseparated("::jsonb")
            .push_bind(p.warnings)
            .push_unseparated("::jsonb");
    });
    builder.build().execute(&mut **tx).await?;
    Ok(())
}

async fn insert_events(
    tx: &mut Transaction<'static, Postgres>,
    session_id: i64,
    rows: &[PacketRow],
) -> Result<(), StorageError> {
    let dns: Vec<_> = rows
        .iter()
        .filter(|r| matches!(r.event, Some(Event::Dns { .. })))
        .collect();
    let http: Vec<_> = rows
        .iter()
        .filter(|r| matches!(r.event, Some(Event::Http { .. })))
        .collect();
    let tls: Vec<_> = rows
        .iter()
        .filter(|r| matches!(r.event, Some(Event::Tls { .. })))
        .collect();

    if !dns.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO dns_events (session_id, packet_index, ts_ns, flow_id, transaction_id, \
             is_response, query_name, query_type, response_code, answer_count, answers) ",
        );
        builder.push_values(dns, |mut b, r| {
            if let Some(Event::Dns {
                transaction_id,
                is_response,
                query_name,
                query_type,
                response_code,
                answer_count,
                answers,
            }) = &r.event
            {
                b.push_bind(session_id)
                    .push_bind(r.packet_index)
                    .push_bind(r.ts_ns)
                    .push_bind(r.flow_id)
                    .push_bind(*transaction_id)
                    .push_bind(*is_response)
                    .push_bind(query_name.clone())
                    .push_bind(*query_type)
                    .push_bind(*response_code)
                    .push_bind(*answer_count)
                    .push_bind(answers.clone());
            }
        });
        builder.build().execute(&mut **tx).await?;
    }

    if !http.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO http_events (session_id, packet_index, ts_ns, flow_id, kind, method, \
             host, path, status_code, content_type, redacted) ",
        );
        builder.push_values(http, |mut b, r| {
            if let Some(Event::Http {
                kind,
                method,
                host,
                path,
                status_code,
                content_type,
                redacted,
            }) = &r.event
            {
                b.push_bind(session_id)
                    .push_bind(r.packet_index)
                    .push_bind(r.ts_ns)
                    .push_bind(r.flow_id)
                    .push_bind(*kind)
                    .push_bind(*method)
                    .push_bind(host.clone())
                    .push_bind(path.clone())
                    .push_bind(*status_code)
                    .push_bind(content_type.clone())
                    .push_bind(*redacted);
            }
        });
        builder.build().execute(&mut **tx).await?;
    }

    if !tls.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO tls_events (session_id, packet_index, ts_ns, flow_id, handshake_type, \
             server_name, alpn, negotiated_version, cipher_suite_count) ",
        );
        builder.push_values(tls, |mut b, r| {
            if let Some(Event::Tls {
                handshake_type,
                server_name,
                alpn,
                negotiated_version,
                cipher_suite_count,
            }) = &r.event
            {
                b.push_bind(session_id)
                    .push_bind(r.packet_index)
                    .push_bind(r.ts_ns)
                    .push_bind(r.flow_id)
                    .push_bind(*handshake_type)
                    .push_bind(server_name.clone())
                    .push_bind(alpn.clone())
                    .push_bind(*negotiated_version)
                    .push_bind(*cipher_suite_count);
            }
        });
        builder.build().execute(&mut **tx).await?;
    }
    Ok(())
}
