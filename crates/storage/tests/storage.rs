//! Storage against a real PostgreSQL server. Each test creates and drops its
//! own database; see `storage::testing` for how to enable them.

use std::path::{Path, PathBuf};

use analysis::{Analysis, AnalysisConfig, analyze_file, replay_packets};
use capture::MonotonicClock;
use sqlx::{Postgres, QueryBuilder};
use storage::testing::TestDatabase;
use storage::{
    FlowSort, ImportMeta, PacketRow, PacketSort, Page, RetentionSettings, SessionDetail,
    SessionSort, SqlCondition, Storage,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pcap")
        .join(name)
}

fn meta(name: &str) -> ImportMeta {
    ImportMeta {
        file_name: name.to_owned(),
        sha256: "0".repeat(64),
        ttl_days: 30,
    }
}

/// Runs both analysis passes and stores the result.
async fn import(storage: &Storage, name: &str, keep: u64) -> SessionDetail {
    let path = fixture(name);
    let config = AnalysisConfig {
        replay_packets: keep,
        ..AnalysisConfig::default()
    };
    let analysis = analyze_file(&path, &config, &MonotonicClock::start()).unwrap();
    let mut tx = storage.begin_import(&analysis, &meta(name)).await.unwrap();
    for batch in replay(&path, &config, &analysis) {
        tx.add_packets(batch).await.unwrap();
    }
    tx.commit(storage).await.unwrap()
}

fn replay(path: &Path, config: &AnalysisConfig, analysis: &Analysis) -> Vec<Vec<PacketRow>> {
    let mut batches = Vec::new();
    let replay = replay_packets(path, config, analysis, 7, &mut |packets| {
        batches.push(
            packets
                .iter()
                .map(|p| PacketRow::from_analyzed(p).unwrap())
                .collect(),
        );
        true
    })
    .unwrap();
    assert_eq!(replay.fingerprint, analysis.fingerprint);
    batches
}

#[tokio::test]
async fn imports_are_stored_and_listed() {
    let Some(db) = TestDatabase::create("imports_are_stored").await else {
        return;
    };
    let s = &db.storage;
    let session = import(s, "flows-mixed.pcap", 100_000).await;
    let info = &session.session;
    assert_eq!(info.file_name, "flows-mixed.pcap");
    assert_eq!(info.packets_processed, 19);
    assert_eq!(info.packets_stored, 19);
    assert_eq!(info.flows_total, 6);
    assert_eq!(info.flows_stored, 6);
    assert_eq!(info.completion_state, "complete");
    assert_eq!(info.source, "upload");
    assert!(info.created_at.ends_with('Z') && info.expires_at.ends_with('Z'));
    assert_eq!(session.flow_summary["flows_total"], 6);
    assert_eq!(session.decode_summary["packets_decoded"], 19);

    let packets = s
        .list_packets(info.id, Page::new(1, 5), PacketSort::Index, None)
        .await
        .unwrap();
    assert_eq!(packets.total, 19);
    assert_eq!(packets.items.len(), 5);
    assert_eq!(packets.items[0].packet_index, 1);
    assert_eq!(packets.items[0].top_protocol.as_deref(), Some("DNS"));
    let last_page = s
        .list_packets(info.id, Page::new(4, 5), PacketSort::Index, None)
        .await
        .unwrap();
    assert_eq!(last_page.items.len(), 4);
    let beyond = s
        .list_packets(info.id, Page::new(9, 5), PacketSort::Index, None)
        .await
        .unwrap();
    assert!(beyond.items.is_empty());
    assert_eq!(beyond.total, 19);

    let detail = s.get_packet(info.id, 1).await.unwrap().unwrap();
    assert_eq!(
        detail.layers.as_array().unwrap().last().unwrap()["layer"],
        "dns"
    );
    assert!(s.get_packet(info.id, 999).await.unwrap().is_none());

    let flows = s
        .list_flows(info.id, Page::new(1, 50), FlowSort::BytesDesc, None)
        .await
        .unwrap();
    assert_eq!(flows.total, 6);
    assert!(
        flows
            .items
            .windows(2)
            .all(|w| w[0].bytes_total >= w[1].bytes_total)
    );
    let flow = s.get_flow(info.id, 2).await.unwrap().unwrap();
    assert_eq!(flow.summary.tcp_state.as_deref(), Some("closed"));
    assert_eq!(flow.summary.responder_port, 443);
    assert_eq!(
        flow.record["application"]["tls_server_names"][0],
        "www.example.com"
    );

    let dns = s.list_dns_events(info.id, Page::new(1, 50)).await.unwrap();
    assert_eq!(dns.total, 2);
    assert_eq!(dns.items[0].query_name.as_deref(), Some("www.example.com"));
    let tls = s.list_tls_events(info.id, Page::new(1, 50)).await.unwrap();
    assert_eq!(
        tls.total, 3,
        "two ClientHellos (one duplicated) and a ServerHello"
    );
    assert_eq!(tls.items[0].server_name.as_deref(), Some("www.example.com"));
    assert!(tls.items[0].visibility.contains("nothing is decrypted"));

    let sessions = s
        .list_sessions(Page::new(1, 10), SessionSort::NewestFirst)
        .await
        .unwrap();
    assert_eq!(sessions.total, 1);
    db.drop_database().await;
}

#[tokio::test]
async fn packet_storage_is_capped_but_flows_are_complete() {
    let Some(db) = TestDatabase::create("packet_cap").await else {
        return;
    };
    let session = import(&db.storage, "flows-mixed.pcap", 5).await;
    assert_eq!(session.session.packets_stored, 5);
    assert_eq!(session.session.packets_processed, 19);
    assert_eq!(session.session.flows_stored, 6);
    let none = import(&db.storage, "flows-mixed.pcap", 0).await;
    assert_eq!(none.session.packets_stored, 0);
    db.drop_database().await;
}

#[tokio::test]
async fn uncommitted_imports_leave_nothing_behind() {
    let Some(db) = TestDatabase::create("rollback").await else {
        return;
    };
    let s = &db.storage;
    let path = fixture("flows-mixed.pcap");
    let config = AnalysisConfig::default();
    let analysis = analyze_file(&path, &config, &MonotonicClock::start()).unwrap();
    {
        let mut tx = s.begin_import(&analysis, &meta("x.pcap")).await.unwrap();
        for batch in replay(&path, &config, &analysis) {
            tx.add_packets(batch).await.unwrap();
        }
        // Dropped without commit.
    }
    let sessions = s
        .list_sessions(Page::new(1, 10), SessionSort::NewestFirst)
        .await
        .unwrap();
    assert_eq!(sessions.total, 0);
    let packets: i64 = sqlx::query_scalar("SELECT count(*) FROM packets")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(packets, 0);
    db.drop_database().await;
}

#[tokio::test]
async fn application_fixtures_store_events_without_secrets() {
    let Some(db) = TestDatabase::create("app_events").await else {
        return;
    };
    let s = &db.storage;
    for name in [
        "app-dns.pcap",
        "app-dhcp.pcap",
        "app-http.pcap",
        "app-tls.pcap",
    ] {
        import(s, name, 100_000).await;
    }
    let http_session = s
        .list_sessions(Page::new(1, 10), SessionSort::OldestFirst)
        .await
        .unwrap()
        .items[2]
        .id;
    let http = s
        .list_http_events(http_session, Page::new(1, 50))
        .await
        .unwrap();
    assert!(http.items.iter().any(|e| e.redacted));
    assert!(http.items.iter().any(|e| e.kind == "response"));

    // No stored text anywhere contains a secret or payload marker.
    let dump: String = sqlx::query_scalar(
        "SELECT concat_ws(' ', \
           (SELECT string_agg(p::text, ' ') FROM packets p), \
           (SELECT string_agg(f::text, ' ') FROM flows f), \
           (SELECT string_agg(d::text, ' ') FROM dns_events d), \
           (SELECT string_agg(h::text, ' ') FROM http_events h), \
           (SELECT string_agg(t::text, ' ') FROM tls_events t), \
           (SELECT string_agg(c::text, ' ') FROM capture_sessions c))",
    )
    .fetch_one(s.pool())
    .await
    .unwrap();
    let lower = dump.to_ascii_lowercase();
    assert!(
        !lower.contains("flowsentinel-secret"),
        "secret marker stored"
    );
    assert!(
        !lower.contains("flowsentinel-synthetic-payload-marker"),
        "payload stored"
    );
    assert!(lower.contains("www.example.com"));
    db.drop_database().await;
}

/// A condition built like the display-filter translator does it: fixed SQL
/// text, values bound as parameters.
struct PortIs(i32);

impl SqlCondition for PortIs {
    fn push(&self, builder: &mut QueryBuilder<'_, Postgres>) {
        builder.push("dst_port = ");
        builder.push_bind(self.0);
    }
}

struct Hostile;

impl SqlCondition for Hostile {
    fn push(&self, builder: &mut QueryBuilder<'_, Postgres>) {
        builder.push("info = ");
        builder.push_bind("x'; DROP TABLE packets; --");
    }
}

#[tokio::test]
async fn conditions_filter_with_bound_parameters() {
    let Some(db) = TestDatabase::create("conditions").await else {
        return;
    };
    let s = &db.storage;
    let id = import(s, "flows-mixed.pcap", 100_000).await.session.id;
    let https = s
        .list_packets(id, Page::new(1, 50), PacketSort::Index, Some(&PortIs(443)))
        .await
        .unwrap();
    assert_eq!(https.total, 6);
    assert!(https.items.iter().all(|p| p.dst_port == Some(443)));
    let none = s
        .list_packets(id, Page::new(1, 50), PacketSort::Index, Some(&Hostile))
        .await
        .unwrap();
    assert_eq!(none.total, 0);
    let still_there = s
        .list_packets(id, Page::new(1, 50), PacketSort::Index, None)
        .await
        .unwrap();
    assert_eq!(still_there.total, 19);
    db.drop_database().await;
}

/// A condition that takes about a second per row.
struct Slow;

impl SqlCondition for Slow {
    fn push(&self, builder: &mut QueryBuilder<'_, Postgres>) {
        builder.push("(SELECT true FROM pg_sleep(1))");
    }
}

#[tokio::test]
async fn slow_list_queries_are_cancelled_at_the_time_limit() {
    let Some(db) = TestDatabase::create("query_timeout").await else {
        return;
    };
    let id = import(&db.storage, "flows-mixed.pcap", 100_000)
        .await
        .session
        .id;
    let limited = db
        .storage
        .clone()
        .with_query_timeout(std::time::Duration::from_millis(200));
    let started = std::time::Instant::now();
    let err = limited
        .list_packets(id, Page::new(1, 50), PacketSort::Index, Some(&Slow))
        .await
        .unwrap_err();
    assert!(matches!(err, storage::StorageError::QueryTimeout), "{err}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let err = limited
        .list_flows(id, Page::new(1, 50), FlowSort::Start, Some(&Slow))
        .await
        .unwrap_err();
    assert!(matches!(err, storage::StorageError::QueryTimeout), "{err}");
    // The connection is usable afterwards, and quick queries still work.
    let all = limited
        .list_packets(id, Page::new(1, 50), PacketSort::Index, None)
        .await
        .unwrap();
    assert_eq!(all.total, 19);
    db.drop_database().await;
}

#[tokio::test]
async fn retention_settings_and_purge() {
    let Some(db) = TestDatabase::create("retention").await else {
        return;
    };
    let s = &db.storage;
    let defaults = s.retention().await.unwrap();
    assert_eq!(
        defaults,
        RetentionSettings {
            session_ttl_days: 30,
            max_packets_stored: 100_000
        }
    );
    let updated = s
        .update_retention(RetentionSettings {
            session_ttl_days: 7,
            max_packets_stored: 10,
        })
        .await
        .unwrap();
    assert_eq!(updated.session_ttl_days, 7);
    // The database rejects out-of-range values too.
    assert!(
        s.update_retention(RetentionSettings {
            session_ttl_days: 0,
            max_packets_stored: 10,
        })
        .await
        .is_err()
    );

    let keep = import(s, "flows-mixed.pcap", 100_000).await.session.id;
    let expire = import(s, "flows-mixed.pcap", 100_000).await.session.id;
    sqlx::query(
        "UPDATE capture_sessions SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(expire)
    .execute(s.pool())
    .await
    .unwrap();
    assert_eq!(s.purge_expired().await.unwrap(), 1);
    assert!(s.get_session(expire).await.unwrap().is_none());
    assert!(s.get_session(keep).await.unwrap().is_some());
    let orphans: i64 = sqlx::query_scalar("SELECT count(*) FROM packets WHERE session_id = $1")
        .bind(expire)
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(orphans, 0, "cascade removes packets");
    assert!(s.delete_session(keep).await.unwrap());
    assert!(!s.delete_session(keep).await.unwrap());
    db.drop_database().await;
}

#[tokio::test]
async fn migrations_are_idempotent() {
    let Some(db) = TestDatabase::create("migrations").await else {
        return;
    };
    db.storage.migrate().await.unwrap();
    db.storage.ping().await.unwrap();
    db.drop_database().await;
}
