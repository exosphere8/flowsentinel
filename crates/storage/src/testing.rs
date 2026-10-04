//! Disposable PostgreSQL databases for integration tests (feature
//! `test-support`).
//!
//! Tests run only when `FLOWSENTINEL_TEST_DATABASE_URL` points at a server
//! where the user may create databases, for example
//! `postgres://postgres@127.0.0.1:5432/postgres`. Each test gets a fresh,
//! uniquely named, migrated database that is dropped afterwards.
//!
//! Without the variable, database tests print a notice and return early, so
//! `cargo test` works on machines without PostgreSQL. CI sets
//! `FLOWSENTINEL_REQUIRE_DB_TESTS=1`, which turns a missing variable into a
//! failure so the tests cannot be skipped silently.

use std::sync::atomic::{AtomicU32, Ordering};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Connection, Executor, PgConnection};

use crate::Storage;

pub const DATABASE_URL_VAR: &str = "FLOWSENTINEL_TEST_DATABASE_URL";
pub const REQUIRE_VAR: &str = "FLOWSENTINEL_REQUIRE_DB_TESTS";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A migrated database that exists for one test. It is dropped by
/// [`drop_database`](Self::drop_database), or when this value is dropped
/// (including when the test panics).
#[derive(Debug)]
pub struct TestDatabase {
    pub storage: Storage,
    admin: PgConnectOptions,
    name: String,
    dropped: bool,
}

impl TestDatabase {
    /// Creates a migrated database, or returns `None` when no test server is
    /// configured (and none is required).
    ///
    /// # Panics
    ///
    /// When the server is configured but unusable, or required but not
    /// configured: a test helper should fail loudly.
    pub async fn create(test: &str) -> Option<Self> {
        let Ok(url) = std::env::var(DATABASE_URL_VAR) else {
            assert!(
                std::env::var_os(REQUIRE_VAR).is_none(),
                "{REQUIRE_VAR} is set but {DATABASE_URL_VAR} is not"
            );
            eprintln!("{DATABASE_URL_VAR} is not set; skipping database test {test}");
            return None;
        };
        let admin: PgConnectOptions = url.parse().expect("valid test database URL");
        let suffix: String = test
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(24)
            .collect();
        let name = format!(
            "fs_test_{}_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            suffix
        )
        .to_ascii_lowercase();
        let mut conn = admin.connect().await.expect("connect to the test server");
        // The name is built only from digits, lowercase ASCII letters and
        // underscores, so it is safe as an identifier.
        conn.execute(format!("CREATE DATABASE {name}").as_str())
            .await
            .expect("create the test database");
        conn.close().await.ok();

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(admin.clone().database(&name))
            .await
            .expect("connect to the test database");
        let storage = Storage::from_pool(pool);
        storage.migrate().await.expect("migrations apply");
        Some(Self {
            storage,
            admin,
            name,
            dropped: false,
        })
    }

    /// Drops the database. Call at the end of each test.
    pub async fn drop_database(mut self) {
        self.storage.pool().close().await;
        drop_named(&self.admin, &self.name).await;
        self.dropped = true;
    }
}

async fn drop_named(admin: &PgConnectOptions, name: &str) {
    if let Ok(mut conn) = PgConnection::connect_with(admin).await {
        let _ = conn
            .execute(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)").as_str())
            .await;
        let _ = conn.close().await;
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        // Reached when a test panicked before cleaning up. The test's own
        // runtime may be unusable here, so use a fresh one on another thread.
        let admin = self.admin.clone();
        let name = std::mem::take(&mut self.name);
        let cleanup = std::thread::spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                runtime.block_on(drop_named(&admin, &name));
            }
        });
        let _ = cleanup.join();
    }
}
