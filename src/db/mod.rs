pub mod models;
pub mod queries;

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use tracing::info;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS dhcp_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    mac_address TEXT NOT NULL,
    message_type TEXT NOT NULL,
    xid TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    vendor_class TEXT,
    raw_options TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON dhcp_requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_mac_address ON dhcp_requests(mac_address);
CREATE INDEX IF NOT EXISTS idx_message_type ON dhcp_requests(message_type);
CREATE INDEX IF NOT EXISTS idx_created_at ON dhcp_requests(created_at);
"#;

pub async fn create_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    info!("Initializing database at {}", database_url);

    // Create connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;

    // Run migrations (create table and indexes)
    info!("Running database migrations");
    sqlx::query(SCHEMA).execute(&pool).await?;

    info!("Database initialized successfully");
    Ok(pool)
}
