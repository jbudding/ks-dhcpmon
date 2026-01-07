use crate::dhcp::DhcpRequest;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct DbDhcpRequest {
    pub id: i64,
    pub timestamp: String,
    pub source_ip: String,
    pub source_port: i64,
    pub mac_address: String,
    pub message_type: String,
    pub xid: String,
    pub fingerprint: String,
    pub vendor_class: Option<String>,
    pub os_name: Option<String>,
    pub device_class: Option<String>,
    pub raw_options: String,
    pub created_at: String,
}

impl From<DbDhcpRequest> for DhcpRequest {
    fn from(db_req: DbDhcpRequest) -> Self {
        // Parse raw_options back from JSON
        let raw_options = serde_json::from_str(&db_req.raw_options).unwrap_or_default();

        DhcpRequest {
            timestamp: db_req.timestamp,
            source_ip: db_req.source_ip,
            source_port: db_req.source_port as u16,
            mac_address: db_req.mac_address,
            message_type: db_req.message_type,
            xid: db_req.xid,
            fingerprint: db_req.fingerprint,
            vendor_class: db_req.vendor_class,
            os_name: db_req.os_name,
            device_class: db_req.device_class,
            raw_options,
        }
    }
}
