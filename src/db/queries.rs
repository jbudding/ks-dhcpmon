use sqlx::SqlitePool;
use crate::dhcp::DhcpRequest;
use super::models::DbDhcpRequest;

#[derive(Debug, Clone)]
pub struct QueryFilters {
    pub mac_address: Option<String>,
    pub vendor_class: Option<String>,
    pub message_type: Option<String>,
    pub xid: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub sort_by: String,
    pub sort_order: String,
    pub page: i64,
    pub page_size: i64,
}

impl Default for QueryFilters {
    fn default() -> Self {
        Self {
            mac_address: None,
            vendor_class: None,
            message_type: None,
            xid: None,
            start_date: None,
            end_date: None,
            sort_by: "timestamp".to_string(),
            sort_order: "DESC".to_string(),
            page: 1,
            page_size: 100,
        }
    }
}

pub async fn insert_request(pool: &SqlitePool, request: &DhcpRequest) -> Result<i64, sqlx::Error> {
    // Serialize raw_options to JSON
    let raw_options_json = serde_json::to_string(&request.raw_options)
        .unwrap_or_else(|_| "[]".to_string());

    let result = sqlx::query(
        r#"
        INSERT INTO dhcp_requests (
            timestamp, source_ip, source_port, mac_address, message_type,
            xid, fingerprint, vendor_class, os_name, device_class, raw_options,
            detection_method, confidence, smb_dialect, smb_build
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&request.timestamp)
    .bind(&request.source_ip)
    .bind(request.source_port as i64)
    .bind(&request.mac_address)
    .bind(&request.message_type)
    .bind(&request.xid)
    .bind(&request.fingerprint)
    .bind(&request.vendor_class)
    .bind(&request.os_name)
    .bind(&request.device_class)
    .bind(&raw_options_json)
    .bind(&request.detection_method)
    .bind(request.confidence.map(|c| c as f64))
    .bind(&request.smb_dialect)
    .bind(request.smb_build.map(|b| b as i64))
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

pub async fn query_requests(
    pool: &SqlitePool,
    filters: &QueryFilters,
) -> Result<Vec<DhcpRequest>, sqlx::Error> {
    let mut query = String::from("SELECT * FROM dhcp_requests WHERE 1=1");
    let mut conditions = Vec::new();

    // Build WHERE clause
    if filters.mac_address.is_some() {
        conditions.push(format!(
            "mac_address LIKE '%{}%'",
            filters.mac_address.as_ref().unwrap()
        ));
    }
    if filters.vendor_class.is_some() {
        conditions.push(format!(
            "vendor_class LIKE '%{}%'",
            filters.vendor_class.as_ref().unwrap()
        ));
    }
    if filters.message_type.is_some() {
        conditions.push(format!(
            "message_type = '{}'",
            filters.message_type.as_ref().unwrap()
        ));
    }
    if filters.xid.is_some() {
        conditions.push(format!("xid LIKE '%{}%'", filters.xid.as_ref().unwrap()));
    }
    if filters.start_date.is_some() {
        conditions.push(format!(
            "timestamp >= '{}'",
            filters.start_date.as_ref().unwrap()
        ));
    }
    if filters.end_date.is_some() {
        conditions.push(format!(
            "timestamp <= '{}'",
            filters.end_date.as_ref().unwrap()
        ));
    }

    for condition in conditions {
        query.push_str(" AND ");
        query.push_str(&condition);
    }

    // Add ORDER BY
    let sort_by = sanitize_column_name(&filters.sort_by);
    let sort_order = if filters.sort_order.to_uppercase() == "ASC" {
        "ASC"
    } else {
        "DESC"
    };
    query.push_str(&format!(" ORDER BY {} {}", sort_by, sort_order));

    // Add LIMIT and OFFSET for pagination
    let offset = (filters.page - 1) * filters.page_size;
    query.push_str(&format!(" LIMIT {} OFFSET {}", filters.page_size, offset));

    // Execute query
    let db_requests: Vec<DbDhcpRequest> = sqlx::query_as(&query).fetch_all(pool).await?;

    // Convert to DhcpRequest
    let requests: Vec<DhcpRequest> = db_requests.into_iter().map(|db_req| db_req.into()).collect();

    Ok(requests)
}

pub async fn count_requests(
    pool: &SqlitePool,
    filters: &QueryFilters,
) -> Result<i64, sqlx::Error> {
    let mut query = String::from("SELECT COUNT(*) as count FROM dhcp_requests WHERE 1=1");
    let mut conditions = Vec::new();

    // Build WHERE clause (same as query_requests)
    if filters.mac_address.is_some() {
        conditions.push(format!(
            "mac_address LIKE '%{}%'",
            filters.mac_address.as_ref().unwrap()
        ));
    }
    if filters.vendor_class.is_some() {
        conditions.push(format!(
            "vendor_class LIKE '%{}%'",
            filters.vendor_class.as_ref().unwrap()
        ));
    }
    if filters.message_type.is_some() {
        conditions.push(format!(
            "message_type = '{}'",
            filters.message_type.as_ref().unwrap()
        ));
    }
    if filters.xid.is_some() {
        conditions.push(format!("xid LIKE '%{}%'", filters.xid.as_ref().unwrap()));
    }
    if filters.start_date.is_some() {
        conditions.push(format!(
            "timestamp >= '{}'",
            filters.start_date.as_ref().unwrap()
        ));
    }
    if filters.end_date.is_some() {
        conditions.push(format!(
            "timestamp <= '{}'",
            filters.end_date.as_ref().unwrap()
        ));
    }

    for condition in conditions {
        query.push_str(" AND ");
        query.push_str(&condition);
    }

    // Execute count query
    let result: (i64,) = sqlx::query_as(&query).fetch_one(pool).await?;

    Ok(result.0)
}

pub async fn export_requests(
    pool: &SqlitePool,
    filters: &QueryFilters,
    format: &str,
) -> Result<String, sqlx::Error> {
    // Query without pagination for export
    let mut export_filters = filters.clone();
    export_filters.page_size = 100000; // Large limit for export

    let requests = query_requests(pool, &export_filters).await?;

    match format {
        "csv" => Ok(export_as_csv(&requests)),
        "json" => Ok(export_as_json(&requests)),
        _ => Ok(export_as_json(&requests)),
    }
}

fn export_as_csv(requests: &[DhcpRequest]) -> String {
    let mut csv = String::from("timestamp,source_ip,source_port,mac_address,message_type,xid,fingerprint,vendor_class\n");

    for req in requests {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            req.timestamp,
            req.source_ip,
            req.source_port,
            req.mac_address,
            req.message_type,
            req.xid,
            escape_csv_field(&req.fingerprint),
            req.vendor_class.as_ref().unwrap_or(&"-".to_string())
        ));
    }

    csv
}

fn export_as_json(requests: &[DhcpRequest]) -> String {
    serde_json::to_string_pretty(&requests).unwrap_or_else(|_| "[]".to_string())
}

fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn sanitize_column_name(column: &str) -> &str {
    match column {
        "timestamp" => "timestamp",
        "source_ip" => "source_ip",
        "source_port" => "source_port",
        "mac_address" => "mac_address",
        "message_type" => "message_type",
        "xid" => "xid",
        "fingerprint" => "fingerprint",
        "vendor_class" => "vendor_class",
        "created_at" => "created_at",
        _ => "timestamp", // Default to timestamp
    }
}
