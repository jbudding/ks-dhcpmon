use super::state::AppState;
use axum::{
    extract::{Query, State, WebSocketUpgrade},
    response::{Html, IntoResponse, Response},
    Json,
};
use axum::extract::ws::{WebSocket, Message};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};

// Serve embedded HTML
pub async fn serve_index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

// Serve embedded JavaScript
pub async fn serve_js() -> impl IntoResponse {
    (
        [("content-type", "application/javascript")],
        include_str!("../static/app.js"),
    )
}

// Serve embedded CSS
pub async fn serve_css() -> impl IntoResponse {
    (
        [("content-type", "text/css")],
        include_str!("../static/styles.css"),
    )
}

// Get recent history
#[derive(Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

pub async fn get_history(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryQuery>,
) -> Json<Vec<crate::dhcp::DhcpRequest>> {
    let history = state.get_history(params.limit).await;
    // Convert Arc to owned values
    let owned: Vec<_> = history.iter().map(|r| (**r).clone()).collect();
    Json(owned)
}

// Get statistics
pub async fn get_statistics(
    State(state): State<Arc<AppState>>,
) -> Json<super::state::Statistics> {
    let stats = state.get_stats().await;
    Json(stats)
}

// Search requests
#[derive(Deserialize)]
pub struct SearchQuery {
    mac: Option<String>,
    vendor: Option<String>,
    msg_type: Option<String>,
}

pub async fn search_requests(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchQuery>,
) -> Json<Vec<crate::dhcp::DhcpRequest>> {
    let results = state.search_history(
        params.mac.as_deref(),
        params.vendor.as_deref(),
        params.msg_type.as_deref(),
    ).await;
    // Convert Arc to owned values
    let owned: Vec<_> = results.iter().map(|r| (**r).clone()).collect();
    Json(owned)
}

// WebSocket handler
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to broadcast channel
    let mut rx = state.broadcast_tx.subscribe();

    info!("WebSocket client connected");

    // Send initial history on connection
    let history = state.get_history(50).await;
    for request in history {
        let json = match serde_json::to_string(&*request) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to serialize request: {}", e);
                continue;
            }
        };

        if sender.send(Message::Text(json)).await.is_err() {
            warn!("Failed to send initial history to client");
            return;
        }
    }

    // Spawn task to handle incoming messages (ping/pong)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            // Handle client messages (e.g., ping)
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    // Spawn task to send broadcast updates to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(request) = rx.recv().await {
            let json = match serde_json::to_string(&*request) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to serialize request: {}", e);
                    continue;
                }
            };

            if sender.send(Message::Text(json)).await.is_err() {
                // Client disconnected
                break;
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        }
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    }

    info!("WebSocket client disconnected");
}

// Serve historical logs page
pub async fn serve_logs_page() -> Html<&'static str> {
    Html(include_str!("../static/logs.html"))
}

// Serve logs JavaScript
pub async fn serve_logs_js() -> impl IntoResponse {
    (
        [("content-type", "application/javascript")],
        include_str!("../static/logs.js"),
    )
}

// Serve logs CSS
pub async fn serve_logs_css() -> impl IntoResponse {
    (
        [("content-type", "text/css")],
        include_str!("../static/logs.css"),
    )
}

// Query parameters for logs
#[derive(Deserialize)]
pub struct LogsQuery {
    mac_address: Option<String>,
    vendor_class: Option<String>,
    message_type: Option<String>,
    xid: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    sort_by: Option<String>,
    sort_order: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
}

// Response for count
#[derive(serde::Serialize)]
pub struct CountResponse {
    count: i64,
}

// Get logs with filters and pagination
pub async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsQuery>,
) -> Json<Vec<crate::dhcp::DhcpRequest>> {
    let filters = crate::db::queries::QueryFilters {
        mac_address: params.mac_address,
        vendor_class: params.vendor_class,
        message_type: params.message_type,
        xid: params.xid,
        start_date: params.start_date,
        end_date: params.end_date,
        sort_by: params.sort_by.unwrap_or_else(|| "timestamp".to_string()),
        sort_order: params.sort_order.unwrap_or_else(|| "DESC".to_string()),
        page: params.page.unwrap_or(1),
        page_size: params.page_size.unwrap_or(100).min(500),
    };

    match crate::db::queries::query_requests(&state.db_pool, &filters).await {
        Ok(requests) => Json(requests),
        Err(e) => {
            error!("Database query error: {}", e);
            Json(vec![])
        }
    }
}

// Get count of logs matching filters
pub async fn get_logs_count(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsQuery>,
) -> Json<CountResponse> {
    let filters = crate::db::queries::QueryFilters {
        mac_address: params.mac_address,
        vendor_class: params.vendor_class,
        message_type: params.message_type,
        xid: params.xid,
        start_date: params.start_date,
        end_date: params.end_date,
        sort_by: "timestamp".to_string(),
        sort_order: "DESC".to_string(),
        page: 1,
        page_size: 1,
    };

    let count = crate::db::queries::count_requests(&state.db_pool, &filters)
        .await
        .unwrap_or(0);

    Json(CountResponse { count })
}

// Export logs
#[derive(Deserialize)]
pub struct ExportQuery {
    format: String,
    mac_address: Option<String>,
    vendor_class: Option<String>,
    message_type: Option<String>,
    xid: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
}

pub async fn export_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ExportQuery>,
) -> impl IntoResponse {
    let filters = crate::db::queries::QueryFilters {
        mac_address: params.mac_address,
        vendor_class: params.vendor_class,
        message_type: params.message_type,
        xid: params.xid,
        start_date: params.start_date,
        end_date: params.end_date,
        sort_by: "timestamp".to_string(),
        sort_order: "DESC".to_string(),
        page: 1,
        page_size: 100000,
    };

    match crate::db::queries::export_requests(&state.db_pool, &filters, &params.format).await {
        Ok(data) => {
            let content_type = if params.format == "csv" {
                "text/csv"
            } else {
                "application/json"
            };

            let filename = format!(
                "dhcp_logs_{}.{}",
                chrono::Utc::now().format("%Y%m%d_%H%M%S"),
                params.format
            );

            (
                [
                    ("content-type", content_type),
                    ("content-disposition", &format!("attachment; filename=\"{}\"", filename)),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => {
            error!("Export error: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Export failed",
            )
                .into_response()
        }
    }
}
