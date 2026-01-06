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
