use super::handlers;
use super::state::AppState;
use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;

pub async fn run_server(state: Arc<AppState>, port: u16) -> anyhow::Result<()> {
    // Build router with all endpoints
    let app = Router::new()
        // Serve static HTML page
        .route("/", get(handlers::serve_index))

        // WebSocket endpoint for real-time updates
        .route("/ws", get(handlers::websocket_handler))

        // REST API endpoints
        .route("/api/history", get(handlers::get_history))
        .route("/api/stats", get(handlers::get_statistics))
        .route("/api/search", get(handlers::search_requests))

        // Static assets (CSS, JS)
        .route("/app.js", get(handlers::serve_js))
        .route("/styles.css", get(handlers::serve_css))

        // Historical logs page
        .route("/logs", get(handlers::serve_logs_page))
        .route("/logs.js", get(handlers::serve_logs_js))
        .route("/logs.css", get(handlers::serve_logs_css))

        // Historical logs API endpoints
        .route("/api/logs", get(handlers::get_logs))
        .route("/api/logs/count", get(handlers::get_logs_count))
        .route("/api/logs/export", get(handlers::export_logs))

        // Add application state
        .with_state(state)

        // Add tracing middleware
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{}", port);
    info!("Web UI available at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
