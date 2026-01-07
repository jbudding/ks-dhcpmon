mod dhcp;
mod logger;
mod web;
mod db;

use anyhow::Result;
use dhcp::{DhcpPacket, DhcpRequest};
use logger::RequestLogger;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};
use web::state::{AppState, WEB_SERVER_PORT};

const DHCP_SERVER_PORT: u16 = 67;
const BUFFER_SIZE: usize = 4096;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    info!("Starting DHCP Monitor with Web UI");

    // Create the logger
    let logger = Arc::new(RequestLogger::new("request.json")?);
    info!("Logging requests to request.json");

    // Create database pool
    let db_pool = db::create_pool("sqlite:dhcp_monitor.db").await?;
    info!("Database initialized at dhcp_monitor.db");

    // Create shared application state
    let app_state = Arc::new(AppState::new(logger, db_pool));

    // Spawn UDP listener task
    let udp_state = app_state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_udp_listener(udp_state).await {
            error!("UDP listener error: {}", e);
        }
    });

    // Run web server (blocks on main thread)
    info!("Starting web server on port {}", WEB_SERVER_PORT);
    web::server::run_server(app_state, WEB_SERVER_PORT).await?;

    Ok(())
}

async fn run_udp_listener(state: Arc<AppState>) -> Result<()> {
    info!("Starting DHCP listener on port {}", DHCP_SERVER_PORT);

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", DHCP_SERVER_PORT)).await?;
    info!("Listening for DHCP requests on 0.0.0.0:{}", DHCP_SERVER_PORT);

    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, source)) => {
                let data = buffer[..len].to_vec();
                let state = state.clone();

                // Spawn a task to handle the request
                tokio::spawn(async move {
                    if let Err(e) = handle_dhcp_request(data, source, state).await {
                        error!("Error handling DHCP request: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Error receiving data: {}", e);
            }
        }
    }
}

async fn handle_dhcp_request(
    data: Vec<u8>,
    source: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    // Parse the DHCP packet
    let packet = match DhcpPacket::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to parse DHCP packet from {}: {}", source, e);
            return Ok(());
        }
    };

    let message_type = packet.get_message_type();
    let mac = packet.get_mac_address();

    info!(
        "Received DHCP {} from {} (MAC: {})",
        match message_type {
            Some(1) => "DISCOVER",
            Some(3) => "REQUEST",
            Some(4) => "DECLINE",
            Some(7) => "RELEASE",
            Some(8) => "INFORM",
            _ => "UNKNOWN",
        },
        source,
        mac
    );

    // Create request object
    let request = DhcpRequest::from_packet(&packet, source.ip().to_string(), source.port());

    // Extract options and ciaddr
    let option_12 = packet.get_option(12);
    let option_55 = packet.get_option(55);
    let option_60 = packet.get_option(60);
    let option_81 = packet.get_option(81);
    let ciaddr = packet.ciaddr;

    // Log relevant data to console as JSON if any field is present
    if option_12.is_some() || option_55.is_some() || option_60.is_some() || option_81.is_some() || !ciaddr.is_unspecified() {
        let mut options_json = serde_json::json!({
            "mac_address": mac,
            "source_ip": source.ip().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        // Add ciaddr if not 0.0.0.0
        if !ciaddr.is_unspecified() {
            options_json["ciaddr"] = serde_json::json!(ciaddr.to_string());
        }

        // Add Option 12 (Hostname) if present
        if let Some(opt12) = option_12 {
            options_json["option_12"] = serde_json::json!(opt12.data);
            options_json["option_12_hostname"] = serde_json::json!(
                String::from_utf8_lossy(&opt12.data).to_string()
            );
        }

        // Add Option 55 if present
        if let Some(opt55) = option_55 {
            options_json["option_55"] = serde_json::json!(opt55.data);
            options_json["option_55_csv"] = serde_json::json!(
                opt55.data.iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }

        // Add Option 60 if present
        if let Some(opt60) = option_60 {
            options_json["option_60"] = serde_json::json!(opt60.data);
            options_json["option_60_string"] = serde_json::json!(
                String::from_utf8_lossy(&opt60.data).to_string()
            );
        }

        // Add Option 81 (Client FQDN) if present
        if let Some(opt81) = option_81 {
            options_json["option_81"] = serde_json::json!(opt81.data);
            // Parse Option 81 structure: Flags (1 byte) + RCODE1 (1 byte) + RCODE2 (1 byte) + Domain Name
            if opt81.data.len() >= 3 {
                let flags = opt81.data[0];
                let fqdn_bytes = &opt81.data[3..];
                options_json["option_81_flags"] = serde_json::json!(flags);
                options_json["option_81_fqdn"] = serde_json::json!(
                    String::from_utf8_lossy(fqdn_bytes).to_string()
                );
            }
        }

        println!("{}", serde_json::to_string_pretty(&options_json)?);
    }

    // Process request through state manager (handles logging, broadcasting, stats)
    state.process_request(request).await?;

    Ok(())
}
