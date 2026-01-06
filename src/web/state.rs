use crate::dhcp::DhcpRequest;
use crate::logger::RequestLogger;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use ringbuf::{HeapRb, Rb};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

// Configuration constants
pub const HISTORY_BUFFER_SIZE: usize = 1000;
pub const BROADCAST_CHANNEL_SIZE: usize = 100;
pub const WEB_SERVER_PORT: u16 = 8080;

// Statistics structure
#[derive(Debug, Clone, serde::Serialize)]
pub struct Statistics {
    pub total_requests: u64,
    pub request_types: HashMap<String, u64>,
    pub unique_macs: u64,
    pub requests_per_minute: f64,
    pub last_updated: DateTime<Utc>,
    pub uptime_seconds: u64,
    pub vendor_classes: HashMap<String, u64>,
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            request_types: HashMap::new(),
            unique_macs: 0,
            requests_per_minute: 0.0,
            last_updated: Utc::now(),
            uptime_seconds: 0,
            vendor_classes: HashMap::new(),
        }
    }
}

// Application state shared across all tasks
pub struct AppState {
    // Broadcast channel for real-time updates to WebSocket clients
    pub broadcast_tx: broadcast::Sender<Arc<DhcpRequest>>,

    // File logger (existing)
    pub logger: Arc<RequestLogger>,

    // Circular buffer for recent requests (thread-safe)
    pub history: Arc<RwLock<HeapRb<Arc<DhcpRequest>>>>,

    // Statistics (thread-safe)
    pub stats: Arc<RwLock<Statistics>>,

    // Set of unique MAC addresses (for stats)
    pub unique_macs: Arc<RwLock<HashSet<String>>>,

    // Application start time
    pub start_time: DateTime<Utc>,
}

impl AppState {
    pub fn new(logger: Arc<RequestLogger>) -> Self {
        let (broadcast_tx, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);

        Self {
            broadcast_tx,
            logger,
            history: Arc::new(RwLock::new(HeapRb::new(HISTORY_BUFFER_SIZE))),
            stats: Arc::new(RwLock::new(Statistics::default())),
            unique_macs: Arc::new(RwLock::new(HashSet::new())),
            start_time: Utc::now(),
        }
    }

    // Process a new DHCP request (called from UDP handler)
    pub async fn process_request(&self, request: DhcpRequest) -> anyhow::Result<()> {
        let request_arc = Arc::new(request);

        // 1. Log to file (existing functionality)
        if let Err(e) = self.logger.log(&request_arc) {
            tracing::error!("Failed to log request: {}", e);
        }

        // 2. Add to history buffer
        {
            let mut history = self.history.write().await;
            history.push_overwrite(request_arc.clone());
        }

        // 3. Update statistics
        self.update_statistics(&request_arc).await;

        // 4. Broadcast to WebSocket clients (don't wait for receivers)
        let _ = self.broadcast_tx.send(request_arc);

        Ok(())
    }

    async fn update_statistics(&self, request: &DhcpRequest) {
        let mut stats = self.stats.write().await;
        let mut macs = self.unique_macs.write().await;

        // Increment total
        stats.total_requests += 1;

        // Track message types
        *stats.request_types.entry(request.message_type.clone()).or_insert(0) += 1;

        // Track unique MACs
        macs.insert(request.mac_address.clone());
        stats.unique_macs = macs.len() as u64;

        // Track vendor classes
        if let Some(ref vendor) = request.vendor_class {
            *stats.vendor_classes.entry(vendor.clone()).or_insert(0) += 1;
        }

        // Calculate requests per minute
        let elapsed = (Utc::now() - self.start_time).num_seconds() as f64;
        if elapsed > 0.0 {
            stats.requests_per_minute = (stats.total_requests as f64) / (elapsed / 60.0);
        }

        stats.uptime_seconds = elapsed as u64;
        stats.last_updated = Utc::now();
    }

    // Get recent history (for API endpoint)
    pub async fn get_history(&self, limit: usize) -> Vec<Arc<DhcpRequest>> {
        let history = self.history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    // Search history (for filtering)
    pub async fn search_history(
        &self,
        mac: Option<&str>,
        vendor: Option<&str>,
        msg_type: Option<&str>,
    ) -> Vec<Arc<DhcpRequest>> {
        let history = self.history.read().await;

        history.iter()
            .filter(|req| {
                let mac_match = mac.map_or(true, |m| req.mac_address.contains(m));
                let vendor_match = vendor.map_or(true, |v| {
                    req.vendor_class.as_ref().map_or(false, |vc| vc.contains(v))
                });
                let type_match = msg_type.map_or(true, |t| req.message_type.eq_ignore_ascii_case(t));

                mac_match && vendor_match && type_match
            })
            .cloned()
            .collect()
    }

    // Get current statistics
    pub async fn get_stats(&self) -> Statistics {
        self.stats.read().await.clone()
    }
}
