use crate::fingerprint;
use crate::smb;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;

/// Configuration for hybrid detection
#[derive(Debug, Clone)]
pub struct HybridConfig {
    /// Enable SMB probing as fallback
    pub enable_smb_probing: bool,
    /// SMB probe timeout in seconds
    pub smb_timeout_secs: u64,
    /// Only probe when DHCP confidence is below this threshold
    pub smb_probe_confidence_threshold: f32,
    /// Cache SMB results for this many seconds
    pub smb_cache_ttl_secs: u64,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            enable_smb_probing: true,
            smb_timeout_secs: 3,
            smb_probe_confidence_threshold: 0.8,
            smb_cache_ttl_secs: 3600, // 1 hour
        }
    }
}

/// Result of hybrid detection
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub os_name: String,
    pub device_class: String,
    pub vendor: String,
    pub confidence: f32,
    pub detection_method: String,
    pub smb_dialect: Option<String>,
    pub smb_build: Option<u32>,
}

/// Cache entry for SMB probe results
#[derive(Debug, Clone)]
struct SmbCacheEntry {
    result: smb::SmbProbeResult,
    timestamp: u64,
}

/// Hybrid detection engine that combines DHCP fingerprinting with SMB probing
pub struct HybridDetector {
    config: HybridConfig,
    smb_cache: Arc<RwLock<HashMap<String, SmbCacheEntry>>>,
}

impl HybridDetector {
    pub fn new(config: HybridConfig) -> Self {
        Self {
            config,
            smb_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Detect OS using hybrid approach: Use DHCP IP for active SMB scanning
    pub async fn detect(
        &self,
        mac_address: &str,
        ip_address: &str,
        dhcp_fingerprint: &str,
        vendor_class: Option<&str>,
    ) -> DetectionResult {
        // Step 1: Get basic DHCP fingerprint info for fallback
        let dhcp_result = self.detect_via_dhcp(mac_address, dhcp_fingerprint);

        // Step 2: Only try SMB probing if enabled AND conditions are met
        // Conditions: IP is not 0.0.0.0 AND vendor class contains "MSFT"
        let should_probe_smb = self.config.enable_smb_probing
            && ip_address != "0.0.0.0"
            && vendor_class.map_or(false, |vc| vc.contains("MSFT"));

        if should_probe_smb {
            println!("🔍 SMB PROBE: Attempting probe to {} (MAC: {}, vendor: {:?})",
                ip_address, mac_address, vendor_class);
            tracing::info!(
                "Attempting SMB probe to {} (MAC: {}, vendor: {:?})",
                ip_address,
                mac_address,
                vendor_class
            );

            // First, check if host is reachable via ping
            match Self::ping_host(ip_address).await {
                Ok(true) => {
                    println!("✅ PING SUCCESS: {} is reachable", ip_address);
                }
                Ok(false) => {
                    println!("❌ PING FAILED: {} is not reachable, skipping SMB probe", ip_address);
                    tracing::debug!("Host {} not reachable via ping, skipping SMB probe", ip_address);
                    // Don't probe if host is not reachable
                    return dhcp_result;
                }
                Err(e) => {
                    println!("⚠️  PING ERROR: {} - {}, continuing with SMB probe anyway", ip_address, e);
                    tracing::debug!("Ping error for {}: {}, continuing with SMB probe", ip_address, e);
                    // Continue with SMB probe even if ping fails (some hosts may block ICMP)
                }
            }

            match self.probe_smb_cached(ip_address).await {
                Some(smb_result) if smb_result.success => {
                    println!("✅ SMB PROBE SUCCESS: {} => {} (dialect: {}, build: {:?})",
                        ip_address, smb_result.os_version, smb_result.smb_dialect, smb_result.build_number);
                    // Use SMB results - this is more accurate than DHCP fingerprinting
                    return self.combine_results(dhcp_result, smb_result);
                }
                Some(smb_result) => {
                    println!("❌ SMB PROBE FAILED: {} => {}", ip_address, smb_result.os_version);
                    tracing::debug!("SMB probe failed for {}: {}", ip_address, smb_result.os_version);
                }
                None => {
                    println!("⚠️  SMB PROBE ERROR: {} returned no result", ip_address);
                    tracing::debug!("SMB probe returned no result for {}", ip_address);
                }
            }
        } else if self.config.enable_smb_probing {
            let reason = if ip_address == "0.0.0.0" {
                "IP is 0.0.0.0"
            } else if vendor_class.is_none() {
                "no vendor class"
            } else if !vendor_class.map_or(false, |vc| vc.contains("MSFT")) {
                "vendor class doesn't contain MSFT"
            } else {
                "unknown"
            };
            println!("⏭️  SMB PROBE SKIP: {} (MAC: {}) - {}", ip_address, mac_address, reason);
            tracing::debug!(
                "Skipping SMB probe for {} (IP: {}, vendor: {:?}) - conditions not met",
                mac_address,
                ip_address,
                vendor_class
            );
        }

        // Fall back to DHCP result if SMB fails or is disabled
        tracing::debug!("Using DHCP-only detection for {}", mac_address);
        dhcp_result
    }

    /// Detect via DHCP fingerprinting only
    /// Priority: 1) MAC address mapping, 2) Exact fingerprint match, 3) Unknown
    fn detect_via_dhcp(&self, mac_address: &str, fingerprint: &str) -> DetectionResult {
        // Priority 1: Check MAC address mapping first (most reliable)
        // This uses lookup_os which checks MAC mapping before fingerprint
        if let Some(info) = fingerprint::lookup_os(mac_address, fingerprint) {
            return DetectionResult {
                os_name: info.os_name.to_string(),
                device_class: info.device_class.to_string(),
                vendor: info.vendor.to_string(),
                confidence: 0.95, // High confidence for explicit mapping or exact match
                detection_method: "MAC/Fingerprint lookup".to_string(),
                smb_dialect: None,
                smb_build: None,
            };
        }

        // Unknown - no match found
        DetectionResult {
            os_name: "Unknown".to_string(),
            device_class: "Unknown".to_string(),
            vendor: "Unknown".to_string(),
            confidence: 0.0,
            detection_method: "None".to_string(),
            smb_dialect: None,
            smb_build: None,
        }
    }

    /// Ping a host to check if it's reachable
    /// Returns Ok(true) if reachable, Ok(false) if not reachable, Err if ping command fails
    async fn ping_host(ip: &str) -> Result<bool, String> {
        println!("📡 PING: Checking reachability of {}...", ip);

        // Use platform-specific ping command
        // Linux: ping -c 1 -W 1 <ip>
        // -c 1: send 1 packet
        // -W 1: wait 1 second for response
        let output = Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("1")
            .arg(ip)
            .output()
            .await
            .map_err(|e| format!("Failed to execute ping: {}", e))?;

        let success = output.status.success();

        if success {
            // Parse output to get response time if available
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                if let Some(time_line) = stdout.lines().find(|line| line.contains("time=")) {
                    if let Some(time_str) = time_line.split("time=").nth(1) {
                        if let Some(time_ms) = time_str.split_whitespace().next() {
                            println!("  ⏱️  Response time: {} ms", time_ms);
                        }
                    }
                }
            }
        }

        Ok(success)
    }

    /// Probe SMB with caching
    async fn probe_smb_cached(&self, ip: &str) -> Option<smb::SmbProbeResult> {
        // Check cache first
        {
            let cache = self.smb_cache.read().await;
            if let Some(entry) = cache.get(ip) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if now - entry.timestamp < self.config.smb_cache_ttl_secs {
                    println!("💾 SMB CACHE HIT: {} (age: {}s)", ip, now - entry.timestamp);
                    tracing::debug!("SMB cache hit for {}", ip);
                    return Some(entry.result.clone());
                }
            }
        }

        println!("🌐 SMB PROBE: Connecting to {}:445 (timeout: {}s)...", ip, self.config.smb_timeout_secs);

        // Probe SMB
        match smb::probe_smb(ip, self.config.smb_timeout_secs).await {
            Ok(result) => {
                println!("📦 SMB RESPONSE: {} returned (success: {})", ip, result.success);

                // Cache the result
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let mut cache = self.smb_cache.write().await;
                cache.insert(ip.to_string(), SmbCacheEntry {
                    result: result.clone(),
                    timestamp: now,
                });

                Some(result)
            }
            Err(e) => {
                println!("❌ SMB PROBE ERROR: {} failed - {}", ip, e);
                tracing::warn!("SMB probe error for {}: {}", ip, e);
                None
            }
        }
    }

    /// Combine DHCP and SMB results
    fn combine_results(
        &self,
        dhcp_result: DetectionResult,
        smb_result: smb::SmbProbeResult,
    ) -> DetectionResult {
        // Use SMB detection results directly - they are more accurate
        let os_name = &smb_result.os_version;

        DetectionResult {
            os_name: os_name.to_string(),
            device_class: dhcp_result.device_class,
            vendor: "Microsoft".to_string(),
            confidence: 0.95, // Very high confidence with SMB probing
            detection_method: format!("SMB probe ({})", smb_result.smb_dialect),
            smb_dialect: Some(smb_result.smb_dialect),
            smb_build: smb_result.build_number,
        }
    }

    /// Clear SMB cache
    pub async fn clear_cache(&self) {
        let mut cache = self.smb_cache.write().await;
        cache.clear();
        tracing::info!("SMB probe cache cleared");
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.smb_cache.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let total = cache.len();
        let expired = cache.values()
            .filter(|entry| now - entry.timestamp >= self.config.smb_cache_ttl_secs)
            .count();

        (total, expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HybridConfig::default();
        assert!(config.enable_smb_probing);
        assert_eq!(config.smb_timeout_secs, 3);
    }

    #[tokio::test]
    async fn test_dhcp_detection() {
        let detector = HybridDetector::new(HybridConfig::default());

        // Windows fingerprint (exact match)
        let result = detector.detect_via_dhcp(
            "aa:bb:cc:dd:ee:ff",
            "1,3,6,15,31,33,43,44,46,47,121,249,252"
        );

        assert!(result.os_name.contains("Windows"));
        assert!(result.confidence > 0.5);
    }

    #[tokio::test]
    async fn test_cache() {
        let detector = HybridDetector::new(HybridConfig::default());

        let (total, _) = detector.cache_stats().await;
        assert_eq!(total, 0);

        detector.clear_cache().await;
    }
}
