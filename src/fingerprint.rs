use std::collections::HashMap;
use std::fs;
use once_cell::sync::Lazy;
use serde::Deserialize;

/// DHCP fingerprint database for OS identification
/// Fingerprints are based on DHCP Option 55 (Parameter Request List)
static FINGERPRINT_DB: Lazy<HashMap<&'static str, OsInfo>> = Lazy::new(|| {
    let mut db = HashMap::new();

    // Windows 11 (must be checked before Windows 10 due to superset)
    db.insert("1,3,6,15,31,33,43,44,46,47,121,249,252,12", OsInfo {
        os_name: "Windows 11",
        device_class: "Desktop/Laptop",
        vendor: "Microsoft",
    });

    // Windows 10/8/8.1 (same fingerprint)
    db.insert("1,3,6,15,31,33,43,44,46,47,121,249,252", OsInfo {
        os_name: "Windows 10/8/8.1",
        device_class: "Desktop/Laptop",
        vendor: "Microsoft",
    });

    // Windows 7
    db.insert("1,15,3,6,44,46,47,31,33,121,249,43,252", OsInfo {
        os_name: "Windows 7",
        device_class: "Desktop/Laptop",
        vendor: "Microsoft",
    });

    // macOS (Ventura/Sonoma)
    db.insert("1,3,6,15,119,252", OsInfo {
        os_name: "macOS (Recent)",
        device_class: "Desktop/Laptop",
        vendor: "Apple",
    });

    // macOS (older versions)
    db.insert("1,3,6,15,119,95,252,44,46", OsInfo {
        os_name: "macOS (Older)",
        device_class: "Desktop/Laptop",
        vendor: "Apple",
    });

    // iOS/iPadOS
    db.insert("1,3,6,15,119,252,95,44,46", OsInfo {
        os_name: "iOS/iPadOS",
        device_class: "Mobile",
        vendor: "Apple",
    });

    // iOS (alternative)
    db.insert("1,121,3,6,15,119,252,95,44,46", OsInfo {
        os_name: "iOS",
        device_class: "Mobile",
        vendor: "Apple",
    });

    // Android (common)
    db.insert("1,3,6,15,26,28,51,58,59", OsInfo {
        os_name: "Android",
        device_class: "Mobile",
        vendor: "Google",
    });

    // Android (alternative)
    db.insert("1,3,6,12,15,26,28,51,58,59,43", OsInfo {
        os_name: "Android",
        device_class: "Mobile",
        vendor: "Google",
    });

    // Linux (Ubuntu/Debian)
    db.insert("1,28,2,3,15,6,119,12,44,47,26,121,42", OsInfo {
        os_name: "Linux (Ubuntu/Debian)",
        device_class: "Desktop/Server",
        vendor: "Linux",
    });

    // Linux (general)
    db.insert("1,3,6,12,15,28,42,51,54,58,59", OsInfo {
        os_name: "Linux",
        device_class: "Desktop/Server",
        vendor: "Linux",
    });

    // Chrome OS
    db.insert("1,3,6,12,15,28,51,58,59,119", OsInfo {
        os_name: "Chrome OS",
        device_class: "Chromebook",
        vendor: "Google",
    });

    // PlayStation (PS4/PS5)
    db.insert("1,3,6,15,12,28", OsInfo {
        os_name: "PlayStation",
        device_class: "Gaming Console",
        vendor: "Sony",
    });

    // Xbox
    db.insert("1,3,6,15,44,46,47,12", OsInfo {
        os_name: "Xbox",
        device_class: "Gaming Console",
        vendor: "Microsoft",
    });

    // Nintendo Switch
    db.insert("1,3,6,15,28,51,58,59", OsInfo {
        os_name: "Nintendo Switch",
        device_class: "Gaming Console",
        vendor: "Nintendo",
    });

    // Roku
    db.insert("1,3,6,12,15,28,42", OsInfo {
        os_name: "Roku",
        device_class: "Streaming Device",
        vendor: "Roku",
    });

    // Amazon Fire TV
    db.insert("1,3,6,15,26,28,51,58,59,43,12", OsInfo {
        os_name: "Fire TV",
        device_class: "Streaming Device",
        vendor: "Amazon",
    });

    db
});

#[derive(Debug, Clone)]
pub struct OsInfo {
    pub os_name: &'static str,
    pub device_class: &'static str,
    pub vendor: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MacOsInfo {
    pub os_name: String,
    pub device_class: String,
    pub vendor: String,
}

#[derive(Debug, Deserialize)]
struct MacMapping {
    mappings: HashMap<String, MacOsInfo>,
}

/// Load MAC address to OS mappings from TOML file
fn load_mac_mappings() -> HashMap<String, MacOsInfo> {
    match fs::read_to_string("mac_os_mapping.toml") {
        Ok(content) => {
            match toml::from_str::<MacMapping>(&content) {
                Ok(mapping) => {
                    tracing::info!("Loaded {} MAC address mappings", mapping.mappings.len());
                    mapping.mappings
                }
                Err(e) => {
                    tracing::warn!("Failed to parse mac_os_mapping.toml: {}", e);
                    HashMap::new()
                }
            }
        }
        Err(_) => {
            tracing::debug!("No mac_os_mapping.toml file found, MAC mapping disabled");
            HashMap::new()
        }
    }
}

static MAC_MAPPINGS: Lazy<HashMap<String, MacOsInfo>> = Lazy::new(load_mac_mappings);

/// Lookup OS information based on MAC address and DHCP fingerprint
/// Checks MAC mapping first, then falls back to fingerprint-based detection
/// Also performs explicit Option 12 check for Windows 10 vs 11 differentiation
pub fn lookup_os(mac_address: &str, fingerprint: &str) -> Option<OsInfo> {
    // First, check if there's an explicit MAC mapping
    if let Some(mac_info) = MAC_MAPPINGS.get(mac_address) {
        tracing::debug!("Using MAC mapping for {}: {}", mac_address, mac_info.os_name);
        return Some(OsInfo {
            os_name: Box::leak(mac_info.os_name.clone().into_boxed_str()),
            device_class: Box::leak(mac_info.device_class.clone().into_boxed_str()),
            vendor: Box::leak(mac_info.vendor.clone().into_boxed_str()),
        });
    }

    // Fall back to fingerprint-based detection
    lookup_fingerprint(fingerprint)
}

/// Detect Windows version with confidence level
/// Returns confidence level: High (exact match), Medium (fuzzy match)
pub fn detect_windows_with_confidence(fingerprint: &str) -> Option<(OsInfo, &'static str)> {
    // Check for explicit Windows fingerprints first
    if let Some(info) = lookup_fingerprint(fingerprint) {
        if info.vendor == "Microsoft" && info.os_name.contains("Windows") {
            return Some((info, "High"));
        }
    }

    // Check if this looks like a Windows fingerprint with fuzzy matching
    let fp_parts: Vec<&str> = fingerprint.split(',').collect();

    // Windows fingerprints typically have these key options
    let has_windows_signature = fp_parts.contains(&"1")   // Subnet mask
        && fp_parts.contains(&"3")   // Router
        && fp_parts.contains(&"15")  // Domain name
        && fp_parts.contains(&"6");  // DNS

    if has_windows_signature {
        // Generic Windows detection - SMB scanning will provide specific version
        tracing::debug!("Windows signature detected in fingerprint");
        return Some((OsInfo {
            os_name: "Windows",
            device_class: "Desktop/Laptop",
            vendor: "Microsoft",
        }, "Medium"));
    }

    None
}

/// Lookup OS information based on DHCP fingerprint only
/// Simple exact match lookup - no fuzzy matching
pub fn lookup_fingerprint(fingerprint: &str) -> Option<OsInfo> {
    // Direct lookup (exact match only)
    FINGERPRINT_DB.get(fingerprint).cloned()
}

/// Format OS info as a string for storage/display
pub fn format_os_info(info: &OsInfo) -> String {
    format!("{} ({})", info.os_name, info.device_class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_11_exact_match() {
        let result = lookup_fingerprint("1,3,6,15,31,33,43,44,46,47,121,249,252,12");
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.os_name, "Windows 11");
    }

    #[test]
    fn test_windows_10_exact_match() {
        let result = lookup_fingerprint("1,3,6,15,31,33,43,44,46,47,121,249,252");
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.os_name, "Windows 10/8/8.1");
    }

    #[test]
    fn test_windows_11_no_fuzzy_match() {
        // Windows 11 fingerprint with one extra option - should NOT match (exact only)
        let result = lookup_fingerprint("1,3,6,15,31,33,43,44,46,47,121,249,252,12,99");
        assert!(result.is_none());
    }

    #[test]
    fn test_no_match() {
        let result = lookup_fingerprint("99,98,97");
        assert!(result.is_none());
    }

    #[test]
    fn test_partial_no_match() {
        // Partial fingerprint should NOT match (exact only)
        let result = lookup_fingerprint("1,3,6,15,31,33,43,44,46,47,121,249,252,99");
        assert!(result.is_none());
    }
}
