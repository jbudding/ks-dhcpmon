use std::collections::HashMap;
use once_cell::sync::Lazy;

/// DHCP fingerprint database for OS identification
/// Fingerprints are based on DHCP Option 55 (Parameter Request List)
static FINGERPRINT_DB: Lazy<HashMap<&'static str, OsInfo>> = Lazy::new(|| {
    let mut db = HashMap::new();

    // Windows 10
    db.insert("1,3,6,15,31,33,43,44,46,47,121,249,252", OsInfo {
        os_name: "Windows 10",
        device_class: "Desktop/Laptop",
        vendor: "Microsoft",
    });

    // Windows 11
    db.insert("1,3,6,15,31,33,43,44,46,47,121,249,252,12", OsInfo {
        os_name: "Windows 11",
        device_class: "Desktop/Laptop",
        vendor: "Microsoft",
    });

    // Windows 7
    db.insert("1,15,3,6,44,46,47,31,33,121,249,43,252", OsInfo {
        os_name: "Windows 7",
        device_class: "Desktop/Laptop",
        vendor: "Microsoft",
    });

    // Windows 8/8.1
    db.insert("1,3,6,15,31,33,43,44,46,47,121,249,252", OsInfo {
        os_name: "Windows 8/8.1",
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

/// Lookup OS information based on DHCP fingerprint
pub fn lookup_fingerprint(fingerprint: &str) -> Option<OsInfo> {
    // Direct lookup
    if let Some(info) = FINGERPRINT_DB.get(fingerprint) {
        return Some(info.clone());
    }

    // Try partial matching for variations
    // This helps with fingerprints that have slight variations
    let fingerprint_parts: Vec<&str> = fingerprint.split(',').collect();

    for (db_fp, info) in FINGERPRINT_DB.iter() {
        let db_parts: Vec<&str> = db_fp.split(',').collect();

        // Calculate similarity (percentage of matching options)
        if db_parts.len() > 3 && fingerprint_parts.len() > 3 {
            let matches = db_parts.iter()
                .filter(|p| fingerprint_parts.contains(p))
                .count();

            let similarity = (matches as f32 / db_parts.len() as f32) * 100.0;

            // If 80% or more of the options match, consider it a match
            if similarity >= 80.0 {
                return Some((*info).clone());
            }
        }
    }

    None
}

/// Format OS info as a string for storage/display
pub fn format_os_info(info: &OsInfo) -> String {
    format!("{} ({})", info.os_name, info.device_class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let result = lookup_fingerprint("1,3,6,15,31,33,43,44,46,47,121,249,252,12");
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.os_name, "Windows 11");
    }

    #[test]
    fn test_no_match() {
        let result = lookup_fingerprint("99,98,97");
        assert!(result.is_none());
    }

    #[test]
    fn test_partial_match() {
        // Windows 10 fingerprint with one extra option
        let result = lookup_fingerprint("1,3,6,15,31,33,43,44,46,47,121,249,252,99");
        assert!(result.is_some());
    }
}
