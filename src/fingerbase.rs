use std::process::Command;
use anyhow::Result;

pub struct Fingerbase;

impl Fingerbase {
    pub fn lookup(fingerprint: &str) -> Result<Option<String>> {
        if fingerprint.is_empty() {
            return Ok(None);
        }

        // Try to execute fingerbase command
        match Command::new("fingerbase")
            .arg("dhcp")
            .arg(fingerprint)
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if result.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(result))
                    }
                } else {
                    // fingerbase command failed, but don't crash
                    tracing::warn!("fingerbase command failed: {}", String::from_utf8_lossy(&output.stderr));
                    Ok(None)
                }
            }
            Err(e) => {
                // fingerbase not installed or not in PATH
                tracing::warn!("fingerbase command not available: {}", e);
                Ok(None)
            }
        }
    }
}
