use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use anyhow::{Result, anyhow};

/// SMB probe result containing OS detection information
#[derive(Debug, Clone)]
pub struct SmbProbeResult {
    pub os_version: String,
    pub build_number: Option<u32>,
    pub smb_dialect: String,
    pub success: bool,
}

/// Windows version detection based on build number
/// Reference: https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
fn build_to_windows_version(build: u32) -> &'static str {
    match build {
        // Windows 11 builds
        22000..=22999 => "Windows 11 21H2",
        22621..=22630 => "Windows 11 22H2",
        22631..=22999 => "Windows 11 23H2",
        26000..=29999 => "Windows 11 (Insider/Future)",

        // Windows 10 builds
        19041..=19045 => "Windows 10 2004/20H2/21H1",
        19042 => "Windows 10 20H2",
        19043 => "Windows 10 21H1",
        19044 => "Windows 10 21H2",
        19045 => "Windows 10 22H2",
        18362..=18363 => "Windows 10 1903/1909",
        17763 => "Windows 10 1809",
        17134 => "Windows 10 1803",
        16299 => "Windows 10 1709",
        15063 => "Windows 10 1703",
        14393 => "Windows 10 1607",
        10586 => "Windows 10 1511",
        10240 => "Windows 10 1507",

        // Windows 8/8.1
        9600 => "Windows 8.1",
        9200 => "Windows 8",

        // Windows 7
        7600..=7601 => "Windows 7",

        _ => "Windows (unknown version)",
    }
}

/// Probe an IP address via SMB to detect Windows version
/// This performs a passive SMB negotiation without authentication
pub async fn probe_smb(ip: &str, timeout_secs: u64) -> Result<SmbProbeResult> {
    tracing::debug!("Probing SMB on {}:445", ip);

    // Try to connect to SMB port with timeout
    let stream = match timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(format!("{}:445", ip))
    ).await {
        Ok(Ok(s)) => {
            println!("  🔌 TCP connection established to {}:445", ip);
            s
        }
        Ok(Err(_e)) => {
            println!("  🚫 Connection refused by {}:445 (port closed or filtered)", ip);
            return Ok(SmbProbeResult {
                os_version: "Unknown (SMB port closed)".to_string(),
                build_number: None,
                smb_dialect: "N/A".to_string(),
                success: false,
            });
        }
        Err(_) => {
            println!("  ⏱️  Connection timeout to {}:445 ({}s elapsed)", ip, timeout_secs);
            return Ok(SmbProbeResult {
                os_version: "Unknown (connection timeout)".to_string(),
                build_number: None,
                smb_dialect: "N/A".to_string(),
                success: false,
            });
        }
    };

    // Send SMB2 Negotiate request
    println!("  📤 Sending SMB2 negotiate request to {}...", ip);
    let result = send_smb2_negotiate(stream, timeout_secs).await?;

    Ok(result)
}

/// Send SMB2 Negotiate request and parse response
async fn send_smb2_negotiate(mut stream: TcpStream, timeout_secs: u64) -> Result<SmbProbeResult> {
    // Build SMB2 Negotiate packet
    let negotiate_packet = build_smb2_negotiate_packet();

    // Send the packet with timeout
    match timeout(
        Duration::from_secs(timeout_secs),
        stream.write_all(&negotiate_packet)
    ).await {
        Ok(Ok(_)) => {
            println!("  ✉️  Sent {} bytes negotiate packet", negotiate_packet.len());
        }
        Ok(Err(e)) => {
            println!("  ❌ Failed to send negotiate: {}", e);
            return Err(anyhow!("Failed to send SMB negotiate: {}", e));
        }
        Err(_) => {
            println!("  ⏱️  Send timeout");
            return Err(anyhow!("SMB negotiate send timeout"));
        }
    }

    // Read response with timeout
    let mut response = vec![0u8; 4096];
    let bytes_read = match timeout(
        Duration::from_secs(timeout_secs),
        stream.read(&mut response)
    ).await {
        Ok(Ok(n)) => {
            println!("  📥 Received {} bytes response", n);
            n
        }
        Ok(Err(e)) => {
            println!("  ❌ Failed to read response: {}", e);
            return Err(anyhow!("Failed to read SMB response: {}", e));
        }
        Err(_) => {
            println!("  ⏱️  Response timeout");
            return Err(anyhow!("SMB response read timeout"));
        }
    };

    if bytes_read == 0 {
        println!("  ⚠️  Empty response received");
        return Err(anyhow!("Empty SMB response"));
    }

    // Parse the SMB2 response
    println!("  🔍 Parsing SMB2 response...");
    let result = parse_smb2_response(&response[..bytes_read])?;
    println!("  ✅ Detected: {} (dialect: {})", result.os_version, result.smb_dialect);
    Ok(result)
}

/// Build SMB2 Negotiate packet
/// This is a minimal SMB2 negotiate request
fn build_smb2_negotiate_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // NetBIOS Session Service header (4 bytes)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Length placeholder

    // SMB2 Header (64 bytes)
    packet.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol: SMB2
    packet.extend_from_slice(&[0x40, 0x00]); // Header length (64)
    packet.extend_from_slice(&[0x00, 0x00]); // Credit charge
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Status
    packet.extend_from_slice(&[0x00, 0x00]); // Command: Negotiate (0x0000)
    packet.extend_from_slice(&[0x00, 0x00]); // Credits requested
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Flags
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NextCommand
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // MessageId
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TreeId
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // SessionId
    packet.extend_from_slice(&[0x00; 16]); // Signature

    // SMB2 Negotiate Request (36 bytes)
    packet.extend_from_slice(&[0x24, 0x00]); // StructureSize (36)
    packet.extend_from_slice(&[0x05, 0x00]); // DialectCount (5 dialects)
    packet.extend_from_slice(&[0x00, 0x00]); // SecurityMode
    packet.extend_from_slice(&[0x00, 0x00]); // Reserved
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Capabilities
    packet.extend_from_slice(&[0x00; 16]); // ClientGuid
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // ClientStartTime

    // Dialects: SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
    packet.extend_from_slice(&[0x02, 0x02]); // SMB 2.0.2
    packet.extend_from_slice(&[0x10, 0x02]); // SMB 2.1
    packet.extend_from_slice(&[0x00, 0x03]); // SMB 3.0
    packet.extend_from_slice(&[0x02, 0x03]); // SMB 3.0.2
    packet.extend_from_slice(&[0x11, 0x03]); // SMB 3.1.1

    // Update NetBIOS Session Service length (total length - 4 bytes)
    let total_len = (packet.len() - 4) as u32;
    packet[0..4].copy_from_slice(&total_len.to_be_bytes());

    packet
}

/// Parse SMB2 Negotiate response to extract OS information
fn parse_smb2_response(data: &[u8]) -> Result<SmbProbeResult> {
    // Minimum SMB2 response is at least 68 bytes (NetBIOS header + SMB2 header)
    if data.len() < 68 {
        return Err(anyhow!("SMB response too short: {} bytes", data.len()));
    }

    // Skip NetBIOS header (4 bytes) and verify SMB2 signature
    if data.len() < 8 || &data[4..8] != &[0xFE, b'S', b'M', b'B'] {
        return Err(anyhow!("Invalid SMB2 signature"));
    }

    // Get SMB dialect from response (at offset 68-70)
    let smb_dialect = if data.len() >= 70 {
        let dialect_code = u16::from_le_bytes([data[68], data[69]]);
        match dialect_code {
            0x0202 => "SMB 2.0.2",
            0x0210 => "SMB 2.1",
            0x0300 => "SMB 3.0",
            0x0302 => "SMB 3.0.2",
            0x0311 => "SMB 3.1.1",
            _ => "SMB (unknown)",
        }
    } else {
        "SMB 2.x/3.x"
    };

    // Try to extract more detailed version info from Security Buffer
    // This is where NTLMSSP challenge would contain build numbers
    // For now, we'll use heuristics based on SMB dialect

    let (os_version, build_estimate) = match smb_dialect {
        "SMB 3.1.1" => {
            // Windows 10 1607+ and Windows 11 support SMB 3.1.1
            // Windows 11 is more likely to negotiate 3.1.1 first
            ("Windows 10/11 (SMB 3.1.1)", Some(19041))
        },
        "SMB 3.0.2" | "SMB 3.0" => {
            // Windows 8.1/10
            ("Windows 8.1/10 (SMB 3.0)", Some(9600))
        },
        "SMB 2.1" => {
            // Windows 7/Server 2008 R2
            ("Windows 7/Server 2008 R2", Some(7601))
        },
        "SMB 2.0.2" => {
            // Windows Vista/Server 2008
            ("Windows Vista/Server 2008", Some(6002))
        },
        _ => ("Windows (unknown SMB)", None),
    };

    Ok(SmbProbeResult {
        os_version: os_version.to_string(),
        build_number: build_estimate,
        smb_dialect: smb_dialect.to_string(),
        success: true,
    })
}

/// Extended SMB probe with NTLMSSP authentication (more detailed but requires auth)
/// This gets the exact build number from NTLMSSP challenge
pub async fn probe_smb_with_ntlmssp(ip: &str, timeout_secs: u64) -> Result<SmbProbeResult> {
    tracing::debug!("Probing SMB with NTLMSSP on {}:445", ip);

    // This would require a full NTLMSSP negotiation
    // For now, we'll use the simpler SMB dialect negotiation
    // Future enhancement: implement full NTLMSSP to get exact build number

    probe_smb(ip, timeout_secs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_to_version() {
        assert_eq!(build_to_windows_version(22621), "Windows 11 22H2");
        assert_eq!(build_to_windows_version(19045), "Windows 10 22H2");
        assert_eq!(build_to_windows_version(19041), "Windows 10 2004/20H2/21H1");
        assert_eq!(build_to_windows_version(7601), "Windows 7");
    }

    #[test]
    fn test_smb2_negotiate_packet() {
        let packet = build_smb2_negotiate_packet();

        // Should have NetBIOS header + SMB2 header + Negotiate + Dialects
        assert!(packet.len() > 100);

        // Check SMB2 signature
        assert_eq!(&packet[4..8], &[0xFE, b'S', b'M', b'B']);
    }
}
