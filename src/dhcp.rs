use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub options: Vec<DhcpOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpOption {
    pub code: u8,
    pub data: Vec<u8>,
}

impl DhcpPacket {
    pub fn parse(data: &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() < 236 {
            anyhow::bail!("DHCP packet too short");
        }

        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);

        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&data[28..44]);

        // Skip server name (64 bytes) and boot file (128 bytes)
        // Options start at byte 236
        let options = Self::parse_options(&data[236..])?;

        Ok(DhcpPacket {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            options,
        })
    }

    fn parse_options(data: &[u8]) -> Result<Vec<DhcpOption>, anyhow::Error> {
        let mut options = Vec::new();

        // Check for magic cookie
        if data.len() < 4 || &data[0..4] != &[99, 130, 83, 99] {
            anyhow::bail!("Invalid DHCP magic cookie");
        }
        let mut i = 4;

        while i < data.len() {
            let code = data[i];
            i += 1;

            // End option
            if code == 255 {
                break;
            }

            // Pad option
            if code == 0 {
                continue;
            }

            if i >= data.len() {
                break;
            }

            let len = data[i] as usize;
            i += 1;

            if i + len > data.len() {
                break;
            }

            let option_data = data[i..i + len].to_vec();
            options.push(DhcpOption {
                code,
                data: option_data,
            });

            i += len;
        }

        Ok(options)
    }

    pub fn get_mac_address(&self) -> String {
        let hlen = self.hlen as usize;
        if hlen > 16 {
            return String::new();
        }

        self.chaddr[..hlen]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn get_option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|opt| opt.code == code)
    }

    pub fn get_message_type(&self) -> Option<u8> {
        self.get_option(53).and_then(|opt| opt.data.first().copied())
    }

    pub fn get_fingerprint(&self) -> String {
        // Option 55: Parameter Request List
        if let Some(opt) = self.get_option(55) {
            opt.data
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(",")
        } else {
            String::new()
        }
    }

    pub fn get_vendor_class(&self) -> Option<String> {
        // Option 60: Vendor Class Identifier
        self.get_option(60).map(|opt| {
            String::from_utf8_lossy(&opt.data).to_string()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRequest {
    pub timestamp: String,
    pub source_ip: String,
    pub source_port: u16,
    pub mac_address: String,
    pub message_type: String,
    pub xid: String,
    pub fingerprint: String,
    pub vendor_class: Option<String>,
    pub os_name: Option<String>,
    pub device_class: Option<String>,
    pub raw_options: Vec<DhcpOption>,
    pub detection_method: Option<String>,
    pub confidence: Option<f32>,
    pub smb_dialect: Option<String>,
    pub smb_build: Option<u32>,
}

impl DhcpRequest {
    pub fn from_packet(packet: &DhcpPacket, source_ip: String, source_port: u16) -> Self {
        let message_type = match packet.get_message_type() {
            Some(1) => "DISCOVER",
            Some(3) => "REQUEST",
            Some(4) => "DECLINE",
            Some(5) => "ACK",
            Some(6) => "NAK",
            Some(7) => "RELEASE",
            Some(8) => "INFORM",
            _ => "UNKNOWN",
        }.to_string();

        let fingerprint = packet.get_fingerprint();
        let mac_address = packet.get_mac_address();

        // Lookup OS information from MAC mapping and fingerprint
        let (os_name, device_class) = if !fingerprint.is_empty() {
            if let Some(os_info) = crate::fingerprint::lookup_os(&mac_address, &fingerprint) {
                (Some(os_info.os_name.to_string()), Some(os_info.device_class.to_string()))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        DhcpRequest {
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_ip,
            source_port,
            mac_address,
            message_type,
            xid: format!("{:08x}", packet.xid),
            fingerprint,
            vendor_class: packet.get_vendor_class(),
            os_name,
            device_class,
            raw_options: packet.options.clone(),
            detection_method: None,
            confidence: None,
            smb_dialect: None,
            smb_build: None,
        }
    }
}
