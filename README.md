# DHCP Listener with DHCP Field Extraction

A Rust-based DHCP server that listens to DHCP requests without responding to them. It extracts and logs key DHCP fields (ciaddr, Option 12, Option 55, Option 60, Option 81) to the console and logs all requests to `request.json`.

## Features

- Listens for DHCP requests on port 67 (standard DHCP server port)
- Parses DHCP packets and extracts:
  - ciaddr (Client IP Address)
  - Option 12 (Hostname)
  - Option 55 (Parameter Request List)
  - Option 60 (Vendor Class Identifier)
  - Option 81 (Client FQDN)
- Logs extracted fields to console in JSON format
- Logs all requests to `request.json` in JSON format
- Non-intrusive: Does not respond to DHCP requests
- Async/concurrent handling using Tokio

## Requirements

- Rust 1.70 or later
- Root/sudo privileges to bind to port 67

## Installation

Build the project in release mode:

```bash
cargo build --release
```

The binary will be available at `./target/release/ks-dhcpmon`

## Usage

Run the server with sudo (required to bind to port 67):

```bash
sudo ./target/release/ks-dhcpmon
```

The server will:
1. Bind to UDP port 67 on all interfaces (0.0.0.0:67)
2. Listen for incoming DHCP requests
3. Parse each request and extract:
   - MAC address
   - DHCP message type (DISCOVER, REQUEST, etc.)
   - ciaddr (Client IP Address)
   - Option 12 (Hostname)
   - Option 55 (Parameter Request List)
   - Option 60 (Vendor Class Identifier)
   - Option 81 (Client FQDN)
   - Other DHCP options
4. Print extracted fields to console in pretty JSON format
5. Log complete request data to `request.json`

## Output Format

### Console Output

When a DHCP request is received with any of the tracked fields, it prints to console in pretty JSON:

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "source_ip": "192.168.1.100",
  "timestamp": "2025-10-24T12:34:56.789Z",
  "ciaddr": "192.168.1.50",
  "option_12": [109, 121, 45, 104, 111, 115, 116],
  "option_12_hostname": "my-host",
  "option_55": [1, 3, 6, 15, 119, 252],
  "option_55_csv": "1,3,6,15,119,252",
  "option_60": [77, 83, 70, 84, 32, 53, 46, 48],
  "option_60_string": "MSFT 5.0",
  "option_81": [0, 0, 0, 109, 121, 45, 104, 111, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109],
  "option_81_flags": 0,
  "option_81_fqdn": "my-host.example.com"
}
```

**Note:** Only fields that are present will be included in the output:
- `ciaddr` is only shown if not 0.0.0.0
- Options are only shown if present in the DHCP packet
- Option 81 (Client FQDN) contains flags and the fully qualified domain name of the client

### File Log Format

Each line in `request.json` contains a complete JSON object:

```json
{
  "timestamp": "2025-10-24T12:34:56.789Z",
  "source_ip": "192.168.1.100",
  "source_port": 68,
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "message_type": "DISCOVER",
  "xid": "12345678",
  "fingerprint": "1,3,6,15,119,252",
  "vendor_class": "MSFT 5.0",
  "raw_options": [...]
}
```

## Architecture

- `src/main.rs`: Main application logic, UDP socket handling, and console logging of extracted fields
- `src/dhcp.rs`: DHCP packet parsing and structures
- `src/logger.rs`: JSON file logging functionality

## DHCP Field Reference

- **ciaddr**: Client IP Address - The current IP address of the client (if renewing/rebinding)
- **Option 12**: Hostname - The hostname of the client device
- **Option 55**: Parameter Request List - List of DHCP options the client is requesting
- **Option 60**: Vendor Class Identifier - Identifies the vendor and device type (e.g., "MSFT 5.0" for Windows)
- **Option 81**: Client FQDN - Contains flags and the fully qualified domain name of the client (used for dynamic DNS updates)

## Notes

- The server does not respond to DHCP requests, making it safe to run alongside existing DHCP servers
- All requests are logged asynchronously to minimize performance impact
- The server uses structured logging with the `tracing` crate for better observability
- MAC address and source IP are always included in console output when any tracked field is present

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Jeff Buddington (https://www.linkedin.com/in/jeff-buddington-5178ba4)

**Attribution Requirement:** Any use, redistribution, or incorporation of this Software must include clear attribution to Jeff Buddington.
