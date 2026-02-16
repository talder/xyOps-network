<p align="center"><img src="https://raw.githubusercontent.com/talder/xyOps-network/refs/heads/main/logo.png" height="108" alt="Logo"/></p>
<h1 align="center">xyOps Network</h1>

# xyOps Network Plugin

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](https://github.com/talder/xyOps-network/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

A comprehensive xyOps Event Plugin containing 23 network diagnostic and analysis tools for network testing, DNS resolution, certificate checking, email security validation, SMTP testing, and more.

**Multi-Input Support:** All diagnostic tools support testing multiple hosts/URLs/domains in a single run via textarea fields or array input from previous jobs.

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Tools Overview](#tools-overview)
- [Diagnostic Tools](#diagnostic-tools)
- [Analysis Tools](#analysis-tools)
- [Email & Security Tools](#email--security-tools)
- [Testing & Monitoring Tools](#testing--monitoring-tools)
- [Infrastructure Tools](#infrastructure-tools)
- [Input Data (From Previous Job or Bucket)](#input-data-from-previous-job-or-bucket)
- [Output Data Reference](#output-data-reference)
- [Dependencies](#dependencies)
- [License](#license)
- [Version History](#version-history)

---

## Quick Start

1. Install the plugin in xyOps (copy to plugins directory or install from Marketplace)
2. Add the Network event to any job
3. Select a tool from the dropdown menu
4. Configure parameters specific to the selected tool
5. Run the job

---

## Installation

### From xyOps Marketplace

1. Navigate to xyOps Marketplace
2. Search for "Network"
3. Click Install

### Manual Installation

```bash
cd /opt/xyops/plugins
git clone https://github.com/talder/xyOps-network.git
```

---

## Tools Overview

| Category | Tool | Description |
|----------|------|-------------|
| **Diagnostic** | Ping Test | Ping host(s) with configurable count and timeout, includes latency statistics |
| | Traceroute | Trace network path to host(s), showing each hop with latency |
| | Port Scanner | Check if ports are open on host(s) (supports ranges, max 100 ports) |
| | DNS Lookup | Resolve DNS records (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR) |
| | NTP Server Check | Check NTP server(s) for time sync, stratum, offset, and reachability |
| | Network Scanner | Scan network(s) for active hosts with hostname resolution and MAC addresses |
| | Wake-on-LAN | Send magic packets to wake up devices on the network |
| **Analysis** | IP Address Tools | Validate, convert (decimal/binary), analyze IPs with subnet calculator |
| | Subnet Calculator | Advanced VLSM planning and supernetting calculations |
| | IP Geolocation | Look up geographic location, ISP, and organization for IPs |
| | HTTP Status Checker | Check HTTP status, response time, and headers for URL(s) |
| | WHOIS Lookup | Look up domain registration information for domain(s) |
| **Email & Security** | Email Auth Checker | Check and score SPF, DKIM, and DMARC records (A-F grade) |
| | Blacklist Checker | Check if IPs/domains are on spam/security blacklists |
| | SMTP Checker | Test SMTP server connectivity, STARTTLS, and send test emails |
| | SSL Certificate Checker | Check SSL/TLS certificate details, expiry, chain, and SANs |
| | JWT Decoder | Decode and inspect JWT tokens (header, payload, expiration) |
| **Testing & Monitoring** | Bandwidth Test | Test network speed using Cloudflare or custom URLs |
| | TCP/UDP Listener | Open a port and listen for incoming connections/data |
| | WebSocket Tester | Test WebSocket connections, send/receive messages |
| | API Health Monitor | Monitor API endpoints with status code and JSON validation |
| **Infrastructure** | SNMP Query | Query SNMP-enabled devices (v1/v2c/v3) with custom OIDs |
| | LDAP/AD Test | Test LDAP/Active Directory connectivity and search |

---

## Diagnostic Tools

### Ping Test

Ping one or more hosts with configurable count and timeout, includes round-trip latency statistics.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of host(s)/IP(s) to ping |
| Host(s) | Textarea | - | Target host(s) or IP address(es). Separate multiple with commas or newlines (max 20) |
| Count | Number | 4 | Number of ping packets (1-10) |
| Timeout | Number | 1000 | Timeout per packet in milliseconds (100-30000) |

**Example Output (multiple hosts):**

```json
{
  "tool": "Ping Test",
  "hostsChecked": 2,
  "successful": 2,
  "failed": 0,
  "results": [
    {
      "host": "google.com",
      "resolvedIP": "142.250.185.78",
      "count": 4,
      "successful": 4,
      "failed": 0,
      "lossPercent": 0,
      "minLatency": 12,
      "maxLatency": 18,
      "avgLatency": 14.5
    }
  ]
}
```

**Bucket Input Example:**
```json
{
  "hosts": ["google.com", "cloudflare.com", "github.com"]
}
```
Input Data Path: `hosts`

---

### Traceroute

Trace the network path to one or more hosts, showing each hop with latency.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of target host(s) |
| Host(s) | Textarea | - | Target hostname(s) or IP(s). Separate multiple with commas or newlines (max 20) |
| Max Hops | Number | 30 | Maximum number of hops (1-64) |
| Timeout | Number | 3000 | Timeout per hop in milliseconds |

**Example Output:**

```json
{
  "tool": "Traceroute",
  "destination": "github.com",
  "hops": [
    { "hop": 1, "ip": "192.168.1.1", "hostname": "router.local", "latency": 1.2 },
    { "hop": 2, "ip": "10.0.0.1", "hostname": "isp-gateway", "latency": 8.5 }
  ],
  "completed": true,
  "totalHops": 12
}
```

**Bucket Input Example:**
```json
{
  "hosts": ["github.com", "8.8.8.8"]
}
```
Input Data Path: `hosts`

---

### Port Scanner

Check if specific ports are open on one or more hosts (supports port ranges, maximum 100 ports).

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of target host(s) |
| Host(s) | Textarea | - | Target hostname(s) or IP(s). Separate multiple with commas or newlines (max 20) |
| Ports | Text | 80,443 | Comma-separated ports or ranges (e.g., "22,80,443" or "8080-8090"). Max 100 ports |
| Timeout | Number | 1000 | Connection timeout in milliseconds |

**Example Output:**

```json
{
  "tool": "Port Scanner",
  "host": "example.com",
  "scanned": 3,
  "openPorts": [80, 443],
  "closedPorts": [22],
  "results": [
    { "port": 22, "status": "closed" },
    { "port": 80, "status": "open" },
    { "port": 443, "status": "open" }
  ]
}
```

---

### DNS Lookup

Resolve DNS records for one or more domains with support for multiple record types.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of domain name(s) |
| Domain(s) / IP(s) | Textarea | - | Domain(s) or IP(s) to look up. Separate multiple with commas or newlines (max 20) |
| Record Type | Select | A | A, AAAA, MX, TXT, CNAME, NS, SOA, PTR |
| DNS Server | Text | - | Optional custom DNS server (e.g., 8.8.8.8, 1.1.1.1) |

**Record Types:**

| Type | Description |
|------|-------------|
| A | IPv4 address records |
| AAAA | IPv6 address records |
| MX | Mail exchange servers |
| TXT | Text records (SPF, DKIM, etc.) |
| CNAME | Canonical name aliases |
| NS | Name server records |
| SOA | Start of authority |
| PTR | Reverse DNS lookup |

**Example Output:**

```json
{
  "tool": "DNS Lookup",
  "domain": "example.com",
  "recordType": "MX",
  "dnsServer": "8.8.8.8",
  "records": [
    { "preference": 10, "exchange": "mail1.example.com" },
    { "preference": 20, "exchange": "mail2.example.com" }
  ]
}
```

**Bucket Input Example:**
```json
{
  "domains": ["example.com", "github.com", "google.com"]
}
```
Input Data Path: `domains`

---

### NTP Server Check

Check NTP server(s) for time synchronization, stratum, offset, and reachability.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of NTP server(s) |
| NTP Server(s) | Textarea | pool.ntp.org | NTP server hostname(s) or IP(s). Separate multiple with commas or newlines (max 10) |
| Timeout | Number | 3000 | Timeout per server in milliseconds (500-10000) |

**Example Output:**

```json
{
  "tool": "NTP Server Check",
  "results": [
    {
      "server": "pool.ntp.org",
      "reachable": "OK",
      "responseMs": 45,
      "offsetMs": 12.5,
      "stratum": 2,
      "refId": "GPS",
      "serverTime": "2026-02-15T14:30:22Z",
      "ntpVersion": 4
    },
    {
      "server": "time.google.com",
      "reachable": "OK",
      "responseMs": 32,
      "offsetMs": 8.2,
      "stratum": 1,
      "refId": "GOOG",
      "serverTime": "2026-02-15T14:30:22Z",
      "ntpVersion": 4
    }
  ],
  "summary": {
    "total": 2,
    "reachable": 2,
    "unreachable": 0
  }
}
```

---

### Network Scanner

Scan network(s) for active hosts using ICMP ping with TCP port fallback. Resolves hostnames and retrieves MAC addresses (local subnet only).

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of network(s) |
| Network(s) CIDR | Textarea | - | Network(s) in CIDR notation (e.g., 192.168.1.0/24). Max /22 (1024 hosts). Separate multiple with commas or newlines |
| Timeout | Number | 500 | Timeout per host in milliseconds (100-5000). Lower = faster but may miss slow hosts |

**Features:**
- Parallel scanning (25 concurrent hosts) for fast network discovery
- ICMP ping as primary detection method
- TCP port fallback (22, 80, 443, 3389, 445) for hosts blocking ICMP
- Automatic hostname resolution via reverse DNS
- MAC address lookup from ARP cache (local subnet only)
- Maximum network size: /22 (1024 hosts)

**Example Output:**

```json
{
  "tool": "Network Scanner",
  "networksScanned": 1,
  "totalHostsScanned": 254,
  "totalActiveHosts": 12,
  "activeIPs": ["192.168.1.1", "192.168.1.10", "192.168.1.50"],
  "hosts": [
    {
      "IP": "192.168.1.1",
      "Hostname": "router.local",
      "Method": "ICMP",
      "ResponseTime": 1,
      "MAC": "AA:BB:CC:DD:EE:FF"
    },
    {
      "IP": "192.168.1.10",
      "Hostname": "server.local",
      "Method": "TCP/22",
      "ResponseTime": null,
      "MAC": "11:22:33:44:55:66"
    }
  ]
}
```

**Bucket Input Example:**
```json
{
  "networks": ["192.168.1.0/24", "10.0.0.0/24"]
}
```
Input Data Path: `networks`

**Using Output in Next Job:**

The scanner outputs `activeIPs` array which can be used directly by other tools:
- Input Data Path: `activeIPs` - to ping, port scan, or check SSL on all discovered hosts

---

### Wake-on-LAN

Send Wake-on-LAN (WoL) magic packets to wake up devices on the network.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of MAC address(es) |
| MAC Address(es) | Textarea | - | MAC address(es) in AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF format. Separate multiple with commas or newlines (max 20) |
| Broadcast Address | Text | 255.255.255.255 | Broadcast IP for the magic packet. Use subnet broadcast for specific networks |
| Port | Number | 9 | UDP port (usually 7 or 9) |

**Example Output:**

```json
{
  "tool": "Wake-on-LAN",
  "packetsSent": 3,
  "results": [
    { "mac": "AA:BB:CC:DD:EE:FF", "broadcast": "192.168.1.255", "sent": true },
    { "mac": "11:22:33:44:55:66", "broadcast": "192.168.1.255", "sent": true }
  ]
}
```

---

## Analysis Tools

### IP Address Tools

Validate, convert, and analyze IP addresses with subnet calculator.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of IP address |
| IP / CIDR | Text | - | IP address or CIDR notation |
| Mode | Select | validate | Operation mode |

**Modes:**

| Mode | Description |
|------|-------------|
| Validate & Analyze | Validate IP and show details (type, class, private/public) |
| IP to Decimal | Convert IP address to decimal number |
| Decimal to IP | Convert decimal number to IP address |
| IP to Binary | Convert IP address to binary representation |
| Subnet Calculator | Calculate network details from CIDR notation |

**Example Output (Validate):**

```json
{
  "tool": "IP Address Tools",
  "mode": "validate",
  "ip": "192.168.1.100",
  "valid": true,
  "version": "IPv4",
  "class": "C",
  "type": "private",
  "isLoopback": false,
  "isPrivate": true
}
```

**Example Output (Subnet Calculator):**

```json
{
  "tool": "IP Address Tools",
  "mode": "subnet",
  "cidr": "192.168.1.0/24",
  "networkAddress": "192.168.1.0",
  "broadcastAddress": "192.168.1.255",
  "subnetMask": "255.255.255.0",
  "firstHost": "192.168.1.1",
  "lastHost": "192.168.1.254",
  "totalHosts": 254
}
```

---

### Subnet Calculator (Advanced)

Advanced subnet calculator with VLSM planning and supernetting capabilities.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Mode | Select | calculate | Calculate details, VLSM Planning, or Supernet/Aggregate |
| Network CIDR | Text | - | Network in CIDR notation (e.g., 192.168.1.0/24) |
| VLSM Host Requirements | Textarea | - | For VLSM: comma-separated host counts (e.g., 50,30,20,10) |
| Networks to Aggregate | Textarea | - | For supernet: networks to aggregate, one per line |

**Modes:**

| Mode | Description |
|------|-------------|
| Calculate | Full subnet details with all IP ranges |
| VLSM Planning | Variable Length Subnet Masking - create optimally-sized subnets |
| Supernet/Aggregate | Combine multiple networks into a summary route |

**Example Output (VLSM):**

```json
{
  "tool": "Subnet Calculator",
  "mode": "vlsm",
  "baseNetwork": "192.168.1.0/24",
  "subnets": [
    { "name": "Subnet 1", "cidr": "192.168.1.0/26", "hosts": 62, "requested": 50 },
    { "name": "Subnet 2", "cidr": "192.168.1.64/26", "hosts": 62, "requested": 30 },
    { "name": "Subnet 3", "cidr": "192.168.1.128/27", "hosts": 30, "requested": 20 }
  ],
  "totalAllocated": 154,
  "remaining": 100
}
```

---

### IP Geolocation

Look up geographic location, ISP, and organization for IP addresses using the free ip-api.com service.

> **Note:** This tool requires outbound HTTP access to `http://ip-api.com`. A firewall rule may be required to allow this traffic from the xysat server.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of IP address(es) |
| IP Address(es) | Textarea | - | IP address(es) or domains. Separate multiple with commas or newlines (max 20) |

**Example Output:**

```json
{
  "tool": "IP Geolocation",
  "results": [
    {
      "query": "8.8.8.8",
      "country": "United States",
      "countryCode": "US",
      "region": "Virginia",
      "city": "Ashburn",
      "zip": "20149",
      "lat": 39.03,
      "lon": -77.5,
      "timezone": "America/New_York",
      "isp": "Google LLC",
      "org": "Google Public DNS",
      "as": "AS15169 Google LLC"
    }
  ]
}
```

---

### HTTP Status Checker

Check HTTP status code, response time, and headers for one or more URLs.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of URL(s) |
| URL(s) | Textarea | - | URL(s) to check (https:// added if not specified). Separate multiple with commas or newlines (max 20) |
| HTTP Method | Select | GET | GET, HEAD, or POST |
| Follow Redirects | Checkbox | Yes | Follow HTTP redirects |
| Timeout | Number | 10 | Request timeout in seconds (1-60) |

**Example Output:**

```json
{
  "tool": "HTTP Status Checker",
  "url": "https://api.example.com/health",
  "statusCode": 200,
  "statusText": "OK",
  "responseTimeMs": 156,
  "redirected": false,
  "finalUrl": "https://api.example.com/health",
  "headers": {
    "content-type": "application/json",
    "server": "nginx"
  }
}
```

---

### WHOIS Lookup

Look up domain registration information via WHOIS for one or more domains.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of domain(s) |
| Domain(s) | Textarea | - | Domain name(s) to look up. Separate multiple with commas or newlines (max 20) |

**Supported TLDs:** 16+ TLDs with automatic WHOIS server selection including .com, .net, .org, .io, .dev, .co, .info, .biz, and country codes.

**Example Output:**

```json
{
  "tool": "WHOIS Lookup",
  "domain": "github.com",
  "registrar": "MarkMonitor Inc.",
  "creationDate": "2007-10-09",
  "expirationDate": "2026-10-09",
  "nameServers": ["ns1.github.com", "ns2.github.com"],
  "status": ["clientTransferProhibited", "clientDeleteProhibited"]
}
```

---

## Email & Security Tools

### Email Auth Checker (SPF/DKIM/DMARC)

Check and score SPF, DKIM, and DMARC records for email security compliance.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of domain(s) |
| Domain(s) | Textarea | - | Domain(s) to check. Separate multiple with commas or newlines (max 10) |
| DKIM Selector(s) | Text | default,google,selector1,selector2,k1,s1 | DKIM selectors to check (comma-separated) |
| DNS Server | Select | internal | Use internal DNS or external DNS for lookups |
| External DNS Server | Text | 1.1.1.1 | External DNS server IP (when DNS Server is set to external) |

> **Note:** For split-DNS environments, use "external" DNS mode to query public DNS records. When using external DNS, a firewall rule may be required to allow outbound DNS traffic (UDP/TCP port 53) from the xysat server to the specified DNS server.

**Scoring System:**

| Grade | Score | Description |
|-------|-------|-------------|
| A | 90-100 | Excellent - All records properly configured |
| B | 75-89 | Good - Minor improvements possible |
| C | 60-74 | Fair - Some records missing or weak |
| D | 40-59 | Poor - Significant issues |
| F | 0-39 | Failing - Critical records missing |

**Example Output:**

```json
{
  "tool": "Email Auth Checker",
  "results": [
    {
      "domain": "example.com",
      "score": 85,
      "grade": "B",
      "spf": {
        "found": true,
        "record": "v=spf1 include:_spf.google.com ~all",
        "valid": true,
        "issues": ["Consider using -all instead of ~all"]
      },
      "dkim": {
        "found": true,
        "selector": "google",
        "valid": true
      },
      "dmarc": {
        "found": true,
        "policy": "quarantine",
        "pct": 100,
        "issues": ["Consider upgrading to p=reject"]
      }
    }
  ]
}
```

**Bucket Input Example:**
```json
{
  "domains": ["example.com", "company.com", "partner.org"]
}
```
Input Data Path: `domains`

---

### Blacklist Checker

Check if IP addresses or domains are listed on spam/security blacklists.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of IP/domain(s) |
| IP Address(es) / Domain(s) | Textarea | - | IP(s) or domain(s) to check. Separate multiple with commas or newlines (max 10) |

**Blacklists Checked:**
- **IP-based:** Spamhaus ZEN, Barracuda, SORBS, SpamCop, UCEProtect, PSBL, Invaluement
- **Domain-based:** Spamhaus DBL, SURBL, URIBL

**Example Output:**

```json
{
  "tool": "Blacklist Checker",
  "results": [
    {
      "target": "1.2.3.4",
      "type": "ip",
      "listed": 0,
      "clean": 7,
      "status": "clean",
      "blacklists": [
        { "name": "Spamhaus ZEN", "listed": false },
        { "name": "Barracuda", "listed": false }
      ]
    }
  ]
}
```

---

### SMTP Checker

Test SMTP server connectivity, STARTTLS support, authentication methods, and send test emails.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of SMTP server(s) |
| SMTP Server(s) | Textarea | - | Server hostname(s) or IP(s). Separate multiple with commas or newlines (max 10) |
| Port | Number | 25 | SMTP port (25, 465, 587) |
| Open Relay Test Address | Text | - | Email for open relay test (leave empty to skip) |
| Send Test Email | Checkbox | No | Enable to send a test email |
| Test Email From | Text | - | Sender address for test email |
| Test Email To | Text | - | Recipient address for test email |
| SMTP Username | Text | - | Username for authentication (optional) |
| SMTP Password | Password | - | Password for authentication (optional) |

**Example Output:**

```json
{
  "tool": "SMTP Checker",
  "results": [
    {
      "server": "smtp.example.com",
      "port": 587,
      "connected": true,
      "banner": "220 smtp.example.com ESMTP",
      "starttls": true,
      "authMethods": ["PLAIN", "LOGIN", "XOAUTH2"],
      "openRelay": false,
      "testEmailSent": true
    }
  ]
}
```

---

### SSL Certificate Checker

Check SSL/TLS certificate details, expiration, chain, and Subject Alternative Names for one or more hosts.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of hostname(s) |
| Host(s) | Textarea | - | Hostname(s) or URL(s). Separate multiple with commas or newlines (max 20). Port 443 default, or specify host:port |

**Example Output:**

```json
{
  "tool": "SSL Certificate Checker",
  "host": "github.com",
  "port": 443,
  "subject": "CN=github.com",
  "issuer": "CN=DigiCert SHA2 High Assurance Server CA",
  "validFrom": "2024-03-15T00:00:00Z",
  "validTo": "2025-03-16T23:59:59Z",
  "daysUntilExpiry": 180,
  "isExpired": false,
  "sans": ["github.com", "www.github.com"],
  "chain": [
    { "subject": "CN=github.com", "issuer": "DigiCert SHA2 High Assurance Server CA" },
    { "subject": "CN=DigiCert SHA2 High Assurance Server CA", "issuer": "DigiCert High Assurance EV Root CA" }
  ]
}
```

---

### JWT Decoder

Decode and inspect JWT (JSON Web Token) tokens.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of JWT token |
| JWT Token | Text | - | JWT token to decode |

**Example Output:**

```json
{
  "tool": "JWT Decoder",
  "valid": true,
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022,
    "exp": 1516242622
  },
  "issuedAt": "2018-01-18T01:30:22Z",
  "expiresAt": "2018-01-18T02:30:22Z",
  "isExpired": true
}
```

---

## Testing & Monitoring Tools

### Bandwidth/Speed Test

Test network bandwidth using Cloudflare Speed Test or a custom URL.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Mode | Select | cloudflare | Cloudflare Speed Test or Custom URL |
| Custom URL | Text | - | URL for download test (when mode is 'custom'). Use a large file for accuracy |
| Test Size | Select | medium | Small (1 MB), Medium (10 MB), or Large (25 MB) |

**Example Output:**

```json
{
  "tool": "Bandwidth Test",
  "mode": "cloudflare",
  "downloadSpeed": 156.42,
  "uploadSpeed": 45.23,
  "latency": 12,
  "downloadBytes": 10000000,
  "downloadTime": 0.51
}
```

---

### TCP/UDP Listener

Open a TCP or UDP port and listen for incoming connections and data.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Protocol | Select | TCP | TCP or UDP |
| Port | Number | 8080 | Port to listen on (1-65535) |
| Listen Duration | Number | 60 | How long to listen in seconds (5-300) |
| Max Connections | Number | 10 | Stop after this many connections |

**Example Output:**

```json
{
  "tool": "Port Listener",
  "protocol": "TCP",
  "port": 8080,
  "duration": 60,
  "connectionsReceived": 2,
  "connections": [
    {
      "timestamp": "14:32:15",
      "sourceIP": "192.168.1.50",
      "sourcePort": 52341,
      "data": "GET / HTTP/1.1\r\nHost: ..."
    }
  ]
}
```

---

### WebSocket Tester

Test WebSocket connections, send messages, and receive responses.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| WebSocket URL | Text | - | WebSocket URL (ws:// or wss://) |
| Message to Send | Textarea | - | Message to send after connecting (optional) |
| Timeout | Number | 10 | Connection timeout in seconds |

**Example Output:**

```json
{
  "tool": "WebSocket Tester",
  "url": "wss://echo.websocket.org",
  "connected": true,
  "messagesSent": 1,
  "messagesReceived": 1,
  "messages": [
    { "direction": "Sent", "data": "Hello World", "timestamp": "14:32:15.123" },
    { "direction": "Received", "data": "Hello World", "timestamp": "14:32:15.456" }
  ]
}
```

---

### API Health Monitor

Monitor API endpoints with status code checking and optional JSON response validation.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of endpoint(s) |
| API Endpoint(s) | Textarea | - | API URL(s) to monitor. Separate multiple with commas or newlines (max 20) |
| Expected Status Code(s) | Text | 200 | Expected HTTP status code(s), comma-separated |
| Timeout | Number | 10 | Request timeout in seconds |
| JSON Validation | Textarea | - | Validation rules: 'field=value' or 'field' (exists). Separate with semicolons |

**JSON Validation Examples:**
- `status=ok` - Check that field "status" equals "ok"
- `data` - Check that field "data" exists
- `status=ok;data;version=2` - Multiple checks

**Example Output:**

```json
{
  "tool": "API Health Monitor",
  "endpointsChecked": 3,
  "healthy": 2,
  "unhealthy": 1,
  "results": [
    {
      "endpoint": "https://api.example.com/health",
      "healthy": true,
      "statusCode": 200,
      "responseTime": 45
    },
    {
      "endpoint": "https://api.example.com/v2/status",
      "healthy": false,
      "statusCode": 503,
      "error": "Service Unavailable"
    }
  ]
}
```

**Bucket Input Example:**
```json
{
  "endpoints": [
    "https://api.example.com/health",
    "https://api.company.com/v1/status",
    "https://internal.service.local/ping"
  ]
}
```
Input Data Path: `endpoints`

---

## Infrastructure Tools

### SNMP Query

Query SNMP-enabled devices using SNMPv1, v2c, or v3 with support for standard and custom OIDs.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of host(s) |
| Host(s) | Textarea | - | SNMP host(s) to query. Separate multiple with commas or newlines (max 10) |
| SNMP Version | Select | v2c | v1, v2c, or v3 |
| Community String | Text | public | Community string for v1/v2c |
| Port | Number | 161 | SNMP port |
| Timeout | Number | 5000 | Query timeout in milliseconds |
| Custom OIDs | Textarea | - | Additional OIDs: 'name=1.3.6.1...' or just the OID |
| SNMPv3 Username | Text | - | Username for v3 authentication |
| SNMPv3 Auth Protocol | Select | SHA | SHA or MD5 |
| SNMPv3 Auth Password | Password | - | Authentication password for v3 |
| SNMPv3 Privacy Protocol | Select | AES | AES or DES |
| SNMPv3 Privacy Password | Password | - | Encryption password for v3 |

**Standard OIDs Queried:**
- sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation

**Example Output:**

```json
{
  "tool": "SNMP Query",
  "version": "v2c",
  "results": [
    {
      "host": "192.168.1.1",
      "success": true,
      "values": {
        "sysDescr": "Cisco IOS Software, C2960 Software",
        "sysName": "switch01",
        "sysUpTime": "45 days, 12:34:56",
        "sysLocation": "Server Room A"
      }
    }
  ]
}
```

**Bucket Input Example:**
```json
{
  "hosts": ["192.168.1.1", "192.168.1.2", "switch.local"]
}
```
Input Data Path: `hosts`

---

### LDAP/AD Test

Test LDAP/Active Directory connectivity, authentication, and search queries.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Source of LDAP server(s) |
| LDAP Server(s) | Textarea | - | Server hostname(s) or IP(s). Separate multiple with commas or newlines (max 10) |
| Port | Number | 389 | LDAP port (389 for LDAP, 636 for LDAPS) |
| Use SSL/TLS | Checkbox | No | Enable for LDAPS (auto-changes port to 636) |
| Bind DN (Username) | Text | - | Bind DN for authentication. Leave empty for anonymous bind |
| Bind Password | Password | - | Password for authentication |
| Base DN | Text | - | Base DN for search (e.g., DC=example,DC=com). Leave empty to skip search |
| Search Filter | Text | (objectClass=*) | LDAP search filter |
| Search Scope | Select | base | Base, One Level, or Subtree |

**Example Output:**

```json
{
  "tool": "LDAP Test",
  "results": [
    {
      "server": "dc01.example.com",
      "port": 389,
      "ssl": false,
      "connected": true,
      "bound": true,
      "bindType": "Authenticated",
      "searchSuccess": true,
      "searchResults": 5
    }
  ]
}
```

**Bucket Input Example:**
```json
{
  "servers": ["dc01.example.com", "dc02.example.com"]
}
```
Input Data Path: `servers`

---

## Input Data

All tools support receiving input data from a previous job's output or from a user-created bucket.

### How to Use Input Data

**IMPORTANT:** You must configure BOTH settings:

1. **Data Source** → Set to "Use job input data"
2. **Input Data Path** → Set to the field name that contains your data (e.g., `hosts`, `domains`, `urls`)

> ⚠️ **The Input Data Path is required!** Without it, the tool won't find your data.

### Multi-Input Support

All diagnostic tools support multiple inputs:

1. **Textarea field**: Enter multiple values separated by commas or newlines
2. **Array from input data**: Pass an array from a previous job or bucket
3. **Single value**: Traditional single-value input still works

### Input Data Examples

If your bucket or previous job contains:
```json
{
  "hosts": ["google.com", "cloudflare.com", "github.com"]
}
```

**Configuration:**
- Data Source: `Use job input data`
- Input Data Path: `hosts` ← **This tells the tool where to find the array!**

**Result:** The tool will check google.com, cloudflare.com, and github.com.

### Common Input Data Paths

**Diagnostic Tools:**

| Tool | Input Data Path | Example bucket data |
|------|-----------------|--------------------|
| Ping Test | `hosts` | `{"hosts": ["server1.com", "server2.com"]}` |
| Traceroute | `hosts` | `{"hosts": ["8.8.8.8", "1.1.1.1"]}` |
| Port Scanner | `hosts` | `{"hosts": ["server1.com", "server2.com"]}` |
| DNS Lookup | `domains` | `{"domains": ["example.com", "github.com"]}` |
| NTP Check | `servers` | `{"servers": ["pool.ntp.org", "time.google.com"]}` |
| Network Scanner | `networks` | `{"networks": ["192.168.1.0/24", "10.0.0.0/24"]}` |
| Wake-on-LAN | `macs` | `{"macs": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]}` |

**Analysis Tools:**

| Tool | Input Data Path | Example bucket data |
|------|-----------------|--------------------|
| IP Geolocation | `ips` | `{"ips": ["8.8.8.8", "1.1.1.1"]}` |
| HTTP Checker | `urls` | `{"urls": ["https://api.example.com", "https://google.com"]}` |
| WHOIS Lookup | `domains` | `{"domains": ["example.com", "github.com"]}` |
| SSL Checker | `hosts` | `{"hosts": ["github.com:443", "google.com"]}` |

**Email & Security Tools:**

| Tool | Input Data Path | Example bucket data |
|------|-----------------|--------------------|
| Email Auth Checker | `domains` | `{"domains": ["example.com", "company.com"]}` |
| Blacklist Checker | `targets` | `{"targets": ["1.2.3.4", "example.com"]}` |
| SMTP Checker | `servers` | `{"servers": ["smtp.example.com", "mail.company.com"]}` |

**Testing & Monitoring Tools:**

| Tool | Input Data Path | Example bucket data |
|------|-----------------|--------------------|
| API Health Monitor | `endpoints` | `{"endpoints": ["https://api.example.com/health", "https://api.company.com/status"]}` |

**Infrastructure Tools:**

| Tool | Input Data Path | Example bucket data |
|------|-----------------|--------------------|
| SNMP Query | `hosts` | `{"hosts": ["192.168.1.1", "switch.local"]}` |
| LDAP/AD Test | `servers` | `{"servers": ["dc01.example.com", "dc02.example.com"]}` |

### Nested Data

For nested structures, use dot-notation:

```json
{
  "network": {
    "servers": ["server1.com", "server2.com"]
  }
}
```

Input Data Path: `network.servers`

---

## Output Data Reference

**Diagnostic Tools:**

| Tool | Key Output Fields |
|------|-------------------|
| Ping Test | `data.hostsChecked`, `data.successful`, `data.failed`, `data.results[]` |
| Traceroute | `data.results[]`, `data.completed`, `data.totalHops` |
| Port Scanner | `data.hostsScanned`, `data.results[]`, `data.results[].openPorts` |
| DNS Lookup | `data.results[]`, `data.results[].records[]` |
| NTP Server Check | `data.results[]`, `data.results[].stratum`, `data.results[].offsetMs` |
| Network Scanner | `data.activeIPs[]`, `data.hosts[]`, `data.totalActiveHosts` |
| Wake-on-LAN | `data.deviceCount`, `data.sent`, `data.results[]` |

**Analysis Tools:**

| Tool | Key Output Fields |
|------|-------------------|
| IP Address Tools | `data.valid`, `data.type`, `data.class`, `data.isPrivate` |
| Subnet Calculator | `data.mode`, `data.subnets[]`, `data.network`, `data.broadcast` |
| IP Geolocation | `data.ipsChecked`, `data.results[]`, `data.results[].country`, `data.results[].city` |
| HTTP Status Checker | `data.urlsChecked`, `data.results[]`, `data.results[].statusCode` |
| WHOIS Lookup | `data.domainsChecked`, `data.results[]`, `data.results[].registrar` |

**Email & Security Tools:**

| Tool | Key Output Fields |
|------|-------------------|
| Email Auth Checker | `data.domainsChecked`, `data.results[]`, `data.results[].grade`, `data.results[].score` |
| Blacklist Checker | `data.targetsChecked`, `data.results[]`, `data.results[].listedCount` |
| SMTP Checker | `data.results[]`, `data.results[].starttls`, `data.results[].authMethods` |
| SSL Certificate Checker | `data.hostsChecked`, `data.results[]`, `data.results[].daysUntilExpiry` |
| JWT Decoder | `data.algorithm`, `data.header`, `data.payload`, `data.isExpired` |

**Testing & Monitoring Tools:**

| Tool | Key Output Fields |
|------|-------------------|
| Bandwidth Test | `data.downloadSpeed`, `data.uploadSpeed`, `data.latency` |
| TCP/UDP Listener | `data.protocol`, `data.port`, `data.connectionsReceived`, `data.connections[]` |
| WebSocket Tester | `data.connected`, `data.messagesSent`, `data.messagesReceived`, `data.messages[]` |
| API Health Monitor | `data.endpointsChecked`, `data.healthy`, `data.unhealthy`, `data.results[]` |

**Infrastructure Tools:**

| Tool | Key Output Fields |
|------|-------------------|
| SNMP Query | `data.hostsQueried`, `data.results[]`, `data.results[].values` |
| LDAP/AD Test | `data.serversTested`, `data.results[]`, `data.results[].bound`, `data.results[].searchResults` |

---

## Dependencies

- PowerShell 7.0 or higher
- Network access for remote operations

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Version History

### v1.3.0 (2026-02-16)
- Added 12 new network tools:
  - **Wake-on-LAN**: Send magic packets to wake devices on the network
  - **Subnet Calculator**: Advanced VLSM planning and supernetting
  - **IP Geolocation**: Look up geographic location using ip-api.com
  - **Email Auth Checker**: SPF/DKIM/DMARC validation with A-F scoring
  - **Blacklist Checker**: Check IPs/domains on spam blacklists
  - **SMTP Checker**: Test SMTP servers, STARTTLS, send test emails
  - **Bandwidth Test**: Speed test via Cloudflare or custom URL
  - **TCP/UDP Listener**: Listen for incoming connections and data
  - **WebSocket Tester**: Test WebSocket connections and messaging
  - **API Health Monitor**: Monitor endpoints with JSON validation
  - **SNMP Query**: Query devices via SNMPv1/v2c/v3
  - **LDAP/AD Test**: Test LDAP/Active Directory connectivity and search
- Total tools now: 23

### v1.2.0 (2026-02-16)
- Added Network Scanner tool with parallel scanning (25 concurrent), ICMP + TCP port fallback, hostname resolution, MAC address lookup
- Maximum network size /22 (1024 hosts)

### v1.1.0 (2026-02-16)
- Added NTP Server Check tool
- Added multi-input support for all diagnostic tools (Ping, DNS, Traceroute, Port Scanner, HTTP, SSL, WHOIS)
- Tools now accept multiple hosts/URLs/domains via textarea or array input from bucket data
- Maximum 20 items per tool (10 for NTP)

### v1.0.0 (2026-02-15)
- Initial release
- Split from xyOps Toolbox plugin
- 9 network diagnostic and analysis tools

---

## Copyright

(c) 2026 Tim Alderweireldt
