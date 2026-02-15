# xyOps Network Plugin

A comprehensive network diagnostic and analysis plugin for xyOps workflows. Provides 9 tools for network testing, DNS resolution, certificate checking, and more.

## Tools

| Tool | Description |
|------|-------------|
| **IP Address Tools** | Validate, convert (decimal/binary), and analyze IP addresses with subnet calculator |
| **JWT Decoder** | Decode and inspect JWT tokens (header, payload, expiration status) |
| **Ping Test** | Ping a host with configurable count and timeout, includes latency statistics |
| **DNS Lookup** | Resolve DNS records (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR) with optional custom DNS server |
| **Traceroute** | Trace network path to a host, showing each hop with latency |
| **Port Scanner** | Check if specific ports are open on a host (supports ranges, max 100 ports) |
| **HTTP Status Checker** | Check HTTP status, response time, and headers for a URL |
| **SSL Certificate Checker** | Check SSL/TLS certificate details, expiry, chain, and SANs |
| **WHOIS Lookup** | Look up domain registration information via WHOIS |

## Requirements

- PowerShell 7.0 or higher
- Network access for remote operations

## Installation

```bash
# Via NPX (recommended for xyOps)
npx -y github:talder/xyOps-network

# Or clone the repository
git clone https://github.com/talder/xyOps-network.git
```

## Usage

### Local Testing

```bash
# Ping Test
echo '{"params":{"tool":"pingTest","pingHost":"google.com","pingCount":4}}' | pwsh -NoProfile -File network.ps1

# DNS Lookup
echo '{"params":{"tool":"dnsLookup","dnsQuery":"google.com","dnsRecordType":"MX"}}' | pwsh -NoProfile -File network.ps1

# Port Scanner
echo '{"params":{"tool":"portScanner","portHost":"google.com","portPorts":"80,443"}}' | pwsh -NoProfile -File network.ps1

# SSL Certificate Checker
echo '{"params":{"tool":"sslChecker","sslHost":"github.com"}}' | pwsh -NoProfile -File network.ps1

# WHOIS Lookup
echo '{"params":{"tool":"whoisLookup","whoisDomain":"github.com"}}' | pwsh -NoProfile -File network.ps1

# HTTP Status Checker
echo '{"params":{"tool":"httpChecker","httpUrl":"https://github.com"}}' | pwsh -NoProfile -File network.ps1

# IP Address Tools - Validate
echo '{"params":{"tool":"ipAddressTools","ipMode":"validate","ipInput":"192.168.1.1"}}' | pwsh -NoProfile -File network.ps1

# IP Address Tools - Subnet Calculator
echo '{"params":{"tool":"ipAddressTools","ipMode":"subnet","ipInput":"192.168.1.0/24"}}' | pwsh -NoProfile -File network.ps1

# JWT Decoder
echo '{"params":{"tool":"jwtDecoder","jwtInput":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}}' | pwsh -NoProfile -File network.ps1

# Traceroute
echo '{"params":{"tool":"traceroute","traceHost":"google.com","traceMaxHops":15}}' | pwsh -NoProfile -File network.ps1
```

## Tool Details

### IP Address Tools
- **Modes**: Validate & Analyze, IP to Decimal, Decimal to IP, IP to Binary, Subnet Calculator
- **Supports**: IPv4 and IPv6 validation, private/loopback detection, IP class identification
- **Subnet Calculator**: CIDR notation input, calculates subnet mask, network address, and usable hosts

### DNS Lookup
- **Record Types**: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR (reverse DNS)
- **Custom DNS**: Optionally specify a DNS server (e.g., 8.8.8.8, 1.1.1.1)

### SSL Certificate Checker
- **Details**: Subject, issuer, validity dates, days until expiry
- **Chain**: Shows full certificate chain
- **SANs**: Lists Subject Alternative Names

### WHOIS Lookup
- **Supports**: 16+ TLDs with automatic WHOIS server selection
- **Fields**: Registrar, creation/expiration dates, name servers, status

## I/O Contract

The plugin follows the standard xyOps event plugin protocol:

**Input** (JSON on STDIN):
```json
{
  "params": { "tool": "toolName", ...toolParams },
  "input": { "data": {...} },
  "cwd": "/working/directory"
}
```

**Output** (JSON lines on STDOUT):
- Progress: `{ "xy": 1, "progress": 0.5, "status": "..." }`
- Table: `{ "xy": 1, "table": { "title": "...", "header": [...], "rows": [...] } }`
- Success: `{ "xy": 1, "code": 0, "data": {...}, "description": "..." }`
- Error: `{ "xy": 1, "code": 1, "description": "..." }`

## License

MIT License - see [LICENSE](LICENSE) for details.
