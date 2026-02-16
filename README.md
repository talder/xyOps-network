# xyOps Network diagnostic Plugin

A comprehensive network diagnostic and analysis plugin for xyOps workflows. Provides 9 tools for network testing, DNS resolution, certificate checking, and more.

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first. By using this plugin, you acknowledge that you have read, understood, and accepted this disclaimer.

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

## Bucket Data (Input from Previous Jobs)

All tools support receiving input data from a previous job's bucket. Set the "Data Source" to "Use job input data" and specify the data path.

### Bucket JSON Examples

**Ping Test** - expects a host/IP:
```json
{
  "params": { "tool": "pingTest", "pingSource": "input", "pingDataPath": "server.ip" },
  "input": { "data": { "server": { "ip": "192.168.1.1" } } }
}
```

**DNS Lookup** - expects a domain:
```json
{
  "params": { "tool": "dnsLookup", "dnsSource": "input", "dnsDataPath": "domain", "dnsRecordType": "MX" },
  "input": { "data": { "domain": "example.com" } } }
}
```

**HTTP Status Checker** - expects a URL:
```json
{
  "params": { "tool": "httpChecker", "httpSource": "input", "httpDataPath": "endpoint.url" },
  "input": { "data": { "endpoint": { "url": "https://api.example.com/health" } } }
}
```

**SSL Certificate Checker** - expects a hostname:
```json
{
  "params": { "tool": "sslChecker", "sslSource": "input", "sslDataPath": "host" },
  "input": { "data": { "host": "github.com" } }
}
```

**Port Scanner** - expects a host:
```json
{
  "params": { "tool": "portScanner", "portSource": "input", "portDataPath": "target", "portPorts": "22,80,443" },
  "input": { "data": { "target": "192.168.1.100" } }
}
```

**JWT Decoder** - expects a token:
```json
{
  "params": { "tool": "jwtDecoder", "jwtSource": "input", "jwtDataPath": "auth.token" },
  "input": { "data": { "auth": { "token": "eyJhbGciOiJIUzI1NiIs..." } } }
}
```

**IP Address Tools** - expects an IP or CIDR:
```json
{
  "params": { "tool": "ipAddressTools", "ipSource": "input", "ipDataPath": "network.ip", "ipMode": "validate" },
  "input": { "data": { "network": { "ip": "10.0.0.1" } } }
}
```

**Traceroute** - expects a host:
```json
{
  "params": { "tool": "traceroute", "traceSource": "input", "traceDataPath": "destination" },
  "input": { "data": { "destination": "google.com" } }
}
```

**WHOIS Lookup** - expects a domain:
```json
{
  "params": { "tool": "whoisLookup", "whoisSource": "input", "whoisDataPath": "site.domain" },
  "input": { "data": { "site": { "domain": "github.com" } } }
}
```

### Data Path Notation

The data path uses dot-notation to navigate nested objects:
- `host` → `data.host`
- `server.ip` → `data.server.ip`
- `config.targets.primary` → `data.config.targets.primary`

## License

MIT License - see [LICENSE](LICENSE) for details.

## Copyright

(2026) Tim Alderweireldt
