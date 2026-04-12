# NetGuard — Network Security Monitor

Desktop security monitor built with **.NET 9 MAUI** for **Windows** and **Linux**.  
Monitors network connections, active processes and checks them against multiple threat
intelligence databases in real time.

---

## Features

| Feature | Detail |
|---|---|
| **Network monitor** | Lists all active TCP/UDP connections with PID, domain and threat status |
| **DNS check** | Resolves every domain via Quad9 DoH — blocked domains = immediate alert |
| **IP reputation** | Checks remote IPs against AbuseIPDB (configurable API key) |
| **Process scanner** | Enumerates all running processes, computes SHA-256 hashes |
| **File signature** | Verifies Authenticode signatures (Windows) |
| **MalwareBazaar** | Free hash lookup — no API key required |
| **VirusTotal** | Optional hash + URL scan (free key = 4 req/min) |
| **Whitelist engine** | Pattern-based rules: `*.google.com`, IP, IP range, process name |
| **Alert history** | Persisted in SQLite with severity and deduplication |
| **Dark / Light mode** | Follows OS theme automatically |

---

## Prerequisites

### Windows
```
Windows 10 1904+ (build 19041)
.NET 9 SDK
Visual Studio 2022 (17.8+) with "MAUI" workload
```

### Linux
```
.NET 9 SDK
GTK 3 (libgtk-3-dev)
notify-send  (for OS notifications — optional)

# Install GTK on Debian/Ubuntu:
sudo apt install libgtk-3-dev

# Install .NET 9:
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 9.0
```

---

## Build & Run

```bash
# Clone
git clone https://github.com/your-org/netguard.git
cd netguard/NetGuard

# Restore packages
dotnet restore

# Run on Windows
dotnet build -f net9.0-windows10.0.19041.0
dotnet run   -f net9.0-windows10.0.19041.0

# Run on Linux
dotnet build -f net9.0
dotnet run   -f net9.0
```

> **Note:** For full process names in network connections on Windows, run as Administrator.  
> On Linux, process resolution from `/proc/pid/fd` requires read access to `/proc`.

---

## API Keys Setup

Open **Settings** in the app and enter your keys.

### VirusTotal (free tier)
1. Register at https://www.virustotal.com/gui/join-us
2. Go to **Profile → API Key**
3. Free tier: **4 requests/minute**, 500 req/day
4. NetGuard auto-throttles requests to respect the limit

### AbuseIPDB (free tier)
1. Register at https://www.abuseipdb.com/register
2. Go to **Account → API**
3. Free tier: **1,000 checks/day**
4. Provides IP abuse confidence score (0–100)

### MalwareBazaar (no key needed)
- Provided by abuse.ch — free, unlimited
- SHA-256 hash lookups only
- https://bazaar.abuse.ch/api/

---

## DNS Configuration

| Server | IP | Notes |
|---|---|---|
| **Quad9** | `9.9.9.9` | Blocks known malicious domains (default primary) |
| **Cloudflare** | `1.1.1.1` | No filtering — used to detect Quad9 blocks |
| **OpenDNS** | `208.67.222.222` | Alternative malware-blocking DNS |
| **Google** | `8.8.8.8` | Pure resolution, no filtering |

When a domain resolves on Cloudflare but **not** on Quad9 → flagged as `High` threat.

---

## Whitelist Rules

Rules are stored in SQLite (`~/.config/NetGuard/netguard.db`).

| Pattern | Type | Example |
|---|---|---|
| `*.google.com` | Domain | All Google subdomains |
| `google.com` | Domain | Exact domain |
| `8.8.8.8` | IP | Single IP |
| `192.168.0.0/24` | IpRange | Subnet (future) |
| `svchost` | ProcessName | Windows system process |

Default rules include: Google, Microsoft, Apple, Ubuntu, Debian, Cloudflare DNS.

---

## Architecture

```
UI (MAUI Pages)
    │
    ▼
ViewModels (CommunityToolkit.MVVM)
    │
    ▼
ThreatAnalysisPipeline
    ├── WhitelistEngine      → SQLite rules
    ├── DnsCheckerService    → Quad9 DoH + Cloudflare DoH
    ├── ThreatIntelService   → VirusTotal + MalwareBazaar + AbuseIPDB
    └── DatabaseService      → SQLite (cache + alerts + settings)
    
NetworkMonitorService
    ├── Windows: IPGlobalProperties + netstat -ano
    └── Linux:   /proc/net/tcp, /proc/net/udp + inode→PID map

ProcessScannerService
    ├── System.Diagnostics.Process.GetProcesses()
    ├── SHA-256 hash via System.Security.Cryptography
    └── Windows: Authenticode / X509Certificate
```

---

## Data Storage

All data is stored locally at:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\NetGuard\netguard.db` |
| Linux | `~/.config/NetGuard/netguard.db` |

Tables: `whitelist_rules`, `alerts`, `settings`, `threat_cache` (24h TTL).

---

## Permissions

| Feature | Windows | Linux |
|---|---|---|
| List connections | No elevation | No root |
| Process names in connections | Administrator | Read `/proc` |
| WMI real-time events | Administrator | N/A |
| Block process (firewall) | Administrator | `iptables` / `nft` |
| eBPF monitoring | N/A | `CAP_BPF` or root |

The app runs fully in user mode — elevated features degrade gracefully.

---

## Roadmap

- [ ] eBPF integration for real-time Linux syscall monitoring
- [ ] Windows ETW network events (kernel-level)
- [ ] Export alerts to CSV / SIEM syslog
- [ ] IP geolocation overlay (MaxMind GeoLite2)
- [ ] Custom YARA rules for process scanning
- [ ] Automatic firewall block on High severity (opt-in)

---

## License

MIT — see LICENSE file.
