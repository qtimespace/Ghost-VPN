# Ghost-VPN (AntiZapret VPN)

## Project Overview

Infrastructure automation project for deploying a VPN server with split tunneling (AntiZapret).
Supports OpenVPN and WireGuard protocols on Ubuntu 22+ / Debian 12+.

**Core functionality:**

- Split tunneling: only blocked/restricted sites go through VPN, everything else direct
- DNS proxy (Python, dnslib) maps real IPs to fake IPs via iptables NAT for transparent routing
- Knot Resolver (Lua config) with RPZ zones for domain-based routing decisions
- Ad/tracker/phishing blocking via AdGuard and OISD lists
- Anti-censorship OpenVPN patch (C code injected via sed into OpenVPN source)
- Proxy relay server for cases when the VPN server itself is blocked
- Client management (OpenVPN certificates via EasyRSA, WireGuard key pairs)
- Network security: SSH brute-force protection, DDoS/scan protection via ipset, torrent guard, client isolation

## Tech Stack

- **Shell (bash):** setup.sh (~605 lines), proxy.sh, client.sh, up.sh, down.sh, parse.sh, update.sh, patch-openvpn.sh, doall.sh
- **Python 3:** proxy.py (DNS proxy resolver, ~198 lines, uses dnslib)
- **Lua:** kresd.conf (Knot Resolver configuration, ~189 lines)
- **C (inline patch):** Anti-censorship patch injected into OpenVPN source via sed in patch-openvpn.sh
- **System tools:** iptables/ip6tables, ipset, systemd, WireGuard (wg-quick), OpenVPN, EasyRSA, ethtool, sipcalc, socat, idn

## Project Structure

```text
setup.sh              - Main installation script (interactive, runs on target server)
proxy.sh              - Proxy relay server installation script
setup/
  etc/
    knot-resolver/     - DNS resolver config (kresd.conf, RPZ zones, Lua modules)
    openvpn/           - OpenVPN server/client configs and templates
    wireguard/         - WireGuard templates
    sysctl.d/          - Kernel parameters
    systemd/system/    - Service units (antizapret, update timer, overrides)
  root/antizapret/
    proxy.py           - DNS proxy (fake IP mapping)
    client.sh          - Client add/remove/backup management
    up.sh              - Firewall rules setup (iptables, ipset, NAT)
    down.sh            - Firewall rules teardown
    parse.sh           - Process host/IP lists into routing configs
    update.sh          - Download fresh block lists from upstream
    doall.sh           - Orchestrator: update + parse
    patch-openvpn.sh   - Build patched OpenVPN from source
    openvpn-dco.sh     - Toggle OpenVPN Data Channel Offload
    config/            - User-editable include/exclude lists
    download/          - Downloaded block lists and IP ranges
    result/            - Generated routing/RPZ files
  usr/lib/knot-resolver/ - Custom Lua modules (fallback_tls)
docs/
  agents/              - Agent definitions for NEXUS pipeline
```

## Key Weaknesses Found (Code Review)

### Critical

1. **No input sanitization in client.sh `render()` function** (line 62-71): Uses `eval` to expand variables from template files - potential command injection if templates are tampered with
2. **Download integrity not verified cryptographically** in update.sh: Only checks Content-Length, no checksum/signature verification. Lists downloaded over HTTPS but from third-party sources
3. **DNSSEC disabled** in kresd.conf (line 164: `trust_anchors.remove('.')`) - DNS responses can be spoofed

### High

1. **`exec 2>/dev/null`** in down.sh (line 2) silently suppresses ALL stderr - masks real errors during teardown
2. **Race condition in proxy.py** `get_fake_ip()`: Lock released before iptables rule is added (lines 52-53), another thread could see inconsistent state
3. **Hardcoded third-party proxy** in update.sh (line 100): `api.codetabs.com` used as fallback proxy - untrusted third party could intercept/modify downloaded lists
4. **`srand((unsigned)time(NULL))`** in patch-openvpn.sh C patch: time-based seed is predictable, weakens anti-censorship obfuscation
5. **Swap file creation** (setup.sh:589-598) lacks `set -e` restore and appends to fstab without checking for duplicates

### Medium

1. **Unquoted variables** in several places: `$DEFAULT_INTERFACE`, `$WARP_PATH`, `$DESTINATION_IP` used unquoted in commands
2. **`rm -rf` on critical paths** without guards: e.g., `rm -rf /etc/openvpn/server/*` (setup.sh:306)
3. **`apt-get purge` called individually** for each package instead of batched - slow and noisy
4. **No lock file** for update.sh/parse.sh - concurrent runs could corrupt result files
5. **`while read` loop** in parse.sh (line 58-65) for generating iptables routes is slow for large IP lists - could use awk/sed

## Development Guidelines

- All scripts run as root on the target server
- Scripts are POSIX-incompatible (bash-specific: `[[ ]]`, `$( )`, arrays)
- Config is stored in `/root/antizapret/setup` (sourced as shell variables)
- Testing must be done on a real Ubuntu/Debian server (not locally on Windows)
- The project is a fork/evolution of ValdikSS's antizapret-vpn-container

## Agents Structure

Relevant agents are in `docs/agents/`:

- **engineering-backend-architect.md** - Network services architecture, DNS proxy
- **engineering-devops-automator.md** - Core agent: automation, iptables, systemd
- **engineering-security-engineer.md** - Critical: VPN is a security product
- **engineering-code-reviewer.md** - Shell/Python code review
- **engineering-software-architect.md** - System architecture
- **engineering-technical-writer.md** - Documentation
- **testing-evidence-collector.md** - QA validation
- **testing-api-tester.md** - DNS proxy and VPN endpoint testing
- **testing-reality-checker.md** - Final integration check
