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
- Proxy relay server with WireGuard site-to-site encryption between relay and main server
- Multi-hop relay chain: Client → VPN1 → [VPN2] → VPN3 (all inter-server traffic encrypted)
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
proxy.sh              - Proxy relay server installation script (with WireGuard s2s support)
deploy.sh             - Automated deployment of entire VPN + relay chain
deploy.conf           - Server topology and deployment configuration
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

## Network Topology (зафиксирована, не менять)

```text
Client ──[OpenVPN]──→ VPN1 ──[WireGuard s2s]──→ VPN2 (опц.) ──[WireGuard s2s]──→ VPN3
```

- **VPN1** (72.56.11.181, Timeweb) — relay, deploy-машина
- **VPN2** (157.22.172.160, imody.ru) — relay (опциональный)
- **VPN3** (5.42.199.85, Германия) — main VPN сервер

### WireGuard Site-to-Site

- Порт: 51820 UDP, интерфейс: `wg-s2s`
- IP: 10.99.1.0/30 (VPN1↔next hop), 10.99.2.0/30 (VPN2↔VPN3)
- Ключи генерируются deploy.sh, конфиги раскладываются через SCP
- proxy.sh делает DNAT к tunnel IP (не к публичному) + SNAT от tunnel IP
- VPN3 принимает трафик от wg-s2s (iptables FORWARD с конкретными VPN портами, не blanket ACCEPT)
- VPN2 имеет 2 WireGuard интерфейса: `wg-s2s` (принимает от VPN1) + `wg-s2s-up` (к VPN3), КАЖДЫЙ со своим keypair
- `TUNNEL_DESTINATION_IP` передаётся из deploy.sh в proxy.sh через env (не вычисляется из конфига!)

## Deploy Script Gotchas (не забывать!)

1. **deploy.sh генерирует ВРЕМЕННЫЙ SSH ключ** — при resume (state file) ключ не установлен на серверах. Нужен `install_deploy_key` перед каждой фазой
2. **`while read` в proxy.sh/setup.sh** перезаписывает env при EOF stdin — передавать значения через env export ДО pipe
3. **`-o BatchMode=yes`** блокирует sshpass (пароли) — нужна подмена на `BatchMode=no`
4. **VPN1 = deploy-машина И relay** — proxy.sh делает reboot → deploy.sh умирает. VPN1 устанавливается ПОСЛЕДНИМ
5. **`wg genkey` требует umask 077** — без этого предупреждение "writing to world accessible file"
6. **VPN2 с двумя WG интерфейсами** — нельзя использовать один private key на 2 интерфейса (WireGuard запрещает)
7. **wg-s2s-up на VPN2** — `Table = off` обязательно (иначе AllowedIPs=0.0.0.0/0 перехватит весь трафик)
8. **Timeweb (VPN1) долго ребутается** — REBOOT_TIMEOUT=600 минимум
9. **SNAT в proxy.sh** — при s2s source = upstream tunnel IP (не downstream), иначе VPN3 ответит не туда
10. **deploy.sh cleanup удаляет ВСЕ ключи с `ghost-vpn-deploy`** — `sed -i '/ghost-vpn-deploy/d'` стирает и постоянный ключ! Фиксить на удаление только по PID: `ghost-vpn-deploy-$$`
11. **wg-s2s-up PostUp `ip route add`** падает с `RTNETLINK File exists` — маршрут /30 уже создаётся из Address. Убрать PostUp route
12. **НИКОГДА не удалять пароли из deploy.conf** — пароли нужны как fallback для восстановления SSH доступа. deploy.conf защищён chmod 600, не коммитится в git (.gitignore)
13. **VPN1 (Timeweb) SSH может быть заблокирован scan protection** — iptables DROP на порт 22 при превышении лимита. Доступ через WireGuard tunnel (10.99.1.2) как fallback
14. **OPENVPN_HOST и WIREGUARD_HOST** в setup.sh на VPN3 — определяют `remote` в клиентских конфигах. Должны указывать на **VPN1** (точку входа клиента: RELAY1_DOMAIN), НЕ на VPN3. Если пустые — конфиги генерируются с IP VPN3, и клиенты будут подключаться напрямую, минуя relay
15. **deploy.conf содержит RELAY1_DOMAIN** (www.imody.ru) — deploy.sh должен передавать его в setup.sh как OPENVPN_HOST/WIREGUARD_HOST при установке main сервера

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
