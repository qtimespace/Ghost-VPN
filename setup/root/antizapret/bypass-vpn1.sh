#!/bin/bash
# bypass-vpn1.sh — VPN1-side MASQUERADE для bypass routing
#
# Запускается на VPN1 (relay, 72.56.11.181) при первичной настройке
# или вызывается из proxy.sh после запуска iptables.
#
# proxy.sh НЕ добавляет MASQUERADE для обычного интернет-трафика,
# только DNAT/SNAT для VPN-протокола. Этот скрипт добавляет
# MASQUERADE для bypass-трафика прилетающего с VPN3 через wg-s2s.

set -euo pipefail

LOG_PREFIX="bypass-vpn1.sh:"
log() { echo "$LOG_PREFIX $*"; }

if [[ "$EUID" -ne 0 ]]; then
    echo "$LOG_PREFIX ERROR: must run as root" >&2; exit 1
fi

if ! ip link show wg-s2s &>/dev/null; then
    log "WARNING: wg-s2s interface not found"
    exit 0
fi

# Физический интерфейс — НЕ через 'ip route get' (может вернуть wg-s2s)
# Gotcha #16/#26 из CLAUDE.md
PHYS_IFACE="$(ip route show default | grep -v wg | awk '/default/ {print $5}' | head -1)"
if [[ -z "$PHYS_IFACE" ]]; then
    log "ERROR: cannot detect physical interface" >&2; exit 1
fi

log "Physical interface: $PHYS_IFACE"

# FORWARD: разрешить трафик с wg-s2s на физический интерфейс
iptables -w -C FORWARD \
    -i wg-s2s -o "$PHYS_IFACE" -j ACCEPT 2>/dev/null || \
iptables -w -I FORWARD 1 \
    -i wg-s2s -o "$PHYS_IFACE" -j ACCEPT

# POSTROUTING: MASQUERADE трафик выходящий через eth0 с tunnel IP (10.99.x.x)
# Source будет VPN3's wg-s2s tunnel IP (10.99.2.1, MASQUERADE'd на VPN3)
# POSTROUTING не поддерживает -i (input interface), используем -s match
iptables -w -t nat -C POSTROUTING \
    -s 10.99.0.0/16 -o "$PHYS_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -w -t nat -I POSTROUTING 1 \
    -s 10.99.0.0/16 -o "$PHYS_IFACE" -j MASQUERADE

log "VPN1 bypass MASQUERADE active: wg-s2s → $PHYS_IFACE"
log "Bypass traffic will appear to originate from VPN1's Russian IP"
