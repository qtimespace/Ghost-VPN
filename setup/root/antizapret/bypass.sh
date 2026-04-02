#!/bin/bash
# Ghost-VPN Bypass Routing — трафик к российским сервисам выходит с VPN1 (Россия)
#
# Архитектура (запускается на VPN3 — main VPN server):
#   VPN client → VPN3 [tun] → bypass.sh routes via wg-s2s → VPN2 → VPN1 → eth0 (Россия)
#
# VPN3 — единственный сервер где виден реальный inner IP (после decapsulation OpenVPN).
# VPN1/VPN2 — relay, видят только зашифрованный OpenVPN outer трафик.
#
# Обновление: каждые 30 мин через systemd timer antizapret-bypass.timer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN_LIST="$SCRIPT_DIR/config/bypass-domains.lst"
BYPASS_SET="bypass_direct"
LOG_PREFIX="bypass.sh:"

# VPN2's wg-s2s-up pubkey и tunnel IP (на VPN3, wg-s2s peer = VPN2)
VPN2_WG_PUBKEY="${VPN2_WG_PUBKEY:-W832EMCzk7NA7pUwzCgZTnzh2gXh6cDvGm3MIq/1Ago=}"
VPN2_TUNNEL_IP="${VPN2_TUNNEL_IP:-10.99.2.2}"

log()  { echo "$LOG_PREFIX $*"; }
err()  { echo "$LOG_PREFIX ERROR: $*" >&2; }
safe() { "$@" 2>/dev/null || true; }

bypass_create_set() {
    # -exist fails if set already exists with different params (e.g. timeout vs no-timeout)
    # Check existence first to avoid parameter mismatch error
    ipset list "$BYPASS_SET" &>/dev/null || ipset create "$BYPASS_SET" hash:net comment
}

bypass_update() {
    if [[ ! -f "$DOMAIN_LIST" ]]; then
        err "domain list not found: $DOMAIN_LIST"; exit 1
    fi

    local tmp_set="${BYPASS_SET}_new"
    safe ipset destroy "$tmp_set"
    ipset create "$tmp_set" hash:net comment

    local count=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Пропустить комментарии и пустые строки
        line="${line%%#*}"
        line="${line// /}"
        [[ -z "$line" ]] && continue

        # Резолвить A-записи
        readarray -t ips < <(
            dig +short +time=3 +tries=2 A "$line" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true
        )
        for ip in "${ips[@]:-}"; do
            [[ -n "$ip" ]] || continue
            safe ipset add "$tmp_set" "$ip" comment "$line"
            (( count++ )) || true
        done
    done < "$DOMAIN_LIST"

    # Атомарный swap — без разрыва трафика
    bypass_create_set
    ipset swap "$tmp_set" "$BYPASS_SET"
    safe ipset destroy "$tmp_set"

    log "ipset $BYPASS_SET: $count IPs from $(grep -cE '^[^[:space:]#]' "$DOMAIN_LIST" || echo 0) domains"
}

bypass_up() {
    log "Starting bypass routing..."

    if ! ip link show wg-s2s &>/dev/null; then
        log "WARNING: wg-s2s interface not found, bypass not applicable"
        exit 0
    fi

    # 1. Создать ipset и наполнить
    bypass_create_set
    bypass_update

    # 2. Обновить WireGuard AllowedIPs для wg-s2s peer VPN2
    #    Базовые IPs: tunnel VPN2 + весь 10.99.1.0/30 (чтобы Hub мог достучаться до VPN1 через VPN2)
    local aips="$VPN2_TUNNEL_IP/32,10.99.1.0/30"
    while IFS= read -r entry; do
        aips="$aips,$entry/32"
    done < <(ipset list "$BYPASS_SET" | grep -E '^[0-9]' | awk '{print $1}')

    if safe wg set wg-s2s peer "$VPN2_WG_PUBKEY" allowed-ips "$aips"; then
        log "WireGuard AllowedIPs updated for wg-s2s → VPN2"
    else
        log "WARNING: wg set failed (check VPN2_WG_PUBKEY)"
    fi

    # 3. Маршруты: bypass IPs через wg-s2s (VPN2 → VPN1 → Russia)
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        safe ip route replace "$ip" dev wg-s2s
    done < <(ipset list "$BYPASS_SET" | grep -E '^[0-9]' | awk '{print $1}')

    # 4. FORWARD: разрешить клиентский трафик → wg-s2s для bypass IP
    iptables -w -C FORWARD \
        -m set --match-set "$BYPASS_SET" dst \
        -o wg-s2s -m comment --comment "bypass_direct" -j ACCEPT 2>/dev/null || \
    iptables -w -I FORWARD 1 \
        -m set --match-set "$BYPASS_SET" dst \
        -o wg-s2s -m comment --comment "bypass_direct" -j ACCEPT

    # 5. POSTROUTING MASQUERADE на wg-s2s:
    #    Source VPN client IP → VPN3's wg-s2s tunnel IP (10.99.2.1)
    #    На VPN1: 10.99.2.1 → 72.56.11.181 (Russian IP), см. bypass-vpn1.sh
    iptables -w -t nat -C POSTROUTING \
        -m set --match-set "$BYPASS_SET" dst \
        -o wg-s2s -m comment --comment "bypass_direct" -j MASQUERADE 2>/dev/null || \
    iptables -w -t nat -I POSTROUTING 1 \
        -m set --match-set "$BYPASS_SET" dst \
        -o wg-s2s -m comment --comment "bypass_direct" -j MASQUERADE

    log "Bypass routing UP — $(ipset list $BYPASS_SET | grep -cE '^[0-9]') IPs via wg-s2s → VPN1 (Russia)"
}

bypass_down() {
    log "Stopping bypass routing..."

    safe iptables -w -D FORWARD \
        -m set --match-set "$BYPASS_SET" dst \
        -o wg-s2s -m comment --comment "bypass_direct" -j ACCEPT

    safe iptables -w -t nat -D POSTROUTING \
        -m set --match-set "$BYPASS_SET" dst \
        -o wg-s2s -m comment --comment "bypass_direct" -j MASQUERADE

    # Удалить маршруты bypass
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        safe ip route del "$ip" dev wg-s2s
    done < <(ipset list "$BYPASS_SET" 2>/dev/null | grep -E '^[0-9]' | awk '{print $1}')

    # Восстановить WireGuard AllowedIPs (только tunnel IP)
    safe wg set wg-s2s peer "$VPN2_WG_PUBKEY" allowed-ips "$VPN2_TUNNEL_IP/32"

    safe ipset flush "$BYPASS_SET"
    log "Bypass routing DOWN"
}

bypass_status() {
    echo "=== ipset bypass_direct ==="
    ipset list "$BYPASS_SET" 2>/dev/null | head -30 || echo "(not found)"
    echo
    echo "=== WG wg-s2s AllowedIPs ==="
    wg show wg-s2s allowed-ips 2>/dev/null || echo "(no wg-s2s)"
    echo
    echo "=== iptables FORWARD (bypass) ==="
    iptables -w -L FORWARD -n | grep bypass || echo "(none)"
    echo
    echo "=== iptables nat POSTROUTING (bypass) ==="
    iptables -w -t nat -L POSTROUTING -n | grep bypass || echo "(none)"
    echo
    echo "=== Routes via wg-s2s ==="
    ip route show dev wg-s2s 2>/dev/null | head -20 || echo "(none)"
}

case "${1:-}" in
    up)     bypass_up ;;
    down)   bypass_down ;;
    update)
        # bypass_up уже вызывает bypass_update внутри + обновляет маршруты/WG AllowedIPs
        bypass_up
        ;;
    status) bypass_status ;;
    *)
        echo "Usage: $0 {up|down|update|status}"
        echo "  up     — resolve domains, install routes + iptables rules"
        echo "  down   — remove rules and routes"
        echo "  update — re-resolve domains, refresh ipset (atomic, no downtime)"
        echo "  status — show current state"
        exit 1
        ;;
esac
