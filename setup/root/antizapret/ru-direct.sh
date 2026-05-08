#!/bin/bash
# ru-direct.sh — direct exit на VPN1 для ne-blocked RU-доменов.
#
# Цель: уменьшить RTT клиент→RU-сайт с ~240ms (через VPN3 и обратно)
# до ~60ms (через VPN1 → eth0 direct). Это нужно чтобы VPN-детекторы
# с RTT triangulation (RKNHardering и аналоги) видели «российский»
# RTT для yandex.ru, mail.ru, vk.com, sberbank.ru, gosuslugi.ru.
#
# Запускается: ТОЛЬКО на VPN1 (relay БЕЗ wg-s2s-up).
# Управление: systemd timer ru-direct.timer (каждые 30 мин — refresh + ensure rules).
#
# Использование:
#   up      — поднять (ipset + mangle + ip rule + route + NAT + FORWARD)
#   down    — убрать всё (трафик пойдёт по умолчанию через VPN3)
#   refresh — обновить ipset из списка доменов (резолв через 1.1.1.1)
#   status  — показать текущее состояние
#
# fwmark 0x10 — локальный для VPN1, не пересекается с другими (51820 WG,
# 0x2 bypass, 0x3 RU routing на VPN3, 0x4 VPN2 transit, 0x5 WARP TG).
#
# См. ADR-003.

set -uo pipefail

RU_SET="ru_direct"
FWMARK="0x10"
TABLE="300"
HOSTS_FILE="/root/antizapret/config/ru-direct-hosts.txt"
RESOLVER="1.1.1.1"
LOG_PREFIX="ru-direct:"
log() { echo "$LOG_PREFIX $*"; }

if [[ "$EUID" -ne 0 ]]; then
    echo "$LOG_PREFIX ERROR: must run as root" >&2; exit 1
fi

# Физический интерфейс (Gotcha #16/#26 — НЕ через 'ip route get')
detect_phys() {
    ip route show default | grep -v wg | awk '/default/ {print $5}' | head -1
}

PHYS_IFACE="$(detect_phys)"
PHYS_GW="$(ip route show default | grep -v wg | awk '/default/ {print $3}' | head -1)"

if [[ -z "$PHYS_IFACE" || -z "$PHYS_GW" ]]; then
    log "ERROR: cannot detect physical interface or gateway" >&2; exit 1
fi

# VPN client subnet (10.28/15 = full VPN + antizapret)
VPN_SUBNET="10.28.0.0/15"

ensure_ipset() {
    if ! ipset list "$RU_SET" &>/dev/null; then
        ipset create "$RU_SET" hash:ip family inet maxelem 65536 timeout 0
    fi
}

resolve_hosts() {
    [[ -f "$HOSTS_FILE" ]] || { log "ERROR: $HOSTS_FILE not found"; return 1; }

    local total=0 added=0
    while IFS= read -r host; do
        # Skip comments and empty lines
        host="${host%%#*}"
        host="${host// /}"
        [[ -z "$host" ]] && continue
        total=$((total+1))

        # Resolve A records via public resolver (no dependence on local kresd)
        local ips
        ips=$(dig +short +time=2 +tries=1 @"$RESOLVER" "$host" A 2>/dev/null \
              | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
        if [[ -z "$ips" ]]; then
            log "WARN: failed to resolve $host"
            continue
        fi
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            ipset add "$RU_SET" "$ip" -exist && added=$((added+1))
        done <<< "$ips"
    done < "$HOSTS_FILE"

    log "resolved $total hosts, $added IPs in ipset"
}

apply_up() {
    ensure_ipset
    resolve_hosts

    # mangle PREROUTING: mark VPN-client packets to RU-direct destinations.
    # ВАЖНО: matched ПОСЛЕ декапсуляции OpenVPN (пакет уже на tun+ или 10.28/15 src).
    # Используем -s VPN_SUBNET (надёжнее чем -i tun+, т.к. имя tun-iface может варьироваться).
    iptables -w -t mangle -C PREROUTING -s "$VPN_SUBNET" -m set --match-set "$RU_SET" dst \
        -j MARK --set-mark "$FWMARK" -m comment --comment "ru_direct" 2>/dev/null \
        || iptables -w -t mangle -A PREROUTING -s "$VPN_SUBNET" -m set --match-set "$RU_SET" dst \
            -j MARK --set-mark "$FWMARK" -m comment --comment "ru_direct"

    # policy routing: fwmark 0x10 → table 300 → default via PHYS_GW dev PHYS_IFACE
    ip rule show | grep -q "fwmark $FWMARK lookup $TABLE" \
        || ip rule add fwmark "$FWMARK" lookup "$TABLE" priority 200
    ip route replace default via "$PHYS_GW" dev "$PHYS_IFACE" table "$TABLE"

    # FORWARD: разрешить tun-клиента → eth0 для ru_direct
    iptables -w -C FORWARD -s "$VPN_SUBNET" -o "$PHYS_IFACE" \
        -m set --match-set "$RU_SET" dst -j ACCEPT \
        -m comment --comment "ru_direct_fwd" 2>/dev/null \
        || iptables -w -I FORWARD 1 -s "$VPN_SUBNET" -o "$PHYS_IFACE" \
            -m set --match-set "$RU_SET" dst -j ACCEPT \
            -m comment --comment "ru_direct_fwd"

    # NAT MASQUERADE: -s VPN_SUBNET → eth0 для ru_direct (yandex.ru видит VPN1 IP)
    iptables -w -t nat -C POSTROUTING -s "$VPN_SUBNET" -o "$PHYS_IFACE" \
        -m set --match-set "$RU_SET" dst -j MASQUERADE \
        -m comment --comment "ru_direct_masq" 2>/dev/null \
        || iptables -w -t nat -I POSTROUTING 1 -s "$VPN_SUBNET" -o "$PHYS_IFACE" \
            -m set --match-set "$RU_SET" dst -j MASQUERADE \
            -m comment --comment "ru_direct_masq"

    log "UP: RU-direct via $PHYS_IFACE ($PHYS_GW), fwmark=$FWMARK table=$TABLE"
}

apply_down() {
    iptables -w -t mangle -D PREROUTING -s "$VPN_SUBNET" -m set --match-set "$RU_SET" dst \
        -j MARK --set-mark "$FWMARK" -m comment --comment "ru_direct" 2>/dev/null || true
    iptables -w -D FORWARD -s "$VPN_SUBNET" -o "$PHYS_IFACE" \
        -m set --match-set "$RU_SET" dst -j ACCEPT \
        -m comment --comment "ru_direct_fwd" 2>/dev/null || true
    iptables -w -t nat -D POSTROUTING -s "$VPN_SUBNET" -o "$PHYS_IFACE" \
        -m set --match-set "$RU_SET" dst -j MASQUERADE \
        -m comment --comment "ru_direct_masq" 2>/dev/null || true
    ip rule del fwmark "$FWMARK" lookup "$TABLE" 2>/dev/null || true
    ip route del default dev "$PHYS_IFACE" table "$TABLE" 2>/dev/null || true
    ipset destroy "$RU_SET" 2>/dev/null || true
    log "DOWN: RU traffic falls back to default route (VPN3 via wg-s2s)"
}

apply_refresh() {
    # Ensure rules present (idempotent), then re-resolve IPs
    apply_up
}

apply_status() {
    echo "--- physical iface ---"
    echo "iface=$PHYS_IFACE  gw=$PHYS_GW"
    echo "--- ipset $RU_SET ---"
    ipset list "$RU_SET" 2>&1 | grep -E "Name:|Number of entries|^[0-9]" | head -20
    echo "--- mangle ru_direct ---"
    iptables -t mangle -L PREROUTING -n -v | grep ru_direct || echo "NOT present"
    echo "--- FORWARD ru_direct_fwd ---"
    iptables -L FORWARD -n -v | grep ru_direct_fwd || echo "NOT present"
    echo "--- nat ru_direct_masq ---"
    iptables -t nat -L POSTROUTING -n -v | grep ru_direct_masq || echo "NOT present"
    echo "--- ip rule ---"
    ip rule show | grep "fwmark $FWMARK" || echo "no rule"
    echo "--- table $TABLE ---"
    ip route show table "$TABLE" 2>&1
}

case "${1:-}" in
    up)      apply_up ;;
    down)    apply_down ;;
    refresh) apply_refresh ;;
    status)  apply_status ;;
    *)       echo "Usage: $0 up|down|refresh|status" >&2; exit 1 ;;
esac
