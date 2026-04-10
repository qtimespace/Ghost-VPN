#!/bin/bash
# Ghost-VPN AntiZapret Classic Routing
#
# Классический подход антизапрет: только заблокированные сайты из antizapret-списка
# идут через VPN3 (Германия), весь остальной трафик — через wg-s2s → VPN1 (Россия).
#
# Архитектура (запускается на VPN3 — main VPN server):
#   VPN client → VPN3 [tun]
#     ├── antizapret IPs (route-ips.txt) → eth0 VPN3 → Internet (Германия)
#     └── всё остальное → wg-s2s → VPN2 → VPN1 → eth0 (Россия)
#
# Заменяет bypass.sh (который делал наоборот: всё через Германию,
# кроме bypass-списка через Россию).
#
# Обновление: каждые 30 мин через systemd timer antizapret-bypass.timer
# (тот же timer, просто вызывает этот скрипт вместо bypass.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AZ_SET="antizapret_route"
LOG_PREFIX="antizapret-routing.sh:"

# VPN2's wg-s2s-up pubkey и tunnel IP
# VPN2 pubkey: from env, or detect from wg-s2s peer (VPN3 has single peer = VPN2)
VPN2_WG_PUBKEY="${VPN2_WG_PUBKEY:-$(wg show wg-s2s peers 2>/dev/null | head -1)}"
VPN2_TUNNEL_IP="${VPN2_TUNNEL_IP:-10.99.2.2}"

# VPN subnet (из setup)
source "$SCRIPT_DIR/setup" 2>/dev/null || true
[[ "$ALTERNATIVE_IP" == 'y' ]] && IP="${IP:-172}" || IP="${IP:-10}"

log()  { echo "$LOG_PREFIX $*"; }
err()  { echo "$LOG_PREFIX ERROR: $*" >&2; }
safe() { "$@" 2>/dev/null || true; }

# Физический интерфейс (Gotcha #16/#26)
get_phys_iface() {
    ip route show default | grep -v wg | awk '/default/ {print $5}' | head -1
}

get_phys_ip() {
    local iface="$1"
    ip -4 addr show "$iface" | grep -oP 'inet \K[0-9.]+' | head -1
}

# ── Создание ipset из antizapret route-ips.txt ──

az_create_set() {
    ipset list "$AZ_SET" &>/dev/null || ipset create "$AZ_SET" hash:net maxelem 131072
}

az_update_set() {
    local route_ips="$SCRIPT_DIR/result/route-ips.txt"
    if [[ ! -f "$route_ips" ]]; then
        err "route-ips.txt not found: $route_ips"
        err "Run parse.sh first!"
        exit 1
    fi

    local count
    count="$(wc -l < "$route_ips")"
    log "Loading $count CIDRs from route-ips.txt"

    local tmp_set="${AZ_SET}_new"
    safe ipset destroy "$tmp_set"
    ipset create "$tmp_set" hash:net maxelem 131072

    # Bulk load через ipset restore (быстрее чем по одному)
    {
        while IFS= read -r cidr; do
            [[ -n "$cidr" ]] || continue
            echo "add $tmp_set $cidr"
        done < "$route_ips"
    } | ipset restore -!

    # Добавить fake IP range — mangle видит пакеты ДО DNAT,
    # т.е. dst = fake IP (10.30.x.x), не real IP.
    # Без этого все antizapret-пакеты получат mark 0x3 (Россия) вместо 0x0 (Германия).
    [[ "$ALTERNATIVE_FAKE_IP" == 'y' ]] && FAKE_IP="${FAKE_IP:-198.18}" || FAKE_IP="$IP.30"
    echo "add $tmp_set ${FAKE_IP}.0.0/15" | ipset restore -!
    log "Added fake IP range ${FAKE_IP}.0.0/15"

    # Атомарный swap
    az_create_set
    ipset swap "$tmp_set" "$AZ_SET"
    safe ipset destroy "$tmp_set"

    log "ipset $AZ_SET: $((count + 1)) entries loaded (${count} CIDRs + fake IP range)"
}

# ── UP: включить классический antizapret routing ──

az_up() {
    log "Starting antizapret classic routing..."

    if ! ip link show wg-s2s &>/dev/null; then
        log "WARNING: wg-s2s interface not found, antizapret routing not applicable"
        exit 0
    fi

    local phys_iface
    phys_iface="$(get_phys_iface)"
    if [[ -z "$phys_iface" ]]; then
        err "Cannot detect physical interface"; exit 1
    fi
    local phys_ip
    phys_ip="$(get_phys_ip "$phys_iface")"
    log "Physical: $phys_iface ($phys_ip)"

    # 1. Снять старый bypass.sh (если был)
    safe "$SCRIPT_DIR/bypass.sh" down

    # 2. Создать ipset с antizapret IPs
    az_create_set
    az_update_set

    # 3. WireGuard AllowedIPs: 0.0.0.0/0 чтобы разрешить отправку произвольного dst.
    #    БЕЗОПАСНО: `wg set` через userspace НЕ создаёт маршруты в routing table.
    #    Маршрутизация управляется только через ip rule fwmark 0x3 → table 100.
    #    Серверный трафик (SSH и т.д.) не имеет fwmark → идёт через main table → eth0.
    if safe wg set wg-s2s peer "$VPN2_WG_PUBKEY" allowed-ips "0.0.0.0/0"; then
        log "WireGuard AllowedIPs → 0.0.0.0/0 (cryptokey routing only, no route table changes)"
    else
        err "wg set failed (check VPN2_WG_PUBKEY)"
    fi

    # 4. Policy routing через ip rule + ip route table
    #    Таблица 100: default route → wg-s2s (Россия)
    #    Main таблица: antizapret IPs → eth0 (Германия)

    # Очистить таблицу 100
    safe ip route flush table 100

    # Default route через wg-s2s в таблице 100
    ip route add default dev wg-s2s table 100

    # Правило: VPN-клиенты помеченные fwmark 0x3 → таблица 100
    if ! ip rule list | grep -q "fwmark 0x3 lookup 100"; then
        ip rule add fwmark 0x3 lookup 100 priority 200
    fi

    # 5. iptables mangle: пометить трафик клиентов который НЕ идёт в antizapret
    #    Все клиентские пакеты → mark 0x3 (route via wg-s2s)
    #    Antizapret IPs → снять mark (route via eth0, main table)

    # Очистить старые правила (цикл на случай накопленных дублей)
    for _ in 1 2 3; do
        safe iptables -w -t mangle -D PREROUTING \
            -s $IP.29.0.0/16 -m comment --comment "az_default_russia" -j MARK --set-mark 0x3
        safe iptables -w -t mangle -D PREROUTING \
            -s $IP.29.0.0/16 -m set --match-set "$AZ_SET" dst \
            -m comment --comment "az_blocked_germany" -j MARK --set-mark 0x0
    done

    # Добавить в начало цепочки (-I) чтобы гарантировать порядок:
    # Порядок критичен: az_blocked_germany должен идти ПОСЛЕ az_default_russia.
    # Вставляем в обратном порядке через -I 1 — az_blocked_germany окажется первым,
    # поэтому используем -A (append) чтобы сохранить правильный порядок:
    # 1) az_default_russia (mark 0x3 всем клиентам)
    # 2) az_blocked_germany (override mark 0x0 для antizapret IPs)
    # Only mark antizapret clients (10.29.x.x), NOT full VPN clients (10.28.x.x)
    # Full VPN clients use redirect-gateway → all traffic via eth0 (Germany) by default
    iptables -w -t mangle -A PREROUTING \
        -s $IP.29.0.0/16 -m comment --comment "az_default_russia" -j MARK --set-mark 0x3
    iptables -w -t mangle -A PREROUTING \
        -s $IP.29.0.0/16 -m set --match-set "$AZ_SET" dst \
        -m comment --comment "az_blocked_germany" -j MARK --set-mark 0x0

    # 6. FORWARD: разрешить клиентский трафик → wg-s2s
    iptables -w -C FORWARD \
        -s $IP.28.0.0/15 -o wg-s2s \
        -m comment --comment "az_forward_russia" -j ACCEPT 2>/dev/null || \
    iptables -w -I FORWARD 1 \
        -s $IP.28.0.0/15 -o wg-s2s \
        -m comment --comment "az_forward_russia" -j ACCEPT

    # 7. POSTROUTING: MASQUERADE клиентского трафика уходящего в wg-s2s
    #    Source: 10.28.x.x/10.29.x.x → VPN3's tunnel IP (10.99.2.1)
    iptables -w -t nat -C POSTROUTING \
        -s $IP.28.0.0/15 -o wg-s2s \
        -m comment --comment "az_masq_russia" -j MASQUERADE 2>/dev/null || \
    iptables -w -t nat -I POSTROUTING 1 \
        -s $IP.28.0.0/15 -o wg-s2s \
        -m comment --comment "az_masq_russia" -j MASQUERADE

    # 8. FORWARD: разрешить return traffic wg-s2s → tun (client isolation safety)
    iptables -w -C FORWARD \
        -i wg-s2s -d $IP.28.0.0/15 \
        -m comment --comment "az_return_russia" -j ACCEPT 2>/dev/null || \
    iptables -w -I FORWARD 1 \
        -i wg-s2s -d $IP.28.0.0/15 \
        -m comment --comment "az_return_russia" -j ACCEPT

    local az_count
    az_count="$(ipset list "$AZ_SET" 2>/dev/null | grep -cE '^[0-9]' || echo 0)"
    log "AntiZapret classic routing UP"
    log "  Blocked sites ($az_count CIDRs) → eth0 ($phys_iface, Germany)"
    log "  Everything else → wg-s2s → VPN2 → VPN1 (Russia)"
}

# ── DOWN: снять routing ──

az_down() {
    log "Stopping antizapret classic routing..."

    [[ "$ALTERNATIVE_IP" == 'y' ]] && IP="${IP:-172}" || IP="${IP:-10}"

    # mangle rules — only antizapret clients (10.29.x.x), not full VPN (10.28.x.x)
    # Also clean up legacy /15 rules from older versions
    safe iptables -w -t mangle -D PREROUTING \
        -s $IP.29.0.0/16 -m comment --comment "az_default_russia" -j MARK --set-mark 0x3
    safe iptables -w -t mangle -D PREROUTING \
        -s $IP.29.0.0/16 -m set --match-set "$AZ_SET" dst \
        -m comment --comment "az_blocked_germany" -j MARK --set-mark 0x0
    safe iptables -w -t mangle -D PREROUTING \
        -s $IP.28.0.0/15 -m comment --comment "az_default_russia" -j MARK --set-mark 0x3
    safe iptables -w -t mangle -D PREROUTING \
        -s $IP.28.0.0/15 -m set --match-set "$AZ_SET" dst \
        -m comment --comment "az_blocked_germany" -j MARK --set-mark 0x0

    # FORWARD
    safe iptables -w -D FORWARD \
        -s $IP.28.0.0/15 -o wg-s2s \
        -m comment --comment "az_forward_russia" -j ACCEPT

    # FORWARD return
    safe iptables -w -D FORWARD \
        -i wg-s2s -d $IP.28.0.0/15 \
        -m comment --comment "az_return_russia" -j ACCEPT

    # POSTROUTING
    safe iptables -w -t nat -D POSTROUTING \
        -s $IP.28.0.0/15 -o wg-s2s \
        -m comment --comment "az_masq_russia" -j MASQUERADE

    # ip rule
    safe ip rule del fwmark 0x3 lookup 100

    # Route table
    safe ip route flush table 100

    # Восстановить WireGuard AllowedIPs (tunnel IPs only)
    safe wg set wg-s2s peer "$VPN2_WG_PUBKEY" allowed-ips "$VPN2_TUNNEL_IP/32,10.99.1.0/30"

    # ipset оставляем (не мешает)
    log "AntiZapret classic routing DOWN"
}

# ── STATUS ──

az_status() {
    echo "=== AntiZapret Classic Routing Status ==="
    echo ""

    echo "--- ipset $AZ_SET ---"
    ipset list "$AZ_SET" -t 2>/dev/null || echo "(not found)"
    echo ""

    echo "--- ip rule (fwmark 0x3) ---"
    ip rule list | grep "fwmark 0x3" || echo "(no rule)"
    echo ""

    echo "--- ip route table 100 ---"
    ip route show table 100 2>/dev/null || echo "(empty)"
    echo ""

    echo "--- WG wg-s2s AllowedIPs ---"
    wg show wg-s2s allowed-ips 2>/dev/null || echo "(no wg-s2s)"
    echo ""

    echo "--- mangle PREROUTING (az_*) ---"
    iptables -w -t mangle -L PREROUTING -n 2>/dev/null | grep "az_" || echo "(none)"
    echo ""

    echo "--- FORWARD (az_*) ---"
    iptables -w -L FORWARD -n 2>/dev/null | grep "az_" || echo "(none)"
    echo ""

    echo "--- nat POSTROUTING (az_*) ---"
    iptables -w -t nat -L POSTROUTING -n 2>/dev/null | grep "az_" || echo "(none)"
    echo ""

    echo "--- Bypass (old, should be empty) ---"
    ipset list bypass_direct -t 2>/dev/null && echo "(bypass_direct still exists)" || echo "(bypass_direct removed, OK)"
}

# ── Main ──

case "${1:-}" in
    up)     az_up ;;
    down)   az_down ;;
    update) az_up ;;   # update = полный up (пересоздание ipset + правил)
    status) az_status ;;
    *)
        echo "Usage: $0 {up|down|update|status}"
        echo ""
        echo "  up     — включить классический antizapret routing"
        echo "  down   — снять все правила"
        echo "  update — обновить ipset из route-ips.txt (атомарный swap)"
        echo "  status — показать текущее состояние"
        echo ""
        echo "Логика: заблокированные сайты → Германия (VPN3 eth0)"
        echo "        всё остальное → Россия (wg-s2s → VPN1)"
        exit 1
        ;;
esac
