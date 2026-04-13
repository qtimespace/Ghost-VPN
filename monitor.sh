#!/bin/bash
#
# Ghost-VPN Traffic Monitor
# Мониторинг прохождения трафика по цепочке Client → VPN1 → VPN2 → VPN3
#
# Использование:
#   ./monitor.sh [collect|live|report]
#
# Режимы:
#   collect  — собрать метрики один раз (JSON в stdout, для cron)
#   live     — интерактивный дашборд в терминале (обновление каждые 2 сек)
#   report   — анализ истории из лога с выявлением проблем
#
# Устанавливается на каждый сервер (VPN1, VPN2, VPN3)
# Автоматически определяет свою роль в цепочке
#
# Лог: /var/log/ghost-vpn-monitor.jsonl

set -euo pipefail
shopt -s nullglob

# ── Цвета ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Константы ────────────────────────────────────────────────────────────────

LOG_FILE="/var/log/ghost-vpn-monitor.jsonl"
PING_COUNT=5
PING_TIMEOUT=2
LIVE_INTERVAL=2
REPORT_LINES=100

# Пороги (для report/live)
THRESH_LATENCY_WARN=100    # ms
THRESH_LATENCY_CRIT=200
THRESH_LOSS_WARN=1         # %
THRESH_LOSS_CRIT=5
THRESH_CONNTRACK_WARN=80   # %
THRESH_CONNTRACK_CRIT=95
THRESH_HANDSHAKE_WARN=180  # sec
THRESH_HANDSHAKE_CRIT=300
THRESH_RETRANS_WARN=10     # /sec
THRESH_RETRANS_CRIT=50

# ── Вспомогательные функции ──────────────────────────────────────────────────

log()       { echo -e "${BLUE}[*]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
log_err()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
log_warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
log_phase() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${RESET}"; }

die() { log_err "$*"; exit 1; }

# Проверка прав root
[[ "$EUID" -ne 0 ]] && die "Требуются права root"

# ── Определение роли сервера ─────────────────────────────────────────────────

ROLE=""
SERVER_NAME=""
DEFAULT_INTERFACE=""
TUNNEL_INTERFACES=()

detect_role() {
    # VPN3 (main) — есть /root/antizapret/setup
    if [[ -f /root/antizapret/setup ]]; then
        ROLE="main"
        SERVER_NAME="VPN3"
    # VPN2 (relay2) — есть оба wg-s2s и wg-s2s-up
    elif ip link show wg-s2s &>/dev/null && ip link show wg-s2s-up &>/dev/null; then
        ROLE="relay2"
        SERVER_NAME="VPN2"
    # VPN1 (relay1) — есть только wg-s2s
    elif ip link show wg-s2s &>/dev/null; then
        ROLE="relay1"
        SERVER_NAME="VPN1"
    # Fallback по iptables
    elif iptables -w -t nat -S PREROUTING 2>/dev/null | grep -q DNAT; then
        ROLE="relay"
        SERVER_NAME="RELAY"
    else
        ROLE="unknown"
        SERVER_NAME="UNKNOWN"
    fi

    # Физический интерфейс (Gotcha #16/#26: не через ip route get, фильтруем wg)
    DEFAULT_INTERFACE="$(ip route show default | grep -v wg | awk '/default/ {print $5}' | head -1)"
    if [[ -z "$DEFAULT_INTERFACE" ]]; then
        DEFAULT_INTERFACE="$(ip route show default | awk '/default/ {print $5}' | head -1)"
    fi

    # Tunnel interfaces
    TUNNEL_INTERFACES=()
    if ip link show wg-s2s &>/dev/null; then TUNNEL_INTERFACES+=("wg-s2s"); fi
    if ip link show wg-s2s-up &>/dev/null; then TUNNEL_INTERFACES+=("wg-s2s-up"); fi
}

# ── Коллекторы метрик ────────────────────────────────────────────────────────
# Каждый выводит фрагмент JSON

# Получить tunnel IP для интерфейса
get_tunnel_ip() {
    local iface="$1"
    ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1
}

# Peer IP = другой конец /30
get_peer_ip() {
    local my_ip="$1"
    local last_octet="${my_ip##*.}"
    local prefix="${my_ip%.*}"
    if (( last_octet % 2 == 1 )); then
        echo "${prefix}.$((last_octet + 1))"
    else
        echo "${prefix}.$((last_octet - 1))"
    fi
}

# ─── Latency & Packet Loss ───────────────────────────────────────────────────

collect_latency() {
    local targets=()
    local labels=()

    case "$ROLE" in
        relay1)
            # VPN1 → VPN2
            if ip link show wg-s2s &>/dev/null; then
                local my_ip peer_ip
                my_ip="$(get_tunnel_ip wg-s2s)"
                peer_ip="$(get_peer_ip "$my_ip")"
                targets+=("$peer_ip")
                labels+=("VPN1→VPN2(wg-s2s)")
            fi
            targets+=("1.1.1.1")
            labels+=("VPN1→Internet")
            ;;
        relay2)
            # VPN2 → VPN1 (downstream)
            if ip link show wg-s2s &>/dev/null; then
                local my_ip peer_ip
                my_ip="$(get_tunnel_ip wg-s2s)"
                peer_ip="$(get_peer_ip "$my_ip")"
                targets+=("$peer_ip")
                labels+=("VPN2→VPN1(wg-s2s)")
            fi
            # VPN2 → VPN3 (upstream)
            if ip link show wg-s2s-up &>/dev/null; then
                local my_ip2 peer_ip2
                my_ip2="$(get_tunnel_ip wg-s2s-up)"
                peer_ip2="$(get_peer_ip "$my_ip2")"
                targets+=("$peer_ip2")
                labels+=("VPN2→VPN3(wg-s2s-up)")
            fi
            targets+=("1.1.1.1")
            labels+=("VPN2→Internet")
            ;;
        main)
            # VPN3 → relay (через wg-s2s)
            if ip link show wg-s2s &>/dev/null; then
                local my_ip peer_ip
                my_ip="$(get_tunnel_ip wg-s2s)"
                peer_ip="$(get_peer_ip "$my_ip")"
                targets+=("$peer_ip")
                labels+=("VPN3→Relay(wg-s2s)")
            fi
            targets+=("1.1.1.1")
            labels+=("VPN3→Internet")
            targets+=("8.8.8.8")
            labels+=("VPN3→Google")
            ;;
    esac

    local first=1
    echo -n '"latency":['
    for i in "${!targets[@]}"; do
        local target="${targets[$i]}"
        local label="${labels[$i]}"

        local result
        result="$(ping -c "$PING_COUNT" -W "$PING_TIMEOUT" "$target" 2>&1)" || true

        local loss rtt_min rtt_avg rtt_max rtt_mdev
        loss="$(echo "$result" | grep -oP '[0-9.]+(?=% packet loss)' || echo "100")"
        if echo "$result" | grep -q 'min/avg/max'; then
            rtt_min="$(echo "$result" | grep -oP 'min/avg/max/mdev = \K[0-9.]+')"
            rtt_avg="$(echo "$result" | grep -oP 'min/avg/max/mdev = [0-9.]+/\K[0-9.]+')"
            rtt_max="$(echo "$result" | grep -oP 'min/avg/max/mdev = [0-9.]+/[0-9.]+/\K[0-9.]+')"
            rtt_mdev="$(echo "$result" | grep -oP 'min/avg/max/mdev = [0-9.]+/[0-9.]+/[0-9.]+/\K[0-9.]+')"
        else
            rtt_min="-1"; rtt_avg="-1"; rtt_max="-1"; rtt_mdev="-1"
        fi

        [[ "$first" == "1" ]] && first=0 || echo -n ','
        printf '{"hop":"%s","target":"%s","rtt_min":%s,"rtt_avg":%s,"rtt_max":%s,"rtt_mdev":%s,"loss_pct":%s}' \
            "$label" "$target" "$rtt_min" "$rtt_avg" "$rtt_max" "$rtt_mdev" "$loss"
    done
    echo -n ']'
}

# ─── Interface Stats ─────────────────────────────────────────────────────────

collect_interfaces() {
    local ifaces=("$DEFAULT_INTERFACE" "${TUNNEL_INTERFACES[@]}")

    # Добавить tun-интерфейсы на main
    if [[ "$ROLE" == "main" ]]; then
        local tun
        for tun in /sys/class/net/tun*; do
            [[ -e "$tun" ]] && ifaces+=("$(basename "$tun")")
        done
    fi

    # Первый замер
    declare -A rx1 tx1 rxp1 txp1 rxe1 txe1 rxd1 txd1
    for iface in "${ifaces[@]}"; do
        [[ -d "/sys/class/net/$iface/statistics" ]] || continue
        rx1[$iface]="$(cat "/sys/class/net/$iface/statistics/rx_bytes")"
        tx1[$iface]="$(cat "/sys/class/net/$iface/statistics/tx_bytes")"
        rxp1[$iface]="$(cat "/sys/class/net/$iface/statistics/rx_packets")"
        txp1[$iface]="$(cat "/sys/class/net/$iface/statistics/tx_packets")"
        rxe1[$iface]="$(cat "/sys/class/net/$iface/statistics/rx_errors")"
        txe1[$iface]="$(cat "/sys/class/net/$iface/statistics/tx_errors")"
        rxd1[$iface]="$(cat "/sys/class/net/$iface/statistics/rx_dropped")"
        txd1[$iface]="$(cat "/sys/class/net/$iface/statistics/tx_dropped")"
    done

    sleep 1

    # Второй замер + дельта
    local first=1
    echo -n '"interfaces":['
    for iface in "${ifaces[@]}"; do
        [[ -d "/sys/class/net/$iface/statistics" ]] || continue

        local rx2 tx2 rxp2 txp2
        rx2="$(cat "/sys/class/net/$iface/statistics/rx_bytes")"
        tx2="$(cat "/sys/class/net/$iface/statistics/tx_bytes")"
        rxp2="$(cat "/sys/class/net/$iface/statistics/rx_packets")"
        txp2="$(cat "/sys/class/net/$iface/statistics/tx_packets")"

        local rx_bps tx_bps rx_pps tx_pps rx_err tx_err rx_drop tx_drop
        rx_bps=$(( rx2 - ${rx1[$iface]} ))
        tx_bps=$(( tx2 - ${tx1[$iface]} ))
        rx_pps=$(( rxp2 - ${rxp1[$iface]} ))
        tx_pps=$(( txp2 - ${txp1[$iface]} ))
        rx_err="$(cat "/sys/class/net/$iface/statistics/rx_errors")"
        tx_err="$(cat "/sys/class/net/$iface/statistics/tx_errors")"
        rx_drop="$(cat "/sys/class/net/$iface/statistics/rx_dropped")"
        tx_drop="$(cat "/sys/class/net/$iface/statistics/tx_dropped")"

        [[ "$first" == "1" ]] && first=0 || echo -n ','
        printf '{"iface":"%s","rx_bps":%d,"tx_bps":%d,"rx_pps":%d,"tx_pps":%d,"rx_errors":%s,"tx_errors":%s,"rx_dropped":%s,"tx_dropped":%s}' \
            "$iface" "$rx_bps" "$tx_bps" "$rx_pps" "$tx_pps" "$rx_err" "$tx_err" "$rx_drop" "$tx_drop"
    done
    echo -n ']'
}

# ─── Conntrack ───────────────────────────────────────────────────────────────

collect_conntrack() {
    echo -n '"conntrack":{'

    local count=0 max=131072

    if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
        count="$(cat /proc/sys/net/netfilter/nf_conntrack_count)"
    fi
    if [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        max="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
    fi

    local usage_pct=0
    (( max > 0 )) && usage_pct=$(( count * 100 / max ))

    printf '"count":%d,"max":%d,"usage_pct":%d' "$count" "$max" "$usage_pct"

    # Состояния из conntrack (предпочитаем conntrack CLI, fallback на /proc)
    if command -v conntrack &>/dev/null; then
        local ct_dump
        ct_dump="$(conntrack -L 2>/dev/null)"
        if [[ -n "$ct_dump" ]]; then
            local established syn_sent time_wait close_wait fin_wait
            established="$(echo "$ct_dump" | grep -c 'ESTABLISHED' || echo 0)"
            syn_sent="$(echo "$ct_dump" | grep -c 'SYN_SENT' || echo 0)"
            time_wait="$(echo "$ct_dump" | grep -c 'TIME_WAIT' || echo 0)"
            close_wait="$(echo "$ct_dump" | grep -c 'CLOSE_WAIT' || echo 0)"
            fin_wait="$(echo "$ct_dump" | grep -c 'FIN_WAIT' || echo 0)"
            printf ',"established":%d,"syn_sent":%d,"time_wait":%d,"close_wait":%d,"fin_wait":%d' \
                "$established" "$syn_sent" "$time_wait" "$close_wait" "$fin_wait"

            # VPN-specific conntrack entries (порты 50080/50443 — VPN relay traffic)
            local vpn_entries
            vpn_entries="$(echo "$ct_dump" | grep -cE 'dport=50080|dport=50443' || echo 0)"
            printf ',"vpn_entries":%d' "$vpn_entries"
        fi
    elif [[ -f /proc/net/nf_conntrack ]]; then
        local established syn_sent time_wait close_wait fin_wait
        established="$(awk '/ESTABLISHED/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
        syn_sent="$(awk '/SYN_SENT/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
        time_wait="$(awk '/TIME_WAIT/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
        close_wait="$(awk '/CLOSE_WAIT/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
        fin_wait="$(awk '/FIN_WAIT/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
        printf ',"established":%d,"syn_sent":%d,"time_wait":%d,"close_wait":%d,"fin_wait":%d' \
            "$established" "$syn_sent" "$time_wait" "$close_wait" "$fin_wait"
    fi

    # Conntrack drops (если conntrack binary доступен)
    if command -v conntrack &>/dev/null; then
        local drops
        drops="$(conntrack -S 2>/dev/null | awk -F= '/drop=/ {s+=$2} END {print s+0}')"
        printf ',"drops":%d' "$drops"
    fi

    echo -n '}'
}

# ─── iptables NAT Counters ───────────────────────────────────────────────────

collect_iptables() {
    echo -n '"iptables":{'

    local first=1

    # DNAT counters (relay)
    if [[ "$ROLE" == relay* ]]; then
        local dnat_lines
        dnat_lines="$(iptables -w -W 1 -t nat -L PREROUTING -nvx 2>/dev/null | grep DNAT || true)"

        if [[ -n "$dnat_lines" ]]; then
            local total_dnat_pkts=0 total_dnat_bytes=0
            while IFS= read -r line; do
                local pkts bytes dport
                pkts="$(echo "$line" | awk '{print $1}')"
                bytes="$(echo "$line" | awk '{print $2}')"
                dport="$(echo "$line" | grep -oP 'dpt:\K[0-9]+' || echo "0")"
                total_dnat_pkts=$((total_dnat_pkts + pkts))
                total_dnat_bytes=$((total_dnat_bytes + bytes))

                if [[ "$dport" != "0" ]]; then
                    [[ "$first" == "1" ]] && first=0 || echo -n ','
                    printf '"dnat_%s_pkts":%d,"dnat_%s_bytes":%d' "$dport" "$pkts" "$dport" "$bytes"
                fi
            done <<< "$dnat_lines"

            [[ "$first" == "1" ]] && first=0 || echo -n ','
            printf '"dnat_total_pkts":%d,"dnat_total_bytes":%d' "$total_dnat_pkts" "$total_dnat_bytes"
        fi

        # SNAT/MASQUERADE
        local snat_pkts snat_bytes
        snat_pkts="$(iptables -w -W 1 -t nat -L POSTROUTING -nvx 2>/dev/null | grep -E 'SNAT|MASQUERADE' | awk '{s+=$1} END {print s+0}')"
        snat_bytes="$(iptables -w -W 1 -t nat -L POSTROUTING -nvx 2>/dev/null | grep -E 'SNAT|MASQUERADE' | awk '{s+=$2} END {print s+0}')"
        [[ "$first" == "1" ]] && first=0 || echo -n ','
        printf '"snat_pkts":%d,"snat_bytes":%d' "$snat_pkts" "$snat_bytes"
    fi

    # Main server: ANTIZAPRET-MAPPING
    if [[ "$ROLE" == "main" ]]; then
        local mapping_count
        mapping_count="$(iptables -w -W 1 -t nat -S ANTIZAPRET-MAPPING 2>/dev/null | grep -c DNAT || true)"
        [[ "$first" == "1" ]] && first=0 || echo -n ','
        printf '"antizapret_mappings":%d' "$mapping_count"

        # MASQUERADE/SNAT for VPN clients
        local vpn_snat_pkts
        vpn_snat_pkts="$(iptables -w -W 1 -t nat -L POSTROUTING -nvx 2>/dev/null | grep -E 'SNAT|MASQUERADE' | awk '{s+=$1} END {print s+0}')"
        echo -n ','
        printf '"vpn_snat_pkts":%d' "$vpn_snat_pkts"
    fi

    # INVALID drops (filter table)
    local inv_fwd inv_inp invalid_drops
    inv_fwd="$(iptables -w -W 1 -L FORWARD -nvx 2>/dev/null | grep -i 'INVALID' | awk '{s+=$1} END {print s+0}' || echo 0)"
    inv_inp="$(iptables -w -W 1 -L INPUT -nvx 2>/dev/null | grep -i 'INVALID' | awk '{s+=$1} END {print s+0}' || echo 0)"
    inv_fwd="${inv_fwd//[^0-9]/}"
    inv_inp="${inv_inp//[^0-9]/}"
    invalid_drops=$(( ${inv_fwd:-0} + ${inv_inp:-0} ))
    if [[ "$first" == "1" ]]; then first=0; else echo -n ','; fi
    printf '"invalid_drops":%d' "$invalid_drops"

    echo -n '}'
}

# ─── WireGuard ───────────────────────────────────────────────────────────────

collect_wireguard() {
    echo -n '"wireguard":['

    local first=1
    local now
    now="$(date +%s)"

    for iface in "${TUNNEL_INTERFACES[@]}"; do
        local dump
        dump="$(wg show "$iface" dump 2>/dev/null | tail -n +2)" || continue

        while IFS=$'\t' read -r pubkey psk endpoint allowed_ips latest_hs rx tx keepalive; do
            local hs_age=-1 status="unknown"
            if [[ "$latest_hs" != "0" && -n "$latest_hs" ]]; then
                hs_age=$((now - latest_hs))
                if (( hs_age < THRESH_HANDSHAKE_WARN )); then
                    status="ok"
                elif (( hs_age < THRESH_HANDSHAKE_CRIT )); then
                    status="warn"
                else
                    status="stale"
                fi
            else
                status="no_handshake"
            fi

            [[ "$first" == "1" ]] && first=0 || echo -n ','
            printf '{"iface":"%s","endpoint":"%s","allowed_ips":"%s","handshake_age_s":%d,"rx_bytes":%s,"tx_bytes":%s,"status":"%s"}' \
                "$iface" "$endpoint" "$allowed_ips" "$hs_age" "${rx:-0}" "${tx:-0}" "$status"
        done <<< "$dump"
    done

    echo -n ']'
}

# ─── TCP Retransmits ─────────────────────────────────────────────────────────

collect_tcp_retransmits() {
    echo -n '"tcp":{'

    # Первый замер из /proc/net/netstat
    local retrans1 syn_retrans1 loss_probes1
    retrans1="$(awk '/TcpExt:/ && !/^TcpExt: [A-Z]/ {print}' /proc/net/netstat | awk '{print $13}' | head -1 2>/dev/null || echo 0)"
    syn_retrans1="$(awk '/TcpExt:/ && !/^TcpExt: [A-Z]/ {print}' /proc/net/netstat | awk '{print $21}' | head -1 2>/dev/null || echo 0)"

    # Более надёжный способ: по имени поля
    local header values
    header="$(grep '^TcpExt:' /proc/net/netstat | head -1)"
    values="$(grep '^TcpExt:' /proc/net/netstat | tail -1)"

    # Найти позицию TCPRetransSegs
    local idx=1 retrans_idx=0 syn_retrans_idx=0 loss_probes_idx=0
    for field in $header; do
        case "$field" in
            TCPRetransSegs) retrans_idx=$idx ;;
            TCPSynRetrans) syn_retrans_idx=$idx ;;
            TCPLossProbes) loss_probes_idx=$idx ;;
        esac
        ((idx++))
    done

    retrans1=0; syn_retrans1=0; loss_probes1=0
    [[ $retrans_idx -gt 0 ]] && retrans1="$(echo "$values" | awk "{print \$$retrans_idx}")"
    [[ $syn_retrans_idx -gt 0 ]] && syn_retrans1="$(echo "$values" | awk "{print \$$syn_retrans_idx}")"
    [[ $loss_probes_idx -gt 0 ]] && loss_probes1="$(echo "$values" | awk "{print \$$loss_probes_idx}")"

    sleep 1

    # Второй замер
    values="$(grep '^TcpExt:' /proc/net/netstat | tail -1)"
    local retrans2=0 syn_retrans2=0 loss_probes2=0
    [[ $retrans_idx -gt 0 ]] && retrans2="$(echo "$values" | awk "{print \$$retrans_idx}")"
    [[ $syn_retrans_idx -gt 0 ]] && syn_retrans2="$(echo "$values" | awk "{print \$$syn_retrans_idx}")"
    [[ $loss_probes_idx -gt 0 ]] && loss_probes2="$(echo "$values" | awk "{print \$$loss_probes_idx}")"

    local retrans_ps=$((retrans2 - retrans1))
    local syn_retrans_ps=$((syn_retrans2 - syn_retrans1))
    local loss_probes_ps=$((loss_probes2 - loss_probes1))

    printf '"retrans_per_sec":%d,"syn_retrans_per_sec":%d,"loss_probes_per_sec":%d' \
        "$retrans_ps" "$syn_retrans_ps" "$loss_probes_ps"

    # Общие TCP-метрики
    local tcp_header tcp_values
    tcp_header="$(grep '^Tcp:' /proc/net/snmp | head -1)"
    tcp_values="$(grep '^Tcp:' /proc/net/snmp | tail -1)"

    idx=1
    local active_opens_idx=0 passive_opens_idx=0 curr_estab_idx=0
    for field in $tcp_header; do
        case "$field" in
            ActiveOpens) active_opens_idx=$idx ;;
            PassiveOpens) passive_opens_idx=$idx ;;
            CurrEstab) curr_estab_idx=$idx ;;
        esac
        ((idx++))
    done

    local active_opens=0 passive_opens=0 curr_estab=0
    [[ $active_opens_idx -gt 0 ]] && active_opens="$(echo "$tcp_values" | awk "{print \$$active_opens_idx}")"
    [[ $passive_opens_idx -gt 0 ]] && passive_opens="$(echo "$tcp_values" | awk "{print \$$passive_opens_idx}")"
    [[ $curr_estab_idx -gt 0 ]] && curr_estab="$(echo "$tcp_values" | awk "{print \$$curr_estab_idx}")"

    printf ',"active_opens":%d,"passive_opens":%d,"curr_estab":%d' \
        "$active_opens" "$passive_opens" "$curr_estab"

    echo -n '}'
}

# ─── DNS (main only) ────────────────────────────────────────────────────────

collect_dns() {
    echo -n '"dns":{'

    if [[ "$ROLE" != "main" ]]; then
        echo -n '"available":false}'
        return
    fi

    echo -n '"available":true'

    # DNS timing
    if command -v dig &>/dev/null; then
        local dig_result query_time
        dig_result="$(dig @127.0.0.1 google.com +time=3 +tries=1 2>/dev/null)" || true
        query_time="$(echo "$dig_result" | grep -oP 'Query time: \K[0-9]+' || echo "-1")"
        printf ',"dns_query_ms":%s' "$query_time"

        # Проверка AntiZapret DNS (fake IP в 10.30.0.0/15)
        local az_test
        az_test="$(dig @127.0.0.1 rutracker.org +short 2>/dev/null | head -1)" || true
        if [[ "$az_test" =~ ^10\.(30|31)\. ]]; then
            echo -n ',"antizapret_dns":"ok"'
        elif [[ -n "$az_test" ]]; then
            printf ',"antizapret_dns":"unexpected:%s"' "$az_test"
        else
            echo -n ',"antizapret_dns":"fail"'
        fi
    fi

    # Knot Resolver cache (если socat доступен)
    if command -v socat &>/dev/null && [[ -S /run/knot-resolver/control/1 ]]; then
        local cache_count
        cache_count="$(echo 'cache.count()' | socat - /run/knot-resolver/control/1 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo "-1")"
        printf ',"kresd_cache":%s' "$cache_count"
    fi

    echo -n '}'
}

# ─── Routing Info ────────────────────────────────────────────────────────────

collect_routes() {
    echo -n '"routing":{'

    # ip rules count
    local rules_count
    rules_count="$(ip rule list 2>/dev/null | wc -l)"
    printf '"ip_rules":%d' "$rules_count"

    # Default route
    local default_gw default_dev
    default_gw="$(ip route show default | grep -v wg | awk '/default/ {print $3}' | head -1)"
    default_dev="$(ip route show default | grep -v wg | awk '/default/ {print $5}' | head -1)"
    printf ',"default_gw":"%s","default_dev":"%s"' "${default_gw:-none}" "${default_dev:-none}"

    # WireGuard routes
    for iface in "${TUNNEL_INTERFACES[@]}"; do
        local wg_routes
        wg_routes="$(ip route show dev "$iface" 2>/dev/null | wc -l)"
        printf ',"%s_routes":%d' "$iface" "$wg_routes"
    done

    # Bypass ipset (если есть)
    if ipset list bypass_direct -t &>/dev/null; then
        local bypass_count
        bypass_count="$(ipset list bypass_direct -t 2>/dev/null | grep -oP 'Number of entries: \K[0-9]+' || echo 0)"
        printf ',"bypass_entries":%d' "$bypass_count"
    fi

    # Количество OpenVPN клиентов (main)
    if [[ "$ROLE" == "main" ]]; then
        local ovpn_clients=0
        local status_files
        status_files="$(ls /etc/openvpn/server/logs/*.status 2>/dev/null || true)"
        if [[ -n "$status_files" ]]; then
            while IFS= read -r status_file; do
                [[ -f "$status_file" ]] || continue
                local c
                c="$(grep -c '^CLIENT_LIST' "$status_file" 2>/dev/null || true)"
                ovpn_clients=$((ovpn_clients + c))
            done <<< "$status_files"
        fi
        printf ',"openvpn_clients":%d' "$ovpn_clients"

        # WireGuard clients
        local wg_clients=0
        local wg_confs
        wg_confs="$(ls /etc/wireguard/antizapret*.conf /etc/wireguard/vpn*.conf 2>/dev/null || true)"
        if [[ -n "$wg_confs" ]]; then
            while IFS= read -r wg_iface; do
                [[ -f "$wg_iface" ]] || continue
                local iface_name
                iface_name="$(basename "$wg_iface" .conf)"
                ip link show "$iface_name" &>/dev/null || continue
                local peers
                peers="$(wg show "$iface_name" peers 2>/dev/null | wc -l)"
                wg_clients=$((wg_clients + peers))
            done <<< "$wg_confs"
        fi
        printf ',"wireguard_clients":%d' "$wg_clients"
    fi

    echo -n '}'
}

# ─── System ──────────────────────────────────────────────────────────────────

collect_system() {
    echo -n '"system":{'

    # Uptime
    local uptime_s
    uptime_s="$(awk '{print int($1)}' /proc/uptime)"
    printf '"uptime_s":%d' "$uptime_s"

    # Load average
    local load1 load5 load15
    read -r load1 load5 load15 _ _ < /proc/loadavg
    printf ',"load1":"%s","load5":"%s","load15":"%s"' "$load1" "$load5" "$load15"

    # Memory
    local mem_total mem_avail mem_used_pct
    mem_total="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    mem_avail="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"
    mem_used_pct=$(( (mem_total - mem_avail) * 100 / mem_total ))
    printf ',"mem_total_kb":%d,"mem_avail_kb":%d,"mem_used_pct":%d' "$mem_total" "$mem_avail" "$mem_used_pct"

    echo -n '}'
}

# ── Режим collect ────────────────────────────────────────────────────────────

do_collect() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"

    printf '{"ts":"%s","role":"%s","server":"%s",' "$ts" "$ROLE" "$SERVER_NAME"

    collect_system
    echo -n ','
    collect_latency
    echo -n ','
    collect_interfaces
    echo -n ','
    collect_conntrack
    echo -n ','
    collect_iptables
    echo -n ','
    collect_wireguard
    echo -n ','
    collect_tcp_retransmits
    echo -n ','
    collect_dns
    echo -n ','
    collect_routes

    echo '}'
}

# ── Режим live ───────────────────────────────────────────────────────────────

format_bytes() {
    local bytes="$1"
    if (( bytes >= 1073741824 )); then
        printf "%.1f GB/s" "$(echo "scale=1; $bytes/1073741824" | bc 2>/dev/null || echo "?")"
    elif (( bytes >= 1048576 )); then
        printf "%.1f MB/s" "$(echo "scale=1; $bytes/1048576" | bc 2>/dev/null || echo "?")"
    elif (( bytes >= 1024 )); then
        printf "%.1f KB/s" "$(echo "scale=1; $bytes/1024" | bc 2>/dev/null || echo "?")"
    else
        printf "%d B/s" "$bytes"
    fi
}

format_bytes_total() {
    local bytes="$1"
    if (( bytes >= 1073741824 )); then
        printf "%.1f GB" "$(echo "scale=1; $bytes/1073741824" | bc 2>/dev/null || echo "?")"
    elif (( bytes >= 1048576 )); then
        printf "%.1f MB" "$(echo "scale=1; $bytes/1048576" | bc 2>/dev/null || echo "?")"
    elif (( bytes >= 1024 )); then
        printf "%.1f KB" "$(echo "scale=1; $bytes/1024" | bc 2>/dev/null || echo "?")"
    else
        printf "%d B" "$bytes"
    fi
}

colorize_value() {
    local val="$1" warn="$2" crit="$3" invert="${4:-0}"
    # invert=1 means lower is worse (e.g., для handshake age)
    if [[ "$invert" == "1" ]]; then
        if (( val >= crit )); then echo -ne "${RED}"; return; fi
        if (( val >= warn )); then echo -ne "${YELLOW}"; return; fi
    else
        if (( val >= crit )); then echo -ne "${RED}"; return; fi
        if (( val >= warn )); then echo -ne "${YELLOW}"; return; fi
    fi
    echo -ne "${GREEN}"
}

do_live() {
    local running=1
    trap 'running=0' INT TERM

    while (( running )); do
        clear

        local ts
        ts="$(date '+%Y-%m-%d %H:%M:%S')"
        echo -e "${BOLD}${BLUE}═══ Ghost-VPN Monitor: ${SERVER_NAME} (${ROLE}) ═══${RESET}  ${DIM}${ts}${RESET}"
        echo ""

        # ── Latency ──
        echo -e "${BOLD}── Latency ──────────────────────────────────────────${RESET}"
        case "$ROLE" in
            relay1)
                if ip link show wg-s2s &>/dev/null; then
                    local my_ip peer_ip
                    my_ip="$(get_tunnel_ip wg-s2s)"
                    peer_ip="$(get_peer_ip "$my_ip")"
                    local result loss rtt_avg
                    result="$(ping -c 3 -W 2 "$peer_ip" 2>&1)" || true
                    loss="$(echo "$result" | grep -oP '[0-9.]+(?=% packet loss)' || echo "100")"
                    rtt_avg="$(echo "$result" | grep -oP 'min/avg/max/mdev = [0-9.]+/\K[0-9.]+' || echo "-1")"
                    local rtt_int="${rtt_avg%%.*}"
                    [[ "$rtt_int" == "-1" ]] && rtt_int=999
                    colorize_value "$rtt_int" "$THRESH_LATENCY_WARN" "$THRESH_LATENCY_CRIT"
                    printf "  VPN1 → VPN2 (wg-s2s):   %sms avg  %s%% loss${RESET}\n" "$rtt_avg" "$loss"
                fi
                ;;
            relay2)
                for pair in "wg-s2s:VPN2→VPN1" "wg-s2s-up:VPN2→VPN3"; do
                    local iface="${pair%%:*}" label="${pair##*:}"
                    if ip link show "$iface" &>/dev/null; then
                        local my_ip peer_ip result loss rtt_avg
                        my_ip="$(get_tunnel_ip "$iface")"
                        peer_ip="$(get_peer_ip "$my_ip")"
                        result="$(ping -c 3 -W 2 "$peer_ip" 2>&1)" || true
                        loss="$(echo "$result" | grep -oP '[0-9.]+(?=% packet loss)' || echo "100")"
                        rtt_avg="$(echo "$result" | grep -oP 'min/avg/max/mdev = [0-9.]+/\K[0-9.]+' || echo "-1")"
                        local rtt_int="${rtt_avg%%.*}"
                        [[ "$rtt_int" == "-1" ]] && rtt_int=999
                        colorize_value "$rtt_int" "$THRESH_LATENCY_WARN" "$THRESH_LATENCY_CRIT"
                        printf "  %s (%s):   %sms avg  %s%% loss${RESET}\n" "$label" "$iface" "$rtt_avg" "$loss"
                    fi
                done
                ;;
            main)
                if ip link show wg-s2s &>/dev/null; then
                    local my_ip peer_ip result loss rtt_avg
                    my_ip="$(get_tunnel_ip wg-s2s)"
                    peer_ip="$(get_peer_ip "$my_ip")"
                    result="$(ping -c 3 -W 2 "$peer_ip" 2>&1)" || true
                    loss="$(echo "$result" | grep -oP '[0-9.]+(?=% packet loss)' || echo "100")"
                    rtt_avg="$(echo "$result" | grep -oP 'min/avg/max/mdev = [0-9.]+/\K[0-9.]+' || echo "-1")"
                    local rtt_int="${rtt_avg%%.*}"
                    [[ "$rtt_int" == "-1" ]] && rtt_int=999
                    colorize_value "$rtt_int" "$THRESH_LATENCY_WARN" "$THRESH_LATENCY_CRIT"
                    printf "  VPN3 → Relay (wg-s2s):   %sms avg  %s%% loss${RESET}\n" "$rtt_avg" "$loss"
                fi
                ;;
        esac

        # Internet
        local result loss rtt_avg
        result="$(ping -c 3 -W 2 1.1.1.1 2>&1)" || true
        loss="$(echo "$result" | grep -oP '[0-9.]+(?=% packet loss)' || echo "100")"
        rtt_avg="$(echo "$result" | grep -oP 'min/avg/max/mdev = [0-9.]+/\K[0-9.]+' || echo "-1")"
        local rtt_int="${rtt_avg%%.*}"
        [[ "$rtt_int" == "-1" ]] && rtt_int=999
        colorize_value "$rtt_int" "$THRESH_LATENCY_WARN" "$THRESH_LATENCY_CRIT"
        printf "  %s → Internet:   %sms avg  %s%% loss${RESET}\n" "$SERVER_NAME" "$rtt_avg" "$loss"

        echo ""

        # ── Interfaces ──
        echo -e "${BOLD}── Interfaces ───────────────────────────────────────${RESET}"
        local all_ifaces=("$DEFAULT_INTERFACE" "${TUNNEL_INTERFACES[@]}")
        for iface in "${all_ifaces[@]}"; do
            [[ -d "/sys/class/net/$iface/statistics" ]] || continue
            local rx1 tx1
            rx1="$(cat "/sys/class/net/$iface/statistics/rx_bytes")"
            tx1="$(cat "/sys/class/net/$iface/statistics/tx_bytes")"
            sleep 0.5
            local rx2 tx2
            rx2="$(cat "/sys/class/net/$iface/statistics/rx_bytes")"
            tx2="$(cat "/sys/class/net/$iface/statistics/tx_bytes")"
            local rx_rate=$((( rx2 - rx1 ) * 2))
            local tx_rate=$((( tx2 - tx1 ) * 2))
            local rx_err tx_err rx_drop tx_drop
            rx_err="$(cat "/sys/class/net/$iface/statistics/rx_errors")"
            tx_err="$(cat "/sys/class/net/$iface/statistics/tx_errors")"
            rx_drop="$(cat "/sys/class/net/$iface/statistics/rx_dropped")"
            tx_drop="$(cat "/sys/class/net/$iface/statistics/tx_dropped")"
            printf "  %-12s  ↓ %-12s  ↑ %-12s" "$iface:" "$(format_bytes $rx_rate)" "$(format_bytes $tx_rate)"
            if (( rx_err + tx_err > 0 )); then
                echo -ne "  ${RED}err:$((rx_err+tx_err))${RESET}"
            else
                echo -ne "  ${GREEN}err:0${RESET}"
            fi
            if (( rx_drop + tx_drop > 0 )); then
                echo -e "  ${YELLOW}drop:$((rx_drop+tx_drop))${RESET}"
            else
                echo -e "  ${GREEN}drop:0${RESET}"
            fi
        done

        echo ""

        # ── Conntrack ──
        echo -e "${BOLD}── Conntrack ────────────────────────────────────────${RESET}"
        local ct_count=0 ct_max=131072
        [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]] && ct_count="$(cat /proc/sys/net/netfilter/nf_conntrack_count)"
        [[ -f /proc/sys/net/netfilter/nf_conntrack_max ]] && ct_max="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
        local ct_pct=$(( ct_count * 100 / ct_max ))
        colorize_value "$ct_pct" "$THRESH_CONNTRACK_WARN" "$THRESH_CONNTRACK_CRIT"
        printf "  %d / %d (%d%%)${RESET}" "$ct_count" "$ct_max" "$ct_pct"
        if command -v conntrack &>/dev/null; then
            local ct_dump
            ct_dump="$(conntrack -L 2>/dev/null)"
            if [[ -n "$ct_dump" ]]; then
                local est syn tw vpn_ct
                est="$(echo "$ct_dump" | grep -c 'ESTABLISHED' || echo 0)"
                syn="$(echo "$ct_dump" | grep -c 'SYN_SENT' || echo 0)"
                tw="$(echo "$ct_dump" | grep -c 'TIME_WAIT' || echo 0)"
                vpn_ct="$(echo "$ct_dump" | grep -cE 'dport=50080|dport=50443' || echo 0)"
                printf "  EST:%d SYN:%d TW:%d" "$est" "$syn" "$tw"
                (( vpn_ct > 0 )) && echo -ne "  ${CYAN}VPN:%d${RESET}" "$vpn_ct"
            fi
            local drops
            drops="$(conntrack -S 2>/dev/null | awk -F= '/drop=/ {s+=$2} END {print s+0}')"
            (( drops > 0 )) && echo -ne "  ${RED}drops:${drops}${RESET}" || echo -ne "  ${GREEN}drops:0${RESET}"
        elif [[ -f /proc/net/nf_conntrack ]]; then
            local est syn tw
            est="$(awk '/ESTABLISHED/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
            syn="$(awk '/SYN_SENT/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
            tw="$(awk '/TIME_WAIT/ {c++} END {print c+0}' /proc/net/nf_conntrack 2>/dev/null)"
            printf "  EST:%d SYN:%d TW:%d" "$est" "$syn" "$tw"
        fi
        echo ""
        echo ""

        # ── WireGuard ──
        echo -e "${BOLD}── WireGuard ────────────────────────────────────────${RESET}"
        local now
        now="$(date +%s)"
        for iface in "${TUNNEL_INTERFACES[@]}"; do
            local dump
            dump="$(wg show "$iface" dump 2>/dev/null | tail -n +2)" || continue
            while IFS=$'\t' read -r _ _ endpoint _ latest_hs rx tx _; do
                local hs_age=-1 status_icon=""
                if [[ "$latest_hs" != "0" && -n "$latest_hs" ]]; then
                    hs_age=$((now - latest_hs))
                    if (( hs_age < THRESH_HANDSHAKE_WARN )); then
                        status_icon="${GREEN}✓${RESET}"
                    elif (( hs_age < THRESH_HANDSHAKE_CRIT )); then
                        status_icon="${YELLOW}⚠${RESET}"
                    else
                        status_icon="${RED}✗${RESET}"
                    fi
                else
                    status_icon="${RED}✗ no handshake${RESET}"
                fi
                printf "  %s peer: handshake %ds ago %b  rx:%s tx:%s\n" \
                    "$iface" "$hs_age" "$status_icon" "$(format_bytes_total "$rx")" "$(format_bytes_total "$tx")"
            done <<< "$dump"
        done

        echo ""

        # ── iptables NAT ──
        echo -e "${BOLD}── iptables NAT ─────────────────────────────────────${RESET}"
        if [[ "$ROLE" == relay* ]]; then
            local dnat_lines
            dnat_lines="$(iptables -w -W 1 -t nat -L PREROUTING -nvx 2>/dev/null | grep DNAT || true)"
            if [[ -n "$dnat_lines" ]]; then
                while IFS= read -r line; do
                    local pkts dport proto
                    pkts="$(echo "$line" | awk '{print $1}')"
                    dport="$(echo "$line" | grep -oP 'dpt:\K[0-9]+' || echo "?")"
                    proto="$(echo "$line" | awk '{print $4}')"
                    printf "  DNAT %s/%s: %s pkts\n" "$proto" "$dport" "$pkts"
                done <<< "$dnat_lines"
            fi
        fi
        local inv_drops
        inv_drops="$(iptables -w -W 1 -L FORWARD -nvx 2>/dev/null | grep -i INVALID | awk '{s+=$1} END {print s+0}')"
        (( inv_drops > 0 )) && echo -e "  ${RED}INVALID drops: ${inv_drops}${RESET}" || echo -e "  ${GREEN}INVALID drops: 0${RESET}"

        echo ""

        # ── TCP ──
        echo -e "${BOLD}── TCP Retransmits ──────────────────────────────────${RESET}"
        local header values
        header="$(grep '^TcpExt:' /proc/net/netstat | head -1)"
        values="$(grep '^TcpExt:' /proc/net/netstat | tail -1)"
        local idx=1 retrans_idx=0
        for field in $header; do
            [[ "$field" == "TCPRetransSegs" ]] && retrans_idx=$idx
            ((idx++))
        done
        local retrans_total=0
        [[ $retrans_idx -gt 0 ]] && retrans_total="$(echo "$values" | awk "{print \$$retrans_idx}")"

        local tcp_curr_estab=0
        local tcp_values
        tcp_values="$(grep '^Tcp:' /proc/net/snmp | tail -1)"
        local tcp_header
        tcp_header="$(grep '^Tcp:' /proc/net/snmp | head -1)"
        idx=1
        for field in $tcp_header; do
            if [[ "$field" == "CurrEstab" ]]; then
                tcp_curr_estab="$(echo "$tcp_values" | awk "{print \$$idx}")"
            fi
            ((idx++))
        done

        printf "  Total retransmissions: %d  Established TCP: %d\n" "$retrans_total" "$tcp_curr_estab"

        # ── Clients (main only) ──
        if [[ "$ROLE" == "main" ]]; then
            echo ""
            echo -e "${BOLD}── VPN Clients ──────────────────────────────────────${RESET}"
            local ovpn_clients=0
            local sf_list
            sf_list="$(ls /etc/openvpn/server/logs/*.status 2>/dev/null || true)"
            if [[ -n "$sf_list" ]]; then
                while IFS= read -r sf; do
                    [[ -f "$sf" ]] || continue
                    local c
                    c="$(grep -c '^CLIENT_LIST' "$sf" 2>/dev/null || true)"
                    ovpn_clients=$((ovpn_clients + c))
                done <<< "$sf_list"
            fi
            printf "  OpenVPN: %d" "$ovpn_clients"

            local wg_clients=0
            local wg_list
            wg_list="$(ls /etc/wireguard/antizapret*.conf /etc/wireguard/vpn*.conf 2>/dev/null || true)"
            if [[ -n "$wg_list" ]]; then
                while IFS= read -r wg_conf; do
                    [[ -f "$wg_conf" ]] || continue
                    local iface_name
                    iface_name="$(basename "$wg_conf" .conf)"
                    ip link show "$iface_name" &>/dev/null || continue
                    local peers
                    peers="$(wg show "$iface_name" peers 2>/dev/null | wc -l)"
                    wg_clients=$((wg_clients + peers))
                done <<< "$wg_list"
            fi
            printf "  WireGuard: %d\n" "$wg_clients"
        fi

        echo ""
        echo -e "${DIM}Press Ctrl+C to exit${RESET}"
        sleep "$LIVE_INTERVAL"
    done
}

# ── Режим report ─────────────────────────────────────────────────────────────

do_report() {
    if [[ ! -f "$LOG_FILE" ]]; then
        die "Лог-файл не найден: $LOG_FILE. Запустите 'monitor.sh collect' для сбора данных."
    fi

    local lines
    lines="$(tail -n "$REPORT_LINES" "$LOG_FILE")"
    local total
    total="$(echo "$lines" | wc -l)"

    log_phase "Ghost-VPN Monitor Report: ${SERVER_NAME} (${ROLE})"
    echo -e "${DIM}Анализ последних $total записей из $LOG_FILE${RESET}"
    echo ""

    # ── Latency Analysis ──
    echo -e "${BOLD}── Latency Analysis ─────────────────────────────────${RESET}"

    # Извлечь все rtt_avg из JSON (простой grep/sed парсинг)
    local rtt_values
    rtt_values="$(echo "$lines" | grep -oP '"rtt_avg":\K[0-9.]+' || true)"

    if [[ -n "$rtt_values" ]]; then
        local rtt_min rtt_max rtt_avg_calc count_above_warn count_above_crit
        rtt_min="$(echo "$rtt_values" | sort -n | head -1)"
        rtt_max="$(echo "$rtt_values" | sort -n | tail -1)"
        rtt_avg_calc="$(echo "$rtt_values" | awk '{s+=$1; c++} END {printf "%.1f", s/c}')"
        count_above_warn="$(echo "$rtt_values" | awk -v t="$THRESH_LATENCY_WARN" '$1>t {c++} END {print c+0}')"
        count_above_crit="$(echo "$rtt_values" | awk -v t="$THRESH_LATENCY_CRIT" '$1>t {c++} END {print c+0}')"

        printf "  Min: %sms  Avg: %sms  Max: %sms\n" "$rtt_min" "$rtt_avg_calc" "$rtt_max"
        (( count_above_warn > 0 )) && log_warn "  Latency > ${THRESH_LATENCY_WARN}ms: $count_above_warn замеров"
        (( count_above_crit > 0 )) && log_err "  Latency > ${THRESH_LATENCY_CRIT}ms: $count_above_crit замеров"
        (( count_above_warn == 0 )) && log_ok "  Все замеры ниже ${THRESH_LATENCY_WARN}ms"
    else
        log_warn "  Нет данных о latency"
    fi

    echo ""

    # ── Packet Loss ──
    echo -e "${BOLD}── Packet Loss ──────────────────────────────────────${RESET}"
    local loss_values
    loss_values="$(echo "$lines" | grep -oP '"loss_pct":\K[0-9.]+' || true)"

    if [[ -n "$loss_values" ]]; then
        local loss_max loss_avg count_loss
        loss_max="$(echo "$loss_values" | sort -n | tail -1)"
        loss_avg="$(echo "$loss_values" | awk '{s+=$1; c++} END {printf "%.1f", s/c}')"
        count_loss="$(echo "$loss_values" | awk '$1>0 {c++} END {print c+0}')"
        printf "  Avg loss: %s%%  Max loss: %s%%\n" "$loss_avg" "$loss_max"
        (( count_loss > 0 )) && log_warn "  Замеры с потерей пакетов: $count_loss" || log_ok "  Потерь пакетов нет"
    fi

    echo ""

    # ── Conntrack ──
    echo -e "${BOLD}── Conntrack ────────────────────────────────────────${RESET}"
    local ct_values
    ct_values="$(echo "$lines" | grep -oP '"usage_pct":\K[0-9]+' || true)"

    if [[ -n "$ct_values" ]]; then
        local ct_max_usage ct_avg_usage
        ct_max_usage="$(echo "$ct_values" | sort -n | tail -1)"
        ct_avg_usage="$(echo "$ct_values" | awk '{s+=$1; c++} END {printf "%.0f", s/c}')"
        printf "  Avg usage: %s%%  Max usage: %s%%\n" "$ct_avg_usage" "$ct_max_usage"
        (( ct_max_usage >= THRESH_CONNTRACK_CRIT )) && log_err "  CRITICAL: conntrack достигал ${ct_max_usage}%!"
        (( ct_max_usage >= THRESH_CONNTRACK_WARN && ct_max_usage < THRESH_CONNTRACK_CRIT )) && log_warn "  WARNING: conntrack достигал ${ct_max_usage}%"
        (( ct_max_usage < THRESH_CONNTRACK_WARN )) && log_ok "  Conntrack в норме"
    fi

    echo ""

    # ── TCP Retransmits ──
    echo -e "${BOLD}── TCP Retransmits ──────────────────────────────────${RESET}"
    local retrans_values
    retrans_values="$(echo "$lines" | grep -oP '"retrans_per_sec":\K[0-9]+' || true)"

    if [[ -n "$retrans_values" ]]; then
        local retrans_max retrans_avg
        retrans_max="$(echo "$retrans_values" | sort -n | tail -1)"
        retrans_avg="$(echo "$retrans_values" | awk '{s+=$1; c++} END {printf "%.1f", s/c}')"
        printf "  Avg retransmits/sec: %s  Max: %s\n" "$retrans_avg" "$retrans_max"
        (( retrans_max >= THRESH_RETRANS_CRIT )) && log_err "  CRITICAL: retransmits пиковые ${retrans_max}/s!"
        (( retrans_max >= THRESH_RETRANS_WARN && retrans_max < THRESH_RETRANS_CRIT )) && log_warn "  WARNING: retransmits пиковые ${retrans_max}/s"
        (( retrans_max < THRESH_RETRANS_WARN )) && log_ok "  TCP retransmits в норме"
    fi

    echo ""

    # ── WireGuard Health ──
    echo -e "${BOLD}── WireGuard Health ─────────────────────────────────${RESET}"
    local stale_count
    stale_count="$(echo "$lines" | grep -oP '"status":"stale"' | wc -l)"
    local warn_count
    warn_count="$(echo "$lines" | grep -oP '"status":"warn"' | wc -l)"
    local no_hs_count
    no_hs_count="$(echo "$lines" | grep -oP '"status":"no_handshake"' | wc -l)"

    (( stale_count > 0 )) && log_err "  Stale handshakes (> ${THRESH_HANDSHAKE_CRIT}s): $stale_count замеров"
    (( warn_count > 0 )) && log_warn "  Warn handshakes (> ${THRESH_HANDSHAKE_WARN}s): $warn_count замеров"
    (( no_hs_count > 0 )) && log_err "  No handshake: $no_hs_count замеров"
    (( stale_count + warn_count + no_hs_count == 0 )) && log_ok "  Все handshakes в норме"

    echo ""
    echo -e "${DIM}Последняя запись: $(echo "$lines" | tail -1 | grep -oP '"ts":"\K[^"]+' || echo "N/A")${RESET}"
}

# ── Main ─────────────────────────────────────────────────────────────────────

detect_role

MODE="${1:-collect}"

case "$MODE" in
    collect)
        do_collect
        ;;
    live)
        do_live
        ;;
    report)
        do_report
        ;;
    *)
        echo "Usage: $0 [collect|live|report]"
        echo ""
        echo "  collect  — собрать метрики один раз (JSON stdout)"
        echo "  live     — интерактивный дашборд"
        echo "  report   — анализ истории из лога"
        exit 1
        ;;
esac
