#!/bin/bash
#
# Ghost-VPN Centralized Traffic Monitor
# Сбор и анализ метрик со всех серверов цепочки
#
# Использование:
#   ./monitor-report.sh [status|live|report|deploy]
#
# Режимы:
#   status   — текущее состояние всех серверов (разовый снимок)
#   live     — интерактивный дашборд всей цепочки (обновление каждые 5 сек)
#   report   — анализ истории с выявлением проблем
#   deploy   — установить monitor.sh на все серверы + настроить cron
#
# Требует: deploy.conf (с SSH-доступами серверов)

set -euo pipefail

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KNOWN_HOSTS="/tmp/ghost_vpn_monitor_hosts_$$"
REPORT_LINES=100
LIVE_INTERVAL=5

# Пороги
THRESH_LATENCY_WARN=100
THRESH_LATENCY_CRIT=200
THRESH_LOSS_WARN=1
THRESH_LOSS_CRIT=5
THRESH_CONNTRACK_WARN=80
THRESH_CONNTRACK_CRIT=95
THRESH_HANDSHAKE_WARN=180
THRESH_HANDSHAKE_CRIT=300
THRESH_RETRANS_WARN=10
THRESH_RETRANS_CRIT=50

# ── Вспомогательные функции ──────────────────────────────────────────────────

log()       { echo -e "${BLUE}[*]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
log_err()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
log_warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
log_phase() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${RESET}"; }
log_sep()   { echo -e "${BLUE}────────────────────────────────────────────────────${RESET}"; }

die() { log_err "$*"; exit 1; }

cleanup() {
    rm -f "$KNOWN_HOSTS"
    # Удалить временные файлы сбора
    rm -f /tmp/ghost_vpn_mon_*.json 2>/dev/null || true
}
trap cleanup EXIT SIGINT SIGTERM

# ── Загрузка конфига ─────────────────────────────────────────────────────────

CONF_FILE="${SCRIPT_DIR}/deploy.conf"
[[ -f "$CONF_FILE" ]] || die "deploy.conf не найден в $SCRIPT_DIR"

# shellcheck disable=SC1090
source "$CONF_FILE"

# Проверка минимальных переменных
[[ -n "${MAIN_HOST:-}" ]] || die "MAIN_HOST не задан в deploy.conf"

# Собрать список серверов
declare -a SERVERS=()     # host
declare -a SERVER_NAMES=()  # VPN1, VPN2, VPN3
declare -a SERVER_USERS=()  # user
declare -a SERVER_KEYS=()   # ssh key path
declare -a SERVER_PASS=()   # password (fallback)

# VPN1 (Relay1) — если есть
if [[ -n "${RELAY1_HOST:-}" ]]; then
    SERVERS+=("$RELAY1_HOST")
    SERVER_NAMES+=("VPN1")
    SERVER_USERS+=("${RELAY1_USER:-root}")
    SERVER_KEYS+=("${RELAY1_SSH_KEY:-}")
    SERVER_PASS+=("${RELAY1_PASSWORD:-}")
fi

# VPN2 (Relay2) — если есть
if [[ -n "${RELAY2_HOST:-}" ]]; then
    SERVERS+=("$RELAY2_HOST")
    SERVER_NAMES+=("VPN2")
    SERVER_USERS+=("${RELAY2_USER:-root}")
    SERVER_KEYS+=("${RELAY2_SSH_KEY:-}")
    SERVER_PASS+=("${RELAY2_PASSWORD:-}")
fi

# VPN3 (Main)
SERVERS+=("$MAIN_HOST")
SERVER_NAMES+=("VPN3")
SERVER_USERS+=("${MAIN_USER:-root}")
SERVER_KEYS+=("${MAIN_SSH_KEY:-}")
SERVER_PASS+=("${MAIN_PASSWORD:-}")

SERVER_COUNT="${#SERVERS[@]}"

# ── SSH функции ──────────────────────────────────────────────────────────────

ssh_opts() {
    echo "-o StrictHostKeyChecking=no -o UserKnownHostsFile=${KNOWN_HOSTS} -o ConnectTimeout=10 -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=2"
}

ssh_exec() {
    local host="$1" user="$2" key="$3" pass="$4"
    shift 4
    local cmd="$*"
    local opts
    opts="$(ssh_opts)"

    if [[ -n "$key" && -f "$key" ]]; then
        # shellcheck disable=SC2086
        ssh $opts -i "$key" "${user}@${host}" "$cmd" 2>/dev/null
    elif [[ -n "$pass" ]] && command -v sshpass &>/dev/null; then
        # shellcheck disable=SC2086
        SSHPASS="$pass" sshpass -e ssh ${opts/-o BatchMode=yes/-o BatchMode=no} "${user}@${host}" "$cmd" 2>/dev/null
    else
        # shellcheck disable=SC2086
        ssh $opts "${user}@${host}" "$cmd" 2>/dev/null
    fi
}

scp_upload() {
    local src="$1" host="$2" user="$3" key="$4" pass="$5" dst="$6"
    local opts
    opts="$(ssh_opts)"

    if [[ -n "$key" && -f "$key" ]]; then
        # shellcheck disable=SC2086
        scp $opts -i "$key" "$src" "${user}@${host}:${dst}" 2>/dev/null
    elif [[ -n "$pass" ]] && command -v sshpass &>/dev/null; then
        # shellcheck disable=SC2086
        SSHPASS="$pass" sshpass -e scp ${opts/-o BatchMode=yes/-o BatchMode=no} "$src" "${user}@${host}:${dst}" 2>/dev/null
    else
        # shellcheck disable=SC2086
        scp $opts "$src" "${user}@${host}:${dst}" 2>/dev/null
    fi
}

# ── Сбор метрик с сервера ────────────────────────────────────────────────────

# Выполнить monitor.sh collect на удалённом сервере
collect_from_server() {
    local idx="$1"
    local host="${SERVERS[$idx]}"
    local user="${SERVER_USERS[$idx]}"
    local key="${SERVER_KEYS[$idx]}"
    local pass="${SERVER_PASS[$idx]}"
    local name="${SERVER_NAMES[$idx]}"
    local tmpfile="/tmp/ghost_vpn_mon_${name}.json"

    if ssh_exec "$host" "$user" "$key" "$pass" "bash /root/monitor.sh collect" > "$tmpfile" 2>/dev/null; then
        echo "$name:ok"
    else
        echo '{}' > "$tmpfile"
        echo "$name:fail"
    fi
}

# Параллельный сбор со всех серверов
collect_all() {
    local pids=()
    for ((i=0; i<SERVER_COUNT; i++)); do
        collect_from_server "$i" &
        pids+=($!)
    done

    local results=()
    for pid in "${pids[@]}"; do
        local result
        result="$(wait "$pid" 2>/dev/null)" || result="unknown:fail"
        results+=("$result")
    done
    echo "${results[*]}"
}

# ── JSON парсинг (без jq) ───────────────────────────────────────────────────

# Извлечь числовое значение: json_num '{"key":123}' "key" → 123
json_num() {
    local json="$1" key="$2"
    echo "$json" | grep -oP "\"${key}\":\s*\K-?[0-9.]+" | head -1
}

# Извлечь строковое значение: json_str '{"key":"val"}' "key" → val
json_str() {
    local json="$1" key="$2"
    echo "$json" | grep -oP "\"${key}\":\s*\"\K[^\"]*" | head -1
}

# Извлечь массив latency хопов
json_latency_hops() {
    local json="$1"
    # Извлечь каждый hop объект
    echo "$json" | grep -oP '\{"hop":"[^"]+","target":"[^"]+","rtt_min":[^}]+\}'
}

# ── Форматирование ──────────────────────────────────────────────────────────

format_bytes() {
    local bytes="$1"
    if (( bytes >= 1048576 )); then
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
    else
        printf "%.1f KB" "$(echo "scale=1; $bytes/1024" | bc 2>/dev/null || echo "?")"
    fi
}

status_icon() {
    local val="$1" warn="$2" crit="$3"
    if (( val >= crit )); then echo -ne "${RED}✗${RESET}"
    elif (( val >= warn )); then echo -ne "${YELLOW}⚠${RESET}"
    else echo -ne "${GREEN}✓${RESET}"
    fi
}

# ── Режим status ─────────────────────────────────────────────────────────────

do_status() {
    log_phase "Ghost-VPN Path Analysis"
    echo -e "${DIM}$(date '+%Y-%m-%d %H:%M:%S')  Серверов: ${SERVER_COUNT}${RESET}"
    echo ""

    log "Сбор метрик со всех серверов..."
    local results
    results="$(collect_all)"

    # Проверить доступность
    for name_status in $results; do
        local name="${name_status%%:*}"
        local status="${name_status##*:}"
        if [[ "$status" == "fail" ]]; then
            log_err "$name: недоступен"
        fi
    done
    echo ""

    # ── End-to-End Path ──
    echo -e "${BOLD}── End-to-End Path ──────────────────────────────────${RESET}"

    local total_rtt=0
    local max_loss=0

    for ((i=0; i<SERVER_COUNT; i++)); do
        local name="${SERVER_NAMES[$i]}"
        local host="${SERVERS[$i]}"
        local tmpfile="/tmp/ghost_vpn_mon_${name}.json"
        [[ -f "$tmpfile" ]] || continue

        local json
        json="$(cat "$tmpfile")"
        [[ -z "$json" || "$json" == "{}" ]] && continue

        local role
        role="$(json_str "$json" "role")"
        local server
        server="$(json_str "$json" "server")"

        echo -e "  ${BOLD}${server}${RESET} (${host}) — ${DIM}${role}${RESET}"

        # Latency hops
        local hops
        hops="$(json_latency_hops "$json")"
        if [[ -n "$hops" ]]; then
            while IFS= read -r hop; do
                local hop_name rtt_avg loss_pct
                hop_name="$(json_str "$hop" "hop")"
                rtt_avg="$(json_num "$hop" "rtt_avg")"
                loss_pct="$(json_num "$hop" "loss_pct")"

                [[ -z "$rtt_avg" || "$rtt_avg" == "-1" ]] && rtt_avg="timeout"
                [[ -z "$loss_pct" ]] && loss_pct="?"

                local rtt_int="${rtt_avg%%.*}"
                [[ "$rtt_int" == "timeout" ]] && rtt_int=999

                local icon
                icon="$(status_icon "$rtt_int" "$THRESH_LATENCY_WARN" "$THRESH_LATENCY_CRIT")"

                printf "    %b %-30s  RTT: %sms  loss: %s%%\n" "$icon" "$hop_name" "$rtt_avg" "$loss_pct"

                # Суммируем RTT (только tunnel hops)
                if [[ "$rtt_avg" != "timeout" && "$hop_name" == *"wg-s2s"* ]]; then
                    total_rtt=$(echo "$total_rtt + $rtt_avg" | bc 2>/dev/null || echo "$total_rtt")
                fi
                local loss_int="${loss_pct%%.*}"
                [[ "$loss_int" == "?" ]] && loss_int=0
                (( loss_int > max_loss )) && max_loss="$loss_int"
            done <<< "$hops"
        fi

        # Interface throughput для tunnel
        local iface_data
        iface_data="$(echo "$json" | grep -oP '\{"iface":"wg-s2s[^}]*\}' || true)"
        if [[ -n "$iface_data" ]]; then
            while IFS= read -r ifdata; do
                local iface rx_bps tx_bps
                iface="$(json_str "$ifdata" "iface")"
                rx_bps="$(json_num "$ifdata" "rx_bps")"
                tx_bps="$(json_num "$ifdata" "tx_bps")"
                [[ -z "$rx_bps" ]] && rx_bps=0
                [[ -z "$tx_bps" ]] && tx_bps=0
                printf "    ${DIM}  %-12s  ↓ %-12s  ↑ %-12s${RESET}\n" "$iface" "$(format_bytes "$rx_bps")" "$(format_bytes "$tx_bps")"
            done <<< "$iface_data"
        fi

        echo ""
    done

    # Estimated total RTT
    echo -e "  ${BOLD}Estimated tunnel RTT: ~${total_rtt}ms${RESET}"
    (( max_loss > 0 )) && echo -e "  ${RED}Max packet loss on path: ${max_loss}%${RESET}"
    echo ""

    # ── Bottleneck Analysis ──
    echo -e "${BOLD}── Bottleneck Analysis ──────────────────────────────${RESET}"

    local issues=0

    for ((i=0; i<SERVER_COUNT; i++)); do
        local name="${SERVER_NAMES[$i]}"
        local tmpfile="/tmp/ghost_vpn_mon_${name}.json"
        [[ -f "$tmpfile" ]] || continue

        local json
        json="$(cat "$tmpfile")"
        [[ -z "$json" || "$json" == "{}" ]] && continue

        # Conntrack
        local ct_pct
        ct_pct="$(json_num "$json" "usage_pct")"
        [[ -z "$ct_pct" ]] && ct_pct=0
        if (( ct_pct >= THRESH_CONNTRACK_WARN )); then
            log_warn "$name: conntrack ${ct_pct}%"
            ((issues++))
        fi

        # WireGuard handshake
        local stale
        stale="$(echo "$json" | grep -c '"status":"stale"' || echo 0)"
        local no_hs
        no_hs="$(echo "$json" | grep -c '"status":"no_handshake"' || echo 0)"
        if (( stale + no_hs > 0 )); then
            log_err "$name: WireGuard handshake stale/missing ($stale stale, $no_hs no_hs)"
            ((issues++))
        fi

        # TCP retransmits
        local retrans
        retrans="$(json_num "$json" "retrans_per_sec")"
        [[ -z "$retrans" ]] && retrans=0
        if (( retrans >= THRESH_RETRANS_WARN )); then
            log_warn "$name: TCP retransmits ${retrans}/s"
            ((issues++))
        fi

        # INVALID drops
        local inv_drops
        inv_drops="$(json_num "$json" "invalid_drops")"
        [[ -z "$inv_drops" ]] && inv_drops=0
        if (( inv_drops > 100 )); then
            log_warn "$name: iptables INVALID drops ${inv_drops}"
            ((issues++))
        fi

        # Latency > threshold
        local hops
        hops="$(json_latency_hops "$json")"
        if [[ -n "$hops" ]]; then
            while IFS= read -r hop; do
                local hop_name rtt_avg
                hop_name="$(json_str "$hop" "hop")"
                rtt_avg="$(json_num "$hop" "rtt_avg")"
                [[ -z "$rtt_avg" || "$rtt_avg" == "-1" ]] && continue
                local rtt_int="${rtt_avg%%.*}"
                if (( rtt_int >= THRESH_LATENCY_CRIT )); then
                    log_err "$name: ${hop_name} latency ${rtt_avg}ms (CRITICAL)"
                    ((issues++))
                elif (( rtt_int >= THRESH_LATENCY_WARN )); then
                    log_warn "$name: ${hop_name} latency ${rtt_avg}ms"
                    ((issues++))
                fi
            done <<< "$hops"
        fi
    done

    (( issues == 0 )) && log_ok "Проблем не обнаружено"
    echo ""

    # ── Per-Server Summary ──
    echo -e "${BOLD}── Per-Server Summary ───────────────────────────────${RESET}"

    for ((i=0; i<SERVER_COUNT; i++)); do
        local name="${SERVER_NAMES[$i]}"
        local tmpfile="/tmp/ghost_vpn_mon_${name}.json"
        [[ -f "$tmpfile" ]] || continue

        local json
        json="$(cat "$tmpfile")"
        [[ -z "$json" || "$json" == "{}" ]] && { printf "  ${RED}%-6s недоступен${RESET}\n" "$name"; continue; }

        local role ct_pct retrans load1 mem_pct
        role="$(json_str "$json" "role")"
        ct_pct="$(json_num "$json" "usage_pct")"
        retrans="$(json_num "$json" "retrans_per_sec")"
        load1="$(json_str "$json" "load1")"
        mem_pct="$(json_num "$json" "mem_used_pct")"

        [[ -z "$ct_pct" ]] && ct_pct=0
        [[ -z "$retrans" ]] && retrans=0
        [[ -z "$load1" ]] && load1="?"
        [[ -z "$mem_pct" ]] && mem_pct=0

        printf "  %-6s (%-7s):  " "$name" "$role"
        printf "conntrack %s%%  " "$ct_pct"

        # WG status
        for wg_iface in wg-s2s wg-s2s-up; do
            if echo "$json" | grep -q "\"iface\":\"${wg_iface}\""; then
                local wg_status
                wg_status="$(echo "$json" | grep -oP "\"iface\":\"${wg_iface}\"[^}]*\"status\":\"\K[^\"]*" | head -1)"
                case "$wg_status" in
                    ok) echo -ne "${GREEN}${wg_iface}✓${RESET} " ;;
                    warn) echo -ne "${YELLOW}${wg_iface}⚠${RESET} " ;;
                    *) echo -ne "${RED}${wg_iface}✗${RESET} " ;;
                esac
            fi
        done

        printf " retrans %s/s  load %s  mem %s%%\n" "$retrans" "$load1" "$mem_pct"

        # DNS info (main only)
        if [[ "$role" == "main" ]]; then
            local dns_ms az_dns clients_ovpn clients_wg
            dns_ms="$(json_num "$json" "dns_query_ms")"
            az_dns="$(json_str "$json" "antizapret_dns")"
            clients_ovpn="$(json_num "$json" "openvpn_clients")"
            clients_wg="$(json_num "$json" "wireguard_clients")"
            [[ -n "$dns_ms" ]] && printf "          DNS: %sms  AZ: %s" "$dns_ms" "${az_dns:-?}"
            [[ -n "$clients_ovpn" ]] && printf "  OpenVPN: %s" "$clients_ovpn"
            [[ -n "$clients_wg" ]] && printf "  WG: %s" "$clients_wg"
            echo ""
        fi
    done

    echo ""
}

# ── Режим live ───────────────────────────────────────────────────────────────

do_live() {
    local running=1
    trap 'running=0' INT TERM

    while (( running )); do
        do_status
        echo -e "${DIM}Обновление каждые ${LIVE_INTERVAL}с. Ctrl+C для выхода.${RESET}"
        sleep "$LIVE_INTERVAL"
        clear
    done
}

# ── Режим report ─────────────────────────────────────────────────────────────

do_report() {
    log_phase "Ghost-VPN Historical Report"
    echo -e "${DIM}Сбор логов со всех серверов (последние $REPORT_LINES записей)...${RESET}"
    echo ""

    for ((i=0; i<SERVER_COUNT; i++)); do
        local name="${SERVER_NAMES[$i]}"
        local host="${SERVERS[$i]}"
        local user="${SERVER_USERS[$i]}"
        local key="${SERVER_KEYS[$i]}"
        local pass="${SERVER_PASS[$i]}"

        echo -e "${BOLD}── ${name} (${host}) ──────────────────────────────────${RESET}"

        local log_data
        log_data="$(ssh_exec "$host" "$user" "$key" "$pass" "tail -n $REPORT_LINES /var/log/ghost-vpn-monitor.jsonl 2>/dev/null" || echo "")"

        if [[ -z "$log_data" ]]; then
            log_warn "Нет данных мониторинга. Запустите: monitor-report.sh deploy"
            echo ""
            continue
        fi

        local total
        total="$(echo "$log_data" | wc -l)"
        echo -e "${DIM}  Записей: $total${RESET}"

        # Latency
        local rtt_values
        rtt_values="$(echo "$log_data" | grep -oP '"rtt_avg":\K[0-9.]+' || true)"
        if [[ -n "$rtt_values" ]]; then
            local rtt_min rtt_max rtt_avg
            rtt_min="$(echo "$rtt_values" | sort -n | head -1)"
            rtt_max="$(echo "$rtt_values" | sort -n | tail -1)"
            rtt_avg="$(echo "$rtt_values" | awk '{s+=$1;c++} END {printf "%.1f",s/c}')"
            local above_warn
            above_warn="$(echo "$rtt_values" | awk -v t="$THRESH_LATENCY_WARN" '$1>t{c++} END{print c+0}')"
            printf "  Latency: min=%sms avg=%sms max=%sms" "$rtt_min" "$rtt_avg" "$rtt_max"
            (( above_warn > 0 )) && echo -e "  ${YELLOW}(>100ms: $above_warn)${RESET}" || echo ""
        fi

        # Packet loss
        local loss_values
        loss_values="$(echo "$log_data" | grep -oP '"loss_pct":\K[0-9.]+' || true)"
        if [[ -n "$loss_values" ]]; then
            local loss_max loss_events
            loss_max="$(echo "$loss_values" | sort -n | tail -1)"
            loss_events="$(echo "$loss_values" | awk '$1>0{c++} END{print c+0}')"
            if (( loss_events > 0 )); then
                echo -e "  ${YELLOW}Packet loss events: $loss_events, max: ${loss_max}%${RESET}"
            else
                echo -e "  ${GREEN}No packet loss${RESET}"
            fi
        fi

        # Conntrack peaks
        local ct_values
        ct_values="$(echo "$log_data" | grep -oP '"usage_pct":\K[0-9]+' || true)"
        if [[ -n "$ct_values" ]]; then
            local ct_max ct_avg
            ct_max="$(echo "$ct_values" | sort -n | tail -1)"
            ct_avg="$(echo "$ct_values" | awk '{s+=$1;c++} END{printf "%.0f",s/c}')"
            printf "  Conntrack: avg=%s%% peak=%s%%" "$ct_avg" "$ct_max"
            (( ct_max >= THRESH_CONNTRACK_WARN )) && echo -e "  ${YELLOW}WARNING${RESET}" || echo ""
        fi

        # Retransmits
        local retrans_values
        retrans_values="$(echo "$log_data" | grep -oP '"retrans_per_sec":\K[0-9]+' || true)"
        if [[ -n "$retrans_values" ]]; then
            local retrans_max retrans_avg
            retrans_max="$(echo "$retrans_values" | sort -n | tail -1)"
            retrans_avg="$(echo "$retrans_values" | awk '{s+=$1;c++} END{printf "%.1f",s/c}')"
            printf "  TCP retransmits: avg=%s/s peak=%s/s" "$retrans_avg" "$retrans_max"
            (( retrans_max >= THRESH_RETRANS_WARN )) && echo -e "  ${YELLOW}WARNING${RESET}" || echo ""
        fi

        # WireGuard stale
        local stale_count
        stale_count="$(echo "$log_data" | grep -c '"status":"stale"' || echo 0)"
        local no_hs_count
        no_hs_count="$(echo "$log_data" | grep -c '"status":"no_handshake"' || echo 0)"
        if (( stale_count + no_hs_count > 0 )); then
            echo -e "  ${RED}WireGuard issues: stale=$stale_count no_handshake=$no_hs_count${RESET}"
        else
            echo -e "  ${GREEN}WireGuard: all handshakes OK${RESET}"
        fi

        # Time range
        local first_ts last_ts
        first_ts="$(echo "$log_data" | head -1 | grep -oP '"ts":"\K[^"]+' || echo "?")"
        last_ts="$(echo "$log_data" | tail -1 | grep -oP '"ts":"\K[^"]+' || echo "?")"
        echo -e "  ${DIM}Period: $first_ts → $last_ts${RESET}"
        echo ""
    done

    # ── Cross-server comparison ──
    echo -e "${BOLD}── Cross-Server Comparison ──────────────────────────${RESET}"
    echo ""

    # Найти самый медленный хоп
    local worst_hop="" worst_rtt=0
    for ((i=0; i<SERVER_COUNT; i++)); do
        local name="${SERVER_NAMES[$i]}"
        local host="${SERVERS[$i]}"
        local user="${SERVER_USERS[$i]}"
        local key="${SERVER_KEYS[$i]}"
        local pass="${SERVER_PASS[$i]}"

        local log_data
        log_data="$(ssh_exec "$host" "$user" "$key" "$pass" "tail -n $REPORT_LINES /var/log/ghost-vpn-monitor.jsonl 2>/dev/null" || echo "")"
        [[ -z "$log_data" ]] && continue

        # Извлечь хопы и средние RTT
        local hops
        hops="$(echo "$log_data" | grep -oP '"hop":"[^"]*wg-s2s[^"]*"' | sort -u || true)"
        if [[ -n "$hops" ]]; then
            while IFS= read -r hop_match; do
                local hop_name
                hop_name="${hop_match#*\"hop\":\"}"
                hop_name="${hop_name%\"}"
                local avg_rtt
                # Грубый подсчёт: средний RTT для хопов содержащих wg-s2s
                avg_rtt="$(echo "$log_data" | grep -A5 "$hop_name" | grep -oP '"rtt_avg":\K[0-9.]+' | awk '{s+=$1;c++} END{if(c>0) printf "%.0f",s/c; else print 0}')"
                [[ -z "$avg_rtt" ]] && avg_rtt=0
                if (( avg_rtt > worst_rtt )); then
                    worst_rtt="$avg_rtt"
                    worst_hop="$hop_name (avg ${avg_rtt}ms)"
                fi
            done <<< "$hops"
        fi
    done

    if [[ -n "$worst_hop" ]]; then
        echo -e "  Самый медленный хоп: ${YELLOW}${worst_hop}${RESET}"
    fi
    echo ""
}

# ── Режим deploy ─────────────────────────────────────────────────────────────

do_deploy() {
    log_phase "Deploy monitor.sh to all servers"

    local monitor_script="${SCRIPT_DIR}/monitor.sh"
    [[ -f "$monitor_script" ]] || die "monitor.sh не найден в $SCRIPT_DIR"

    for ((i=0; i<SERVER_COUNT; i++)); do
        local name="${SERVER_NAMES[$i]}"
        local host="${SERVERS[$i]}"
        local user="${SERVER_USERS[$i]}"
        local key="${SERVER_KEYS[$i]}"
        local pass="${SERVER_PASS[$i]}"

        log "Deploying to ${name} (${host})..."

        # Upload monitor.sh
        if scp_upload "$monitor_script" "$host" "$user" "$key" "$pass" "/root/monitor.sh"; then
            log_ok "$name: monitor.sh uploaded"
        else
            log_err "$name: upload failed"
            continue
        fi

        # Set executable
        ssh_exec "$host" "$user" "$key" "$pass" "chmod +x /root/monitor.sh" || true

        # Setup cron (каждые 5 минут)
        local cron_line="*/5 * * * * /root/monitor.sh collect >> /var/log/ghost-vpn-monitor.jsonl 2>&1"
        ssh_exec "$host" "$user" "$key" "$pass" "
            (crontab -l 2>/dev/null | grep -v 'monitor.sh'; echo '$cron_line') | crontab -
        " && log_ok "$name: cron configured" || log_err "$name: cron setup failed"

        # Setup logrotate
        ssh_exec "$host" "$user" "$key" "$pass" "
            cat > /etc/logrotate.d/ghost-vpn-monitor << 'LOGROTATE'
/var/log/ghost-vpn-monitor.jsonl {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
LOGROTATE
        " && log_ok "$name: logrotate configured" || log_err "$name: logrotate setup failed"

        # Тестовый запуск
        local test_output
        test_output="$(ssh_exec "$host" "$user" "$key" "$pass" "/root/monitor.sh collect 2>/dev/null" || echo "")"
        if echo "$test_output" | grep -q '"role"'; then
            log_ok "$name: test collect OK (role=$(echo "$test_output" | grep -oP '"role":"\K[^"]+'))"
        else
            log_warn "$name: test collect returned unexpected output"
        fi

        echo ""
    done

    log_phase "Deploy Complete"
    log "Мониторинг будет собирать метрики каждые 5 минут."
    log "Для просмотра: ./monitor-report.sh status"
    log "Для live-дашборда: ./monitor-report.sh live"
    log "Для истории: ./monitor-report.sh report"
}

# ── Main ─────────────────────────────────────────────────────────────────────

MODE="${1:-status}"

case "$MODE" in
    status)
        do_status
        ;;
    live)
        do_live
        ;;
    report)
        do_report
        ;;
    deploy)
        do_deploy
        ;;
    *)
        echo "Usage: $0 [status|live|report|deploy]"
        echo ""
        echo "  status   — текущее состояние всех серверов"
        echo "  live     — интерактивный дашборд цепочки"
        echo "  report   — анализ истории метрик"
        echo "  deploy   — установить monitor.sh на все серверы + cron"
        exit 1
        ;;
esac
