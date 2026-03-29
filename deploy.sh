#!/bin/bash
#
# Ghost-VPN Deploy Script
# Автоматическое развёртывание VPN сервера с relay цепочкой
#
# Использование:
#   cp deploy.conf.example deploy.conf
#   # Заполни deploy.conf
#   bash deploy.sh [--yes]
#
# Топология: Клиент → [Relay1] → [Relay2] → Main VPN
#
# Требования на deploy-машине: ssh, scp, nc
# При использовании паролей: sshpass
#
# https://github.com/qtimespace/Ghost-VPN

set -euo pipefail

# ── Цвета ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Константы ────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_KEY="/tmp/ghost_vpn_deploy_key_$$"
DEPLOY_KEY_PUB="${DEPLOY_KEY}.pub"
KNOWN_HOSTS="/tmp/ghost_vpn_known_hosts_$$"
# STATE_FILE сохраняется между перезапусками (для resume при падении)
STATE_FILE="${SCRIPT_DIR}/.deploy_state"
REBOOT_TIMEOUT="${REBOOT_TIMEOUT:-600}"
REBOOT_INTERVAL="${REBOOT_INTERVAL:-10}"
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-1800}"
AUTO_YES=0

# Счётчики тестов
TESTS_PASSED=0
TESTS_FAILED=0
TEST_RESULTS=()

# ── Вспомогательные функции ──────────────────────────────────────────────────

log()       { echo -e "${BLUE}[*]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
log_err()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
log_warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
log_phase() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${RESET}"; }
log_sep()   { echo -e "${BLUE}────────────────────────────────────────${RESET}"; }

die() { log_err "$*"; exit 1; }

confirm() {
    local msg="$1"
    if [[ "$AUTO_YES" == "1" ]]; then
        log_warn "$msg — auto-confirmed (--yes)"
        return 0
    fi
    read -rp "$(echo -e "${YELLOW}[?]${RESET} $msg [y/N]: ")" answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

cleanup() {
    rm -f "$DEPLOY_KEY" "$DEPLOY_KEY_PUB" "$KNOWN_HOSTS"
    # STATE_FILE не удаляем — он нужен для resume при перезапуске
}
trap cleanup EXIT SIGINT SIGTERM

# ── Проверка зависимостей ────────────────────────────────────────────────────

check_deps() {
    local missing=()
    for cmd in ssh scp; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    # nc нужен для тестов портов
    if ! command -v nc &>/dev/null && ! command -v ncat &>/dev/null; then
        log_warn "nc (netcat) not found — port tests will be skipped"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required tools: ${missing[*]}"
    fi

    # sshpass нужен если используются пароли
    local needs_sshpass=0
    [[ -n "${MAIN_PASS:-}" && -z "${MAIN_SSH_KEY:-}" ]] && needs_sshpass=1
    [[ -n "${RELAY1_HOST:-}" && -n "${RELAY1_PASS:-}" && -z "${RELAY1_SSH_KEY:-}" ]] && needs_sshpass=1
    [[ -n "${RELAY2_HOST:-}" && -n "${RELAY2_PASS:-}" && -z "${RELAY2_SSH_KEY:-}" ]] && needs_sshpass=1

    if [[ "$needs_sshpass" == "1" ]] && ! command -v sshpass &>/dev/null; then
        die "sshpass is required for password authentication. Install: apt-get install sshpass"
    fi

    # wg нужен для WireGuard s2s ключей
    if [[ -n "${RELAY1_HOST:-}" ]] && ! command -v wg &>/dev/null; then
        die "wg (wireguard-tools) is required for s2s key generation. Install: apt-get install wireguard-tools"
    fi
}

# ── SSH функции ──────────────────────────────────────────────────────────────

ssh_opts() {
    echo "-o StrictHostKeyChecking=no -o UserKnownHostsFile=${KNOWN_HOSTS} -o ConnectTimeout=10 -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3"
}

# Определить режим аутентификации для сервера
get_auth_mode() {
    local key="${1:-}" pass="${2:-}"
    if [[ -n "$key" ]]; then echo "key"
    elif [[ -n "$pass" ]]; then echo "pass"
    else echo "none"
    fi
}

# Выполнить команду по SSH (без eval — напрямую)
ssh_exec() {
    local host="$1" user="$2" key_or_pass="$3" mode="$4"
    shift 4
    local cmd="$*"
    local opts
    opts="$(ssh_opts)"

    case "$mode" in
        key)
            # shellcheck disable=SC2086
            ssh $opts -i "$key_or_pass" "${user}@${host}" "$cmd"
            ;;
        pass)
            # SSHPASS через env (не видна в ps), BatchMode=no для парольной аутентификации
            # shellcheck disable=SC2086
            SSHPASS="$key_or_pass" sshpass -e ssh ${opts/-o BatchMode=yes/-o BatchMode=no} "${user}@${host}" "$cmd"
            ;;
        none)
            # shellcheck disable=SC2086
            ssh $opts "${user}@${host}" "$cmd"
            ;;
    esac
}

# Загрузить файл по SCP
scp_upload() {
    local src="$1" host="$2" user="$3" key_or_pass="$4" mode="$5" dst="$6"
    local opts
    opts="$(ssh_opts)"

    case "$mode" in
        key)
            # shellcheck disable=SC2086
            scp $opts -i "$key_or_pass" "$src" "${user}@${host}:${dst}"
            ;;
        pass)
            # shellcheck disable=SC2086
            SSHPASS="$key_or_pass" sshpass -e scp ${opts/-o BatchMode=yes/-o BatchMode=no} "$src" "${user}@${host}:${dst}"
            ;;
        none)
            # shellcheck disable=SC2086
            scp $opts "$src" "${user}@${host}:${dst}"
            ;;
    esac
}

# Установить SSH ключ деплоя на сервер
install_deploy_key() {
    local host="$1" user="$2" key_or_pass="$3" mode="$4"
    local pub
    pub="$(cat "$DEPLOY_KEY_PUB")"

    log "Installing deploy SSH key on ${host}..."
    ssh_exec "$host" "$user" "$key_or_pass" "$mode" "
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        grep -qF '${pub}' ~/.ssh/authorized_keys 2>/dev/null || echo '${pub}' >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
    "
}

# Быстрая проверка SSH доступности
ssh_check() {
    local host="$1" user="$2"
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=5 \
        -o BatchMode=yes \
        -i "$DEPLOY_KEY" \
        "${user}@${host}" "exit 0" &>/dev/null
}

# ── Ожидание перезагрузки ────────────────────────────────────────────────────

wait_for_reboot() {
    local host="$1" user="$2"
    local timeout="${REBOOT_TIMEOUT}" interval="${REBOOT_INTERVAL}"
    local start elapsed uptime_before uptime_after

    log "Waiting for ${host} to reboot..."

    # Зафиксировать uptime до ребута
    uptime_before="$(ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -i "$DEPLOY_KEY" "${user}@${host}" \
        "awk '{print int(\$1)}' /proc/uptime" 2>/dev/null || echo "999999")"

    start="$(date +%s)"

    # Этап 1: ждать пока сервер уйдёт в ребут
    log "  Waiting for server to go down..."
    local went_down=0
    while true; do
        elapsed=$(( $(date +%s) - start ))
        if [[ $elapsed -ge $timeout ]]; then
            log_warn "Timeout waiting for ${host} to go down. Continuing..."
            break
        fi
        if ! ssh_check "$host" "$user" 2>/dev/null; then
            went_down=1
            break
        fi
        sleep "$interval"
    done

    if [[ "$went_down" == "1" ]]; then
        log "  Server is down. Waiting 30s before reconnect..."
        sleep 30
    fi

    # Этап 2: ждать пока сервер поднимется
    log "  Waiting for server to come back..."
    while true; do
        elapsed=$(( $(date +%s) - start ))
        if [[ $elapsed -ge $timeout ]]; then
            die "Timeout (${timeout}s) waiting for ${host} to come back after reboot!"
        fi

        if ssh_check "$host" "$user" 2>/dev/null; then
            uptime_after="$(ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile="${KNOWN_HOSTS}" \
                -o ConnectTimeout=10 -o BatchMode=yes \
                -i "$DEPLOY_KEY" "${user}@${host}" \
                "awk '{print int(\$1)}' /proc/uptime" 2>/dev/null || echo "999999")"

            if [[ "$uptime_after" -lt "$uptime_before" ]] || [[ "$uptime_after" -lt 120 ]]; then
                log_ok "  Server ${host} is back (uptime: ${uptime_after}s)"
                log "  Waiting 20s for services to start..."
                sleep 20
                return 0
            fi
        fi
        sleep "$interval"
    done
}

# ── Ожидание пока apt/dpkg освободится ──────────────────────────────────────

wait_for_apt() {
    local host="$1" user="$2"
    local timeout=300 start elapsed

    start="$(date +%s)"
    log "  Checking if apt/dpkg is busy on ${host}..."
    while true; do
        elapsed=$(( $(date +%s) - start ))
        if [[ $elapsed -ge $timeout ]]; then
            log_warn "apt/dpkg still busy after ${timeout}s on ${host}, proceeding anyway..."
            return 0
        fi
        local busy
        busy="$(ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile="${KNOWN_HOSTS}" \
            -o ConnectTimeout=10 -o BatchMode=yes \
            -i "$DEPLOY_KEY" "${user}@${host}" \
            "pgrep -x 'apt|apt-get|dpkg|unattended-upgrades' > /dev/null && echo busy || echo free" 2>/dev/null || echo "free")"
        [[ "$busy" == "free" ]] && return 0
        log "  apt/dpkg is busy, waiting 10s..."
        sleep 10
    done
}

# ── Проверка необходимости ребута перед установкой ───────────────────────────

check_reboot_required() {
    local host="$1" user="$2"
    local needs_reboot
    needs_reboot="$(ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -i "$DEPLOY_KEY" "${user}@${host}" \
        "[[ -f /var/run/reboot-required ]] && echo yes || echo no" 2>/dev/null || echo "no")"

    if [[ "$needs_reboot" == "yes" ]]; then
        log_warn "Server ${host} requires reboot before installation"
        log "Rebooting ${host}..."
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile="${KNOWN_HOSTS}" \
            -o ConnectTimeout=10 -o BatchMode=yes \
            -i "$DEPLOY_KEY" "${user}@${host}" "reboot" &>/dev/null || true
        sleep 5
        wait_for_reboot "$host" "$user"
    fi
}

# ── Тесты ────────────────────────────────────────────────────────────────────

record_test() {
    local name="$1" result="$2" detail="${3:-}"
    if [[ "$result" == "pass" ]]; then
        TESTS_PASSED=$(( TESTS_PASSED + 1 ))
        TEST_RESULTS+=("${GREEN}[✓]${RESET} ${name}")
    else
        TESTS_FAILED=$(( TESTS_FAILED + 1 ))
        TEST_RESULTS+=("${RED}[✗]${RESET} ${name}${detail:+ — ${detail}}")
    fi
}

test_port_tcp() {
    local host="$1" port="$2" label="$3"
    if command -v nc &>/dev/null || command -v ncat &>/dev/null; then
        if nc -z -w5 "$host" "$port" &>/dev/null 2>&1; then
            record_test "$label" pass
        else
            record_test "$label" fail "TCP ${host}:${port} unreachable"
        fi
    else
        record_test "$label" pass "(nc not available, skipped)"
    fi
}

test_port_udp() {
    local host="$1" port="$2" label="$3"
    if command -v nc &>/dev/null; then
        if nc -zu -w5 "$host" "$port" &>/dev/null 2>&1; then
            record_test "$label" pass
        else
            record_test "$label" fail "UDP ${host}:${port} unreachable"
        fi
    else
        record_test "$label" pass "(nc not available, skipped)"
    fi
}

test_ssh_cmd() {
    local host="$1" user="$2" label="$3" cmd="$4" expected="${5:-}"
    local output
    if output="$(ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -i "$DEPLOY_KEY" "${user}@${host}" "$cmd" 2>/dev/null)"; then
        if [[ -z "$expected" ]] || echo "$output" | grep -q "$expected"; then
            record_test "$label" pass
        else
            record_test "$label" fail "got: ${output}"
        fi
    else
        record_test "$label" fail "SSH command failed"
    fi
}

test_service() {
    local host="$1" user="$2" svc="$3"
    local status
    status="$(ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -i "$DEPLOY_KEY" "${user}@${host}" \
        "systemctl is-active '$svc' 2>/dev/null || echo inactive" 2>/dev/null || echo "error")"
    if [[ "$status" == "active" ]]; then
        record_test "service: ${svc}" pass
    else
        record_test "service: ${svc}" fail "status=${status}"
    fi
}

run_tests_main() {
    local host="$1" user="$2"
    local header="${BOLD}─── Main VPN: ${host} ───${RESET}"
    TEST_RESULTS+=("$header")

    log "Running tests on main server ${host}..."

    # SSH
    if ssh_check "$host" "$user"; then
        record_test "SSH accessible" pass
    else
        record_test "SSH accessible" fail
    fi

    # TCP порты
    test_port_tcp "$host" 50443 "TCP 50443 (OpenVPN antizapret)"
    test_port_tcp "$host" 50080 "TCP 50080 (OpenVPN vpn)"
    test_port_tcp "$host" 443   "TCP 443 (backup)"

    # UDP порты
    test_port_udp "$host" 50443 "UDP 50443 (OpenVPN antizapret)"
    test_port_udp "$host" 51443 "UDP 51443 (WireGuard antizapret)"

    # Сервисы
    test_service "$host" "$user" "openvpn-server@antizapret-udp"
    test_service "$host" "$user" "openvpn-server@antizapret-tcp"
    test_service "$host" "$user" "openvpn-server@vpn-udp"
    test_service "$host" "$user" "wg-quick@antizapret"
    test_service "$host" "$user" "kresd@1"

    # DNS резолвер
    test_ssh_cmd "$host" "$user" "DNS resolver (kresd)" \
        "dig @127.0.0.1 google.com +short +time=5 +tries=1 2>/dev/null | head -1" \
        "."

    # Клиентские конфиги
    test_ssh_cmd "$host" "$user" "Client configs exist" \
        "ls /root/antizapret/client/openvpn/antizapret/*.ovpn 2>/dev/null | head -1" \
        ".ovpn"

    # antizapret сервис обновления
    test_service "$host" "$user" "antizapret"

    # WireGuard s2s tunnel (если есть)
    test_ssh_cmd "$host" "$user" "WG s2s interface" \
        "ip link show wg-s2s &>/dev/null && echo up || echo missing" "up"
    test_service "$host" "$user" "wg-quick@wg-s2s"
}

run_tests_relay() {
    local host="$1" user="$2" target="$3" relay_num="$4"
    local header="${BOLD}─── Relay${relay_num}: ${host} → ${target} ───${RESET}"
    TEST_RESULTS+=("$header")

    log "Running tests on relay${relay_num} ${host}..."

    # SSH
    if ssh_check "$host" "$user"; then
        record_test "SSH accessible" pass
    else
        record_test "SSH accessible" fail
    fi

    # TCP порты
    test_port_tcp "$host" 50443 "TCP 50443 open"
    test_port_tcp "$host" 50080 "TCP 50080 open"

    # ip_forward
    test_ssh_cmd "$host" "$user" "ip_forward enabled" \
        "cat /proc/sys/net/ipv4/ip_forward" "1"

    # DNAT правила
    test_ssh_cmd "$host" "$user" "DNAT 50443 → ${target}" \
        "iptables -t nat -L PREROUTING -n 2>/dev/null | grep '50443' | grep '${target}'" \
        "${target}"
    test_ssh_cmd "$host" "$user" "DNAT 50080 → ${target}" \
        "iptables -t nat -L PREROUTING -n 2>/dev/null | grep '50080' | grep '${target}'" \
        "${target}"
    test_ssh_cmd "$host" "$user" "DNAT 51443 → ${target}" \
        "iptables -t nat -L PREROUTING -n 2>/dev/null | grep '51443' | grep '${target}'" \
        "${target}"

    # SNAT
    test_ssh_cmd "$host" "$user" "SNAT rule exists" \
        "iptables -t nat -L POSTROUTING -n 2>/dev/null | grep 'SNAT' | grep '${target}'" \
        "SNAT"

    # netfilter-persistent
    test_service "$host" "$user" "netfilter-persistent"

    # WireGuard s2s tunnel (если есть)
    test_ssh_cmd "$host" "$user" "WG s2s interface" \
        "ip link show wg-s2s &>/dev/null && echo up || echo missing" "up"
    test_ssh_cmd "$host" "$user" "WG s2s handshake" \
        "wg show wg-s2s latest-handshakes 2>/dev/null | awk '{print (\$2 > 0 ? \"ok\" : \"none\")}'" "ok"
    test_service "$host" "$user" "wg-quick@wg-s2s"
}

# ── Установка main VPN сервера ────────────────────────────────────────────────

install_main() {
    local host="$1" user="$2" key_or_pass="$3" mode="$4"

    log_phase "Installing Main VPN server: ${host}"

    install_deploy_key "$host" "$user" "$key_or_pass" "$mode"
    check_reboot_required "$host" "$user"
    wait_for_apt "$host" "$user"

    log "Uploading setup.sh to ${host}..."
    scp_upload "${SCRIPT_DIR}/setup.sh" "$host" "$user" "$DEPLOY_KEY" "key" "/root/setup.sh"

    log "Running setup.sh on ${host}..."

    # Экспортируем все переменные для неинтерактивного режима
    # Переменные setup.sh проверяют себя перед read - если уже установлены, read не вызывается
    local env_vars
    env_vars="export DEBIAN_FRONTEND=noninteractive
export OPENVPN_PATCH='${SETUP_OPENVPN_PATCH:-1}'
export OPENVPN_DCO='${SETUP_OPENVPN_DCO:-y}'
export WARP_OUTBOUND='${SETUP_WARP_OUTBOUND:-n}'
export ANTIZAPRET_DNS='${SETUP_ANTIZAPRET_DNS:-1}'
export VPN_DNS='${SETUP_VPN_DNS:-1}'
export BLOCK_ADS='${SETUP_BLOCK_ADS:-y}'
export ALTERNATIVE_IP='${SETUP_ALTERNATIVE_IP:-n}'
export ALTERNATIVE_FAKE_IP='${SETUP_ALTERNATIVE_FAKE_IP:-n}'
export OPENVPN_BACKUP_TCP='${SETUP_OPENVPN_BACKUP_TCP:-n}'
export OPENVPN_BACKUP_UDP='${SETUP_OPENVPN_BACKUP_UDP:-y}'
export WIREGUARD_BACKUP='${SETUP_WIREGUARD_BACKUP:-y}'
export OPENVPN_DUPLICATE='${SETUP_OPENVPN_DUPLICATE:-y}'
export OPENVPN_LOG='${SETUP_OPENVPN_LOG:-n}'
export SSH_PROTECTION='${SETUP_SSH_PROTECTION:-y}'
export ATTACK_PROTECTION='${SETUP_ATTACK_PROTECTION:-y}'
export TORRENT_GUARD='${SETUP_TORRENT_GUARD:-y}'
export RESTRICT_FORWARD='${SETUP_RESTRICT_FORWARD:-y}'
export CLIENT_ISOLATION='${SETUP_CLIENT_ISOLATION:-y}'
export OPENVPN_HOST='${RELAY1_DOMAIN:-${RELAY1_HOST:-${MAIN_DOMAIN:-}}}'
export WIREGUARD_HOST='${RELAY1_DOMAIN:-${RELAY1_HOST:-${MAIN_DOMAIN:-}}}'
export ROUTE_ALL='${SETUP_ROUTE_ALL:-n}'
export DISCORD_INCLUDE='${SETUP_DISCORD_INCLUDE:-y}'
export CLOUDFLARE_INCLUDE='${SETUP_CLOUDFLARE_INCLUDE:-y}'
export TELEGRAM_INCLUDE='${SETUP_TELEGRAM_INCLUDE:-y}'
export WHATSAPP_INCLUDE='${SETUP_WHATSAPP_INCLUDE:-y}'
export ROBLOX_INCLUDE='${SETUP_ROBLOX_INCLUDE:-y}'"

    # Патчим CRLF и запускаем через timeout
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        -o ServerAliveInterval=60 \
        -o ServerAliveCountMax=20 \
        -i "$DEPLOY_KEY" \
        "${user}@${host}" "
            sed -i 's/\r//' /root/setup.sh
            chmod +x /root/setup.sh
            ${env_vars}
            # Передаём домены через stdin (while read для OPENVPN_HOST/WIREGUARD_HOST перезаписывает env)
            printf '%s\n%s\n' '${MAIN_DOMAIN:-}' '${MAIN_DOMAIN:-}' | bash /root/setup.sh
        " || true   # setup.sh завершается ребутом (exit code != 0)

    echo "MAIN_DONE=1" >> "$STATE_FILE"
    wait_for_reboot "$host" "$user"
}

# ── Установка relay сервера ───────────────────────────────────────────────────

install_relay() {
    local host="$1" user="$2" key_or_pass="$3" mode="$4" target_ip="$5" relay_num="$6"
    local tunnel_dst_ip="${7:-}"   # tunnel destination IP for s2s (optional)

    log_phase "Installing Relay${relay_num}: ${host} → ${target_ip}"

    install_deploy_key "$host" "$user" "$key_or_pass" "$mode"
    check_reboot_required "$host" "$user"
    wait_for_apt "$host" "$user"

    log "Uploading proxy.sh to ${host}..."
    scp_upload "${SCRIPT_DIR}/proxy.sh" "$host" "$user" "$DEPLOY_KEY" "key" "/root/proxy.sh"

    log "Running proxy.sh on ${host}..."

    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        -o ServerAliveInterval=60 \
        -o ServerAliveCountMax=20 \
        -i "$DEPLOY_KEY" \
        "${user}@${host}" "
            sed -i 's/\r//' /root/proxy.sh
            chmod +x /root/proxy.sh
            export SSH_PROTECTION='y'
            export SCAN_PROTECTION='y'
            export TUNNEL_DESTINATION_IP='${tunnel_dst_ip}'
            # DESTINATION_IP передаём через stdin (while read перезаписывает env при EOF)
            echo '${target_ip}' | bash /root/proxy.sh
        " || true   # proxy.sh завершается ребутом

    echo "RELAY${relay_num}_DONE=1" >> "$STATE_FILE"
    wait_for_reboot "$host" "$user"
}

# ── WireGuard Site-to-Site ────────────────────────────────────────────────────

setup_s2s_wireguard() {
    log_phase "Setting up WireGuard Site-to-Site tunnels"

    local s2s_port="${S2S_PORT:-51820}"
    local s2s_mtu="${S2S_MTU:-1420}"
    local s2s_dir
    s2s_dir="$(umask 077; mktemp -d /tmp/ghost_vpn_s2s_XXXXXXXX)"

    # ── Определяем топологию линков ──────────────────────────────────────
    # Линк 1: последний relay → main (или relay2 → main если есть relay2)
    # Линк 2: relay1 → relay2 (если relay2 есть)

    local has_relay2=0
    [[ -n "${RELAY2_HOST:-}" ]] && has_relay2=1

    # ── Генерация ключей ─────────────────────────────────────────────────
    log "Generating WireGuard site-to-site keys..."
    local old_umask
    old_umask="$(umask)"
    umask 077

    # Main (VPN3) — всегда участвует
    wg genkey | tee "${s2s_dir}/main.key" | wg pubkey > "${s2s_dir}/main.pub"

    if [[ "$has_relay2" -eq 1 ]]; then
        # VPN2 — два линка, КАЖДЫЙ со своим keypair (WireGuard запрещает один ключ на 2 интерфейса)
        wg genkey | tee "${s2s_dir}/relay2.key" | wg pubkey > "${s2s_dir}/relay2.pub"        # wg-s2s (принимает от VPN1)
        wg genkey | tee "${s2s_dir}/relay2up.key" | wg pubkey > "${s2s_dir}/relay2up.pub"    # wg-s2s-up (к VPN3)
        wg genpsk > "${s2s_dir}/psk_relay2_main.key"
    fi

    # VPN1 (relay1) — подключается к следующему хопу
    wg genkey | tee "${s2s_dir}/relay1.key" | wg pubkey > "${s2s_dir}/relay1.pub"
    wg genpsk > "${s2s_dir}/psk_relay1_next.key"

    umask "$old_umask"

    # ── Сборка конфигов ──────────────────────────────────────────────────

    if [[ "$has_relay2" -eq 1 ]]; then
        # 3-серверная цепочка: VPN1 → VPN2 → VPN3

        # VPN3 (main): сервер, принимает от VPN2 (wg-s2s-up ключ!)
        # Линк: 10.99.2.0/30, VPN3=10.99.2.1, VPN2=10.99.2.2
        cat > "${s2s_dir}/main-wg-s2s.conf" <<WGEOF
[Interface]
PrivateKey = $(cat "${s2s_dir}/main.key")
Address = 10.99.2.1/30
ListenPort = ${s2s_port}
MTU = ${s2s_mtu}
PostUp = ip link set dev %i txqueuelen 10000

[Peer]
# Relay2 upstream (${RELAY2_HOST})
PublicKey = $(cat "${s2s_dir}/relay2up.pub")
PresharedKey = $(cat "${s2s_dir}/psk_relay2_main.key")
AllowedIPs = 10.99.2.2/32
WGEOF

        # VPN2 (relay2): сервер (принимает от VPN1) + клиент (к VPN3)
        # wg-s2s: принимает от VPN1, линк 10.99.1.0/30, VPN2=10.99.1.1
        cat > "${s2s_dir}/relay2-wg-s2s.conf" <<WGEOF
[Interface]
PrivateKey = $(cat "${s2s_dir}/relay2.key")
Address = 10.99.1.1/30
ListenPort = ${s2s_port}
MTU = ${s2s_mtu}
PostUp = ip link set dev %i txqueuelen 10000

[Peer]
# Relay1 (${RELAY1_HOST})
PublicKey = $(cat "${s2s_dir}/relay1.pub")
PresharedKey = $(cat "${s2s_dir}/psk_relay1_next.key")
AllowedIPs = 10.99.1.2/32
WGEOF

        # wg-s2s-up: подключается к VPN3, линк 10.99.2.0/30, VPN2=10.99.2.2
        # ОТДЕЛЬНЫЙ keypair (relay2up) — WireGuard запрещает один ключ на 2 интерфейса
        cat > "${s2s_dir}/relay2-wg-s2s-up.conf" <<WGEOF
[Interface]
PrivateKey = $(cat "${s2s_dir}/relay2up.key")
Address = 10.99.2.2/30
MTU = ${s2s_mtu}
Table = off
PostUp = ip link set dev %i txqueuelen 10000

[Peer]
# Main VPN (${MAIN_HOST})
PublicKey = $(cat "${s2s_dir}/main.pub")
PresharedKey = $(cat "${s2s_dir}/psk_relay2_main.key")
Endpoint = ${MAIN_HOST}:${s2s_port}
AllowedIPs = 10.99.2.1/32
PersistentKeepalive = 25
WGEOF

        # VPN1 (relay1): клиент → VPN2, линк 10.99.1.0/30, VPN1=10.99.1.2
        # Table=off обязательно! Иначе fwmark routing ломает DNAT forwarding
        cat > "${s2s_dir}/relay1-wg-s2s.conf" <<WGEOF
[Interface]
PrivateKey = $(cat "${s2s_dir}/relay1.key")
Address = 10.99.1.2/30
MTU = ${s2s_mtu}
Table = off
PostUp = ip link set dev %i txqueuelen 10000

[Peer]
# Relay2 (${RELAY2_HOST})
PublicKey = $(cat "${s2s_dir}/relay2.pub")
PresharedKey = $(cat "${s2s_dir}/psk_relay1_next.key")
Endpoint = ${RELAY2_HOST}:${s2s_port}
AllowedIPs = 10.99.1.1/32
PersistentKeepalive = 25
WGEOF

    else
        # 2-серверная цепочка: VPN1 → VPN3

        # VPN3 (main): сервер, принимает от VPN1
        # Линк: 10.99.1.0/30, VPN3=10.99.1.1, VPN1=10.99.1.2
        cat > "${s2s_dir}/main-wg-s2s.conf" <<WGEOF
[Interface]
PrivateKey = $(cat "${s2s_dir}/main.key")
Address = 10.99.1.1/30
ListenPort = ${s2s_port}
MTU = ${s2s_mtu}
PostUp = ip link set dev %i txqueuelen 10000

[Peer]
# Relay1 (${RELAY1_HOST})
PublicKey = $(cat "${s2s_dir}/relay1.pub")
PresharedKey = $(cat "${s2s_dir}/psk_relay1_next.key")
AllowedIPs = 10.99.1.2/32
WGEOF

        # VPN1 (relay1): клиент → VPN3, линк 10.99.1.0/30, VPN1=10.99.1.2
        # Table=off обязательно! Иначе fwmark routing ломает DNAT forwarding
        cat > "${s2s_dir}/relay1-wg-s2s.conf" <<WGEOF
[Interface]
PrivateKey = $(cat "${s2s_dir}/relay1.key")
Address = 10.99.1.2/30
MTU = ${s2s_mtu}
Table = off
PostUp = ip link set dev %i txqueuelen 10000

[Peer]
# Main VPN (${MAIN_HOST})
PublicKey = $(cat "${s2s_dir}/main.pub")
PresharedKey = $(cat "${s2s_dir}/psk_relay1_next.key")
Endpoint = ${MAIN_HOST}:${s2s_port}
AllowedIPs = 10.99.1.1/32
PersistentKeepalive = 25
WGEOF
    fi

    # ── Загрузка конфигов и активация ────────────────────────────────────

    # VPN3 (main)
    log "Uploading s2s config to Main (${MAIN_HOST})..."
    scp_upload "${s2s_dir}/main-wg-s2s.conf" "$MAIN_HOST" "${MAIN_USER}" "$DEPLOY_KEY" "key" \
        "/etc/wireguard/wg-s2s.conf"

    log "Activating s2s tunnel on Main (${MAIN_HOST})..."
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -i "$DEPLOY_KEY" \
        "${MAIN_USER}@${MAIN_HOST}" "
            chmod 600 /etc/wireguard/wg-s2s.conf
            wg-quick down wg-s2s 2>/dev/null || true
            wg-quick up wg-s2s
            systemctl enable wg-quick@wg-s2s
            echo 's2s tunnel activated on main'
        "

    # VPN2 (relay2, если есть)
    if [[ "$has_relay2" -eq 1 ]]; then
        log "Uploading s2s configs to Relay2 (${RELAY2_HOST})..."
        scp_upload "${s2s_dir}/relay2-wg-s2s.conf" "$RELAY2_HOST" "${RELAY2_USER:-root}" "$DEPLOY_KEY" "key" \
            "/etc/wireguard/wg-s2s.conf"
        scp_upload "${s2s_dir}/relay2-wg-s2s-up.conf" "$RELAY2_HOST" "${RELAY2_USER:-root}" "$DEPLOY_KEY" "key" \
            "/etc/wireguard/wg-s2s-up.conf"

        log "Activating s2s tunnels on Relay2 (${RELAY2_HOST})..."
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile="${KNOWN_HOSTS}" \
            -o ConnectTimeout=10 -o BatchMode=yes \
            -i "$DEPLOY_KEY" \
            "${RELAY2_USER:-root}@${RELAY2_HOST}" "
                chmod 600 /etc/wireguard/wg-s2s.conf /etc/wireguard/wg-s2s-up.conf
                wg-quick down wg-s2s 2>/dev/null || true
                wg-quick down wg-s2s-up 2>/dev/null || true
                wg-quick up wg-s2s
                wg-quick up wg-s2s-up
                systemctl enable wg-quick@wg-s2s wg-quick@wg-s2s-up
                # Разрешить forwarding между двумя s2s интерфейсами
                iptables -w -I FORWARD -i wg-s2s -o wg-s2s-up -j ACCEPT
                iptables -w -I FORWARD -i wg-s2s-up -o wg-s2s -j ACCEPT
                netfilter-persistent save
                echo 's2s tunnels activated on relay2'
            "
    fi

    # VPN1 (relay1) — конфиг загружается ПЕРЕД proxy.sh (который его подхватит)
    # Если relay1 уже установлен (proxy.sh отработал), активируем туннель
    log "Uploading s2s config to Relay1 (${RELAY1_HOST})..."
    scp_upload "${s2s_dir}/relay1-wg-s2s.conf" "$RELAY1_HOST" "${RELAY1_USER:-root}" "$DEPLOY_KEY" "key" \
        "/etc/wireguard/wg-s2s.conf"

    log "Activating s2s tunnel on Relay1 (${RELAY1_HOST})..."
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -i "$DEPLOY_KEY" \
        "${RELAY1_USER:-root}@${RELAY1_HOST}" "
            chmod 600 /etc/wireguard/wg-s2s.conf
            apt-get install -y wireguard 2>/dev/null || true
            wg-quick down wg-s2s 2>/dev/null || true
            wg-quick up wg-s2s
            systemctl enable wg-quick@wg-s2s
            echo 's2s tunnel activated on relay1'
        "

    # ── Проверка handshake ───────────────────────────────────────────────
    log "Verifying s2s tunnel handshakes..."
    # Проверяем на main — должен видеть handshake
    local hs
    hs="$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 -o BatchMode=yes -i "$DEPLOY_KEY" \
        "${MAIN_USER}@${MAIN_HOST}" "wg show wg-s2s latest-handshakes 2>/dev/null | awk '{print \$2}'" || echo "0")"

    if [[ -n "$hs" && "$hs" != "0" ]]; then
        log_ok "Main (${MAIN_HOST}): s2s handshake OK"
    else
        log_warn "Main (${MAIN_HOST}): no s2s handshake yet (may need traffic to trigger)"
    fi

    # ── Обновить DNAT/SNAT на relay серверах → tunnel IP ────────────────
    log "Reconfiguring relay iptables to use tunnel IPs..."

    if [[ "$has_relay2" -eq 1 ]]; then
        # VPN2: DNAT к VPN3 tunnel IP 10.99.2.1, SNAT от 10.99.2.2
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile="${KNOWN_HOSTS}" \
            -o ConnectTimeout=10 -o BatchMode=yes -i "$DEPLOY_KEY" \
            "${RELAY2_USER:-root}@${RELAY2_HOST}" "
                iptables -t nat -F PREROUTING
                iptables -t nat -F POSTROUTING
                DEF_IF=\$(ip route get 1.2.3.4 | grep -oP 'dev \K\S+')
                for port in 80 443 504 508 50080 50443; do
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p tcp --dport \$port -j DNAT --to-destination 10.99.2.1:\$port
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p udp --dport \$port -j DNAT --to-destination 10.99.2.1:\$port
                done
                for port in 540 580 51080 51443; do
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p udp --dport \$port -j DNAT --to-destination 10.99.2.1:\$port
                done
                iptables -w -t nat -A POSTROUTING -d 10.99.2.1 -j SNAT --to-source 10.99.2.2
                netfilter-persistent save
            "
        log_ok "Relay2 iptables reconfigured → tunnel IP 10.99.2.1"

        # VPN1: DNAT к VPN2 tunnel IP 10.99.1.1, SNAT от 10.99.1.2
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile="${KNOWN_HOSTS}" \
            -o ConnectTimeout=10 -o BatchMode=yes -i "$DEPLOY_KEY" \
            "${RELAY1_USER:-root}@${RELAY1_HOST}" "
                iptables -t nat -F PREROUTING
                iptables -t nat -F POSTROUTING
                DEF_IF=\$(ip route get 1.2.3.4 | grep -oP 'dev \K\S+')
                for port in 80 443 504 508 50080 50443; do
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p tcp --dport \$port -j DNAT --to-destination 10.99.1.1:\$port
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p udp --dport \$port -j DNAT --to-destination 10.99.1.1:\$port
                done
                for port in 540 580 51080 51443; do
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p udp --dport \$port -j DNAT --to-destination 10.99.1.1:\$port
                done
                iptables -w -t nat -A POSTROUTING -d 10.99.1.1 -j SNAT --to-source 10.99.1.2
                netfilter-persistent save
            "
        log_ok "Relay1 iptables reconfigured → tunnel IP 10.99.1.1"
    else
        # VPN1: DNAT к VPN3 tunnel IP 10.99.1.1, SNAT от 10.99.1.2
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile="${KNOWN_HOSTS}" \
            -o ConnectTimeout=10 -o BatchMode=yes -i "$DEPLOY_KEY" \
            "${RELAY1_USER:-root}@${RELAY1_HOST}" "
                iptables -t nat -F PREROUTING
                iptables -t nat -F POSTROUTING
                DEF_IF=\$(ip route get 1.2.3.4 | grep -oP 'dev \K\S+')
                for port in 80 443 504 508 50080 50443; do
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p tcp --dport \$port -j DNAT --to-destination 10.99.1.1:\$port
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p udp --dport \$port -j DNAT --to-destination 10.99.1.1:\$port
                done
                for port in 540 580 51080 51443; do
                    iptables -w -t nat -A PREROUTING -i \$DEF_IF -p udp --dport \$port -j DNAT --to-destination 10.99.1.1:\$port
                done
                iptables -w -t nat -A POSTROUTING -d 10.99.1.1 -j SNAT --to-source 10.99.1.2
                netfilter-persistent save
            "
        log_ok "Relay1 iptables reconfigured → tunnel IP 10.99.1.1"
    fi

    # Cleanup ключей
    rm -rf "$s2s_dir"
    log_ok "S2S WireGuard setup complete"

    echo "S2S_DONE=1" >> "$STATE_FILE"
}

# ── Отчёт ─────────────────────────────────────────────────────────────────────

print_report() {
    echo
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${BLUE}║       Ghost-VPN Deployment Report          ║${RESET}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════╝${RESET}"
    echo -e "  $(date)"
    echo

    # Топология
    echo -e "${BOLD}Topology:${RESET}"
    local chain="Client"
    [[ -n "${RELAY1_HOST:-}" ]] && chain="${chain} → Relay1 (${RELAY1_HOST})"
    [[ -n "${RELAY2_HOST:-}" ]] && chain="${chain} → Relay2 (${RELAY2_HOST})"
    chain="${chain} → Main (${MAIN_HOST})"
    echo -e "  ${chain}"
    echo

    # Результаты тестов
    for line in "${TEST_RESULTS[@]}"; do
        echo -e "  ${line}"
    done

    echo
    log_sep

    local total=$(( TESTS_PASSED + TESTS_FAILED ))
    if [[ "$TESTS_FAILED" -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}All tests passed: ${TESTS_PASSED}/${total}${RESET}"
    else
        echo -e "  ${BOLD}Tests: ${total} total | ${GREEN}${TESTS_PASSED} passed${RESET} | ${RED}${TESTS_FAILED} failed${RESET}"
    fi

    echo
    echo -e "${BOLD}Client config files on main server:${RESET}"
    echo -e "  /root/antizapret/client/openvpn/antizapret/  (AntiZapret OpenVPN)"
    echo -e "  /root/antizapret/client/openvpn/vpn/         (Full VPN OpenVPN)"
    echo -e "  /root/antizapret/client/wireguard/           (WireGuard)"
    echo
    echo -e "${BOLD}Download client configs:${RESET}"
    echo -e "  mkdir -p ./client-configs"
    echo -e "  scp -r root@${MAIN_HOST}:/root/antizapret/client ./client-configs/"
    echo

    if [[ -n "${RELAY1_HOST:-}" ]]; then
        echo -e "${BOLD}Connect clients to:${RESET} ${RELAY1_HOST} (Relay1)"
    elif [[ -n "${RELAY2_HOST:-}" ]]; then
        echo -e "${BOLD}Connect clients to:${RESET} ${RELAY2_HOST} (Relay2)"
    else
        echo -e "${BOLD}Connect clients to:${RESET} ${MAIN_HOST}"
    fi
    echo
}

# ── Основной поток ────────────────────────────────────────────────────────────

main() {
    # Аргументы
    for arg in "$@"; do
        [[ "$arg" == "--yes" ]]   && AUTO_YES=1
        [[ "$arg" == "--reset" ]] && { rm -f "$STATE_FILE"; log "Deploy state reset."; }
        [[ "$arg" == "--help" ]]  && {
            echo "Usage: bash deploy.sh [--yes] [--reset]"
            echo "  --yes    Skip confirmation prompts"
            echo "  --reset  Reset deploy state (re-install all servers)"
            exit 0
        }
    done

    echo -e "${BOLD}${GREEN}"
    echo "╔════════════════════════════════════════════╗"
    echo "║            Ghost-VPN Deploy                ║"
    echo "╚════════════════════════════════════════════╝"
    echo -e "${RESET}"

    # Загрузка конфига
    local conf="${SCRIPT_DIR}/deploy.conf"
    if [[ ! -f "$conf" ]]; then
        die "deploy.conf not found! Create it: cp deploy.conf.example deploy.conf"
    fi
    # Проверка прав доступа к deploy.conf — должен быть 600 (только владелец)
    local conf_perms
    conf_perms="$(stat -c '%a' "$conf" 2>/dev/null || stat -f '%A' "$conf" 2>/dev/null)"
    if [[ "$conf_perms" != "600" ]]; then
        log_warn "deploy.conf has unsafe permissions ($conf_perms). Fixing to 600..."
        chmod 600 "$conf"
    fi
    # Валидация формата deploy.conf (защита от command injection)
    if grep -qP '^[^#=]*[;&|`$()]' "$conf" 2>/dev/null; then
        die "deploy.conf contains shell metacharacters! Only KEY=value lines allowed."
    fi
    # shellcheck source=/dev/null
    source "$conf"

    # Валидация обязательных параметров
    [[ -z "${MAIN_HOST:-}" ]] && die "MAIN_HOST is not set in deploy.conf"
    [[ -z "${MAIN_USER:-}" ]] && die "MAIN_USER is not set in deploy.conf"
    # Валидация хостов (только допустимые символы)
    local _validate_host
    for _validate_host in "${MAIN_HOST:-}" "${RELAY1_HOST:-}" "${RELAY2_HOST:-}"; do
        [[ -z "$_validate_host" ]] && continue
        [[ "$_validate_host" =~ ^[a-zA-Z0-9._-]+$ ]] || die "Invalid hostname: $_validate_host"
    done

    # Проверка зависимостей
    check_deps

    # Генерация временного SSH ключа для деплоя
    log "Generating temporary deploy SSH key..."
    # umask 077 — ключ создаётся с правами 600 (только владелец)
    (umask 077; ssh-keygen -t ed25519 -f "$DEPLOY_KEY" -N "" -C "ghost-vpn-deploy-$$" -q)

    # Инициализация state файла
    touch "$STATE_FILE"

    # Определение режимов аутентификации
    local main_mode relay1_mode relay2_mode
    main_mode="$(get_auth_mode "${MAIN_SSH_KEY:-}" "${MAIN_PASS:-}")"
    relay1_mode="$(get_auth_mode "${RELAY1_SSH_KEY:-}" "${RELAY1_PASS:-}")"
    relay2_mode="$(get_auth_mode "${RELAY2_SSH_KEY:-}" "${RELAY2_PASS:-}")"

    local main_cred relay1_cred relay2_cred
    main_cred="${MAIN_SSH_KEY:-${MAIN_PASS:-}}"
    relay1_cred="${RELAY1_SSH_KEY:-${RELAY1_PASS:-}}"
    relay2_cred="${RELAY2_SSH_KEY:-${RELAY2_PASS:-}}"

    # Определение цепочки relay
    local relay1_target relay2_target
    relay2_target="${MAIN_HOST}"
    relay1_target="${RELAY2_HOST:-${MAIN_HOST}}"

    # Вывод плана
    log_phase "Deployment Plan"
    echo -e "  Main VPN:  ${MAIN_HOST} (user: ${MAIN_USER}, auth: ${main_mode})"
    [[ -n "${RELAY2_HOST:-}" ]] && echo -e "  Relay2:    ${RELAY2_HOST} → ${relay2_target}"
    [[ -n "${RELAY1_HOST:-}" ]] && echo -e "  Relay1:    ${RELAY1_HOST} → ${relay1_target}"
    [[ -n "${MAIN_DOMAIN:-}" ]] && echo -e "  Domain:    ${MAIN_DOMAIN}"
    echo

    if ! confirm "Proceed with installation?"; then
        echo "Aborted."
        exit 0
    fi

    # ── Шаг 1: Main VPN сервер ──────────────────────────────────────────────
    if grep -q "MAIN_DONE=1" "$STATE_FILE" 2>/dev/null; then
        log_warn "Main server already installed (state file found), skipping..."
    else
        install_main "$MAIN_HOST" "$MAIN_USER" "$main_cred" "$main_mode"
    fi

    # ── Шаг 2: Relay2 (если задан) ──────────────────────────────────────────
    if [[ -n "${RELAY2_HOST:-}" ]]; then
        if grep -q "RELAY2_DONE=1" "$STATE_FILE" 2>/dev/null; then
            log_warn "Relay2 already installed (state file found), skipping..."
        else
            # VPN2 DNAT → tunnel IP VPN3 (10.99.2.1 через wg-s2s-up)
            install_relay "$RELAY2_HOST" "${RELAY2_USER:-root}" "$relay2_cred" "$relay2_mode" \
                "$relay2_target" "2" "10.99.2.1"
        fi
    fi

    # ── Шаг 3: Relay1 (если задан) ──────────────────────────────────────────
    if [[ -n "${RELAY1_HOST:-}" ]]; then
        if grep -q "RELAY1_DONE=1" "$STATE_FILE" 2>/dev/null; then
            log_warn "Relay1 already installed (state file found), skipping..."
        else
            # VPN1 DNAT → tunnel IP следующего хопа (10.99.1.1)
            install_relay "$RELAY1_HOST" "${RELAY1_USER:-root}" "$relay1_cred" "$relay1_mode" \
                "$relay1_target" "1" "10.99.1.1"
        fi
    fi

    # ── Шаг 4: WireGuard Site-to-Site ──────────────────────────────────────
    if [[ -n "${RELAY1_HOST:-}" ]]; then
        if grep -q "S2S_DONE=1" "$STATE_FILE" 2>/dev/null; then
            log_warn "S2S WireGuard already configured (state file found), skipping..."
        else
            # Убедимся что deploy key установлен на всех серверах (мог быть пропущен при resume)
            install_deploy_key "$MAIN_HOST" "$MAIN_USER" "$main_cred" "$main_mode"
            [[ -n "${RELAY2_HOST:-}" ]] && install_deploy_key "$RELAY2_HOST" "${RELAY2_USER:-root}" "$relay2_cred" "$relay2_mode"
            install_deploy_key "$RELAY1_HOST" "${RELAY1_USER:-root}" "$relay1_cred" "$relay1_mode"
            setup_s2s_wireguard
        fi
    fi

    # ── Шаг 5: Тесты ────────────────────────────────────────────────────────
    log_phase "Running Tests"

    # С s2s DNAT ведёт на tunnel IP, не на публичный
    local test_relay2_target test_relay1_target
    if grep -q "S2S_DONE=1" "$STATE_FILE" 2>/dev/null; then
        if [[ -n "${RELAY2_HOST:-}" ]]; then
            test_relay2_target="10.99.2.1"   # VPN2→VPN3 tunnel IP
            test_relay1_target="10.99.1.1"   # VPN1→VPN2 tunnel IP
        else
            test_relay1_target="10.99.1.1"   # VPN1→VPN3 tunnel IP
        fi
    else
        test_relay2_target="$relay2_target"
        test_relay1_target="$relay1_target"
    fi

    run_tests_main "$MAIN_HOST" "${MAIN_USER}"
    [[ -n "${RELAY2_HOST:-}" ]] && run_tests_relay "$RELAY2_HOST" "${RELAY2_USER:-root}" "${test_relay2_target:-$relay2_target}" "2"
    [[ -n "${RELAY1_HOST:-}" ]] && run_tests_relay "$RELAY1_HOST" "${RELAY1_USER:-root}" "${test_relay1_target:-$relay1_target}" "1"

    # ── Шаг 6: Удаление временного deploy-ключа с серверов ──────────────────
    # (ключ не должен оставаться в authorized_keys после деплоя)
    log_phase "Cleaning up deploy key from servers"
    local deploy_pub
    deploy_pub="$(cat "$DEPLOY_KEY_PUB" 2>/dev/null || true)"
    if [[ -n "$deploy_pub" ]]; then
        for _host_user in "${MAIN_HOST}:${MAIN_USER}" \
            "${RELAY2_HOST:-}:${RELAY2_USER:-root}" \
            "${RELAY1_HOST:-}:${RELAY1_USER:-root}"; do
            local _h="${_host_user%%:*}" _u="${_host_user##*:}"
            [[ -z "$_h" ]] && continue
            ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile="${KNOWN_HOSTS}" \
                -o ConnectTimeout=10 -o BatchMode=yes \
                -i "$DEPLOY_KEY" "${_u}@${_h}" \
                "sed -i '/ghost-vpn-deploy-$$/d' ~/.ssh/authorized_keys 2>/dev/null" &>/dev/null && \
                log_ok "Deploy key removed from ${_h}" || \
                log_warn "Could not remove deploy key from ${_h} (manual cleanup may be needed)"
        done
    fi

    # ── Шаг 7: Аудит-лог ────────────────────────────────────────────────────
    local audit_log="${SCRIPT_DIR}/deploy-audit.log"
    {
        echo "=== Deploy completed: $(date --iso-8601=seconds 2>/dev/null || date) ==="
        echo "User: ${USER:-unknown}"
        echo "Main: ${MAIN_HOST} (${main_mode})"
        [[ -n "${RELAY2_HOST:-}" ]] && echo "Relay2: ${RELAY2_HOST} → ${relay2_target}"
        [[ -n "${RELAY1_HOST:-}" ]] && echo "Relay1: ${RELAY1_HOST} → ${relay1_target}"
        echo "Tests: passed=${TESTS_PASSED} failed=${TESTS_FAILED}"
        echo "---"
    } >> "$audit_log"
    chmod 600 "$audit_log"

    # ── Шаг 8: Отчёт ────────────────────────────────────────────────────────
    print_report

    if [[ "$TESTS_FAILED" -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
