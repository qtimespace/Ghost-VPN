#!/bin/bash
# warp-tg-routing.sh — routing TG CIDRs via Cloudflare WARP (wgcf interface)
#
# Проблема: провайдер VPN3 (5.42.199.x) имеет сломанный upstream peer
# (149.11.182.153, 70-80% loss) к TG EU. WARP обходит через CF peering.
#
# Использование:
#   up      — поднять routing (ipset + mangle + ip rule + route + NAT)
#   down    — убрать всё (fallback к direct eth0)
#   check   — проверить wgcf healthy + при необходимости up/down/restart
#   status  — показать текущее состояние
#
# Вызывается: systemd timer warp-tg-routing.timer каждую минуту

set -uo pipefail
WARP_SET="warp_route"
FWMARK="0x5"
TABLE="300"
IFACE="wgcf"
LOG_PREFIX="warp-tg:"
log() { echo "$LOG_PREFIX $*"; }

TG_CIDRS=(
  "149.154.160.0/20"
  "91.108.4.0/22"
  "91.108.8.0/21"
  "91.108.16.0/21"
  "91.108.56.0/22"
  "91.105.192.0/23"
  "185.76.151.0/24"
)

ensure_ipset() {
  ipset list "$WARP_SET" &>/dev/null || ipset create "$WARP_SET" hash:net maxelem 1024
  for c in "${TG_CIDRS[@]}"; do ipset add "$WARP_SET" "$c" -exist; done
}

drop_ipset() {
  ipset destroy "$WARP_SET" 2>/dev/null || true
}

# VPN клиентские подсети (full VPN 10.28/15 + antizapret 10.29/15 — обе в 10.28.0.0/15)
VPN_SUBNET="10.28.0.0/15"

is_wgcf_healthy() {
  # 1) интерфейс up
  ip link show "$IFACE" &>/dev/null || return 1
  # 2) handshake свежее 3 мин
  local hs_age
  hs_age=$(wg show "$IFACE" latest-handshakes 2>/dev/null | awk '{print systime()-$2; exit}')
  [[ -n "$hs_age" && "$hs_age" =~ ^[0-9]+$ && "$hs_age" -lt 180 ]] || return 2
  # 3) TCP reachability через wgcf
  timeout 4 curl -ksS --max-time 3 --interface "$IFACE" -o /dev/null "https://1.1.1.1/cdn-cgi/trace" 2>/dev/null || return 3
  return 0
}

apply_up() {
  ensure_ipset

  # mangle: mark TG traffic from antizapret clients (ПОСЛЕ az_blocked_germany clears mark 0x3 → 0x0)
  iptables -w -t mangle -C PREROUTING -s "$VPN_SUBNET" -m set --match-set "$WARP_SET" dst \
    -j MARK --set-mark "$FWMARK" -m comment --comment "warp_tg" 2>/dev/null \
    || iptables -w -t mangle -A PREROUTING -s "$VPN_SUBNET" -m set --match-set "$WARP_SET" dst \
        -j MARK --set-mark "$FWMARK" -m comment --comment "warp_tg"

  # policy routing
  ip rule show | grep -q "fwmark $FWMARK lookup $TABLE" \
    || ip rule add fwmark "$FWMARK" lookup "$TABLE" priority 90
  ip route show table "$TABLE" 2>/dev/null | grep -q "default dev $IFACE" \
    || ip route replace default dev "$IFACE" table "$TABLE"

  # MASQUERADE exit: antizapret subnet → WARP (source will be 172.16.0.2)
  iptables -w -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -w -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

  # FORWARD
  iptables -w -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null \
    || iptables -w -I FORWARD 1 -o "$IFACE" -j ACCEPT
  iptables -w -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null \
    || iptables -w -I FORWARD 2 -i "$IFACE" -j ACCEPT

  log "routing UP (TG CIDRs → wgcf)"
}

apply_down() {
  iptables -w -t mangle -D PREROUTING -s "$VPN_SUBNET" -m set --match-set "$WARP_SET" dst \
    -j MARK --set-mark "$FWMARK" -m comment --comment "warp_tg" 2>/dev/null || true
  ip rule del fwmark "$FWMARK" lookup "$TABLE" 2>/dev/null || true
  ip route del default dev "$IFACE" table "$TABLE" 2>/dev/null || true
  iptables -w -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true
  iptables -w -D FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || true
  iptables -w -D FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || true
  log "routing DOWN (TG falls back to direct eth0)"
}

apply_check() {
  if is_wgcf_healthy; then
    # already up? just ensure rules present
    apply_up >/dev/null
    log "OK: wgcf healthy, routing applied"
    return 0
  fi

  local rc=$?
  log "WARN: wgcf unhealthy (rc=$rc), attempting restart"
  apply_down
  wg-quick down "$IFACE" 2>/dev/null || true
  sleep 1
  if wg-quick up "$IFACE" 2>&1 | tail -3; then
    sleep 3
    if is_wgcf_healthy; then
      apply_up
      log "RECOVERED: wgcf back up, routing restored"
      return 0
    fi
  fi
  log "FAIL: wgcf still down, TG traffic fallbacks to direct eth0"
  return 1
}

apply_status() {
  echo "--- wgcf interface ---"
  ip -br link show "$IFACE" 2>&1 || echo "DOWN"
  echo "--- wgcf handshake ---"
  wg show "$IFACE" latest-handshakes 2>/dev/null || echo "no handshake data"
  echo "--- ipset $WARP_SET ---"
  ipset list "$WARP_SET" 2>&1 | grep -E "Name:|Number of entries|^[0-9]" | head -15
  echo "--- mangle warp_tg rule ---"
  iptables -t mangle -L PREROUTING -n -v | grep warp_tg || echo "NOT present"
  echo "--- ip rule ---"
  ip rule show | grep "fwmark $FWMARK" || echo "no rule"
  echo "--- table $TABLE ---"
  ip route show table "$TABLE" 2>&1
  echo "--- healthy? ---"
  if is_wgcf_healthy; then echo "YES"; else echo "NO (rc=$?)"; fi
}

case "${1:-}" in
  up)     apply_up ;;
  down)   apply_down ;;
  check)  apply_check ;;
  status) apply_status ;;
  *)      echo "Usage: $0 up|down|check|status" >&2; exit 1 ;;
esac
