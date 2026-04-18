#!/bin/bash
# vpn2-transit.sh — настройка/снятие VPN2 transit routing на wg-s2s-up
#
# Запускается из PostUp/PostDown wg-s2s-up на VPN2 (relay2).
# Раньше это был 1400-символьный one-liner прямо в .conf (deploy.sh:671),
# что привело к Gotcha #37/#38 (MTU и Table=off дрифт).
#
# Usage: vpn2-transit.sh up|down <iface>
#
# Gotchas:
#   #33 — fwmark 0x4 routing без рекурсии (-i wg-s2s-up только для входящих)
#   #42 — vpn2_skip_local RETURN ДО vpn2_transit MARK, иначе loop через ICMP unreachable

set -euo pipefail

action="${1:-}"
iface="${2:-}"

if [[ -z "$action" || -z "$iface" ]]; then
	echo "Usage: $0 up|down <iface>" >&2
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "ERROR: must run as root" >&2; exit 1
fi

SUBNET=10.99.2.0/30

apply_up() {
	ip link set dev "$iface" txqueuelen 10000

	# Skip local: ответные VPN-пакеты не маркировать (Gotcha #42)
	iptables -t mangle -C PREROUTING -i "$iface" -d "$SUBNET" -j RETURN \
		-m comment --comment "vpn2_skip_local" 2>/dev/null \
		|| iptables -t mangle -I PREROUTING 1 -i "$iface" -d "$SUBNET" -j RETURN \
			-m comment --comment "vpn2_skip_local"

	# Transit mark: весь остальной трафик с wg-s2s-up → fwmark 0x4
	iptables -t mangle -C PREROUTING -i "$iface" -j MARK --set-mark 0x4 \
		-m comment --comment "vpn2_transit" 2>/dev/null \
		|| iptables -t mangle -A PREROUTING -i "$iface" -j MARK --set-mark 0x4 \
			-m comment --comment "vpn2_transit"

	# Policy routing: fwmark 0x4 → table 200 → default dev wg-s2s
	ip rule add fwmark 0x4 lookup 200 priority 100 2>/dev/null || true
	ip route add default dev wg-s2s table 200 2>/dev/null || true

	# rp_filter off для transit интерфейса
	sysctl -qw "net.ipv4.conf.${iface}.rp_filter=0"

	# FORWARD: transit wg-s2s-up ↔ wg-s2s
	iptables -C FORWARD -i "$iface" -o wg-s2s -j ACCEPT \
		-m comment --comment "vpn2_transit_fwd" 2>/dev/null \
		|| iptables -I FORWARD 1 -i "$iface" -o wg-s2s -j ACCEPT \
			-m comment --comment "vpn2_transit_fwd"
	iptables -C FORWARD -i wg-s2s -o "$iface" -j ACCEPT \
		-m comment --comment "vpn2_transit_ret" 2>/dev/null \
		|| iptables -I FORWARD 2 -i wg-s2s -o "$iface" -j ACCEPT \
			-m comment --comment "vpn2_transit_ret"
}

apply_down() {
	iptables -t mangle -D PREROUTING -i "$iface" -d "$SUBNET" -j RETURN \
		-m comment --comment "vpn2_skip_local" 2>/dev/null || true
	iptables -t mangle -D PREROUTING -i "$iface" -j MARK --set-mark 0x4 \
		-m comment --comment "vpn2_transit" 2>/dev/null || true
	ip rule del fwmark 0x4 lookup 200 2>/dev/null || true
	ip route del default dev wg-s2s table 200 2>/dev/null || true
	iptables -D FORWARD -i "$iface" -o wg-s2s -j ACCEPT \
		-m comment --comment "vpn2_transit_fwd" 2>/dev/null || true
	iptables -D FORWARD -i wg-s2s -o "$iface" -j ACCEPT \
		-m comment --comment "vpn2_transit_ret" 2>/dev/null || true
}

case "$action" in
	up)   apply_up ;;
	down) apply_down ;;
	*) echo "Usage: $0 up|down <iface>" >&2; exit 1 ;;
esac
