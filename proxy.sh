#!/bin/bash
set -euo pipefail

# Обработка ошибок
handle_error() {
	echo "$(lsb_release -ds 2>/dev/null || echo Unknown) $(uname -r) $(date --iso-8601=seconds 2>/dev/null || date)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

# Проверка необходимости перезагрузить
if [[ -f /var/run/reboot-required ]] || pidof apt apt-get dpkg unattended-upgrades >/dev/null 2>&1; then
	echo 'Error: You need to reboot this server before installation!'
	exit 2
fi

# Проверка прав root
if [[ "$EUID" -ne 0 ]]; then
	echo 'Error: You need to run this as root!'
	exit 3
fi

cd /root

# Проверка на OpenVZ и LXC
if [[ "$(systemd-detect-virt)" == 'openvz' || "$(systemd-detect-virt)" == 'lxc' ]]; then
	echo 'Error: OpenVZ and LXC are not supported!'
	exit 4
fi

# Проверка версии системы
OS="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
VERSION="$(lsb_release -rs | cut -d '.' -f1)"

if [[ "$OS" == 'debian' ]]; then
	if (( VERSION < 12 )); then
		echo "Error: Debian $VERSION is not supported! Minimal supported version is 12"
		exit 5
	fi
elif [[ "$OS" == 'ubuntu' ]]; then
	if (( VERSION < 22 )); then
		echo "Error: Ubuntu $VERSION is not supported! Minimal supported version is 22"
		exit 6
	fi
else
	echo "Error: Your Linux distribution ($OS) is not supported!"
	exit 7
fi

DEFAULT_INTERFACE="$(ip route get 1.2.3.4 2>/dev/null | grep -oP 'dev \K\S+')"
if [[ -z "$DEFAULT_INTERFACE" ]]; then
	echo 'Default network interface not found!'
	exit 8
fi

DEFAULT_IP="$(ip route get 1.2.3.4 2>/dev/null | grep -oP 'src \K\S+')"
if [[ -z "$DEFAULT_IP" ]]; then
	echo 'Default IPv4 address not found!'
	exit 9
fi

echo
echo -e '\e[1;32mInstalling proxy for AntiZapret VPN server\e[0m'
echo 'Proxied ports: 80, 443, 504, 508, 540, 580, 50080, 50443, 51080, 51443'
echo 'More details: https://github.com/qtimespace/Ghost-VPN'
echo

MTU=$(< /sys/class/net/$DEFAULT_INTERFACE/mtu)
if (( MTU < 1500 )); then
	echo "Warning! Low MTU on $DEFAULT_INTERFACE: $MTU"
	echo "Change MTU in OpenVPN and WireGuard configs from 1420 to $((MTU-80)) on AntiZapret VPN server"
	echo
fi

# Спрашиваем о настройках
while read -rp 'Enter AntiZapret VPN server IPv4 address: ' -e DESTINATION_IP
do
	[[ -n $(getent ahostsv4 "$DESTINATION_IP") ]] || continue
	break
done
echo
until [[ "$SSH_PROTECTION" =~ (y|n) ]]; do
	read -rp 'Enable SSH brute-force protection? [y/n]: ' -e -i y SSH_PROTECTION
done
echo
until [[ "$SCAN_PROTECTION" =~ (y|n) ]]; do
	read -rp 'Enable scan protection? [y/n]: ' -e -i y SCAN_PROTECTION
done
echo
echo 'Installation, please wait...'

# Удалим ненужные службы (|| true — пакет может быть не установлен)
apt-get purge -y ufw firewalld apparmor apport modemmanager snapd \
	upower multipath-tools rsyslog udisks2 qemu-guest-agent tuned \
	sysstat acpid fwupd watchdog pcscd packagekit 2>/dev/null || true

# SSH protection включён
if [[ "$SSH_PROTECTION" == 'y' ]]; then
	apt-get purge -y fail2ban sshguard 2>/dev/null || true
fi

# Отключим IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1

# Удаляем переопределённые параметры ядра
sed -i '/^$/!{/^#/!d}' /etc/sysctl.conf

# Принудительная загрузка модуля nf_conntrack
echo 'nf_conntrack' > /etc/modules-load.d/nf_conntrack.conf

# Автоматически сохраним правила iptables
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections

# Обновляем систему и ставим необходимые пакеты
export DEBIAN_FRONTEND=noninteractive
apt-get clean
apt-get update
dpkg --configure -a
apt-get install --fix-broken -y
apt-get dist-upgrade -y
apt-get install -y iptables iptables-persistent irqbalance unattended-upgrades wireguard conntrack ethtool jq
apt-get autoremove --purge -y
apt-get clean
dpkg-reconfigure -f noninteractive unattended-upgrades

# Изменим параметры для прокси
echo "# Proxy parameters modification
kernel.printk=3 4 1 3
kernel.panic=1
kernel.panic_on_oops=1
kernel.softlockup_panic=0
kernel.hardlockup_panic=0
kernel.sched_autogroup_enabled=0
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_mtu_probing=1
net.core.rmem_max=6291456
net.core.wmem_max=6291456
net.ipv4.tcp_rmem=16384 131072 6291456
net.ipv4.tcp_wmem=16384 131072 6291456
net.ipv4.tcp_no_metrics_save=1
net.core.netdev_budget=600
net.ipv4.tcp_fastopen=1
net.ipv4.ip_local_port_range=32768 49999
net.netfilter.nf_conntrack_max=131072
net.core.netdev_budget_usecs=8000
net.core.dev_weight=64
net.ipv4.tcp_max_syn_backlog=1024
net.netfilter.nf_conntrack_buckets=32768
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.core.netdev_max_backlog=10000
net.core.somaxconn=4096
net.ipv4.tcp_syncookies=1
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.core.optmem_max=20480
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_tw_reuse=0
net.ipv4.tcp_slow_start_after_idle=0
net.netfilter.nf_conntrack_tcp_timeout_established=86400
net.core.rmem_default=262144
net.core.wmem_default=262144
net.ipv4.tcp_base_mss=1024
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0" > /etc/sysctl.d/99-proxy.conf

# Отключим IPv6
echo "# Disable IPv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1" > /etc/sysctl.d/99-disable-ipv6.conf

# WireGuard site-to-site туннель
S2S_CONF="/etc/wireguard/wg-s2s.conf"
if [[ -f "$S2S_CONF" ]]; then
	echo 'Activating WireGuard site-to-site tunnel...'
	# Выключим если уже был поднят (переустановка)
	wg-quick down wg-s2s 2>/dev/null || true
	wg-quick up wg-s2s
	systemctl enable wg-quick@wg-s2s

	# Извлекаем tunnel IP для DNAT/SNAT
	LOCAL_TUNNEL_IP="$(grep -oP 'Address\s*=\s*\K[0-9.]+' "$S2S_CONF")"
	# Tunnel destination — передаётся через env или вычисляется из конфига
	if [[ -z "$TUNNEL_DESTINATION_IP" ]]; then
		# Вычисляем peer IP из AllowedIPs или Endpoint
		TUNNEL_DESTINATION_IP="$(grep -oP 'AllowedIPs\s*=\s*\K[0-9.]+' "$S2S_CONF" | head -1)"
		# Для клиентского конфига (AllowedIPs=0.0.0.0/0) берём из Endpoint
		if [[ "$TUNNEL_DESTINATION_IP" == "0" || -z "$TUNNEL_DESTINATION_IP" ]]; then
			# /30 подсеть: .2 -> .1, .1 -> .2
			local_last_octet="${LOCAL_TUNNEL_IP##*.}"
			base_ip="${LOCAL_TUNNEL_IP%.*}"
			if [[ "$local_last_octet" == "2" ]]; then
				TUNNEL_DESTINATION_IP="${base_ip}.1"
			else
				TUNNEL_DESTINATION_IP="${base_ip}.2"
			fi
		fi
	fi
	# Поднимаем upstream tunnel если есть (VPN2: wg-s2s-up → VPN3)
	S2S_UP_CONF="/etc/wireguard/wg-s2s-up.conf"
	if [[ -f "$S2S_UP_CONF" ]]; then
		echo 'Activating upstream WireGuard tunnel (wg-s2s-up)...'
		wg-quick down wg-s2s-up 2>/dev/null || true
		wg-quick up wg-s2s-up
		systemctl enable wg-quick@wg-s2s-up
		# SNAT source — upstream tunnel IP (для ответов от VPN3 обратно)
		LOCAL_TUNNEL_IP="$(grep -oP 'Address\s*=\s*\K[0-9.]+' "$S2S_UP_CONF")"
	fi

	echo "  Tunnel: ${LOCAL_TUNNEL_IP} → ${TUNNEL_DESTINATION_IP}"
	DNAT_TARGET="$TUNNEL_DESTINATION_IP"
	SNAT_SOURCE="$LOCAL_TUNNEL_IP"

	# VPN2 transit routing: если есть wg-s2s-up, настраиваем пересылку
	# VPN3 → wg-s2s-up → VPN2 → wg-s2s → VPN1 (Gotcha #33, #42)
	if [[ -f "$S2S_UP_CONF" ]]; then
		echo 'Setting up VPN2 transit routing (wg-s2s-up → wg-s2s)...'
		local up_subnet
		up_subnet="$(grep -oP 'Address\s*=\s*\K[0-9.]+/[0-9]+' "$S2S_UP_CONF" | head -1)"
		up_subnet="${up_subnet%.*}.0/30"
		# Skip local: ответные VPN-пакеты не маркировать (Gotcha #42)
		iptables -w -t mangle -I PREROUTING 1 -i wg-s2s-up -d "$up_subnet" -j RETURN \
			-m comment --comment "vpn2_skip_local"
		# Transit mark: весь остальной трафик с wg-s2s-up → fwmark 0x4
		iptables -w -t mangle -A PREROUTING -i wg-s2s-up -j MARK --set-mark 0x4 \
			-m comment --comment "vpn2_transit"
		# Policy routing: fwmark 0x4 → table 200 → default dev wg-s2s
		ip rule add fwmark 0x4 lookup 200 priority 100 2>/dev/null || true
		ip route add default dev wg-s2s table 200 2>/dev/null || true
		# rp_filter off для WG tunnel interfaces
		sysctl -qw net.ipv4.conf.wg-s2s.rp_filter=0
		sysctl -qw net.ipv4.conf.wg-s2s-up.rp_filter=0
		# FORWARD правила для transit
		iptables -w -I FORWARD 1 -i wg-s2s-up -o wg-s2s -j ACCEPT \
			-m comment --comment "vpn2_transit_fwd"
		iptables -w -I FORWARD 2 -i wg-s2s -o wg-s2s-up -j ACCEPT \
			-m comment --comment "vpn2_transit_ret"
	fi
else
	echo 'No WireGuard s2s config found, using direct DNAT to public IP'
	DNAT_TARGET="$DESTINATION_IP"
	SNAT_SOURCE="$DEFAULT_IP"
fi

# Очистка правил iptables
iptables -w -F
iptables -w -t nat -F
iptables -w -t mangle -F
iptables -w -t raw -F
ip6tables -w -F
ip6tables -w -t nat -F
ip6tables -w -t mangle -F
ip6tables -w -t raw -F

# Новые правила iptables
# filter
# Default policy
iptables -w -P INPUT ACCEPT
iptables -w -P FORWARD ACCEPT
iptables -w -P OUTPUT ACCEPT
ip6tables -w -P INPUT ACCEPT
ip6tables -w -P FORWARD ACCEPT
ip6tables -w -P OUTPUT ACCEPT
# INPUT connection tracking
iptables -w -I INPUT 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I INPUT 1 -m conntrack --ctstate INVALID -j DROP
# FORWARD connection tracking
iptables -w -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
# OUTPUT connection tracking
iptables -w -I OUTPUT 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I OUTPUT 1 -m conntrack --ctstate INVALID -j DROP
# SSH protection
if [[ "$SSH_PROTECTION" == 'y' ]]; then
	iptables -w -I INPUT 2 -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 5/hour --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name proxy-ssh --hashlimit-htable-expire 60000 -j DROP
	ip6tables -w -I INPUT 2 -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 5/hour --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name proxy-ssh6 --hashlimit-htable-expire 60000 -j DROP
fi
# Scan protection
if [[ "$SCAN_PROTECTION" == 'y' ]]; then
	iptables -w -I INPUT 2 -i $DEFAULT_INTERFACE -p icmp --icmp-type echo-request -j DROP
	iptables -w -I OUTPUT 2 -o $DEFAULT_INTERFACE -p tcp --tcp-flags RST RST -j DROP
	iptables -w -I OUTPUT 3 -o $DEFAULT_INTERFACE -p icmp --icmp-type port-unreachable -j DROP
	ip6tables -w -I INPUT 2 -i $DEFAULT_INTERFACE -p icmpv6 --icmpv6-type echo-request -j DROP
	ip6tables -w -I OUTPUT 2 -o $DEFAULT_INTERFACE -p tcp --tcp-flags RST RST -j DROP
	ip6tables -w -I OUTPUT 3 -o $DEFAULT_INTERFACE -p icmpv6 --icmpv6-type port-unreachable -j DROP
fi

# mangle
# Clamp TCP MSS
iptables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# nat
# OpenVPN TCP
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp --dport 80 -j DNAT --to-destination $DNAT_TARGET:80
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp --dport 443 -j DNAT --to-destination $DNAT_TARGET:443
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp --dport 504 -j DNAT --to-destination $DNAT_TARGET:504
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp --dport 508 -j DNAT --to-destination $DNAT_TARGET:508
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp --dport 50080 -j DNAT --to-destination $DNAT_TARGET:50080
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp --dport 50443 -j DNAT --to-destination $DNAT_TARGET:50443
# OpenVPN UDP
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 80 -j DNAT --to-destination $DNAT_TARGET:80
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 443 -j DNAT --to-destination $DNAT_TARGET:443
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 504 -j DNAT --to-destination $DNAT_TARGET:504
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 508 -j DNAT --to-destination $DNAT_TARGET:508
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 50080 -j DNAT --to-destination $DNAT_TARGET:50080
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 50443 -j DNAT --to-destination $DNAT_TARGET:50443
# WireGuard (клиентские порты)
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 540 -j DNAT --to-destination $DNAT_TARGET:540
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 580 -j DNAT --to-destination $DNAT_TARGET:580
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 51080 -j DNAT --to-destination $DNAT_TARGET:51080
iptables -w -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p udp --dport 51443 -j DNAT --to-destination $DNAT_TARGET:51443
# SNAT
iptables -w -t nat -A POSTROUTING -d "$DNAT_TARGET" -j SNAT --to-source "$SNAT_SOURCE"

# Сброс счётчиков
iptables -w -Z
iptables -w -t nat -Z
iptables -w -t mangle -Z
iptables -w -t raw -Z
ip6tables -w -Z
ip6tables -w -t nat -Z
ip6tables -w -t mangle -Z
ip6tables -w -t raw -Z

# VPN1 bypass: MASQUERADE для трафика wg-s2s → eth0 (Gotcha #39)
# Только на relay БЕЗ wg-s2s-up (VPN1, не VPN2)
if [[ -f /etc/wireguard/wg-s2s.conf && ! -f /etc/wireguard/wg-s2s-up.conf ]]; then
	if [[ -f /etc/systemd/system/bypass-vpn1.service && -x /root/antizapret/bypass-vpn1.sh ]]; then
		echo 'Enabling bypass-vpn1.service (VPN1 MASQUERADE persistence)...'
		systemctl daemon-reload
		systemctl enable bypass-vpn1.service
		systemctl start bypass-vpn1.service || true
	else
		echo 'WARNING: bypass-vpn1.service or bypass-vpn1.sh missing — skipping'
	fi
fi

# Сохранение новых правил iptables
netfilter-persistent save
systemctl enable netfilter-persistent

# Перезагружаем
echo
echo -e '\e[1;32mProxy for AntiZapret VPN server installed successfully!\e[0m'
echo 'Rebooting...'

reboot