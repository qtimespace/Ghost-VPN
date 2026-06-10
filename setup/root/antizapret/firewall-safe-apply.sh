#!/bin/bash
#
# Безопасное применение firewall с авто-откатом (dead-man switch).
#
# Защищает от потери SSH-доступа при включении INPUT default-deny (up.sh):
# перед применением планируется отложенный откат через systemd-таймер,
# который вернёт политику INPUT в ACCEPT, если вы не подтвердите успех.
#
# Использование:
#   ./firewall-safe-apply.sh apply [timeout_sec]   # применить up.sh + запланировать откат (по умолчанию 120с)
#   ./firewall-safe-apply.sh confirm               # отменить откат (доступ подтверждён)
#   ./firewall-safe-apply.sh rollback              # немедленно вернуть INPUT в ACCEPT (вызывается таймером)
#   ./firewall-safe-apply.sh status                # показать состояние запланированного отката
#
# Рекомендуемый сценарий:
#   1) ./firewall-safe-apply.sh apply
#   2) НЕ закрывая текущую сессию, откройте НОВУЮ SSH-сессию и проверьте вход.
#   3) Если новая сессия работает:  ./firewall-safe-apply.sh confirm
#   4) Если связь пропала — ничего не делайте: через timeout откат вернёт доступ.
#
# Откат намеренно минимальный: только `iptables -P INPUT ACCEPT` (+IPv6).
# Это восстанавливает управление, НЕ затрагивая NAT/forwarding VPN-клиентов.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK_UNIT="ghost-fw-rollback"
DEFAULT_TIMEOUT=120

clear_scheduled() {
	systemctl stop "${ROLLBACK_UNIT}.timer" 2>/dev/null || true
	systemctl stop "${ROLLBACK_UNIT}.service" 2>/dev/null || true
	systemctl reset-failed "${ROLLBACK_UNIT}.service" "${ROLLBACK_UNIT}.timer" 2>/dev/null || true
}

apply() {
	command -v systemd-run >/dev/null || { echo "Error: systemd-run not found"; exit 1; }
	local timeout="${1:-$DEFAULT_TIMEOUT}"

	# Снять прошлый запланированный откат, если он остался
	clear_scheduled

	# Запланировать откат как transient systemd-юнит — переживёт обрыв SSH-сессии
	systemd-run --quiet --collect \
		--unit="$ROLLBACK_UNIT" --on-active="$timeout" \
		"$SCRIPT_DIR/firewall-safe-apply.sh" rollback

	echo "Rollback запланирован через ${timeout}с (unit: ${ROLLBACK_UNIT}.timer)."
	echo "Применяю новый firewall (up.sh)..."
	"$SCRIPT_DIR/up.sh"

	echo
	echo ">>> Откройте НОВУЮ SSH-сессию и проверьте вход (текущую не закрывайте)."
	echo ">>> Доступ есть:     $0 confirm"
	echo ">>> Доступа нет:     ждите ${timeout}с — откат вернёт INPUT ACCEPT автоматически."
}

confirm() {
	clear_scheduled
	echo "Откат отменён. Изменения firewall подтверждены."
}

rollback() {
	echo "ROLLBACK: возвращаю политику INPUT в ACCEPT..."
	iptables -w -P INPUT ACCEPT 2>/dev/null || true
	ip6tables -w -P INPUT ACCEPT 2>/dev/null || true
	echo "Готово. SSH-доступ восстановлен (INPUT ACCEPT). VPN NAT/forwarding не затронуты."
}

status() {
	echo "=== Запланированный откат (${ROLLBACK_UNIT}) ==="
	if systemctl is-active --quiet "${ROLLBACK_UNIT}.timer"; then
		systemctl list-timers "${ROLLBACK_UNIT}.timer" --no-pager 2>/dev/null || true
		echo "Статус: ОЖИДАЕТ — откат сработает по таймеру, если не вызвать confirm."
	else
		echo "Статус: нет активного отката."
	fi
	echo
	echo "=== Текущая политика INPUT ==="
	iptables -w -S INPUT | head -1
	ip6tables -w -S INPUT | head -1
}

case "${1:-}" in
	apply)    apply "${2:-}" ;;
	confirm)  confirm ;;
	rollback) rollback ;;
	status)   status ;;
	*)
		echo "Usage: $0 {apply [timeout_sec]|confirm|rollback|status}"
		exit 1
		;;
esac
