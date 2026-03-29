# Ghost-VPN Architecture & Anti-Censorship Strategy

## Текущая архитектура (реализовано)

```text
Прямое подключение:
Client (Россия) --[OpenVPN UDP/TCP]--> VPN Server (за рубежом) --> Internet
                --[WireGuard UDP]----> VPN Server (за рубежом) --> Internet

Через relay цепочку (WireGuard site-to-site шифрование между серверами):
Client --[OpenVPN]--> VPN1 (relay) --[WireGuard s2s]--> VPN2 (relay, опц.) --[WireGuard s2s]--> VPN3 (main)
```

### Серверы (текущая конфигурация)

| Сервер | IP | Роль | Расположение |
|--------|-----|------|-------------|
| VPN1 | 72.56.11.181 | Relay + deploy-машина | Timeweb, Россия |
| VPN2 | 157.22.172.160 | Relay (опциональный) | imody.ru, Россия |
| VPN3 | 5.42.199.85 | Main VPN | Германия |

### WireGuard Site-to-Site

- Порт: 51820 UDP (отдельно от клиентских 51443/51080)
- Интерфейс: `wg-s2s` (на VPN2 также `wg-s2s-up`)
- IP-адресация: 10.99.1.0/30 (VPN1↔next), 10.99.2.0/30 (VPN2↔VPN3)
- MTU: 1420
- PresharedKey: да (post-quantum защита)
- Relay использует iptables DNAT к tunnel IP + SNAT от tunnel IP

## Целевая архитектура: Multi-hop + VLESS

### Основная схема

```text
┌──────────┐   VLESS+Reality:443   ┌──────────┐   WireGuard:51443   ┌──────────┐
│  Client  │ ────────────────────> │   VPN1   │ ──────────────────> │   VPN2   │ -> Internet
│ (Россия) │  маскировка HTTPS     │ (relay)  │  внутри туннеля     │(AntiZapret)│
└──────────┘  DPI видит HTTPS      └──────────┘  DPI не видит       └──────────┘
```

### Fallback-цепочка (при усилении блокировок)

| Уровень | Транспорт первого хопа | Когда использовать |
|---------|------------------------|--------------------|
| 1 | OpenVPN UDP + anti-DPI патч | Базовый уровень, работает при блокировке по протоколу |
| 2 | OpenVPN TCP через SOCKS5 | Если UDP заблокирован |
| 3 | OpenVPN TCP через stunnel (TLS) | Если SOCKS5 детектируется |
| 4 | VLESS + XTLS-Reality | Whitelist DPI, SNI-фильтрация, active probing |

---

## WireGuard vs OpenVPN: когда что использовать

| Критерий | OpenVPN | WireGuard |
|----------|---------|-----------|
| DPI-устойчивость | Высокая (с патчем/обфускацией) | Нулевая (фиксированный формат) |
| Throughput | 200-400 Мбит/с | 800-950 Мбит/с |
| Latency overhead | 2-5 мс | 0.5-1 мс |
| CPU нагрузка | Высокая | Минимальная |
| Кодовая база | ~100K строк + OpenSSL | ~4K строк |
| Обфускация | Патч, stunnel, obfs4, VLESS | Только через обёртки |
| TCP поддержка | Да | Нет (только UDP) |
| NAT traversal | Средне | Отлично |

**Вывод:**

- **Первый хоп (Client -> VPN1):** OpenVPN с обфускацией. DPI видит этот участок.
- **Второй хоп (VPN1 -> VPN2):** WireGuard. Внутри туннеля обфускация не нужна, нужна скорость.

---

## Методы обхода DPI: сводная таблица

| Метод | Сложность | DPI-устойчивость | Overhead | Статус |
|-------|-----------|-------------------|----------|--------|
| OpenVPN UDP + патч | 1/5 | 3/5 | Минимальный | Реализовано |
| SOCKS5 proxy | 2/5 | 2/5 | ~5% | Планируется |
| stunnel (TLS-обёртка) | 2/5 | 3/5 | ~15% | Планируется |
| **VLESS + Reality** | **3/5** | **5/5** | **~3%** | **Приоритет** |
| Shadowsocks/Outline | 2/5 | 3/5 | ~5% | Альтернатива |
| Domain fronting | 4/5 | 2/5 | Высокий | Не рекомендуется |
| obfs4 | 4/5 | 4/5 | ~10% | Слишком сложно |

---

## План внедрения

### Этап 1: SOCKS5 поддержка (быстрый)

1. Добавить в клиентские шаблоны OpenVPN TCP директиву `socks-proxy`
2. Установить `microsocks` на relay-сервере
3. Модифицировать `proxy.sh` для установки microsocks

**Конфигурация клиента:**

```text
socks-proxy <relay-ip> 1080
remote <vpn-server-ip> 50443 tcp4
```

### Этап 2: VLESS + Reality (основной)

1. Установить Xray-core на VPN-сервер
2. Xray слушает порт 443 (забрать у OpenVPN fallback)
3. OpenVPN TCP переводится на `local 127.0.0.1:50443`
4. Xray проксирует VLESS -> OpenVPN на localhost
5. Генерация Reality-ключей: `xray x25519`
6. Целевые домены для маскировки: `www.microsoft.com`, `dl.google.com`

**Архитектура на сервере:**

```text
Internet:443 -> Xray (VLESS+Reality) -> 127.0.0.1:50443 (OpenVPN TCP)
Internet:50080 -> OpenVPN UDP (с патчем, прямое подключение)
Internet:51443 -> WireGuard (прямое подключение)
```

**Xray конфигурация (основа):**

```json
{
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "<uuid>", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "www.microsoft.com:443",
        "serverNames": ["www.microsoft.com"],
        "privateKey": "<key>",
        "shortIds": ["<id>"]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom", "settings": {"redirect": "127.0.0.1:50443"}}]
}
```

### Этап 3: Multi-hop VPN ✅ Реализовано

WireGuard site-to-site туннели между relay и main серверами.
Реализовано в `deploy.sh` (функция `setup_s2s_wireguard()`) и `proxy.sh`.

Подробности в секции "Текущая архитектура" выше.

---

## Противодействие Whitelist DPI

При самом жёстком сценарии (разрешены только HTTPS к известным доменам):

1. **VLESS + Reality** -- единственный метод, выдерживающий active probing
2. SNI указывает на домен из белого списка
3. TLS-fingerprint имитирует Chrome/Firefox (uTLS в Xray)
4. При active probing цензора -- сервер возвращает ответ реального сайта

**Что НЕ работает при whitelist DPI:**

- Shadowsocks (случайный трафик блокируется)
- stunnel без valid SNI (самоподписанный сертификат)
- WireGuard (любой)
- OpenVPN (любой, включая патч)
- Domain fronting (CDN-провайдеры отключили)

---

## Рекомендации по безопасности

1. **Исправить `srand(time(NULL))`** в anti-DPI патче на `/dev/urandom`
2. **Добавить `tls-crypt`** в конфигурацию OpenVPN (шифрует TLS-хендшейк)
3. **Включить `port-share`** для OpenVPN TCP + nginx (защита от active probing)
4. Использовать **разные UUID/ключи** для каждого клиента VLESS
5. Регулярно ротировать целевой домен Reality (shortIds позволяют это)
