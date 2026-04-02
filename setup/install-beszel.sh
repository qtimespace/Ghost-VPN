#!/bin/bash
# Ghost-VPN: Установка Beszel мониторинга
# Запускать с deploy.sh или вручную
# Usage: MAIN_HOST=5.42.199.85 RELAY1_HOST=72.56.11.181 RELAY2_HOST=157.22.172.160 ./install-beszel.sh

set -e

BESZEL_VERSION="0.18.6"
BESZEL_HUB_URL="https://github.com/henrygd/beszel/releases/download/v${BESZEL_VERSION}/beszel_linux_amd64.tar.gz"
BESZEL_AGENT_URL="https://github.com/henrygd/beszel/releases/download/v${BESZEL_VERSION}/beszel-agent_linux_amd64.tar.gz"

MAIN_HOST="${MAIN_HOST:-5.42.199.85}"
MAIN_PASS="${MAIN_PASS:-}"
RELAY1_HOST="${RELAY1_HOST:-72.56.11.181}"
RELAY1_PASS="${RELAY1_PASS:-}"
RELAY2_HOST="${RELAY2_HOST:-157.22.172.160}"
RELAY2_PASS="${RELAY2_PASS:-}"

ssh_cmd() {
    local host="$1" pass="$2" cmd="$3"
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no root@"$host" "$cmd"
}

echo "=== Installing Beszel Hub on VPN3 ($MAIN_HOST) ==="
ssh_cmd "$MAIN_HOST" "$MAIN_PASS" "
    mkdir -p /opt/beszel
    curl -sL '$BESZEL_HUB_URL' | tar -xz -C /opt/beszel/
    curl -sL '$BESZEL_AGENT_URL' | tar -xz -C /opt/beszel/
    apt-get install -y nginx -q 2>/dev/null || true

    # Beszel Hub systemd unit
    cat > /etc/systemd/system/beszel.service << 'EOF'
[Unit]
Description=Beszel Hub
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/beszel
ExecStart=/opt/beszel/beszel serve --http 127.0.0.1:8090
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Nginx reverse proxy
    cat > /etc/nginx/sites-available/beszel << 'EOF'
server {
    listen 80;
    server_name www.qfenek.com qfenek.com;
    location / {
        proxy_pass http://127.0.0.1:8090/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
    ln -sf /etc/nginx/sites-available/beszel /etc/nginx/sites-enabled/beszel
    rm -f /etc/nginx/sites-enabled/default
    systemctl daemon-reload
    systemctl enable --now beszel
    systemctl restart nginx
    echo 'Hub started'
"

echo "=== Getting Hub SSH public key ==="
HUB_KEY=$(ssh_cmd "$MAIN_HOST" "$MAIN_PASS" "ssh-keygen -y -f /opt/beszel/beszel_data/id_ed25519 2>/dev/null || sleep 3 && ssh-keygen -y -f /opt/beszel/beszel_data/id_ed25519")
echo "Hub key: $HUB_KEY"

install_agent() {
    local host="$1" pass="$2" name="$3"
    echo "=== Installing Beszel Agent on $name ($host) ==="
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no root@"$host" "
        mkdir -p /opt/beszel
        curl -sL '$BESZEL_AGENT_URL' | tar -xz -C /opt/beszel/

        cat > /etc/systemd/system/beszel-agent.service << EOF
[Unit]
Description=Beszel Agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/beszel/beszel-agent -k \"${HUB_KEY}\" -l :45876
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now beszel-agent
        systemctl is-active beszel-agent && echo '$name agent OK' || echo '$name agent FAILED'
    "
}

install_agent "$MAIN_HOST" "$MAIN_PASS" "VPN3"
install_agent "$RELAY2_HOST" "$RELAY2_PASS" "VPN2"
install_agent "$RELAY1_HOST" "$RELAY1_PASS" "VPN1"

echo ""
echo "=== Beszel Installation Complete ==="
echo "Dashboard: http://$MAIN_HOST:8090/_/"
echo "Or via nginx: http://www.qfenek.com/"
echo ""
echo "Next steps:"
echo "1. Open http://www.qfenek.com/ and create admin account"
echo "2. Add systems in the UI:"
echo "   - VPN3: host=127.0.0.1 port=45876"
echo "   - VPN2: host=10.99.2.2 port=45876 (via wg-s2s)"
echo "   - VPN1: host=10.99.1.2 port=45876 (via wg-s2s, через VPN2)"
echo "3. Hub connects to agents via SSH on port 45876"
