#!/bin/bash

# ==========================================
# MATRIX SYNAPSE + ELEMENT CALL INSTALLER (V4.1)
# Tested on Ubuntu 22.04 / Debian 11+
# ==========================================

# --- НАСТРОЙКИ ПОЛЬЗОВАТЕЛЯ (РЕДАКТИРОВАТЬ ЗДЕСЬ) ---
DOMAIN="broadwall.ru"                 # Ваш домен (без https://)
MATRIX_DOMAIN="matrix.broadwall.ru"   # Мессенджер
LIVEKIT_DOMAIN="livekit.broadwall.ru" # Element Call
SYNOPTIC_DOMAIN="synoptic.broadwall.ru" # админка
EMAIL="al-programmist@yandex.ru"      # Почта для SSL
DB_PASS="StrongPass_$(openssl rand -hex 4)" # Пароль для БД

# Белый список доменов для федерации
WHITELIST_DOMAINS=()

# ==========================================
# ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
# ==========================================

REG_SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
TURN_SECRET=$(openssl rand -base64 32)
LIVEKIT_API_KEY=$(openssl rand -hex 16)
LIVEKIT_API_SECRET=$(openssl rand -hex 32)

# ==========================================
# ФУНКЦИИ
# ==========================================

log() {
    echo -e "\n\e[1;34m>>> $1\e[0m"
}

error() {
    echo -e "\e[1;31mОШИБКА: $1\e[0m"
    exit 1
}

check_success() {
    if [ $? -ne 0 ]; then
        error "$1"
    fi
}

# ==========================================
# НАЧАЛО СКРИПТА
# ==========================================

log "НАЧАЛО УСТАНОВКИ ДЛЯ: $DOMAIN"
log "Пароль БД: $DB_PASS"
log "LiveKit API Key: $LIVEKIT_API_KEY"

# 1. Проверка прав
if [[ $EUID -ne 0 ]]; then
    error "Этот скрипт должен быть запущен с правами root"
fi

# 2. Подготовка системы
log "Обновление системы..."
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt full-upgrade -y
check_success "Не удалось обновить систему"

log "Установка базовых пакетов..."
apt install -y curl wget lsb-release gnupg2 ufw apt-transport-https ca-certificates \
    git build-essential pkg-config libssl-dev nodejs npm yarn postgresql postgresql-contrib \
    redis-server python3-pip python3-venv libpq-dev
check_success "Не удалось установить базовые пакеты"

# 3. Настройка SSH
log "Настройка SSH..."

BACKUP_FILE="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
cp /etc/ssh/sshd_config "$BACKUP_FILE"

cat > /etc/ssh/sshd_config << 'EOF'
Port 4741
Protocol 2

PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

AllowUsers supervisor
DenyUsers root

MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
PermitEmptyPasswords no

X11Forwarding no
PrintMotd no
PrintLastLog yes

TCPKeepAlive yes
AllowTcpForwarding yes

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

UseDNS no
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
Compression no

SyslogFacility AUTH
LogLevel INFO

AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
EOF

sshd -t
systemctl daemon-reload
systemctl restart sshd
check_success "Ошибка настройки SSH"

# 4. Настройка Firewall
log "Настройка Firewall..."
ufw allow 4741/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8448/tcp
ufw allow 3478/tcp
ufw allow 3478/udp
ufw allow 5349/tcp
ufw allow 5349/udp
ufw allow 7880/tcp  # LiveKit
ufw allow 7881/tcp  # LiveKit TLS
ufw allow 7890/tcp  # LiveKit metrics
ufw allow 49152:65535/udp
ufw allow 50000:60000/tcp
ufw --force enable

# 5. Установка Nginx & Certbot
log "Установка Nginx и Certbot..."
apt install -y nginx certbot python3-certbot-nginx
check_success "Не удалось установить Nginx"

# Массив всех доменов
DOMAINS=("$DOMAIN" "$MATRIX_DOMAIN" "$LIVEKIT_DOMAIN" "$SYNOPTIC_DOMAIN")

# Функция для создания заглушки
create_stub_page() {
    local site_name="$1"
    local domain="$2"
    local stub_dir="/var/www/html/$domain"
    
    mkdir -p "$stub_dir"
    cat > "$stub_dir/index.html" <<EOF
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$site_name</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            padding: 20px;
        }
        .container {
            text-align: center;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 50px;
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            max-width: 600px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        h1 {
            font-size: 3rem;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        p {
            font-size: 1.2rem;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        .status {
            display: inline-block;
            background: rgba(76, 175, 80, 0.8);
            padding: 10px 30px;
            border-radius: 50px;
            font-weight: bold;
            margin: 20px 0;
            animation: pulse 2s infinite;
        }
        .domain {
            color: #ffeb3b;
            font-weight: bold;
            font-size: 1.3rem;
            margin-top: 10px;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>$site_name</h1>
        <p>Сервис находится в процессе настройки и скоро будет доступен.</p>
        <div class="status">● В разработке</div>
        <p class="domain">Домен: $domain</p>
    </div>
</body>
</html>
EOF
}

# Создание заглушек для всех сайтов
for domain in "${DOMAINS[@]}"; do
    case "$domain" in
        "broadwall.ru")
            create_stub_page "Broadwall Portal" "$domain"
            ;;
        "matrix.broadwall.ru")
            create_stub_page "Matrix Messenger" "$domain"
            ;;
        "livekit.broadwall.ru")
            create_stub_page "Element Call" "$domain"
            ;;
        "synoptic.broadwall.ru")
            create_stub_page "Synoptic Admin" "$domain"
            ;;
    esac
done

# Временные конфиги для получения сертификатов
for domain in "${DOMAINS[@]}"; do
    cat > "/etc/nginx/sites-available/$domain" <<EOF
server {
    server_name $domain;
    listen 80;
    listen [::]:80;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html/$domain;
    }
    
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
    
    ln -sf "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/"
done

rm -f /etc/nginx/sites-enabled/default
systemctl reload nginx

# Получение сертификатов
log "Получение SSL сертификатов..."
for domain in "${DOMAINS[@]}"; do
    log "Получение сертификата для $domain..."
    certbot certonly --nginx -d "$domain" --non-interactive --agree-tos -m "$EMAIL"
done

# 6. Настройка PostgreSQL
log "Настройка PostgreSQL..."
sudo -u postgres psql -c "CREATE USER synapse WITH PASSWORD '$DB_PASS';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE synapse OWNER synapse;" 2>/dev/null || true
sudo -u postgres psql -c "ALTER USER synapse CREATEDB;" 2>/dev/null || true

# Создание БД для LiveKit
sudo -u postgres psql -c "CREATE USER livekit WITH PASSWORD '${LIVEKIT_API_SECRET}';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE livekit OWNER livekit;" 2>/dev/null || true

# 7. Установка Matrix Synapse
log "Установка Matrix Synapse..."
wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/matrix-org.list
apt update

echo "matrix-synapse-py3 matrix-synapse/server-name string $MATRIX_DOMAIN" | debconf-set-selections
echo "matrix-synapse-py3 matrix-synapse/report-stats boolean false" | debconf-set-selections
apt install -y matrix-synapse-py3

# Конфигурация Synapse
CONFIG_FILE="/etc/matrix-synapse/homeserver.yaml"
sed -i 's/^database:/#database:/' $CONFIG_FILE
sed -i 's/^  name: sqlite3/#  name: sqlite3/' $CONFIG_FILE
sed -i 's/^  args:/#  args:/' $CONFIG_FILE
sed -i 's/^    database: \/var\/lib/#    database: \/var\/lib/' $CONFIG_FILE

cat >> $CONFIG_FILE <<EOF

# --- AUTO CONFIG V4 ---
enable_registration: false
enable_registration_without_verification: true
registration_shared_secret: "$REG_SECRET"

# Настройка базы данных Postgres
database:
  name: psycopg2
  args:
    user: synapse
    password: "$DB_PASS"
    database: synapse
    host: localhost
    cp_min: 5
    cp_max: 10
  allow_unsafe_locale: true

# Настройка TURN для звонков
turn_shared_secret: "$TURN_SECRET"
turn_uris: ["turn:$MATRIX_DOMAIN:3478?transport=udp", "turn:$MATRIX_DOMAIN:3478?transport=tcp"]
turn_user_lifetime: 86400000
turn_allow_guests: true

# Настройка интеграции с Element Call
turn_uris: [
  "turn:$LIVEKIT_DOMAIN:3478?transport=udp",
  "turn:$LIVEKIT_DOMAIN:3478?transport=tcp",
  "turns:$LIVEKIT_DOMAIN:5349?transport=tcp"
]

# Widget для Element Call
widgets:
  - platforms: ["web"]
    path: "/_matrix/app/v1"
    url: "https://$LIVEKIT_DOMAIN"
    allow_guest_access: true
EOF

# Whitelist
if [ ${#WHITELIST_DOMAINS[@]} -gt 0 ]; then
    echo "federation_domain_whitelist:" >> $CONFIG_FILE
    for d in "${WHITELIST_DOMAINS[@]}"; do
        echo "  - \"$d\"" >> $CONFIG_FILE
    done
fi

systemctl restart matrix-synapse
check_success "Ошибка запуска Matrix Synapse"

# 8. Установка Coturn
log "Установка Coturn..."
apt install -y coturn

cat > /etc/turnserver.conf <<EOF
listening-port=3478
tls-listening-port=5349
fingerprint
use-auth-secret
static-auth-secret=$TURN_SECRET
realm=$MATRIX_DOMAIN
cert=/etc/letsencrypt/live/$MATRIX_DOMAIN/fullchain.pem
pkey=/etc/letsencrypt/live/$MATRIX_DOMAIN/privkey.pem
no-multicast-peers
user-quota=100
total-quota=1200
syslog
no-cli
EOF

sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
systemctl restart coturn
check_success "Ошибка запуска Coturn"

# 9. Установка LiveKit (Element Call Backend)
log "Установка LiveKit Backend..."

# Установка Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile

# Создание пользователя для LiveKit
useradd -r -s /bin/false livekit

# Установка LiveKit Server
LIVEKIT_VERSION="1.5.6"
wget "https://github.com/livekit/livekit/releases/download/v${LIVEKIT_VERSION}/livekit_${LIVEKIT_VERSION}_linux_amd64.tar.gz"
tar -xzf livekit_${LIVEKIT_VERSION}_linux_amd64.tar.gz
mv livekit-server /usr/local/bin/
chmod +x /usr/local/bin/livekit-server

# Создание директорий
mkdir -p /etc/livekit /var/log/livekit /var/lib/livekit
chown -R livekit:livekit /var/log/livekit /var/lib/livekit

# Конфигурация LiveKit
cat > /etc/livekit/livekit.yaml <<EOF
port: 7880
bind_addresses:
  - "127.0.0.1"
rtc:
  tcp_port: 7880
  port_range_start: 50000
  port_range_stop: 60000
  use_external_ip: true
  enable_loopback_candidate: true
  
redis:
  address: "localhost:6379"
  
keys:
  "${LIVEKIT_API_KEY}": "${LIVEKIT_API_SECRET}"

logging:
  level: info
  
turn:
  enabled: true
  domain: "${LIVEKIT_DOMAIN}"
  tls_port: 5349
  external_tls: true
  cert_file: "/etc/letsencrypt/live/${LIVEKIT_DOMAIN}/fullchain.pem"
  key_file: "/etc/letsencrypt/live/${LIVEKIT_DOMAIN}/privkey.pem"

analytics:
  disabled: true
EOF

# Systemd служба для LiveKit
cat > /etc/systemd/system/livekit.service <<EOF
[Unit]
Description=LiveKit Server
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=livekit
Group=livekit
Environment=GOMAXPROCS=2
ExecStart=/usr/local/bin/livekit-server \
  --config /etc/livekit/livekit.yaml \
  --dev \
  --bind "0.0.0.0:7880"
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=livekit
LimitNOFILE=65536

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/livekit /var/lib/livekit
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable livekit
systemctl start livekit
check_success "Ошибка запуска LiveKit"

# 10. Установка Element Call Frontend
log "Установка Element Call Frontend..."

# Установка Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Установка зависимостей для сборки
apt install -y build-essential python3

# Клонирование и сборка Element Call
cd /opt
git clone https://github.com/element-hq/element-call.git
chown -R $SUDO_USER:$SUDO_USER element-call
cd element-call

# Конфигурация Element Call
cat > .env <<EOF
VITE_LIVEKIT_URL=wss://${LIVEKIT_DOMAIN}
VITE_LK_SERVER_URL=https://${LIVEKIT_DOMAIN}
VITE_APP_NAME=Element Call
VITE_DEFAULT_SERVER=https://${MATRIX_DOMAIN}
VITE_HOMESERVER_NAME=${DOMAIN}
EOF

# Установка зависимостей и сборка
sudo -u $SUDO_USER npm install
sudo -u $SUDO_USER npm run build

# Копирование собранных файлов
cp -r dist/* /var/www/html/$LIVEKIT_DOMAIN/

# 11. Финальная настройка Nginx (ИСПРАВЛЕННЫЙ РАЗДЕЛ)
log "Финальная настройка Nginx..."

# Обновление конфигов для всех доменов
for domain in "${DOMAINS[@]}"; do
    if [ "$domain" = "$MATRIX_DOMAIN" ]; then
        cat > "/etc/nginx/sites-available/$domain" <<EOF
server {
    server_name $domain;
    listen 80;
    listen [::]:80;
    return 301 https://\$host\$request_uri;
}

server {
    server_name $domain;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    listen 8448 ssl;
    listen [::]:8448 ssl;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    root /var/www/html/$domain;
    index index.html;

    location /.well-known/matrix/client {
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "https://$domain"}}';
    }
    
    location /.well-known/matrix/server {
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.server": "$domain:443"}';
    }

    location ~ ^(/_matrix|/_synapse/client) {
        proxy_pass http://localhost:8008;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;
        client_max_body_size 50M;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    elif [ "$domain" = "$LIVEKIT_DOMAIN" ]; then
        cat > "/etc/nginx/sites-available/$domain" <<EOF
server {
    server_name $domain;
    listen 80;
    listen [::]:80;
    return 301 https://\$host\$request_uri;
}

server {
    server_name $domain;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Frontend Element Call
    location / {
        root /var/www/html/$domain;
        index index.html;
        try_files \$uri \$uri/ /index.html;
        
        # CORS headers
        add_header Access-Control-Allow-Origin "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range" always;
        add_header Access-Control-Expose-Headers "Content-Length,Content-Range" always;
    }

    # LiveKit WebSocket
    location ~ ^/(socket|rtc|livekit) {
        proxy_pass http://127.0.0.1:7880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket timeouts
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # LiveKit API
    location /twirp {
        proxy_pass http://127.0.0.1:7880;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    else
        # КОНФИГУРАЦИЯ ДЛЯ ОСНОВНОГО ДОМЕНА (broadwall.ru) И SYNOPTIC
        # ГЛАВНОЕ ИСПРАВЛЕНИЕ: Добавлен блок location для .well-known/matrix/client
        cat > "/etc/nginx/sites-available/$domain" <<EOF
server {
    server_name $domain;
    listen 80;
    listen [::]:80;
    return 301 https://\$host\$request_uri;
}

server {
    server_name $domain;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Конфигурация для Element Call (Matrix RTC)
    # Этот блок сообщает клиентам адрес сервера видеозвонков
    location = /.well-known/matrix/client {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "https://$MATRIX_DOMAIN"}, "org.matrix.msc4143.rtc_foci": [{"type": "livekit", "livekit_service_url": "https://$LIVEKIT_DOMAIN"}]}';
    }

    # Заглушка для основного сайта или админки
    location / {
        root /var/www/html/$domain;
        index index.html;
        try_files \$uri \$uri/ =404;
    }

    location ~ /\. {
        deny all;
    }
}
EOF
    fi
done

systemctl reload nginx
check_success "Ошибка перезагрузки Nginx"

# 12. Настройка Redis для LiveKit
log "Настройка Redis..."

sed -i 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/' /etc/redis/redis.conf
systemctl restart redis-server

# 13. Создание тестового пользователя Matrix
log "Создание первого пользователя Matrix..."
echo "=================================================="
echo "СОЗДАНИЕ АДМИНИСТРАТОРА MATRIX"
echo "=================================================="
echo "Введите данные для создания администратора:"
echo ""
read -p "Имя пользователя (без @домен): " username
read -p "Пароль: " -s userpass
echo ""

if [ -n "$username" ] && [ -n "$userpass" ]; then
    register_new_matrix_user -c /etc/matrix-synapse/homeserver.yaml \
        -u "$username" -p "$userpass" -a http://localhost:8008 <<EOF
y
EOF
fi

# 14. Создание конфига для Element Call Widget
log "Создание конфига для Element Call Widget..."

cat > /etc/matrix-synapse/conf.d/element-call.yaml <<EOF
# Element Call widget configuration
element_call_config:
  url: "https://$LIVEKIT_DOMAIN"
  widget_id: "element-call"
  name: "Element Call"
  avatar_url: "mxc://element.io/abc123"
  description: "Video calls with Element Call"
  join_rule: "public"
  enable_presence: true
  enable_screensharing: true
  enable_chat: true
  theme: "light"
  
# Jitsi integration (compatibility)
jitsi:
  enabled: true
  domain: "$LIVEKIT_DOMAIN"
  config:
    preferredDomain: "$LIVEKIT_DOMAIN"
    disableAudioLevels: false
    enableNoAudioDetection: true
    enableNoisyMicDetection: true
EOF

systemctl restart matrix-synapse

# 15. ФИНАЛЬНЫЙ ВЫВОД
echo "=================================================="
echo "УСТАНОВКА ЗАВЕРШЕНА!"
echo "=================================================="
echo ""
echo "ДОСТУПНЫЕ СЕРВИСЫ:"
echo "=================================================="
echo "1. Matrix Synapse: https://$MATRIX_DOMAIN"
echo "2. Element Call:    https://$LIVEKIT_DOMAIN"
echo "3. Главный сайт:    https://$DOMAIN"
echo "4. Админка:         https://$SYNOPTIC_DOMAIN"
echo ""
echo "ВАЖНО: Для проверки исправления ошибки звонков:"
echo "Откройте в браузере: https://broadwall.ru/.well-known/matrix/client"
echo "Убедитесь, что в ответе есть поле 'org.matrix.msc4143.rtc_foci'"
echo ""
echo "НАСТРОЙКИ LIVEXIT:"
echo "=================================================="
echo "API Key:    $LIVEKIT_API_KEY"
echo "API Secret: $LIVEKIT_API_SECRET"
echo ""
echo "ТЕСТИРОВАНИЕ:"
echo "=================================================="
echo "1. Проверьте звонки: https://$LIVEKIT_DOMAIN"
echo "2. Проверьте Matrix: https://$MATRIX_DOMAIN"
echo "3. Проверьте конфиг: curl https://$DOMAIN/.well-known/matrix/client"
echo ""
echo "ЛОГИ:"
echo "=================================================="
echo "Matrix:    journalctl -u matrix-synapse -f"
echo "LiveKit:   journalctl -u livekit -f"
echo "Coturn:    journalctl -u coturn -f"
echo "Nginx:     journalctl -u nginx -f"
echo ""
echo "=================================================="
echo "УДАЧНОГО ИСПОЛЬЗОВАНИЯ!"
echo "=================================================="