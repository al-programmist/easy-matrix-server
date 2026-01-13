#!/bin/bash

# ==========================================
# MATRIX SYNAPSE + COTURN INSTALLER (V3)
# Tested on Ubuntu 22.04 / Debian 11+
# ==========================================

# --- НАСТРОЙКИ ПОЛЬЗОВАТЕЛЯ (РЕДАКТИРОВАТЬ ЗДЕСЬ) ---
DOMAIN="broadwall.ru"                 # Ваш домен (без https://)
MATRIX_DOMAIN="matrix.broadwall.ru" # Мессенджер
LIVEKIT_DOMAIN="livekit.broadwall.ru" # Element Call
SYNOPTIC_DOMAIN="synoptic.broadwall.ru" #админка
EMAIL="al-programmist@yandex.ru"            # Почта для SSL
#DB_PASS="StrongPass_$(openssl rand -hex 4)" # Пароль для БД (можно оставить авто-генерацию)

# Белый список доменов для федерации.
# Если хотите общаться со всеми - оставьте скобки пустыми: WHITELIST_DOMAINS=()
# Если только с cupsup.xyz - впишите: WHITELIST_DOMAINS=("abc.xyz")
# WHITELIST_DOMAINS=("abc.xyz")

# ==========================================
# ДАЛЕЕ АВТОМАТИКА (НЕ ТРОГАТЬ)
# ==========================================

 1. Генерация ключей
 REG_SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
 TURN_SECRET=$(openssl rand -base64 32)
 
 echo ">>> НАЧАЛО УСТАНОВКИ ДЛЯ: $DOMAIN"
 echo ">>> БД ПАРОЛЬ: $DB_PASS"

# 2. Подготовка системы
export DEBIAN_FRONTEND=noninteractive

apt update -y
apt install -y curl wget lsb-release gnupg2 ufw apt-transport-https ca-certificates 

# 3. Настройка SSH

set -e

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

# 4. Настройка Firewall
echo ">>> Настройка Firewall..."
ufw allow 4741/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8448/tcp
ufw allow 3478/tcp
ufw allow 3478/udp
ufw allow 5349/tcp
ufw allow 5349/udp
ufw allow 49152:65535/udp
ufw allow 50000:60000/tcp
ufw --force enable
#--------------------------------------------------

#--------------------------------------------------
# 4. Nginx & Certbot

# Массив всех доменов
DOMAINS=("$DOMAIN" "$MATRIX_DOMAIN" "$LIVEKIT_DOMAIN" "$SYNOPTIC_DOMAIN")

# Функция для создания заглушки
create_stub_page() {
    local site_name="$1"
    local domain="$2"
    local stub_dir="/var/www/html/$domain"
    
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


echo ">>> Установка Nginx..."
apt install -y nginx certbot python3-certbot-nginx

# Создание корневых директорий для всех сайтов
for domain in "${DOMAINS[@]}"; do
    mkdir -p "/var/www/html/$domain"
    
    # Создаем уникальную заглушку для каждого сайта
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

# Создание временных конфигов для получения сертификатов
for domain in "${DOMAINS[@]}"; do
    cat > "/etc/nginx/sites-available/$domain" <<EOF
server {
    server_name $domain;
    listen 80;
    listen [::]:80;
    
    # Временный редирект для получения сертификата
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

# Удаляем дефолтный конфиг
rm -f /etc/nginx/sites-enabled/default
systemctl reload nginx

# Получение сертификатов для всех доменов
echo ">>> Получение SSL сертификатов..."
for domain in "${DOMAINS[@]}"; do
    echo "Получение сертификата для $domain..."
    certbot certonly --nginx -d "$domain" --non-interactive --agree-tos -m "$EMAIL"
done

# Создание финальных конфигов
for domain in "${DOMAINS[@]}"; do
    if [ "$domain" = "$MATRIX_DOMAIN" ]; then
        # Специальный конфиг для Matrix
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
    else
        # Стандартный конфиг для остальных сайтов
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

    root /var/www/html/$domain;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Запрещаем доступ к скрытым файлам
    location ~ /\. {
        deny all;
    }
}
EOF
    fi
done

systemctl reload nginx
echo ">>> Настройка Nginx завершена!"
echo ">>> Доступные сайты:"
for domain in "${DOMAINS[@]}"; do
    echo "  - https://$domain"
done



## 5. PostgreSQL
#echo ">>> Установка PostgreSQL..."
#apt install -y postgresql postgresql-contrib
## Создание БД (игнорируем ошибку, если уже есть)
#sudo -u postgres psql -c "CREATE USER synapse WITH PASSWORD '$DB_PASS';" || true
#sudo -u postgres psql -c "CREATE DATABASE synapse OWNER synapse;" || true
#sudo -u postgres psql -c "ALTER USER synapse CREATEDB;" || true
#
## 6. Matrix Synapse
#echo ">>> Установка Matrix Synapse..."
#wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
#echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/matrix-org.list
#apt update
## Предустановка ответов для инсталлятора
#echo "matrix-synapse-py3 matrix-synapse/server-name string $DOMAIN" | debconf-set-selections
#echo "matrix-synapse-py3 matrix-synapse/report-stats boolean false" | debconf-set-selections
#apt install -y matrix-synapse-py3
#
## 7. Настройка Synapse (homeserver.yaml)
#CONFIG_FILE="/etc/matrix-synapse/homeserver.yaml"
#
## Отключаем дефолтную sqlite базу (комментируем строки)
#sed -i 's/^database:/#database:/' $CONFIG_FILE
#sed -i 's/^  name: sqlite3/#  name: sqlite3/' $CONFIG_FILE
#sed -i 's/^  args:/#  args:/' $CONFIG_FILE
#sed -i 's/^    database: \/var\/lib/#    database: \/var\/lib/' $CONFIG_FILE
#
## Добавляем нашу конфигурацию в конец файла
#cat >> $CONFIG_FILE <<EOF
#
## --- AUTO CONFIG V2 ---
## Включаем регистрацию через API (для админ-скрипта)
#enable_registration: false
#enable_registration_without_verification: true
#registration_shared_secret: "$REG_SECRET"
#
## Настройка базы данных Postgres
#database:
#  name: psycopg2
#  args:
#    user: synapse
#    password: "$DB_PASS"
#    database: synapse
#    host: localhost
#    cp_min: 5
#    cp_max: 10
#  allow_unsafe_locale: true
#
## Настройка TURN (Звонки)
#turn_shared_secret: "$TURN_SECRET"
#turn_uris: ["turn:$DOMAIN?transport=udp", "turn:$DOMAIN?transport=tcp"]
#turn_user_lifetime: 86400000
#turn_allow_ip_lifetime: true
#EOF
#
## Добавляем Whitelist, если задан
#if [ ${#WHITELIST_DOMAINS[@]} -gt 0 ]; then
#    echo "federation_domain_whitelist:" >> $CONFIG_FILE
#    for d in "${WHITELIST_DOMAINS[@]}"; do
#        echo "  - \"$d\"" >> $CONFIG_FILE
#    done
#fi
#
## Перезапуск для применения
#systemctl restart matrix-synapse
#
## 8. Coturn (TURN Server)
#echo ">>> Установка Coturn..."
#apt install -y coturn
#
## Полная перезапись конфига
#cat > /etc/turnserver.conf <<EOF
#listening-port=3478
#tls-listening-port=5349
#fingerprint
#use-auth-secret
#static-auth-secret=$TURN_SECRET
#realm=$DOMAIN
#cert=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
#pkey=/etc/letsencrypt/live/$DOMAIN/privkey.pem
#no-multicast-peers
#user-quota=100
#total-quota=1200
#syslog
#no-cli
#EOF
#
## Включаем в /etc/default/coturn
#sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
#systemctl restart coturn
#
#echo "=================================================="
#echo "УСТАНОВКА ЗАВЕРШЕНА!"
#echo "=================================================="
#echo "1. Ваш домен: $DOMAIN"
#echo "2. Создайте первого пользователя командой ниже:"
#echo "register_new_matrix_user -c /etc/matrix-synapse/homeserver.yaml http://localhost:8008"
#echo ""
#echo "При создании пользователя ответьте 'yes' на вопрос Make admin."
#echo "=================================================="