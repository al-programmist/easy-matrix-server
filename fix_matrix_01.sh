#!/bin/bash
# Fix MISSING_MATRIX_RTC_FOCUS error

DOMAIN="broadwall.ru"
MATRIX_DOMAIN="matrix.broadwall.ru"
LIVEKIT_DOMAIN="livekit.broadwall.ru"

# 1. Создаем конфиг для .well-known
cat > /etc/nginx/conf.d/matrix-fix.conf <<EOF
# Matrix client configuration fix
server {
    listen 80;
    server_name $DOMAIN;
    
    location = /.well-known/matrix/client {
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "https://$MATRIX_DOMAIN"}, "org.matrix.msc4143.rtc_foci": [{"type": "livekit", "livekit_service_url": "https://$LIVEKIT_DOMAIN"}]}';
    }
}

server {
    listen 443 ssl;
    server_name $DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    location = /.well-known/matrix/client {
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        add_header Cache-Control "public, max-age=3600";
        return 200 '{"m.homeserver": {"base_url": "https://$MATRIX_DOMAIN"}, "org.matrix.msc4143.rtc_foci": [{"type": "livekit", "livekit_service_url": "https://$LIVEKIT_DOMAIN"}]}';
    }
}
EOF

# 2. Перезагружаем Nginx
nginx -t && systemctl reload nginx

# 3. Проверяем результат
echo "Проверка конфигурации:"
curl -s https://$DOMAIN/.well-known/matrix/client | python3 -m json.tool

echo -e "\nЕсли выше вы видите поле 'rtc_foci', то ошибка должна быть исправлена."
echo "Перезагрузите Element Web или очистите кэш браузера (Ctrl+Shift+R)."