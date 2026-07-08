#!/bin/sh
# Generate self-signed cert if not present
if [ ! -f /etc/nginx/ssl/key.pem ] || [ ! -f /etc/nginx/ssl/cert.pem ]; then
    echo "Generating self-signed SSL certificate..."
    apk add --no-cache openssl >/dev/null 2>&1
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/key.pem \
        -out /etc/nginx/ssl/cert.pem \
        -subj "/C=IT/ST=State/L=City/O=Kraken/CN=localhost" 2>/dev/null
    echo "Self-signed certificate generated."
fi

exec nginx -g "daemon off;"
