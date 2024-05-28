#!/bin/bash

# URL der Nginx-Server
URL="https://your-nginx-server.com"

# Ueberpruefen von HTTP Strict Transport Security (HSTS)
check_hsts() {
    echo "Ueberpruefe HSTS..."
    RESPONSE=$(curl -s -D- $URL | grep -i Strict-Transport-Security)
    if [[ -n "$RESPONSE" ]]; then
        echo "HSTS ist konfiguriert: $RESPONSE"
    else
        echo "HSTS fehlt!"
    fi
}

# Ueberpruefen von SSL/TLS Konfiguration
check_ssl_tls() {
    echo "Ueberpruefe SSL/TLS Konfiguration..."
    SSL_PROTOCOLS=$(echo | openssl s_client -connect your-nginx-server.com:443 -tls1_2 2>/dev/null)
    if [[ -n "$SSL_PROTOCOLS" ]]; then
        echo "TLS 1.2 ist unterstuetzt."
    else
        echo "TLS 1.2 wird nicht unterstuetzt!"
    fi

    SSL_PROTOCOLS=$(echo | openssl s_client -connect your-nginx-server.com:443 -tls1_3 2>/dev/null)
    if [[ -n "$SSL_PROTOCOLS" ]]; then
        echo "TLS 1.3 ist unterstuetzt."
    else
        echo "TLS 1.3 wird nicht unterstuetzt!"
    fi
}

# Ueberpruefen von Content Security Policy (CSP)
check_csp() {
    echo "Ueberpruefe Content Security Policy (CSP)..."
    RESPONSE=$(curl -s -D- $URL | grep -i Content-Security-Policy)
    if [[ -n "$RESPONSE" ]]; then
        echo "CSP ist konfiguriert: $RESPONSE"
    else
        echo "CSP fehlt!"
    fi
}

# Ueberpruefen von X-Frame-Options
check_x_frame_options() {
    echo "Ueberpruefe X-Frame-Options..."
    RESPONSE=$(curl -s -D- $URL | grep -i X-Frame-Options)
    if [[ -n "$RESPONSE" ]]; then
        echo "X-Frame-Options ist konfiguriert: $RESPONSE"
    else
        echo "X-Frame-Options fehlt!"
    fi
}

# Ueberpruefen von X-Content-Type-Options
check_x_content_type_options() {
    echo "Ueberpruefe X-Content-Type-Options..."
    RESPONSE=$(curl -s -D- $URL | grep -i X-Content-Type-Options)
    if [[ -n "$RESPONSE" ]]; then
        echo "X-Content-Type-Options ist konfiguriert: $RESPONSE"
    else
        echo "X-Content-Type-Options fehlt!"
    fi
}

# Ueberpruefen von Rate Limiting
check_rate_limiting() {
    echo "Ueberpruefe Rate Limiting..."
    IP="your_test_ip"
    for i in {1..5}; do
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $URL --interface $IP)
        if [[ "$RESPONSE" == "200" ]]; then
            echo "Anfrage $i erfolgreich"
        else
            echo "Anfrage $i blockiert: HTTP $RESPONSE"
        fi
    done
}

# Hauptfunktion zur Ausfuehrung der Tests
main() {
    echo "Starte Sicherheitsueberpruefung fuer $URL"
    check_hsts
    check_ssl_tls
    check_csp
    check_x_frame_options
    check_x_content_type_options
    check_rate_limiting
    echo "Sicherheitsueberpruefung abgeschlossen."
}

# Skript ausfuehren
main