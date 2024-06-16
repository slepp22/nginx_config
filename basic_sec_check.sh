#!/bin/bash

# URL of your Nginx server (replace with your server IP or hostname)
URL="http://141.100.235.124/"

# Function to check if a header is present in the response
check_header() {
    local HEADER="$1"
    echo "Checking $HEADER..."
    RESPONSE=$(curl -s -D- $URL | grep -i $HEADER)
    if [[ -n "$RESPONSE" ]]; then
        echo "$HEADER is present: $RESPONSE"
    else
        echo "$HEADER is missing!"
    fi
}

# Function to check if Nginx serves content correctly
check_content() {
    echo "Checking if Nginx serves content..."
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $URL)
    if [[ "$HTTP_STATUS" == "200" ]]; then
        echo "Nginx is serving content correctly. HTTP status: $HTTP_STATUS"
    else
        echo "Failed to retrieve content from Nginx. HTTP status: $HTTP_STATUS"
    fi
}

# Function to check Gzip compression
check_gzip() {
    echo "Checking Gzip compression..."
    RESPONSE=$(curl -s -H "Accept-Encoding: gzip" -D- $URL)
    CONTENT_ENCODING=$(echo "$RESPONSE" | grep -i "Content-Encoding")
    if [[ "$CONTENT_ENCODING" =~ gzip ]]; then
        echo "Gzip compression is enabled."
    else
        echo "Gzip compression is not enabled."
    fi
}

# Function to check HTTP Headers related to security
check_security_headers() {
    echo "Checking HTTP security headers..."
    check_header "Strict-Transport-Security"
    check_header "Content-Security-Policy"
    check_header "X-Frame-Options"
    check_header "X-Content-Type-Options"
}

# Function to perform rate limiting test
check_rate_limiting() {
    echo "Checking Rate Limiting..."
    IP="your_test_ip"
    for i in {1..5}; do
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $URL --interface $IP)
        if [[ "$RESPONSE" == "200" ]]; then
            echo "Request $i successful"
        else
            echo "Request $i blocked: HTTP $RESPONSE"
        fi
    done
}

# Main function to execute all checks
main() {
    echo "Starting health and security check for $URL"
    check_security_headers
    check_content
    check_gzip
    check_rate_limiting
    echo "Health and security check completed."
}

# Execute the main function
main