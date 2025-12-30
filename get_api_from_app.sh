#!/bin/bash

# Konfigurasi
AXWAY_SERVER="10.197.56.17:8075"
USERNAME="apiadmin"
PASSWORD="P@ssw0rdBD!"
BASE_URL="https://$AXWAY_SERVER/api/portal/v1.4"
DISCOVERY_URL="https://$AXWAY_SERVER/api/portal/v1.3/discovery"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_CSV="api_from_apps_${TIMESTAMP}.csv"
OUTPUT_XLS="api_from_apps_${TIMESTAMP}.xlsx"

# Authentication
AUTH=$(echo -n "$USERNAME:$PASSWORD" | base64)
HEADERS=(-H "Authorization: Basic $AUTH" -H "Content-Type: application/json")

# Function untuk cleanup
cleanup() {
    echo "Membersihkan file temporary..."
    rm -f temp_apps.json temp_discovery.json temp_subscriptions.json
}

# Trap Ctrl+C untuk cleanup
trap cleanup EXIT INT TERM

echo "Mengambil data dari Axway API Manager..."

# 1. Get applications
echo "Mengambil daftar applications..."
curl -k -s "${HEADERS[@]}" "$BASE_URL/applications" -o temp_apps.json
APP_IDS=$(jq -r '.[].id' temp_apps.json)

# 2. Get discovery APIs
echo "Mengambil daftar APIs dari discovery..."
curl -k -s "${HEADERS[@]}" "$DISCOVERY_URL/apis" -o temp_discovery.json

# Create mapping dari API ID ke API Name
declare -A API_NAME_MAP
while IFS= read -r api; do
    if [ -n "$api" ]; then
        API_ID=$(echo "$api" | jq -r '.id')
        API_NAME=$(echo "$api" | jq -r '.name // "Unknown"')
        API_NAME_MAP["$API_ID"]="$API_NAME"
    fi
done < <(jq -c '.[]' temp_discovery.json)

# Prepare CSV content
CSV_CONTENT="Application Name,API Access\n"

# 3. Process each application
for APP_ID in $APP_IDS; do
    # Get application details
    APP_DETAIL=$(curl -k -s "${HEADERS[@]}" "$BASE_URL/applications/$APP_ID")
    APP_NAME=$(echo "$APP_DETAIL" | jq -r '.name')
    
    # Get subscriptions
    curl -k -s "${HEADERS[@]}" "$BASE_URL/applications/$APP_ID/apis" -o temp_subscriptions.json
    SUBSCRIPTION_COUNT=$(jq length temp_subscriptions.json)
    
    # Tampilkan output simple
    echo "========================================="
    echo "Application: $APP_NAME"
    echo "API Access:"
    
    # Prepare subscriptions list untuk CSV
    SUBSCRIPTIONS_CSV=""
    
    if [ "$SUBSCRIPTION_COUNT" -gt 0 ]; then
        while IFS= read -r subscription; do
            API_ID=$(echo "$subscription" | jq -r '.apiId')
            
            # Get API name from mapping
            if [ -n "${API_NAME_MAP[$API_ID]}" ]; then
                API_NAME="${API_NAME_MAP[$API_ID]}"
            else
                API_NAME="Unknown (ID: $API_ID)"
            fi
            
            # Tampilkan di console
            echo "  - $API_NAME"
            
            # Tambahkan ke CSV content (escape commas)
            CLEAN_API_NAME=$(echo "$API_NAME" | sed 's/,/;/g')
            if [ -z "$SUBSCRIPTIONS_CSV" ]; then
                SUBSCRIPTIONS_CSV="$CLEAN_API_NAME"
            else
                SUBSCRIPTIONS_CSV="$SUBSCRIPTIONS_CSV | $CLEAN_API_NAME"
            fi
            
        done < <(jq -c '.[]' temp_subscriptions.json)
    else
        echo "  - No API Access"
        SUBSCRIPTIONS_CSV="No API Access"
    fi
    
    # Add to CSV content (escape commas in app name too)
    CLEAN_APP_NAME=$(echo "$APP_NAME" | sed 's/,/;/g')
    CSV_CONTENT="$CSV_CONTENT\"$CLEAN_APP_NAME\",\"$SUBSCRIPTIONS_CSV\"\n"
    
    echo ""
done

# 4. Save to CSV file
echo "Menyimpan hasil ke CSV..."
echo -e "$CSV_CONTENT" > "$OUTPUT_CSV"
echo "File CSV disimpan: $OUTPUT_CSV"

# 5. Convert to Excel jika ssconvert tersedia (package gnumeric)
if command -v ssconvert &> /dev/null; then
    echo "Mengkonversi CSV ke Excel..."
    ssconvert "$OUTPUT_CSV" "$OUTPUT_XLS"
    echo "File Excel disimpan: $OUTPUT_XLS"
else
    echo "ssconvert tidak ditemukan. Install gnumeric untuk konversi ke Excel:"
    echo "Ubuntu/Debian: sudo apt-get install gnumeric"
    echo "CentOS/RHEL: sudo yum install gnumeric"
fi

cleanup
