#[file name]: tes.sh
#[file content begin]
#!/bin/bash

# Konfigurasi
AXWAY_SERVER="10.197.56.17:8075"
USERNAME="apiadmin"
PASSWORD="P@ssw0rdBD!"
BASE_URL="https://$AXWAY_SERVER/api/portal/v1.4"
DISCOVERY_URL="https://$AXWAY_SERVER/api/portal/v1.3/discovery"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_CSV="api_owners_${TIMESTAMP}.csv"
OUTPUT_XLS="api_owners_${TIMESTAMP}.xlsx"

# Fungsi warna
print_color() {
    local color_code=$1
    local message=$2
    echo -e "\033[${color_code}m${message}\033[0m"
}

print_success() {
    print_color "32" "✅ $1"
}

print_info() {
    print_color "36" "📌 $1"
}

print_warning() {
    print_color "33" "⚠️  $1"
}

print_error() {
    print_color "31" "❌ $1"
}

print_process() {
    print_color "34" "🔍 $1"
}

# Authentication
AUTH=$(echo -n "$USERNAME:$PASSWORD" | base64)
HEADERS=(-H "Authorization: Basic $AUTH" -H "Content-Type: application/json")

# Function untuk cleanup
cleanup() {
    if [ "$1" != "no-cleanup" ]; then
        echo ""
        print_warning "Membersihkan file temporary..."
        rm -f temp_apps.json temp_discovery.json temp_subscriptions.json
    fi
}

# Trap Ctrl+C untuk cleanup
trap cleanup EXIT INT TERM

# ==================== FUNGSI BANTU ====================

# Fungsi untuk membuat garis tabel
draw_table_line() {
    local left_corner="$1"
    local middle_corner="$2"
    local right_corner="$3"
    local horiz_line="$4"
    local col1_width="$5"
    local col2_width="$6"
    local col3_width="$7"
    
    echo -n "$left_corner"
    for ((i=0; i<col1_width; i++)); do echo -n "$horiz_line"; done
    echo -n "$middle_corner"
    for ((i=0; i<col2_width; i++)); do echo -n "$horiz_line"; done
    echo -n "$middle_corner"
    for ((i=0; i<col3_width; i++)); do echo -n "$horiz_line"; done
    echo "$right_corner"
}

# Fungsi untuk menampilkan tabel dengan semua data
display_full_table() {
    local -n data_ref=$1
    
    # Lebar kolom - diperlebar untuk menampilkan lebih banyak data
    local col1_width=40  # API Name (diperlebar)
    local col2_width=8   # Apps
    local col3_width=50  # Applications (diperlebar)
    
    # Sort API berdasarkan jumlah aplikasi (descending)
    local sorted_apis=""
    for api_id in "${!data_ref[@]}"; do
        local api_name="${API_NAME_MAP[$api_id]}"
        local apps_list="${data_ref[$api_id]}"
        local app_count=0
        
        if [ -n "$apps_list" ]; then
            app_count=$(echo "$apps_list" | tr '|' '\n' | grep -c "^")
        fi
        
        # Format untuk sorting: count|api_id|api_name
        sorted_apis+="$app_count|$api_id|$api_name"$'\n'
    done
    
    # Header tabel
    echo ""
    draw_table_line "┌" "┬" "┐" "─" $col1_width $col2_width $col3_width
    
    # Header kolom
    printf "│ %-${col1_width}s │ %-${col2_width}s │ %-${col3_width}s │\n" \
           "API Name" "Apps" "Applications"
    
    draw_table_line "├" "┼" "┤" "─" $col1_width $col2_width $col3_width
    
    # Data baris - diurutkan berdasarkan jumlah aplikasi
    local row_count=0
    while IFS='|' read -r app_count api_id api_name; do
        [ -z "$api_id" ] && continue
        
        local apps_list="${data_ref[$api_id]}"
        local apps_display_str=""
        
        # Format apps count dengan ikon
        local apps_display=""
        if [ "$app_count" -ge 5 ]; then
            apps_display="🟢 $app_count"
        elif [ "$app_count" -ge 3 ]; then
            apps_display="🟡 $app_count"
        elif [ "$app_count" -ge 1 ]; then
            apps_display="🟠 $app_count"
        else
            apps_display="🔴 $app_count"
        fi
        
        # Truncate API name jika terlalu panjang
        local display_api_name="$api_name"
        if [ ${#display_api_name} -gt $((col1_width - 2)) ]; then
            display_api_name="${display_api_name:0:$((col1_width - 5))}..."
        fi
        
        # Format aplikasi - TAMPILKAN SEMUA
        if [ -n "$apps_list" ] && [ "$app_count" -gt 0 ]; then
            IFS='|' read -ra apps_array <<< "$apps_list"
            local displayed_apps=()
            
            for app_display in "${apps_array[@]}"; do
                if [ -n "$app_display" ]; then
                    # Ambil nama aplikasi tanpa emoji
                    local app_name=""
                    if [[ $app_display == ✅* ]]; then
                        app_name="${app_display#✅ }"
                    elif [[ $app_display == ⏳* ]]; then
                        app_name="${app_display#⏳ }"
                    elif [[ $app_display == ❓* ]]; then
                        app_name="${app_display#❓ }"
                    else
                        app_name="$app_display"
                    fi
                    
                    # Truncate nama aplikasi jika perlu
                    if [ ${#app_name} -gt 20 ]; then
                        app_name="${app_name:0:17}..."
                    fi
                    
                    # Tambahkan kembali emoji
                    if [[ $app_display == ✅* ]]; then
                        displayed_apps+=("✅ $app_name")
                    elif [[ $app_display == ⏳* ]]; then
                        displayed_apps+=("⏳ $app_name")
                    elif [[ $app_display == ❓* ]]; then
                        displayed_apps+=("❓ $app_name")
                    else
                        displayed_apps+=("📌 $app_name")
                    fi
                fi
            done
            
            # Gabungkan SEMUA aplikasi
            if [ ${#displayed_apps[@]} -gt 0 ]; then
                apps_display_str=$(IFS=', '; echo "${displayed_apps[*]}")
            fi
        else
            apps_display_str="-"
        fi
        
        # Handle aplikasi yang sangat panjang dengan multiple lines
        if [ ${#apps_display_str} -gt $((col3_width - 2)) ]; then
            # Split menjadi multiple lines
            local temp_str="$apps_display_str"
            local lines=()
            
            while [ ${#temp_str} -gt $((col3_width - 2)) ]; do
                # Cari posisi koma terakhir sebelum batas
                local cut_pos=$((col3_width - 5))
                while [ $cut_pos -gt 0 ] && [ "${temp_str:$cut_pos:1}" != "," ] && [ "${temp_str:$cut_pos:1}" != " " ]; do
                    cut_pos=$((cut_pos - 1))
                done
                
                if [ $cut_pos -eq 0 ]; then
                    cut_pos=$((col3_width - 5))
                fi
                
                lines+=("${temp_str:0:$cut_pos}")
                temp_str="${temp_str:$((cut_pos + 2))}" # +2 untuk koma dan spasi
            done
            
            if [ -n "$temp_str" ]; then
                lines+=("$temp_str")
            fi
            
            # Print baris pertama
            printf "│ %-${col1_width}s │ %-${col2_width}s │ %-${col3_width}s │\n" \
                   "$display_api_name" "$apps_display" "${lines[0]}"
            
            # Print baris tambahan jika ada
            for ((i=1; i<${#lines[@]}; i++)); do
                printf "│ %-${col1_width}s │ %-${col2_width}s │ %-${col3_width}s │\n" \
                       "" "" "${lines[$i]}"
            done
        else
            # Print baris normal
            printf "│ %-${col1_width}s │ %-${col2_width}s │ %-${col3_width}s │\n" \
                   "$display_api_name" "$apps_display" "$apps_display_str"
        fi
        
        row_count=$((row_count + 1))
        
        # Tambahkan garis pemisah setiap 5 baris untuk readability
        if [ $row_count -lt $(echo "$sorted_apis" | wc -l) ] && [ $((row_count % 5)) -eq 0 ]; then
            draw_table_line "├" "┼" "┤" "─" $col1_width $col2_width $col3_width
        fi
        
    done < <(echo "$sorted_apis" | sort -t'|' -k1,1nr -k3,3)
    
    # Footer tabel
    draw_table_line "└" "┴" "┘" "─" $col1_width $col2_width $col3_width
    
    # Summary jumlah baris
    echo ""
    print_info "Total API ditampilkan: $row_count"
}

# ==================== FUNGSI HELP ====================

show_help() {
    print_color "35" "\n🎯 List of Applications that an API owns"
    print_color "35" "═════════════════════════════════════════════"
    print_color "36" "📋 Deskripsi: Script untuk melihat aplikasi mana saja yang memiliki akses ke setiap API"
    echo ""
    print_color "33" "📌 Penggunaan:"
    echo "  $0 [command] [options]"
    echo ""
    print_color "32" "🚀 Perintah yang tersedia:"
    echo "  run              : Jalankan laporan lengkap (default)"
    echo "  quick            : Jalankan laporan cepat tanpa progress bar"
    echo "  help             : Tampilkan bantuan ini"
    echo "  version          : Tampilkan versi script"
    echo ""
    print_color "34" "⚙️  Opsi:"
    echo "  --csv-only       : Hanya generate CSV, tanpa Excel"
    echo "  --no-cleanup     : Jangan hapus file temporary"
    echo "  --output <file>  : Custom nama output file"
    echo "  --table-only     : Hanya tampilkan tabel summary"
    echo ""
    print_color "36" "📊 Format Output:"
    echo "  ┌──────────────────────────────┬────────┬──────────────────────────┐"
    echo "  │ API Name                     │ Apps   │ Applications             │"
    echo "  ├──────────────────────────────┼────────┼──────────────────────────┤"
    echo "  │ Payment Processing API v1    │ 🟢 4   │ ✅ App1, ⏳ App2, 📌 +2  │"
    echo "  │ Cancel Deal Service          │ 🟡 3   │ ✅ App1, ⏳ App3         │"
    echo "  └──────────────────────────────┴────────┴──────────────────────────┘"
    echo "  • File CSV dengan semua data"
    echo "  • File Excel (jika ssconvert tersedia)"
    echo ""
    print_color "32" "🎯 Contoh penggunaan:"
    echo "  $0 run                     # Jalankan laporan lengkap"
    echo "  $0 quick --csv-only        # Laporan cepat hanya CSV"
    echo "  $0 run --output myreport   # Custom nama file"
    echo "  $0 run --table-only        # Hanya tampilkan tabel"
    echo "  $0 help                    # Tampilkan bantuan"
    echo ""
    print_color "33" "⚠️  Catatan:"
    echo "  • Script membutuhkan akses ke Axway API Manager"
    echo "  • Pastikan konfigurasi server, username, dan password sudah benar"
    echo "  • Install gnumeric untuk konversi ke Excel:"
    echo "      Ubuntu/Debian: sudo apt-get install gnumeric"
    echo "      CentOS/RHEL: sudo yum install gnumeric"
    echo ""
    print_color "35" "📞 Support:"
    echo "  Untuk masalah, hubungi tim API Management"
}

show_version() {
    print_color "35" "\n📦 API Owners Report Script"
    print_color "35" "═══════════════════════════"
    echo "Versi    : 2.3.0"
    echo "Author   : Axway API Management Team"
    echo "Created  : 2024-01-15"
    echo "Update   : 2024-03-15"
    echo ""
    echo "Fitur baru:"
    print_success "• Menampilkan SEMUA data API dalam tabel"
    print_success "• Menampilkan SEMUA aplikasi untuk setiap API"
    print_success "• Multi-line untuk aplikasi yang panjang"
    print_success "• Sorting berdasarkan jumlah aplikasi"
    print_success "• Tabel dengan kolom yang lebih lebar"
}

# ==================== FUNGSI UTAMA ====================

run_report() {
    local quick_mode="$1"
    local options="$2"
    local table_only=false
    
    # Cek apakah ada flag --table-only
    if [[ " $options " =~ " --table-only " ]]; then
        table_only=true
    fi
    
    print_color "35" "\n🎯 List of Applications that an API owns"
    print_color "35" "═════════════════════════════════════════════"
    echo ""
    
    # Test koneksi
    print_process "Memvalidasi koneksi ke API Manager..."
    curl -k -s "${HEADERS[@]}" \
        "$BASE_URL/applications" -w "\nHTTP Status: %{http_code}\n" | tail -1 | grep -q "200" || {
        print_error "Gagal terhubung ke API Manager"
        exit 1
    }
    print_success "Koneksi berhasil!"
    
    echo ""
    print_color "36" "📥 Mengambil data dari Axway API Manager..."
    print_color "36" "═════════════════════════════════════════════"
    
    # 1. Get all applications
    print_process "Mengambil daftar applications..."
    curl -k -s "${HEADERS[@]}" "$BASE_URL/applications" -o temp_apps.json
    APP_COUNT=$(jq '. | length' temp_apps.json 2>/dev/null || echo "0")
    if [ "$APP_COUNT" -eq 0 ]; then
        print_error "Tidak ada aplikasi yang ditemukan"
        exit 1
    fi
    print_success "Ditemukan $APP_COUNT aplikasi"
    
    # 2. Get all APIs from discovery
    print_process "Mengambil daftar APIs dari discovery..."
    curl -k -s "${HEADERS[@]}" "$DISCOVERY_URL/apis" -o temp_discovery.json
    
    # Create mappings
    declare -A API_NAME_MAP
    declare -A API_STATE_MAP
    declare -A API_APPS_MAP
    declare -A APP_NAME_MAP
    declare -A APP_STATE_MAP
    
    # Mapping API ID -> API Name dari discovery
    print_process "Membuat mapping API..."
    DISCOVERY_COUNT=0
    while IFS= read -r api; do
        if [ -n "$api" ]; then
            API_ID=$(echo "$api" | jq -r '.id')
            API_NAME=$(echo "$api" | jq -r '.name // .title // .apiName // "Unknown"')
            API_STATE=$(echo "$api" | jq -r '.state // "unknown"')
            
            if [ -n "$API_ID" ] && [ "$API_NAME" != "Unknown" ]; then
                API_NAME_MAP["$API_ID"]="$API_NAME"
                API_STATE_MAP["$API_ID"]="$API_STATE"
                API_APPS_MAP["$API_ID"]=""
                DISCOVERY_COUNT=$((DISCOVERY_COUNT + 1))
            fi
        fi
    done < <(jq -c '.[]' temp_discovery.json 2>/dev/null)
    print_success "Mapping $DISCOVERY_COUNT API selesai"
    
    # Mapping App ID -> App Name
    print_process "Membuat mapping aplikasi..."
    APP_MAP_COUNT=0
    while IFS= read -r app; do
        if [ -n "$app" ]; then
            APP_ID=$(echo "$app" | jq -r '.id')
            APP_NAME=$(echo "$app" | jq -r '.name // "Unknown"')
            APP_STATE=$(echo "$app" | jq -r '.state // "unknown"')
            
            if [ -n "$APP_ID" ] && [ "$APP_NAME" != "Unknown" ]; then
                APP_NAME_MAP["$APP_ID"]="$APP_NAME"
                APP_STATE_MAP["$APP_ID"]="$APP_STATE"
                APP_MAP_COUNT=$((APP_MAP_COUNT + 1))
            fi
        fi
    done < <(jq -c '.[]' temp_apps.json)
    print_success "Mapping $APP_MAP_COUNT aplikasi selesai"
    
    # 3. Process each application
    echo ""
    if [ "$quick_mode" = "true" ]; then
        print_color "34" "🔍 Memproses subscriptions aplikasi (mode cepat)..."
        print_color "34" "═════════════════════════════════════════════════════"
        
        PROCESSED=0
        APP_IDS=$(jq -r '.[].id' temp_apps.json)
        TOTAL_APPS=$(echo "$APP_IDS" | wc -l)
        
        for APP_ID in $APP_IDS; do
            PROCESSED=$((PROCESSED + 1))
            
            # Progress sederhana
            PERCENT=$((PROCESSED * 100 / TOTAL_APPS))
            echo -ne "\r   Diproses: $PERCENT% ($PROCESSED/$TOTAL_APPS) aplikasi"
            
            # Get subscriptions for this app
            curl -k -s "${HEADERS[@]}" "$BASE_URL/applications/$APP_ID/apis" -o temp_subscriptions.json 2>/dev/null
            
            # Process each subscription
            while IFS= read -r subscription; do
                if [ -n "$subscription" ]; then
                    API_ID=$(echo "$subscription" | jq -r '.apiId')
                    SUB_STATE=$(echo "$subscription" | jq -r '.state // "unknown"')
                    APP_NAME="${APP_NAME_MAP[$APP_ID]}"
                    
                    # Skip jika API tidak ada di mapping
                    if [ -z "${API_NAME_MAP[$API_ID]}" ]; then
                        continue
                    fi
                    
                    # Format app dengan status
                    if [ "$SUB_STATE" = "approved" ]; then
                        APP_DISPLAY="✅ $APP_NAME"
                    elif [ "$SUB_STATE" = "pending" ]; then
                        APP_DISPLAY="⏳ $APP_NAME"
                    else
                        APP_DISPLAY="❓ $APP_NAME"
                    fi
                    
                    # Add app to API's app list
                    if [ -n "${API_APPS_MAP[$API_ID]}" ]; then
                        API_APPS_MAP["$API_ID"]="${API_APPS_MAP[$API_ID]}|$APP_DISPLAY"
                    else
                        API_APPS_MAP["$API_ID"]="$APP_DISPLAY"
                    fi
                fi
            done < <(jq -c '.[]' temp_subscriptions.json 2>/dev/null)
        done
        echo ""
    else
        print_color "34" "🔍 Memproses subscriptions untuk setiap aplikasi..."
        print_color "34" "═══════════════════════════════════════════════════════════"
        
        PROCESSED=0
        APP_IDS=$(jq -r '.[].id' temp_apps.json)
        TOTAL_APPS=$(echo "$APP_IDS" | wc -l)
        
        for APP_ID in $APP_IDS; do
            PROCESSED=$((PROCESSED + 1))
            
            # Progress bar
            PERCENT=$((PROCESSED * 100 / TOTAL_APPS))
            FILL=$((PERCENT / 2))
            BAR=""
            for ((i=0; i<50; i++)); do
                if [ $i -lt $FILL ]; then
                    BAR="${BAR}█"
                else
                    BAR="${BAR}░"
                fi
            done
            
            APP_NAME="${APP_NAME_MAP[$APP_ID]}"
            
            # Truncate nama aplikasi untuk display progress
            if [ ${#APP_NAME} -gt 25 ]; then
                DISPLAY_NAME="${APP_NAME:0:22}..."
            else
                DISPLAY_NAME="$APP_NAME"
            fi
            
            echo -ne "\r   [$BAR] $PERCENT% ($PROCESSED/$TOTAL_APPS) - $DISPLAY_NAME"
            
            # Get subscriptions for this app
            curl -k -s "${HEADERS[@]}" "$BASE_URL/applications/$APP_ID/apis" -o temp_subscriptions.json 2>/dev/null
            
            # Process each subscription
            while IFS= read -r subscription; do
                if [ -n "$subscription" ]; then
                    API_ID=$(echo "$subscription" | jq -r '.apiId')
                    SUB_STATE=$(echo "$subscription" | jq -r '.state // "unknown"')
                    APP_NAME="${APP_NAME_MAP[$APP_ID]}"
                    
                    # Skip jika API tidak ada di mapping
                    if [ -z "${API_NAME_MAP[$API_ID]}" ]; then
                        continue
                    fi
                    
                    # Format app dengan status
                    if [ "$SUB_STATE" = "approved" ]; then
                        APP_DISPLAY="✅ $APP_NAME"
                    elif [ "$SUB_STATE" = "pending" ]; then
                        APP_DISPLAY="⏳ $APP_NAME"
                    else
                        APP_DISPLAY="❓ $APP_NAME"
                    fi
                    
                    # Add app to API's app list
                    if [ -n "${API_APPS_MAP[$API_ID]}" ]; then
                        API_APPS_MAP["$API_ID"]="${API_APPS_MAP[$API_ID]}|$APP_DISPLAY"
                    else
                        API_APPS_MAP["$API_ID"]="$APP_DISPLAY"
                    fi
                fi
            done < <(jq -c '.[]' temp_subscriptions.json 2>/dev/null)
        done
        echo ""
    fi
    
    echo ""
    
    # Validasi data
    if [ ${#API_NAME_MAP[@]} -eq 0 ]; then
        print_error "Tidak ada API yang ditemukan di discovery!"
        cleanup "no-cleanup"
        exit 1
    fi
    
    # Jika mode table-only, tampilkan tabel lengkap dan keluar
    if [ "$table_only" = true ]; then
        print_color "35" "📊 TABEL SUMMARY - SEMUA DATA API"
        print_color "35" "════════════════════════════════════════"
        echo ""
        
        display_full_table API_APPS_MAP
        
        echo ""
        print_info "Gunakan perintah lengkap untuk export ke CSV/Excel"
        print_info "Contoh: $0 run --output laporan_lengkap"
        
        cleanup "no-cleanup"
        exit 0
    fi
    
    print_color "35" "📊 HASIL LAPORAN LENGKAP"
    print_color "35" "════════════════════════"
    
    # Tampilkan tabel summary terlebih dahulu
    echo ""
    print_color "36" "📋 TABEL SUMMARY - SEMUA DATA API"
    display_full_table API_APPS_MAP
    
    echo ""
    print_color "35" "📈 STATISTIK LAPORAN"
    print_color "35" "════════════════════"
    
    # Hitung total
    TOTAL_APIS_WITH_APPS=0
    TOTAL_APIS_WITHOUT_APPS=0
    TOTAL_SUBSCRIPTIONS=0
    TOTAL_APPROVED=0
    TOTAL_PENDING=0
    TOTAL_UNKNOWN=0
    
    for API_ID in "${!API_NAME_MAP[@]}"; do
        APPS_LIST="${API_APPS_MAP[$API_ID]}"
        if [ -z "$APPS_LIST" ]; then
            TOTAL_APIS_WITHOUT_APPS=$((TOTAL_APIS_WITHOUT_APPS + 1))
        else
            TOTAL_APIS_WITH_APPS=$((TOTAL_APIS_WITH_APPS + 1))
            APP_COUNT=$(jq '. | length' temp_apps.json 2>/dev/null || echo "0")
            TOTAL_SUBSCRIPTIONS=$((TOTAL_SUBSCRIPTIONS + APP_COUNT))
            
            # Hitung status
            IFS='|' read -ra APPS_ARRAY <<< "$APPS_LIST"
            for APP in "${APPS_ARRAY[@]}"; do
                if [[ "$APP" == ✅* ]]; then
                    TOTAL_APPROVED=$((TOTAL_APPROVED + 1))
                elif [[ "$APP" == ⏳* ]]; then
                    TOTAL_PENDING=$((TOTAL_PENDING + 1))
                else
                    TOTAL_UNKNOWN=$((TOTAL_UNKNOWN + 1))
                fi
            done
        fi
    done
    
    # Display statistics
    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    printf "│ %-60s │\n" "📊 STATISTIK LAPORAN"
    echo "├─────────────────────────────────────────────────────────────┤"
    printf "│ %-35s : %-22s │\n" "📈 Total API (Discovery)" "${#API_NAME_MAP[@]}"
    printf "│ %-35s : %-22s │\n" "   • Dengan aplikasi" "$TOTAL_APIS_WITH_APPS"
    printf "│ %-35s : %-22s │\n" "   • Tanpa aplikasi" "$TOTAL_APIS_WITHOUT_APPS"
    printf "│ %-35s : %-22s │\n" "📱 Total Aplikasi" "$APP_COUNT"
    #printf "│ %-35s : %-22s │\n" "🔗 Total Subscriptions" "$TOTAL_SUBSCRIPTIONS"
    echo "├─────────────────────────────────────────────────────────────┤"
    printf "│ %-35s : %-22s │\n" "✅ Approved" "$TOTAL_APPROVED"
    printf "│ %-35s : %-22s │\n" "⏳ Pending" "$TOTAL_PENDING"
    printf "│ %-35s : %-22s │\n" "❓ Unknown" "$TOTAL_UNKNOWN"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    
    # 4. Save to CSV file
    echo ""
    print_process "Menyimpan hasil ke CSV..."
    CSV_CONTENT="No,API Name,API ID,API State,Application Count,Applications\n"
    
    COUNT=1
    for API_ID in "${!API_NAME_MAP[@]}"; do
        API_NAME="${API_NAME_MAP[$API_ID]}"
        API_STATE="${API_STATE_MAP[$API_ID]}"
        APPS_LIST="${API_APPS_MAP[$API_ID]}"
        
        # Count applications
        if [ -z "$APPS_LIST" ]; then
            APP_COUNT=0
            APPS_DISPLAY="No Application"
        else
            APP_COUNT=$(jq '. | length' temp_apps.json 2>/dev/null || echo "0")
            # Remove emojis for CSV
            APPS_DISPLAY=$(echo "$APPS_LIST" | sed 's/✅ //g;s/⏳ //g;s/❓ //g;s/📌 //g')
        fi
        
        # Add to CSV content
        CLEAN_API_NAME=$(echo "$API_NAME" | sed 's/,/;/g' | sed 's/"/""/g')
        CLEAN_APPS=$(echo "$APPS_DISPLAY" | sed 's/,/;/g' | sed 's/"/""/g')
        
        CSV_CONTENT="$CSV_CONTENT$COUNT,\"$CLEAN_API_NAME\",\"$API_ID\",\"$API_STATE\",$APP_COUNT,\"$CLEAN_APPS\"\n"
        COUNT=$((COUNT + 1))
    done
    
    echo -e "$CSV_CONTENT" > "$OUTPUT_CSV"
    print_success "File CSV disimpan: $OUTPUT_CSV"
    
    # 5. Convert to Excel jika tidak ada flag --csv-only
       
    echo ""
    print_color "35" "🎉 LAPORAN SELESAI DIBUAT!"
    print_color "35" "═══════════════════════════"
    echo ""
    print_color "32" "✨ Ringkasan:"
    echo "   • 📄 File CSV: $OUTPUT_CSV"
    if [[ ! " $options " =~ " --csv-only " ]] && command -v ssconvert &> /dev/null; then
        echo "   • 📊 File Excel: $OUTPUT_XLS"
    fi
    echo "   • 🖥️  Total API diproses: ${#API_NAME_MAP[@]}"
    echo "   • 📱 Total Aplikasi: $APP_COUNT"
    #echo "   • 🔗 Total Subscriptions: $TOTAL_SUBSCRIPTIONS"
    echo ""
    
    # Legend untuk tabel
    print_color "33" "📖 LEGEND TABEL:"
    echo "   🟢 : 5+ aplikasi"
    echo "   🟡 : 3-4 aplikasi"
    echo "   🟠 : 1-2 aplikasi"
    echo "   🔴 : 0 aplikasi"
    echo "   ✅ : Subscription approved"
    echo "   ⏳ : Subscription pending"
    echo "   ❓ : Status unknown"
    echo ""
    
    # Jangan cleanup jika ada flag --no-cleanup
    if [[ ! " $options " =~ " --no-cleanup " ]]; then
        cleanup
    fi
}

# ==================== MAIN ====================

main() {
    # Parse arguments
    local command="run"
    local quick_mode="false"
    local other_args=()
    
    # Cek jika ada command
    if [ $# -gt 0 ]; then
        case "$1" in
            "run")
                command="run"
                shift
                ;;
            "quick")
                command="run"
                quick_mode="true"
                shift
                ;;
            "help"|"--help"|"-h")
                show_help
                exit 0
                ;;
            "version"|"--version"|"-v")
                show_version
                exit 0
                ;;
            *)
                print_error "Perintah tidak dikenali: $1"
                echo ""
                echo "Gunakan: $0 help untuk melihat bantuan"
                exit 1
                ;;
        esac
    fi
    
    # Collect remaining arguments
    other_args=("$@")
    
    # Custom output file jika ada flag --output
    if [[ " ${other_args[@]} " =~ " --output " ]]; then
        for ((i=0; i<${#other_args[@]}; i++)); do
            if [ "${other_args[i]}" = "--output" ] && [ $((i+1)) -lt ${#other_args[@]} ]; then
                OUTPUT_NAME="${other_args[i+1]}"
                OUTPUT_CSV="${OUTPUT_NAME}_${TIMESTAMP}.csv"
                OUTPUT_XLS="${OUTPUT_NAME}_${TIMESTAMP}.xlsx"
                break
            fi
        done
    fi
    
    # Jalankan perintah
    case "$command" in
        "run")
            run_report "$quick_mode" "${other_args[*]}"
            ;;
        *)
            print_error "Perintah tidak valid"
            show_help
            exit 1
            ;;
    esac
}

# Jalankan main function
main "$@"
