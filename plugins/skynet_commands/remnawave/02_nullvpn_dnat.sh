#!/bin/bash
# TITLE: NullVPN: DNAT-релеи RU-нод (nft) — show/list/probe/add/del
# ============================================================ #
# ==   SKYNET ПЛАГИН: NullVPN DNAT-релеи (nft, v4-вход)     == #
# ============================================================ #
#
# Управление v4 DNAT-релеями: клиент → RU-нода → ES-нода.
# Плагин НЕинтерактивный: все параметры через ENV.
#
# ДВА СЛОЯ:
#   [К] канонический слой  — nft table 'ip nullvpn-dnat' +
#       /etc/nftables.d/nullvpn-dnat.nft, рендерится relay-setup.sh
#       («EDIT ONLY VIA relay-setup.sh»). Плагин только СМОТРИТ и
#       детектит дрейф file↔live и дубли правил.
#   [P] плагин-слой        — nft table 'ip nullvpn-nv-dnat' +
#       /etc/nftables.d/nullvpn-nv-dnat.nft + /etc/nullvpn/nv-dnat.entries +
#       nullvpn-nv-dnat.service. Полностью владеется плагином, канонический
#       слой не трогает никогда.
#
# ЖЁСТКОЕ ПРАВИЛО ВЛАДЕЛЬЦА: DNAT на DE1 (admin-node-1) — НИКОГДА.
# Мутации отклоняются на панельных хостах (hostname admin-node-1/node-de-1
# или живой panel :3000).
#
# ENV:
#   DNAT_ACTION=show|list|probe|add|del    (default: show)
#   DNAT_NAME=<имя>                        add/del: имя релея [a-z0-9-]
#   DNAT_TARGET_IP=<ip>                    add: куда DNAT'им
#   DNAT_LISTEN_PORTS="2053,443"           add: входные порты (csv)
#   DNAT_TARGET_PORT=<порт>                add: optional; если задан — ВСЕ входные
#                                          порты уводятся на него (port-rewrite,
#                                          как RU-1 443→2053); пусто = порт сохраняется
#   DNAT_PROTO=tcp|udp|both                add (default: both)
#   DNAT_IFACE=ens3                        add (optional; default: default-route iface)
#   DNAT_SNAT_IP=<ip>                      add (optional; default: v4 default-route iface)
#   DNAT_CONFIRM=yes                       add/del: обязательное подтверждение
#
set -euo pipefail

C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
log_info()  { echo -e "${C_RESET}[i] $*${C_RESET}"; }
log_ok()    { echo -e "${C_GREEN}[✓] $*${C_RESET}"; }
log_warn()  { echo -e "${C_YELLOW}[!] $*${C_RESET}"; }
log_error() { echo -e "${C_RED}[✗] $*${C_RESET}"; exit 1; }

CANON_TABLE='nullvpn-dnat'
CANON_FILE='/etc/nftables.d/nullvpn-dnat.nft'
CANON_CONF='/etc/nftables.d/nullvpn-dnat.conf'
PLUGIN_TABLE='nullvpn-nv-dnat'
PLUGIN_FILE='/etc/nftables.d/nullvpn-nv-dnat.nft'
PLUGIN_STATE='/etc/nullvpn/nv-dnat.entries'
PLUGIN_UNIT='nullvpn-nv-dnat.service'
PLUGIN_UNIT_PATH="/etc/systemd/system/${PLUGIN_UNIT}"

ACTION="${DNAT_ACTION:-show}"

[[ $EUID -ne 0 ]] && log_error "Нужен root."

# ---------- helpers ----------

detect_iface() {
    ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1
}

detect_local_ip() {
    local iface="${1:-$(detect_iface)}"
    ip -o -4 addr show "$iface" 2>/dev/null | awk '{split($4,a,"/"); print a[1]}' | head -1
}

valid_ipv4() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local o IFS='.'
    read -ra o <<< "$1"
    [[ ${#o[@]} -eq 4 ]] || return 1
    for x in "${o[@]}"; do
        [[ "$x" =~ ^[0-9]+$ ]] && (( x >= 0 && x <= 255 )) || return 1
    done
}

valid_ports_csv() {
    [[ "$1" =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
    local p
    IFS=',' read -ra parts <<< "$1"
    for p in "${parts[@]}"; do
        (( p >= 1 && p <= 65535 )) || return 1
    done
    return 0
}

# Панельный хост? (жёсткое правило владельца: DNAT на DE1 НИКОГДА)
is_panel_host() {
    local h; h="$(hostname)"
    [[ "$h" == "admin-node-1" || "$h" == "node-de-1" ]] && return 0
    if command -v ss >/dev/null 2>&1 && ss -Hlnt 2>/dev/null | grep -q ':3000 '; then
        return 0
    fi
    return 1
}

guard_mutation() {
    if is_panel_host; then
        log_error "ОТКАЗ: мутация DNAT на панельном хосте запрещена (жёсткое правило: DNAT на DE1 — никогда)."
    fi
    [[ "${DNAT_CONFIRM:-}" == "yes" ]] || log_error "Нужно DNAT_CONFIRM=yes (мутация nft-правил входа)."
}

# ---------- канонический слой: разбор live-таблицы ----------

# возвращает строки: proto|ports|target  (ports = csv)
parse_live_dnats() {
    nft -a list table ip "$CANON_TABLE" 2>/dev/null | \
    awk '
        /chain prerouting/ {inr=1; next}
        /chain postrouting/ {inr=0}
        inr && /dnat to/ {
            proto="tcp"; if ($0 ~ / udp /) proto="udp"
            ports=""
            if (match($0, /dport \{ [^}]* \}/)) {
                p=substr($0, RSTART+8, RLENGTH-9); gsub(/ /, "", p); ports=p
            } else if (match($0, /dport [0-9]+/)) {
                ports=substr($0, RSTART+6, RLENGTH-6)
            }
            tgt=""
            if (match($0, /dnat to [0-9.]+(:[0-9]+)?/)) {
                tgt=substr($0, RSTART+8, RLENGTH-8)
            }
            if (ports != "" && tgt != "") print proto"|"(ports)"|"tgt
        }
    '
}

# возвращает строки: proto|ports|target|snat_ip  (postrouting)
parse_live_snats() {
    nft -a list table ip "$CANON_TABLE" 2>/dev/null | \
    awk '
        /chain postrouting/ {inr=1; next}
        inr && / snat to / {
            proto="tcp"; if ($0 ~ / udp /) proto="udp"
            ports=""
            if (match($0, /dport \{ [^}]* \}/)) {
                p=substr($0, RSTART+8, RLENGTH-9); gsub(/ /, "", p); ports=p
            } else if (match($0, /dport [0-9]+/)) {
                ports=substr($0, RSTART+6, RLENGTH-6)
            }
            da=""
            if (match($0, /ip daddr [0-9.]+/)) da=substr($0, RSTART+9, RLENGTH-9)
            si=""
            if (match($0, /snat to [0-9.]+/)) si=substr($0, RSTART+8, RLENGTH-8)
            if (da != "" && si != "") print proto"|"(ports=="?"?"":ports)"|"da"|"si
        }
    '
}

tcp_probe() {
    local ip="$1" port="$2"
    timeout 4 bash -c "exec 3<>/dev/tcp/${ip}/${port}" 2>/dev/null
}

# ---------- plugin-layer state ----------

state_add() {
    mkdir -p "$(dirname "$PLUGIN_STATE")"
    [[ -f "$PLUGIN_STATE" ]] && grep -q "^${NV_NAME}|" "$PLUGIN_STATE" && \
        log_error "Релей '${NV_NAME}' уже есть в ${PLUGIN_STATE}"
    echo "${NV_NAME}|${NV_PROTO}|${NV_PORTS}|${NV_TARGET_IP}|${NV_TARGET_PORT}|${NV_IFACE}|${NV_SNAT_IP}" >> "$PLUGIN_STATE"
}

state_del() {
    [[ -f "$PLUGIN_STATE" ]] || log_error "State-файла нет: ${PLUGIN_STATE}"
    grep -q "^${NV_NAME}|" "$PLUGIN_STATE" || log_error "Релей '${NV_NAME}' не найден. Есть: $(cut -d'|' -f1 "$PLUGIN_STATE" | tr '\n' ' ')"
    local tmp; tmp="$(mktemp)"
    grep -v "^${NV_NAME}|" "$PLUGIN_STATE" > "$tmp" || true
    mv "$tmp" "$PLUGIN_STATE"
}

render_plugin_file() {
    mkdir -p "$(dirname "$PLUGIN_FILE")"
    local tmp; tmp="$(mktemp)"
    cat > "$tmp" <<'HDR'
#!/usr/sbin/nft -f
# Managed by reshala plugin 02_nullvpn_dnat.sh (nullvpnnet/Reshala-Remnawave-Bedolaga fork).
# DO NOT EDIT BY HAND — regenerate via plugin (DNAT_ACTION=add/del).
HDR
    echo "table ip ${PLUGIN_TABLE}" >> "$tmp"
    echo "flush table ip ${PLUGIN_TABLE}" >> "$tmp"
    echo "table ip ${PLUGIN_TABLE} {" >> "$tmp"
    echo "    chain prerouting_nv {" >> "$tmp"
    echo "        type nat hook prerouting priority dstnat; policy accept;" >> "$tmp"
    echo "    }" >> "$tmp"
    echo "    chain postrouting_nv {" >> "$tmp"
    echo "        type nat hook postrouting priority srcnat; policy accept;" >> "$tmp"
    echo "    }" >> "$tmp"
    echo "}" >> "$tmp"
    mv "$tmp" "$PLUGIN_FILE"
}

# Перегенерация ПОЛНОГО файла из state + применение (идемпотентно)
apply_plugin_rules() {
    local tmp rules_f snat_f name proto ports tip tport iface sip p post
    mkdir -p "$(dirname "$PLUGIN_FILE")"
    tmp="$(mktemp)"
    {
        echo "#!/usr/sbin/nft -f"
        echo "# Managed by reshala plugin 02_nullvpn_dnat.sh (nullvpnnet fork). DO NOT EDIT BY HAND."
        echo "table ip ${PLUGIN_TABLE}"
        echo "flush table ip ${PLUGIN_TABLE}"
        echo "table ip ${PLUGIN_TABLE} {"
        echo "    chain prerouting_nv {"
        echo "        type nat hook prerouting priority dstnat; policy accept;"
        while IFS='|' read -r name proto ports tip tport iface sip; do
            [[ -z "$name" ]] && continue
            IFS=',' read -ra plist <<< "$ports"
            for p in "${plist[@]}"; do
                post="$p"; [[ -n "$tport" ]] && post="$tport"
                if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
                    if [[ -n "$tport" ]]; then
                        echo "        iifname \"${iface}\" tcp dport ${p} dnat ip to ${tip}:${post}"
                    else
                        echo "        iifname \"${iface}\" tcp dport ${p} dnat ip to ${tip}"
                    fi
                fi
                if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
                    if [[ -n "$tport" ]]; then
                        echo "        iifname \"${iface}\" udp dport ${p} dnat ip to ${tip}:${post}"
                    else
                        echo "        iifname \"${iface}\" udp dport ${p} dnat ip to ${tip}"
                    fi
                fi
            done
        done < "$PLUGIN_STATE"
        echo "    }"
        echo "    chain postrouting_nv {"
        echo "        type nat hook postrouting priority srcnat; policy accept;"
        while IFS='|' read -r name proto ports tip tport iface sip; do
            [[ -z "$name" ]] && continue
            IFS=',' read -ra plist <<< "$ports"
            for p in "${plist[@]}"; do
                post="$p"; [[ -n "$tport" ]] && post="$tport"
                if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
                    echo "        oifname \"${iface}\" ip daddr ${tip} tcp dport ${post} snat ip to ${sip}"
                fi
                if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
                    echo "        oifname \"${iface}\" ip daddr ${tip} udp dport ${post} snat ip to ${sip}"
                fi
            done
        done < "$PLUGIN_STATE"
        echo "    }"
        echo "}"
    } > "$tmp"
    nft -c -f "$tmp" || { rm -f "$tmp"; log_error "nft -c проверка не прошла — файл НЕ применён."; }
    mv "$tmp" "$PLUGIN_FILE"
    nft -f "$PLUGIN_FILE"
}

ensure_plugin_unit() {
    [[ -f "$PLUGIN_UNIT_PATH" ]] && return 0
    cat > "$PLUGIN_UNIT_PATH" <<EOF
[Unit]
Description=NullVPN plugin relays (managed by reshala 02_nullvpn_dnat.sh)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStartPre=-/usr/sbin/nft delete table ip ${PLUGIN_TABLE}
ExecStart=/usr/sbin/nft -f ${PLUGIN_FILE}
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$PLUGIN_UNIT" >/dev/null 2>&1 || true
}

cleanup_plugin_layer() {
    systemctl disable --now "$PLUGIN_UNIT" >/dev/null 2>&1 || true
    rm -f "$PLUGIN_UNIT_PATH"
    nft delete table ip "$PLUGIN_TABLE" >/dev/null 2>&1 || true
    rm -f "$PLUGIN_FILE" "$PLUGIN_STATE"
    rmdir /etc/nullvpn 2>/dev/null || true
    systemctl daemon-reload
}

# ---------- actions ----------

cmd_list() {
    log_info "Слой [К] (канонический, relay-setup.sh):"
    if nft list table ip "$CANON_TABLE" >/dev/null 2>&1; then
        parse_live_dnats | while IFS='|' read -r pr ports tgt; do
            echo "    ${pr} ${ports} -> ${tgt}"
        done
    else
        echo "    (таблицы нет)"
    fi
    log_info "Слой [P] (плагин, ${PLUGIN_TABLE}):"
    if [[ -f "$PLUGIN_STATE" ]] && [[ -s "$PLUGIN_STATE" ]]; then
        while IFS='|' read -r name proto ports tip tport iface sip; do
            [[ -z "$name" ]] && continue
            local post="сохранение порта"
            [[ -n "$tport" ]] && post="-> :${tport}"
            echo "    ${name}: ${proto} ${ports} -> ${tip} (${post}), iface=${iface}, snat=${sip}"
        done < "$PLUGIN_STATE"
    else
        echo "    (записей нет)"
    fi
}

cmd_probe() {
    local pairsrc rc any=0
    log_info "TCP-пробы до целей (с этой ноды):"
    # уникальные target:port из канонической live-таблицы
    if nft list table ip "$CANON_TABLE" >/dev/null 2>&1; then
        while IFS='|' read -r pr ports tgt; do
            local ip="${tgt%%:*}" tp="${tgt##*:}"
            [[ "$tp" == "$ip" ]] && tp=""   # без порта
            IFS=',' read -ra plist <<< "$ports"
            local p
            for p in "${plist[@]}"; do
                local port="$p"; [[ -n "$tp" ]] && port="$tp"
                if tcp_probe "$ip" "$port"; then
                    log_ok "${CANON_TABLE}: ${ip}:${port} (${pr}) — OK"
                else
                    log_warn "${CANON_TABLE}: ${ip}:${port} (${pr}) — FAIL"
                    any=1
                fi
            done
        done < <(parse_live_dnats)
    fi
    # из плагин-слоя (state)
    if [[ -f "$PLUGIN_STATE" ]]; then
        while IFS='|' read -r name proto ports tip tport iface sip; do
            [[ -z "$name" ]] && continue
            IFS=',' read -ra plist <<< "$ports"
            local p port
            for p in "${plist[@]}"; do
                port="$p"; [[ -n "$tport" ]] && port="$tport"
                if tcp_probe "$tip" "$port"; then
                    log_ok "[P] ${name}: ${tip}:${port} — OK"
                else
                    log_warn "[P] ${name}: ${tip}:${port} — FAIL"
                    any=1
                fi
            done
        done < "$PLUGIN_STATE"
    fi
    (( any == 0 )) && log_ok "Все цели отвечают."
}

cmd_show() {
    echo "=== NullVPN DNAT: $(hostname) ($(detect_local_ip)) ==="
    echo
    log_info "[К] Канонический слой"
    if [[ -f "$CANON_FILE" ]]; then
        echo "  Файл: ${CANON_FILE} (mtime: $(stat -c %y "$CANON_FILE" 2>/dev/null | cut -d. -f1))"
        head -1 "$CANON_FILE" | sed 's/^/    /'
        [[ -f "$CANON_CONF" ]] && echo "  Conf: $(cat "$CANON_CONF" 2>/dev/null | tr '\n' ' ')"
    else
        log_warn "  Файла ${CANON_FILE} нет."
    fi
    if nft list table ip "$CANON_TABLE" >/dev/null 2>&1; then
        echo "  Live-таблица (prerouting dnat):"
        parse_live_dnats | sed 's/^/    /'
        echo "  Live-таблица (postrouting snat):"
        parse_live_snats | sed 's/^/    /'
        # дубликаты
        local dups
        dups="$(parse_live_dnats | sort | uniq -d)"
        if [[ -n "$dups" ]]; then
            log_warn "DNAT-WARN: ДУБЛИ правил в live prerouting (косметика, но лучше вычистить):"
            echo "$dups" | sed 's/^/    dup: /'
        fi
        # дрейф file vs live (port-rewrite)
        local live_rw file_rw
        live_rw="$(nft -a list table ip "$CANON_TABLE" 2>/dev/null | grep -oE 'dnat to [0-9.]+:[0-9]+' | sort -u || true)"
        file_rw="$(grep -oE 'dnat to [0-9.]+:[0-9]+' "$CANON_FILE" 2>/dev/null | sort -u || true)"
        if [[ -n "$live_rw" && "$live_rw" != "$file_rw" ]]; then
            log_warn "DNAT-WARN: ДРЕЙФ file↔live: в live есть port-rewrite, которого нет в файле:"
            echo "$live_rw" | sed 's/^/    live: /'
            log_warn "  Перезапуск nullvpn-dnat.service (или relay-setup.sh) СНЕСЁТ port-rewrite из live!"
        fi
    else
        log_info "  Live-таблицы ${CANON_TABLE} нет."
    fi
    command -v relay-setup.sh >/dev/null 2>&1 && log_info "  Канонический менеджер: $(command -v relay-setup.sh)"
    echo
    log_info "[P] Плагин-слой (${PLUGIN_TABLE})"
    if [[ -f "$PLUGIN_STATE" ]] && [[ -s "$PLUGIN_STATE" ]]; then
        while IFS='|' read -r name proto ports tip tport iface sip; do
            [[ -z "$name" ]] && continue
            local post="сохранение порта"
            [[ -n "$tport" ]] && post="-> :${tport}"
            echo "    ${name}: ${proto} ${ports} -> ${tip} (${post}), iface=${iface}, snat=${sip}"
        done < "$PLUGIN_STATE"
    else
        echo "  (записей нет)"
    fi
    echo
    log_info "Листенеры :443/:2053 локально (норма для entry-ноды: пусто):"
    ss -Hlnt 2>/dev/null | grep -E ':(443|2053)\b' | sed 's/^/    /' || echo "    (пусто)"
    echo
    cmd_probe || true
}

cmd_add() {
    guard_mutation
    NV_NAME="${DNAT_NAME:-}"
    NV_TARGET_IP="${DNAT_TARGET_IP:-}"
    NV_PORTS="${DNAT_LISTEN_PORTS:-}"
    NV_PROTO="${DNAT_PROTO:-both}"
    NV_TARGET_PORT="${DNAT_TARGET_PORT:-}"
    NV_IFACE="${DNAT_IFACE:-$(detect_iface)}"
    NV_SNAT_IP="${DNAT_SNAT_IP:-$(detect_local_ip "$NV_IFACE")}"

    [[ "$NV_NAME" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || log_error "DNAT_NAME: обязателен, [a-z0-9-], до 32 символов."
    valid_ipv4 "$NV_TARGET_IP" || log_error "DNAT_TARGET_IP некорректен: '${NV_TARGET_IP}'"
    valid_ports_csv "$NV_PORTS" || log_error "DNAT_LISTEN_PORTS некорректны: '${NV_PORTS}' (csv 1-65535)"
    [[ "$NV_PROTO" =~ ^(tcp|udp|both)$ ]] || log_error "DNAT_PROTO: tcp|udp|both"
    [[ -n "$NV_TARGET_PORT" ]] && { [[ "$NV_TARGET_PORT" =~ ^[0-9]+$ ]] && (( NV_TARGET_PORT >= 1 && NV_TARGET_PORT <= 65535 )) || log_error "DNAT_TARGET_PORT некорректен"; }
    [[ -n "$NV_IFACE" ]] || log_error "Не смог определить iface — задай DNAT_IFACE."
    [[ -n "$NV_SNAT_IP" ]] || log_error "Не смог определить SNAT IP — задай DNAT_SNAT_IP."
    [[ -n "$NV_TARGET_PORT" && "$NV_TARGET_PORT" == "$NV_PORTS" ]] && log_warn "DNAT_TARGET_PORT = listen port — это просто сохранение порта."

    log_info "Добавляю релей '${NV_NAME}': ${NV_PROTO} ${NV_PORTS} -> ${NV_TARGET_IP}$([[ -n "$NV_TARGET_PORT" ]] && echo ":${NV_TARGET_PORT}") (iface ${NV_IFACE}, snat ${NV_SNAT_IP})"
    state_add
    apply_plugin_rules
    ensure_plugin_unit
    log_ok "Готово. Таблица ${PLUGIN_TABLE} применена, юнит ${PLUGIN_UNIT} включён (переживает reboot)."
    log_info "Проверка: DNAT_ACTION=probe DNAT_NAME=${NV_NAME} bash $(realpath "$0")"
}

cmd_del() {
    guard_mutation
    NV_NAME="${DNAT_NAME:-}"
    [[ "$NV_NAME" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || log_error "DNAT_NAME обязателен."
    state_del
    if [[ -s "$PLUGIN_STATE" ]]; then
        apply_plugin_rules
        log_ok "Релей '${NV_NAME}' удалён; остальные перегенерированы."
    else
        cleanup_plugin_layer
        log_ok "Релей '${NV_NAME}' удалён; это был последний — плагин-слой вычищен (таблица/юнит/файлы)."
    fi
}

case "$ACTION" in
    show)  cmd_show ;;
    list)  cmd_list ;;
    probe) cmd_probe ;;
    add)   cmd_add ;;
    del)   cmd_del ;;
    *)     log_error "DNAT_ACTION: show|list|probe|add|del (получено: '${ACTION}')" ;;
esac

exit 0
