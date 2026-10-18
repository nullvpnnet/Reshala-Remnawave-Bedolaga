#!/bin/bash
# TITLE: NullVPN: статус ноды (remnanode/DNAT/шейпер/система)
# ============================================================ #
# ==   SKYNET ПЛАГИН: NullVPN NODE STATUS (read-only)       == #
# ============================================================ #
#
# Полный статус NullVPN-ноды одним блоком. Read-only, безопасен на
# ЛЮБОЙ ноде (DE1/DE2/RU-1/RU-2/ES-*). Удобно гнать на всём флоте
# через Skynet и смотреть [ok]/[warn] маркеры.
#
# Секции: система → docker/remnanode → core-сервисы → DNAT (оба слоя)
#         → eBPF-шейпер Решалы → fail2ban → публичные листенеры.
# Финальная строка: NV-STATUS: OK|WARN (для grep по флоту).
#
# ENV: нет (полностью автономный).
#
set -uo pipefail

C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'
sec()   { echo -e "\n${C_CYAN}=== $* ===${C_RESET}"; }
ok()    { echo -e "  ${C_GREEN}[ok]${C_RESET} $*"; }
warn()  { echo -e "  ${C_YELLOW}[warn]${C_RESET} $*"; }
info()  { echo -e "  ${C_RESET}[..]  $*"; }

WARNS=0
w() { warn "$*"; WARNS=$((WARNS+1)); }

# ---------- система ----------
sec "Система"
H="$(hostname)"
K="$(uname -r)"
U="$(uptime -p 2>/dev/null || uptime)"
echo "  host=${H}  kernel=${K}"
echo "  uptime: ${U}"
DISK_PCT="$(df -P / | awk 'NR==2 {gsub(/%/,""); print $5}')"
DISK_AVAIL="$(df -Ph / | awk 'NR==2 {print $4}')"
if (( DISK_PCT >= 90 )); then w "диск / заполнен на ${DISK_PCT}% (avail ${DISK_AVAIL}) — КРИТИЧНО"
elif (( DISK_PCT >= 80 )); then w "диск / заполнен на ${DISK_PCT}% (avail ${DISK_AVAIL})"
else ok "диск / : ${DISK_PCT}% (avail ${DISK_AVAIL})"; fi
MEM_AVAIL="$(free -m | awk '/^Mem:/ {print $7}')"
if [[ -n "$MEM_AVAIL" ]] && (( MEM_AVAIL < 200 )); then w "mem avail ${MEM_AVAIL} MB — мало"; else ok "mem avail: ${MEM_AVAIL:-?} MB"; fi

# ---------- docker / remnanode ----------
sec "Docker / remnanode"
if command -v docker >/dev/null 2>&1; then
    RN="$(docker ps -a --format '{{.Names}}|{{.Status}}' 2>/dev/null | grep -i 'remnanode' || true)"
    if [[ -n "$RN" ]]; then
        while IFS='|' read -r n s; do
            if [[ "$s" == Up* ]]; then ok "remnanode '${n}': ${s}"; else w "remnanode '${n}': ${s}"; fi
        done <<< "$RN"
    else
        info "remnanode-контейнеров нет (норма для entry/relay-нод)"
    fi
    NCONT="$(docker ps -q 2>/dev/null | wc -l)"
    info "docker контейнеров запущено: ${NCONT}"
else
    info "docker не установлен"
fi

# ---------- core-сервисы ----------
sec "Core-сервисы"
if systemctl is-active ssh sshd 2>/dev/null | grep -q '^active$'; then
    ok "sshd: active"
else
    w "sshd: НЕ active (при открытом :22 это странно — проверь вручную)"
fi
st_f2b="$(systemctl is-active fail2ban 2>/dev/null)"
[[ "$st_f2b" == "active" ]] && ok "fail2ban: active" || w "fail2ban: ${st_f2b:-нет}"
for u in xray sing-box reshala-traffic-limiter nullvpn-dnat nullvpn-nv-dnat; do
    if ! systemctl cat "$u" >/dev/null 2>&1; then
        info "${u}: нет на ноде (норма, если не предусмотрен)"
        continue
    fi
    st="$(systemctl is-active "$u" 2>/dev/null)"
    en="$(systemctl is-enabled "$u" 2>/dev/null || echo '?')"
    if [[ "$st" == "active" || "$st" == "exited" ]]; then
        ok "${u}: ${st} (enabled=${en})"
    else
        info "${u}: ${st} (enabled=${en}) — выключен/замаскирован"
    fi
done

# ---------- DNAT ----------
sec "DNAT (v4 вход)"
if nft list table ip nullvpn-dnat >/dev/null 2>&1; then
    ND="$(nft -a list table ip nullvpn-dnat 2>/dev/null | grep -c 'dnat to' || true)"
    NS="$(nft -a list table ip nullvpn-dnat 2>/dev/null | grep -c 'snat to' || true)"
    DUP="$(nft -a list table ip nullvpn-dnat 2>/dev/null | grep -E 'dnat to|snat to' | sed 's/ # handle [0-9]*//' | sort | uniq -d | wc -l)"
    ok "таблица nullvpn-dnat: dnat-правил=${ND}, snat-правил=${NS}"
    (( DUP > 0 )) && w "задвоенных правил в nullvpn-dnat: ${DUP} (косметика)"
    DFILE='/etc/nftables.d/nullvpn-dnat.nft'
    if [[ -f "$DFILE" ]]; then
        LIVE_RW="$(nft -a list table ip nullvpn-dnat 2>/dev/null | grep -oE 'dnat to [0-9.]+:[0-9]+' | sort -u || true)"
        FILE_RW="$(grep -oE 'dnat to [0-9.]+:[0-9]+' "$DFILE" 2>/dev/null | sort -u || true)"
        if [[ -n "$LIVE_RW" && "$LIVE_RW" != "$FILE_RW" ]]; then
            w "ДРЕЙФ file↔live (live port-rewrite отсутствует в файле) — рестарт nullvpn-dnat.service снесёт его!"
        fi
    fi
else
    info "таблицы nullvpn-dnat нет (не entry-нода или релей не поднят)"
fi
if nft list table ip nullvpn-nv-dnat >/dev/null 2>&1; then
    ok "плагин-таблица nullvpn-nv-dnat присутствует ($(nft -a list table ip nullvpn-nv-dnat 2>/dev/null | grep -c 'dnat to') dnat)"
else
    info "плагин-таблицы nullvpn-nv-dnat нет"
fi
P443="$(ss -Hlnt 2>/dev/null | grep -cE ':443\b' || true)"
P2053="$(ss -Hlnt 2>/dev/null | grep -cE ':2053\b' || true)"
info "локальные листенеры: :443=${P443}, :2053=${P2053} (для entry-ноды норма 0 — трафик DNAT'ится)"

# ---------- reshala shaper ----------
sec "eBPF-шейпер (reshala)"
if [[ -d /opt/reshala || -d /opt/reshala-src ]]; then
    ok "фреймворк решалы установлен (/opt/reshala$([[ -d /opt/reshala-src ]] && echo ' + /opt/reshala-src'))"
    SHST="$(systemctl is-active reshala-traffic-limiter 2>/dev/null || echo inactive)"
    if [[ "$SHST" == "active" ]]; then
        ok "reshala-traffic-limiter: active"
        IFACE_CFG="$(grep 'IFACE=' /etc/reshala/traffic_limiter/ebpf_config.conf 2>/dev/null | cut -d'"' -f2)"
        info "iface=${IFACE_CFG:-?}, maps: $(ls /sys/fs/bpf/reshala/maps 2>/dev/null | wc -l) pinned"
        NR="$(python3 -c "import json;print(len(json.load(open('/etc/reshala/traffic_limiter/rules.json'))))" 2>/dev/null || echo '?')"
        info "активных правил шейпера: ${NR}"
    else
        info "reshala-traffic-limiter: ${SHST} (шейпер idle)"
        RQ="$(tc -j qdisc show dev "$(ip route | awk '/default/ {print $5; exit}')" 2>/dev/null | grep -oE '"kind":"[a-z0-9_]+"' | head -1 || true)"
        case "$RQ" in
            *noqueue*|*fq*) : ;;
            *) w "root qdisc не дефолтный (${RQ:-?}) — старт shaper-движка ЗАМЕНИТ его (проверь nullvpn-qdisc на RU!)" ;;
        esac
    fi
else
    info "решалы нет (шейпер не устанавливался)"
fi

# ---------- fail2ban ----------
sec "Fail2ban"
if command -v fail2ban-client >/dev/null 2>&1; then
    JAILS="$(fail2ban-client status 2>/dev/null | grep 'Jail list' | sed 's/.*:\s*//' | tr -d ' ')"
    ok "jails: ${JAILS:-?}"
    BANNED=0
    IFS=',' read -ra JLIST <<< "${JAILS}"
    for j in "${JLIST[@]}"; do
        [[ -z "$j" ]] && continue
        jn="$(fail2ban-client status "$j" 2>/dev/null | grep 'Banned IP' | sed 's/.*:\s*//' | wc -w)"
        BANNED=$((BANNED + jn))
    done
    info "забанено суммарно: ${BANNED} IP"
else
    info "fail2ban-client не найден"
fi

# ---------- публичные листенеры ----------
sec "Публичные листенеры (v4)"
ss -Hlnt 2>/dev/null | awk '$4 !~ /^127\.|^\[?::1/ {print "  "$4}' | sort -u || true

echo
if (( WARNS > 0 )); then
    echo -e "${C_YELLOW}NV-STATUS: WARN (${WARNS})${C_RESET}"
else
    echo -e "${C_GREEN}NV-STATUS: OK${C_RESET}"
fi
exit 0
