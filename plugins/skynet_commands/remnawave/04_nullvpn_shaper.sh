#!/bin/bash
# TITLE: NullVPN: eBPF-шейпер Решалы — status/add/del/whitelist
# ============================================================ #
# ==  SKYNET ПЛАГИН: NullVPN SHAPER (reshala eBPF engine)   == #
# ============================================================ #
#
# Управление правилами eBPF-шейпера Решалы через официальный CLI
# движка (reshala_ctrl.py): set/delete обновляют карты ЖИВЬЁМ и
# персистят rules.json (рестарт сервиса не нужен).
#
# БЕЗОПАСНОСТЬ (важно для RU-нод):
#   - Плагин НИКОГДА не стартует/не останавливает движок и не трогает
#     qdisc. Старт движка делает `tc qdisc del dev IFACE root` + `add fq`
#     (ExecStartPre Решалы) — на RU-нодах это УБЬЁТ существующий
#     nullvpn-qdisc! Статус предупреждает, если root qdisc не дефолтный.
#   - Требуется установленный фреймворк Решалы (/opt/reshala или
#     /opt/reshala-src) — см. пилот Task 101.
#
# ENV:
#   SHAPER_ACTION=status|add|del|whitelist     (default: status)
#   SHAPER_RULE_ID=0..31                       add/del: ID правила
#   SHAPER_MODE=1|2|3                          add: 1=статика, 2=динамика
#                                              (burst→штраф), 3=общий пул
#   SHAPER_PORTS="443,2053"                    add: порты (csv)
#   SHAPER_DOWN=50   SHAPER_UP=50              add: МБ/с
#   SHAPER_PEN=0.1  SHAPER_BURST=70  SHAPER_WIN=10  SHAPER_PEN_SEC=60
#                                              add: optional (дефолты движка)
#   SHAPER_WL_FILE=/path/whitelist.txt         whitelist: файл IP
#
set -euo pipefail

C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'
log_info()  { echo -e "${C_RESET}[i] $*${C_RESET}"; }
log_ok()    { echo -e "${C_GREEN}[✓] $*${C_RESET}"; }
log_warn()  { echo -e "${C_YELLOW}[!] $*${C_RESET}"; }
log_error() { echo -e "${C_RED}[✗] $*${C_RESET}"; exit 1; }

ACTION="${SHAPER_ACTION:-status}"
CTRL_CFG='/etc/reshala/traffic_limiter/ebpf_config.conf'
RULES_FILE='/etc/reshala/traffic_limiter/rules.json'
PIN_DIR='/sys/fs/bpf/reshala/maps'

[[ $EUID -ne 0 ]] && log_error "Нужен root."

# ---------- locate engine ----------
CTRL_PY=""
for c in /opt/reshala/modules/local/reshala_ctrl.py /opt/reshala-src/modules/local/reshala_ctrl.py; do
    [[ -f "$c" ]] && { CTRL_PY="$c"; break; }
done
[[ -z "$CTRL_PY" ]] && CTRL_PY="$(find /opt -maxdepth 4 -name reshala_ctrl.py -type f 2>/dev/null | head -1)"
service_active() { [[ "$(systemctl is-active reshala-traffic-limiter 2>/dev/null)" == "active" ]]; }

# ---------- actions ----------

cmd_status() {
    echo "=== NullVPN shaper: $(hostname) ==="
    if [[ -z "$CTRL_PY" ]]; then
        log_warn "reshala_ctrl.py не найден — фреймворк Решалы не установлен. Ставь фреймворк (см. пилот Task 101), НЕ запуская движок на RU без проверки qdisc."
        exit 0
    fi
    log_info "ctrl: ${CTRL_PY}"
    local st; st="$(systemctl is-active reshala-traffic-limiter 2>/dev/null || echo inactive)"
    local en; en="$(systemctl is-enabled reshala-traffic-limiter 2>/dev/null || echo no)"
    if [[ "$st" == "active" ]]; then
        log_ok "движок: ACTIVE (enabled=${en})"
    else
        log_info "движок: ${st} (enabled=${en}) — правила не применяются"
    fi
    local iface=""; [[ -f "$CTRL_CFG" ]] && iface="$(grep 'IFACE=' "$CTRL_CFG" | cut -d'"' -f2)"
    log_info "iface: ${iface:-не задан}"

    # root qdisc advisory — КРИТИЧНО для RU-нод (nullvpn-qdisc)
    if [[ -n "$iface" ]]; then
        local rq; rq="$(tc qdisc show dev "$iface" 2>/dev/null | head -1)"
        if service_active; then
            log_info "root qdisc сейчас: ${rq}"
        else
            case "$rq" in
                *noqueue*|"")
                    log_info "root qdisc: ${rq:-<нет>} (дефолт — старт движка безопасен для qdisc)"
                    ;;
                *)
                    log_warn "ROOT QDISC НЕ ДЕФОЛТНЫЙ: ${rq}"
                    log_warn "  СТАРТ движка (ExecStartPre) СНЕСЁТ его и поставит fq! На RU-нодах это nullvpn-qdisc."
                    log_warn "  Если реально нужен шейпер на этой ноде — сначала инвентарь tc/nft и решение владельца."
                    ;;
            esac
        fi
    fi

    if [[ -f "$RULES_FILE" ]]; then
        local nr; nr="$(python3 -c "import json;d=json.load(open('$RULES_FILE'));print(len(d) if isinstance(d,list) else sum(len(v) for v in d.values()))" 2>/dev/null || echo '?')"
        log_info "rules.json: ${nr} правил(о)"
    fi
    if service_active; then
        log_info "Правила движка:"
        python3 "$CTRL_PY" rules 2>/dev/null | sed 's/^/    /' || log_warn "не смог опросить rules"
        log_info "Карты: $(ls "$PIN_DIR" 2>/dev/null | wc -l) pinned в ${PIN_DIR}"
    fi
    log_ok "Статус собран (read-only)."
}

cmd_add() {
    [[ -n "$CTRL_PY" ]] || log_error "reshala_ctrl.py не найден — сначала установи фреймворк Решалы."
    local id="${SHAPER_RULE_ID:-}" mode="${SHAPER_MODE:-}" ports="${SHAPER_PORTS:-}"
    local down="${SHAPER_DOWN:-}" up="${SHAPER_UP:-}"
    [[ "$id" =~ ^[0-9]+$ ]] && (( id >= 0 && id <= 31 )) || log_error "SHAPER_RULE_ID: 0..31"
    [[ "$mode" =~ ^[1-3]$ ]] || log_error "SHAPER_MODE: 1|2|3"
    [[ "$ports" =~ ^[0-9]+(,[0-9]+)*$ ]] || log_error "SHAPER_PORTS: csv портов"
    [[ "$down" =~ ^[0-9.]+$ && "$up" =~ ^[0-9.]+$ ]] || log_error "SHAPER_DOWN/SHAPER_UP: числа МБ/с"

    # движок должен быть active (set пишет в pinned карты)
    if ! service_active; then
        log_warn "Движок НЕ active — set упадёт или уйдёт в никуда. Старт движка на этой ноде:"
        log_warn "  ВНИМАНИЕ: старт СНЕСЁТ root qdisc и поставит fq (см. статус). На RU — проверь nullvpn-qdisc!"
        log_error "Отказ: сначала запусти движок осознанно (systemctl start reshala-traffic-limiter), затем повтори."
    fi

    local args=(set --rule-id "$id" --mode "$mode" --ports "$ports" --down "$down" --up "$up")
    [[ -n "${SHAPER_PEN:-}" ]]      && args+=(--pen "$SHAPER_PEN")
    [[ -n "${SHAPER_BURST:-}" ]]    && args+=(--burst "$SHAPER_BURST")
    [[ -n "${SHAPER_WIN:-}" ]]      && args+=(--win "$SHAPER_WIN")
    [[ -n "${SHAPER_PEN_SEC:-}" ]]  && args+=(--pen-sec "$SHAPER_PEN_SEC")

    log_info "Применяю: rule#${id} mode=${mode} ports=${ports} down=${down} up=${up} МБ/с"
    python3 "$CTRL_PY" "${args[@]}"
    log_ok "Карта обновлена ЖИВЬЁМ, rules.json персистится. Текущие правила:"
    python3 "$CTRL_PY" rules 2>/dev/null | sed 's/^/    /'
}

cmd_del() {
    [[ -n "$CTRL_PY" ]] || log_error "reshala_ctrl.py не найден."
    local id="${SHAPER_RULE_ID:-}"
    [[ "$id" =~ ^[0-9]+$ ]] && (( id >= 0 && id <= 31 )) || log_error "SHAPER_RULE_ID: 0..31"
    service_active || log_info "движок не active — удаление затронет только rules.json"
    python3 "$CTRL_PY" delete --rule-id "$id"
    log_ok "rule#${id} удалён. Остаток:"
    python3 "$CTRL_PY" rules 2>/dev/null | sed 's/^/    /' || true
}

cmd_whitelist() {
    [[ -n "$CTRL_PY" ]] || log_error "reshala_ctrl.py не найден."
    local f="${SHAPER_WL_FILE:-}"
    [[ -n "$f" && -f "$f" ]] || log_error "SHAPER_WL_FILE: путь к файлу IP (по одному в строке)"
    service_active || log_error "движок не active — whitelist применяется в карты живьём"
    python3 "$CTRL_PY" whitelist-sync --file "$f"
    log_ok "Whitelist синхронизирован из ${f}"
}

case "$ACTION" in
    status)    cmd_status ;;
    add)       cmd_add ;;
    del)       cmd_del ;;
    whitelist) cmd_whitelist ;;
    *)         log_error "SHAPER_ACTION: status|add|del|whitelist (получено: '${ACTION}')" ;;
esac

exit 0
