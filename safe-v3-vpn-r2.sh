cat > /root/install-firewall-selfheal-safe-v3-vpn-r2.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_LOG="/root/firewall-selfheal-install-v3-vpn-r2-$(date +%F-%H%M%S).log"
exec > >(tee -a "$INSTALL_LOG") 2>&1

SCRIPT_PATH="/usr/local/sbin/firewall-selfheal.sh"
SERVICE_PATH="/etc/systemd/system/firewall-selfheal.service"
TIMER_PATH="/etc/systemd/system/firewall-selfheal.timer"
LOG_DIR="/var/log/firewall-selfheal"
LOG_FILE="${LOG_DIR}/selfheal.log"
BACKUP_DIR="/root/firewall-selfheal-backup-v3-vpn-r2-$(date +%F-%H%M%S)"

mkdir -p /usr/local/sbin "$LOG_DIR" "$BACKUP_DIR"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

section() {
  echo
  echo "=================================================="
  echo "$*"
  echo "=================================================="
}

show_failure_context() {
  section "FAILURE CONTEXT"

  echo "--- install log tail ---"
  tail -n 100 "$INSTALL_LOG" || true

  echo "--- selfheal log tail ---"
  tail -n 150 "$LOG_FILE" || true

  echo "--- firewall-selfheal.service status ---"
  systemctl status firewall-selfheal.service --no-pager || true

  echo "--- firewall-selfheal.timer status ---"
  systemctl status firewall-selfheal.timer --no-pager || true

  echo "--- journalctl firewall-selfheal.service ---"
  journalctl -u firewall-selfheal.service -n 150 --no-pager || true

  echo "--- iptables INPUT ---"
  iptables -S INPUT || true
  iptables -nvL INPUT --line-numbers || true

  echo "--- iptables DOCKER-USER ---"
  iptables -S DOCKER-USER || true
  iptables -nvL DOCKER-USER --line-numbers || true

  echo "--- ufw status verbose ---"
  ufw status verbose || true

  echo "--- ufw status numbered ---"
  ufw status numbered || true

  echo "--- listening ports ---"
  ss -lntup || true
}

trap 'red "INSTALL FAILED"; show_failure_context' ERR

section "[1/10] Backup текущих настроек"
iptables-save > "${BACKUP_DIR}/iptables.rules.v4" 2>/dev/null || true
ip6tables-save > "${BACKUP_DIR}/iptables.rules.v6" 2>/dev/null || true
ufw status verbose > "${BACKUP_DIR}/ufw-status.txt" 2>/dev/null || true
ss -lntup > "${BACKUP_DIR}/ss-listen.txt" 2>/dev/null || true
systemctl cat firewall-selfheal.service > "${BACKUP_DIR}/firewall-selfheal.service.txt" 2>/dev/null || true
systemctl cat firewall-selfheal.timer > "${BACKUP_DIR}/firewall-selfheal.timer.txt" 2>/dev/null || true
green "Backup: ${BACKUP_DIR}"

section "[2/10] Установка пакетов"
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y ufw iptables iproute2 curl ca-certificates systemd

section "[3/10] Установка self-heal скрипта"
cat > "$SCRIPT_PATH" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

LOG="/var/log/firewall-selfheal/selfheal.log"
mkdir -p /var/log/firewall-selfheal

NEVER_BLOCK_IPS=(
  "178.253.55.227"
  "212.113.116.136"
)

ADMIN_IPS=(
  "178.253.55.227"
  "212.113.116.136"
)

PUBLIC_TCP_PORTS=(80 443 8443)
PUBLIC_UDP_PORTS=(443)
PUBLIC_UDP_RANGES=("32690:32700")
RESTRICTED_TCP_PORTS=(8080 2053 8888 2096)

log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "ОШИБКА: отсутствует команда $1"
    exit 1
  }
}

ensure_base_packages() {
  need_cmd ufw
  need_cmd iptables
  need_cmd iptables-save
  need_cmd ss
  need_cmd systemctl
  need_cmd grep
  need_cmd awk
  need_cmd sed
}

ufw_active() {
  ufw status | grep -q "^Status: active"
}

ufw_status_text() {
  ufw status numbered 2>/dev/null || true
}

ufw_has_any_tcp() {
  local port="$1"
  ufw_status_text | grep -Eq "(^|[[:space:]])${port}/tcp([[:space:]]|$)"
}

ufw_has_any_udp() {
  local port="$1"
  ufw_status_text | grep -Eq "(^|[[:space:]])${port}/udp([[:space:]]|$)"
}

ufw_has_any_udp_range() {
  local range="$1"
  ufw_status_text | grep -Eq "(^|[[:space:]])${range}/udp([[:space:]]|$)"
}

ufw_has_ip_tcp_rule() {
  local ip="$1"
  local port="$2"
  ufw_status_text | grep -F "$ip" | grep -Eq "(^|[[:space:]])${port}/tcp([[:space:]]|$)"
}

ufw_has_deny_tcp() {
  local port="$1"
  ufw_status_text | grep -Eq "(^|[[:space:]])${port}/tcp([[:space:]]|$).*DENY"
}

ensure_ufw_bootstrap_if_inactive() {
  log "Проверка UFW"
  if ufw_active; then
    log "UFW уже активен"
    return 0
  fi

  log "UFW неактивен -> безопасный bootstrap"
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming
  ufw default allow outgoing

  # 22 открыт с любого IP
  ufw allow 22/tcp

  for port in "${PUBLIC_TCP_PORTS[@]}"; do
    ufw allow "${port}/tcp"
  done

  for port in "${PUBLIC_UDP_PORTS[@]}"; do
    ufw allow "${port}/udp"
  done

  for range in "${PUBLIC_UDP_RANGES[@]}"; do
    ufw allow "${range}/udp"
  done

  for ip in "${ADMIN_IPS[@]}"; do
    for port in "${RESTRICTED_TCP_PORTS[@]}"; do
      ufw allow from "$ip" to any port "$port" proto tcp
    done
  done

  ufw deny 2096/tcp || true
  ufw logging medium || true
  ufw --force enable
  log "UFW bootstrap завершён"
}

ensure_ufw_rules() {
  log "Проверка и доведение правил UFW"

  if ufw_has_any_tcp 22; then
    log "UFW OK: 22/tcp"
  else
    ufw allow 22/tcp
    log "UFW ADD: 22/tcp"
  fi

  for port in "${PUBLIC_TCP_PORTS[@]}"; do
    if ufw_has_any_tcp "$port"; then
      log "UFW OK: ${port}/tcp"
    else
      ufw allow "${port}/tcp"
      log "UFW ADD: ${port}/tcp"
    fi
  done

  for port in "${PUBLIC_UDP_PORTS[@]}"; do
    if ufw_has_any_udp "$port"; then
      log "UFW OK: ${port}/udp"
    else
      ufw allow "${port}/udp"
      log "UFW ADD: ${port}/udp"
    fi
  done

  for range in "${PUBLIC_UDP_RANGES[@]}"; do
    if ufw_has_any_udp_range "$range"; then
      log "UFW OK: ${range}/udp"
    else
      ufw allow "${range}/udp"
      log "UFW ADD: ${range}/udp"
    fi
  done

  for ip in "${ADMIN_IPS[@]}"; do
    for port in "${RESTRICTED_TCP_PORTS[@]}"; do
      if ufw_has_ip_tcp_rule "$ip" "$port"; then
        log "UFW OK: ${ip} -> ${port}/tcp"
      else
        ufw allow from "$ip" to any port "$port" proto tcp
        log "UFW ADD: ${ip} -> ${port}/tcp"
      fi
    done
  done

  if ufw_has_deny_tcp 2096; then
    log "UFW OK: deny 2096/tcp"
  else
    ufw deny 2096/tcp
    log "UFW ADD: deny 2096/tcp"
  fi

  ufw logging medium >/dev/null 2>&1 || true
  log "Проверка UFW завершена"
}

delete_all_matching_input_rule() {
  local ip="$1"
  while iptables -C INPUT -s "$ip" -j ACCEPT >/dev/null 2>&1; do
    iptables -D INPUT -s "$ip" -j ACCEPT || break
  done
}

ensure_trusted_input_rules() {
  log "Проверка прямых trusted-rules в INPUT"

  local ip
  for ip in "${NEVER_BLOCK_IPS[@]}"; do
    delete_all_matching_input_rule "$ip"
  done

  # вставляем в обратном порядке, чтобы итоговый порядок был как в массиве
  for (( idx=${#NEVER_BLOCK_IPS[@]}-1 ; idx>=0 ; idx-- )); do
    ip="${NEVER_BLOCK_IPS[$idx]}"
    iptables -I INPUT 1 -s "$ip" -j ACCEPT
  done

  log "Trusted IP rules установлены в начало INPUT"
}

iptables_rule_exists() {
  iptables -C DOCKER-USER "$@" >/dev/null 2>&1
}

rebuild_docker_user() {
  log "Пересборка DOCKER-USER"

  iptables -N DOCKER-USER 2>/dev/null || true
  iptables -F DOCKER-USER

  iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A DOCKER-USER -m conntrack --ctstate INVALID -j DROP

  local ip
  for ip in "${NEVER_BLOCK_IPS[@]}"; do
    iptables -A DOCKER-USER -s "$ip" -j ACCEPT
  done

  iptables -A DOCKER-USER -p tcp --dport 8080 -j DROP
  iptables -A DOCKER-USER -j RETURN

  log "DOCKER-USER пересобран"
}

verify_docker_user() {
  log "Проверка DOCKER-USER"
  local ok=1
  local ip

  iptables -N DOCKER-USER 2>/dev/null || true

  iptables_rule_exists -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || ok=0
  iptables_rule_exists -m conntrack --ctstate INVALID -j DROP || ok=0
  iptables_rule_exists -p tcp --dport 8080 -j DROP || ok=0

  for ip in "${NEVER_BLOCK_IPS[@]}"; do
    iptables_rule_exists -s "$ip" -j ACCEPT || ok=0
  done

  iptables_rule_exists -j RETURN || ok=0

  if [[ "$ok" -eq 1 ]]; then
    log "DOCKER-USER в порядке"
  else
    log "DOCKER-USER повреждён или неполон -> пересборка"
    rebuild_docker_user
  fi
}

check_ultra_soc_geo_preserved() {
  log "Проверка, что Geo-Block / ULTRA-SOC-GEO не затронут"
  if iptables -S INPUT 2>/dev/null | grep -Eq 'ULTRA-SOC|GEO'; then
    log "ULTRA-SOC/GEO hooks в INPUT присутствуют"
  else
    log "ПРЕДУПРЕЖДЕНИЕ: в INPUT не найдено явных ULTRA-SOC/GEO хуков"
  fi
}

selftest() {
  log "Самопроверка"
  local fail=0
  local ip

  ufw_active || { log "SELFTEST FAIL: UFW inactive"; fail=1; }
  iptables -S DOCKER-USER >/dev/null 2>&1 || { log "SELFTEST FAIL: DOCKER-USER missing"; fail=1; }

  iptables -C DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || {
    log "SELFTEST FAIL: missing RELATED,ESTABLISHED ACCEPT"; fail=1; }

  iptables -C DOCKER-USER -m conntrack --ctstate INVALID -j DROP >/dev/null 2>&1 || {
    log "SELFTEST FAIL: missing INVALID DROP"; fail=1; }

  for ip in "${NEVER_BLOCK_IPS[@]}"; do
    iptables -C INPUT -s "$ip" -j ACCEPT >/dev/null 2>&1 || {
      log "SELFTEST FAIL: INPUT missing trusted ACCEPT for $ip"; fail=1; }
    iptables -C DOCKER-USER -s "$ip" -j ACCEPT >/dev/null 2>&1 || {
      log "SELFTEST FAIL: DOCKER-USER missing never-block ACCEPT for $ip"; fail=1; }
  done

  iptables -C DOCKER-USER -p tcp --dport 8080 -j DROP >/dev/null 2>&1 || {
    log "SELFTEST FAIL: missing DROP on 8080"; fail=1; }

  iptables -C DOCKER-USER -j RETURN >/dev/null 2>&1 || {
    log "SELFTEST FAIL: missing final RETURN"; fail=1; }

  ufw_has_any_tcp 22   || { log "SELFTEST FAIL: missing UFW 22/tcp"; fail=1; }
  ufw_has_any_tcp 80   || { log "SELFTEST FAIL: missing UFW 80/tcp"; fail=1; }
  ufw_has_any_tcp 443  || { log "SELFTEST FAIL: missing UFW 443/tcp"; fail=1; }
  ufw_has_any_udp 443  || { log "SELFTEST FAIL: missing UFW 443/udp"; fail=1; }
  ufw_has_any_tcp 8443 || { log "SELFTEST FAIL: missing UFW 8443/tcp"; fail=1; }
  ufw_has_any_udp_range "32690:32700" || { log "SELFTEST FAIL: missing UFW 32690:32700/udp"; fail=1; }

  for ip in "${ADMIN_IPS[@]}"; do
    for port in "${RESTRICTED_TCP_PORTS[@]}"; do
      ufw_has_ip_tcp_rule "$ip" "$port" || {
        log "SELFTEST FAIL: missing UFW allow from ${ip} to ${port}/tcp"; fail=1; }
    done
  done

  ufw_has_deny_tcp 2096 || {
    log "SELFTEST FAIL: missing UFW deny 2096/tcp"; fail=1; }

  if [[ "$fail" -eq 0 ]]; then
    log "SELFTEST OK"
  else
    log "SELFTEST ERROR"
    return 1
  fi
}

report() {
  log "----- ОТЧЁТ -----"
  {
    echo "### NEVER BLOCK IPS"
    printf '%s\n' "${NEVER_BLOCK_IPS[@]}"
    echo
    echo "### ADMIN IPS"
    printf '%s\n' "${ADMIN_IPS[@]}"
    echo
    echo "### UFW STATUS VERBOSE"
    ufw status verbose || true
    echo
    echo "### UFW STATUS NUMBERED"
    ufw status numbered || true
    echo
    echo "### IPTABLES INPUT"
    iptables -S INPUT || true
    echo
    echo "### IPTABLES DOCKER-USER"
    iptables -S DOCKER-USER || true
    echo
    echo "### LISTEN PORTS"
    ss -lntupH || true
  } | tee -a "$LOG"
  log "----- КОНЕЦ ОТЧЁТА -----"
}

main() {
  ensure_base_packages
  log "Старт firewall self-heal"
  ensure_ufw_bootstrap_if_inactive
  ensure_ufw_rules
  ensure_trusted_input_rules
  verify_docker_user
  check_ultra_soc_geo_preserved
  selftest
  report
  log "Готово"
}

main "$@"
SCRIPT

chmod +x "$SCRIPT_PATH"

section "[4/10] Установка systemd service"
cat > "$SERVICE_PATH" <<'SERVICE'
[Unit]
Description=Firewall self-heal (UFW + DOCKER-USER)
After=network-online.target docker.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/firewall-selfheal.sh
User=root
Group=root
SERVICE

section "[5/10] Установка systemd timer"
cat > "$TIMER_PATH" <<'TIMER'
[Unit]
Description=Run firewall self-heal every 10 minutes

[Timer]
OnBootSec=45s
OnUnitActiveSec=10min
Unit=firewall-selfheal.service
Persistent=true

[Install]
WantedBy=timers.target
TIMER

section "[6/10] Перезагрузка systemd"
systemctl daemon-reload

section "[7/10] Включение timer"
systemctl enable --now firewall-selfheal.timer

section "[8/10] Первый запуск self-heal"
systemctl start firewall-selfheal.service

section "[9/10] Проверка статусов"
systemctl is-enabled firewall-selfheal.timer >/dev/null
systemctl is-active firewall-selfheal.timer >/dev/null
systemctl status firewall-selfheal.service --no-pager || true
systemctl status firewall-selfheal.timer --no-pager || true

section "[10/10] Финальный самотест и отчёт"
if /usr/local/sbin/firewall-selfheal.sh; then
  green "SELF-HEAL FINAL TEST: PASS"
else
  red "SELF-HEAL FINAL TEST: FAIL"
  show_failure_context
  exit 1
fi

echo
echo "===== BACKUP ====="
echo "$BACKUP_DIR"
echo
echo "===== INSTALL LOG ====="
echo "$INSTALL_LOG"
echo
echo "===== SERVICE STATUS ====="
systemctl status firewall-selfheal.service --no-pager || true
echo
echo "===== TIMER STATUS ====="
systemctl status firewall-selfheal.timer --no-pager || true
echo
echo "===== IPTABLES INPUT ====="
iptables -S INPUT || true
echo
echo "===== IPTABLES DOCKER-USER ====="
iptables -S DOCKER-USER || true
echo
echo "===== INPUT GEO/ULTRA-SOC CHECK ====="
iptables -S INPUT 2>/dev/null | grep -E 'ULTRA-SOC|GEO' || true
echo
echo "===== UFW STATUS ====="
ufw status numbered || true
echo
echo "===== LAST LOG LINES ====="
tail -n 150 "$LOG_FILE" || true
echo
green "INSTALL COMPLETE: firewall-selfheal-safe-v3-vpn-r2 installed successfully"
EOF

chmod +x /root/install-firewall-selfheal-safe-v3-vpn-r2.sh
bash /root/install-firewall-selfheal-safe-v3-vpn-r2.sh
