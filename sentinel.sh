#!/usr/bin/env bash
# harden_linux.sh — Automated Linux Server Hardening Toolkit (small-scale, production-minded)
#
# What it does (high-level):
#  - Lock down SSH (safe defaults + backups + validation)
#  - Configure firewall (UFW on Debian/Ubuntu; firewalld on RHEL/Fedora; fallback to iptables rules)
#  - Harden sudo (require pty, log sudo I/O, set sane timeouts)
#  - Enforce password policies (pwquality + login.defs)
#  - Audit basic system security and emit a report
#
# Usage:
#   sudo ./harden_linux.sh
#   sudo ./harden_linux.sh --dry-run
#   sudo ./harden_linux.sh --ssh-port 2222 --allow-ssh-from 203.0.113.10/32
#   sudo ./harden_linux.sh --no-firewall
#
# Notes:
#  - This script aims for "secure by default" but not "break everything".
#  - Review changes, especially on remote servers (avoid locking yourself out).
#  - For SSH: by default it DISABLES root login and password auth (keys recommended).
#
# Exit codes:
#  0 success, non-zero on error

set -euo pipefail

########################################
# Globals / Defaults
########################################
DRY_RUN=0
NO_SSH=0
NO_FIREWALL=0
NO_SUDO=0
NO_PW=0
NO_AUDIT=0

SSH_PORT=22
ALLOW_SSH_FROM=""        # e.g. "203.0.113.10/32"
DISABLE_SSH_PASSWORD=1   # key auth preferred
DISABLE_SSH_ROOT=1

LOG_DIR="/var/log/hardening-toolkit"
LOG_FILE="$LOG_DIR/hardening_$(date +%F_%H%M%S).log"
REPORT_FILE="$LOG_DIR/audit_report_$(date +%F_%H%M%S).txt"

OS_ID=""
OS_LIKE=""
PKG_MGR=""

########################################
# Helpers
########################################
usage() {
  echo "Automated Linux Server Hardening Toolkit"
  echo
  echo "Options:"
  echo "  --dry-run                 Show what would change, do not modify system"
  echo "  --ssh-port N              Set SSH port (default: 22)"
  echo "  --allow-ssh-from CIDR     Restrict SSH to a CIDR (e.g., 203.0.113.10/32)"
  echo "  --keep-ssh-password       Do NOT disable SSH password authentication"
  echo "  --permit-ssh-root         Do NOT disable SSH root login"
  echo "  --no-ssh                  Skip SSH hardening"
  echo "  --no-firewall             Skip firewall configuration"
  echo "  --no-sudo                 Skip sudo hardening"
  echo "  --no-password-policy      Skip password policy enforcement"
  echo "  --no-audit                Skip audit/report generation"
  echo "  -h, --help                Show help"
  echo
  echo "Examples:"
  echo "  sudo ./harden_linux.sh"
  echo "  sudo ./harden_linux.sh --dry-run"
  echo "  sudo ./harden_linux.sh --ssh-port 2222 --allow-ssh-from 203.0.113.10/32"
}

log() { echo "[*] $*" | tee -a "$LOG_FILE" >/dev/null; }
warn() { echo "[!] $*" | tee -a "$LOG_FILE" >/dev/null; }
die() { echo "[X] $*" | tee -a "$LOG_FILE" >/dev/null; exit 1; }

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: $*" | tee -a "$LOG_FILE" >/dev/null
  else
    # shellcheck disable=SC2086
    eval "$@" >>"$LOG_FILE" 2>&1
  fi
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

ensure_log_dir() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: mkdir -p '$LOG_DIR' && chmod 700 '$LOG_DIR'"
  else
    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
  fi
}

detect_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"
  else
    PKG_MGR=""
  fi

  log "Detected OS: ID='${OS_ID}', LIKE='${OS_LIKE}', pkg_mgr='${PKG_MGR}'"
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local b="${f}.bak.$(date +%F_%H%M%S)"
  run "cp -a '$f' '$b'"
  log "Backup: $f -> $b"
}

ensure_pkg() {
  local pkg="$1"
  if command -v "$pkg" >/dev/null 2>&1; then
    return 0
  fi

  [[ -n "$PKG_MGR" ]] || { warn "No package manager detected; cannot install '$pkg'."; return 1; }

  log "Installing package (if available): $pkg"
  case "$PKG_MGR" in
    apt)    run "apt-get update -y"; run "apt-get install -y '$pkg'";;
    dnf)    run "dnf install -y '$pkg'";;
    yum)    run "yum install -y '$pkg'";;
    zypper) run "zypper --non-interactive install '$pkg'";;
    *)      warn "Unknown package manager; cannot install '$pkg'."; return 1;;
  esac
}

set_kv_in_file() {
  local file="$1" key="$2" val="$3" sep="${4:- }"
  [[ -f "$file" ]] || die "Missing file: $file"

  backup_file "$file"

  if grep -Eq "^[#[:space:]]*${key}(${sep}|[[:space:]])" "$file"; then
    run "perl -0777 -i -pe 's/^[#\\s]*${key}(${sep}|\\s+).*\$/\${key}${sep}${val}/mg' '$file'"
  else
    run "printf '\n%s%s%s\n' '${key}' '${sep}' '${val}' >> '$file'"
  fi
}

########################################
# 1) SSH Hardening
########################################
harden_ssh() {
  log "=== SSH Hardening ==="

  local sshd_cfg="/etc/ssh/sshd_config"
  [[ -f "$sshd_cfg" ]] || { warn "sshd_config not found; skipping SSH hardening."; return 0; }

  warn "SSH changes can lock you out. Ensure you have key auth + an open session before applying remotely."

  if [[ "$SSH_PORT" -ne 22 ]]; then
    set_kv_in_file "$sshd_cfg" "Port" "$SSH_PORT"
  else
    set_kv_in_file "$sshd_cfg" "Port" "22"
  fi

  if [[ "$DISABLE_SSH_ROOT" -eq 1 ]]; then
    set_kv_in_file "$sshd_cfg" "PermitRootLogin" "no"
  else
    set_kv_in_file "$sshd_cfg" "PermitRootLogin" "yes"
  fi

  if [[ "$DISABLE_SSH_PASSWORD" -eq 1 ]]; then
    set_kv_in_file "$sshd_cfg" "PasswordAuthentication" "no"
    set_kv_in_file "$sshd_cfg" "KbdInteractiveAuthentication" "no"
    set_kv_in_file "$sshd_cfg" "ChallengeResponseAuthentication" "no"
  else
    set_kv_in_file "$sshd_cfg" "PasswordAuthentication" "yes"
  fi

  set_kv_in_file "$sshd_cfg" "PermitEmptyPasswords" "no"
  set_kv_in_file "$sshd_cfg" "X11Forwarding" "no"
  set_kv_in_file "$sshd_cfg" "AllowTcpForwarding" "no"
  set_kv_in_file "$sshd_cfg" "ClientAliveInterval" "300"
  set_kv_in_file "$sshd_cfg" "ClientAliveCountMax" "2"
  set_kv_in_file "$sshd_cfg" "MaxAuthTries" "3"
  set_kv_in_file "$sshd_cfg" "LoginGraceTime" "30"
  set_kv_in_file "$sshd_cfg" "UseDNS" "no"

  if command -v sshd >/dev/null 2>&1; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      log "DRY-RUN: would validate sshd config (sshd -t) and restart sshd"
    else
      if ! sshd -t >>"$LOG_FILE" 2>&1; then
        die "sshd config validation failed. Check $LOG_FILE and restore backup if needed."
      fi
      if systemctl list-unit-files | grep -qE '^sshd\.service'; then
        run "systemctl restart sshd"
      else
        run "systemctl restart ssh"
      fi
    fi
  else
    warn "sshd binary not found; skipping validation/restart."
  fi

  log "SSH hardening done."
}

########################################
# 2) Firewall Configuration
########################################
configure_firewall() {
  log "=== Firewall Configuration ==="

  if command -v ufw >/dev/null 2>&1; then
    log "Using UFW"
    run "ufw --force reset"
    run "ufw default deny incoming"
    run "ufw default allow outgoing"

    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      run "ufw allow from '$ALLOW_SSH_FROM' to any port '$SSH_PORT' proto tcp"
    else
      run "ufw allow '$SSH_PORT'/tcp"
    fi

    run "ufw --force enable"
    run "ufw status verbose"
    log "Firewall configured (UFW)."
    return 0
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && systemctl list-unit-files | grep -qE '^firewalld\.service'; then
    log "Using firewalld"
    run "systemctl enable --now firewalld"
    run "firewall-cmd --set-default-zone=public"
    run "firewall-cmd --permanent --remove-service=ssh || true"

    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      run "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=${ALLOW_SSH_FROM} port port=${SSH_PORT} protocol=tcp accept'"
      run "firewall-cmd --permanent --add-rich-rule='rule family=ipv6 source address=${ALLOW_SSH_FROM} port port=${SSH_PORT} protocol=tcp accept' || true"
    else
      run "firewall-cmd --permanent --add-port=${SSH_PORT}/tcp"
    fi

    run "firewall-cmd --reload"
    run "firewall-cmd --list-all"
    log "Firewall configured (firewalld)."
    return 0
  fi

  warn "No UFW/firewalld detected. Applying minimal iptables rules (may not persist after reboot)."
  if command -v iptables >/dev/null 2>&1; then
    run "iptables -P INPUT DROP"
    run "iptables -P FORWARD DROP"
    run "iptables -P OUTPUT ACCEPT"
    run "iptables -A INPUT -i lo -j ACCEPT"
    run "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      run "iptables -A INPUT -p tcp -s '$ALLOW_SSH_FROM' --dport '$SSH_PORT' -j ACCEPT"
    else
      run "iptables -A INPUT -p tcp --dport '$SSH_PORT' -j ACCEPT"
    fi
    run "iptables -S"
  else
    warn "iptables not available; skipping firewall configuration."
  fi

  log "Firewall configuration done."
}

########################################
# 3) Sudo Hardening
########################################
harden_sudo() {
  log "=== Sudo Hardening ==="
  local sudoers_dir="/etc/sudoers.d"
  local hard_file="${sudoers_dir}/99-hardening"

  [[ -d "$sudoers_dir" ]] || { warn "sudoers.d not found; skipping sudo hardening."; return 0; }

  backup_file "$hard_file" || true

  # Build file content WITHOUT heredocs / EOF blocks
  local content=""
  content+="# 99-hardening — sudo hardening defaults\n"
  content+="#\n"
  content+="# Rationale:\n"
  content+="#  - use_pty: prevents certain tty-less trickery; improves auditability\n"
  content+="#  - log_output / iolog_dir: records stdin/stdout for sudo sessions (where supported)\n"
  content+="#  - timestamp_timeout: reduces window for reused sudo credentials\n"
  content+="\n"
  content+="Defaults use_pty\n"
  content+="Defaults timestamp_timeout=5\n"
  content+="Defaults passwd_timeout=1\n"
  content+="\n"
  content+="# Log sudo I/O (supported on many distros / sudo builds)\n"
  content+="Defaults log_output\n"
  content+="Defaults iolog_dir=/var/log/sudo-io\n"
  content+="Defaults iolog_file=%{seq}\n"
  content+="\n"
  content+="# Optional: set a consistent secure path (adjust to your environment)\n"
  content+="Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY-RUN: would write $hard_file and create /var/log/sudo-io"
    echo "----- $hard_file (new) -----"
    echo -e "$content"
  else
    echo -e "$content" >"$hard_file"
    chmod 440 "$hard_file"
    mkdir -p /var/log/sudo-io
    chmod 700 /var/log/sudo-io

    if command -v visudo >/dev/null 2>&1; then
      if ! visudo -cf /etc/sudoers >>"$LOG_FILE" 2>&1; then
        die "visudo validation failed. Check $LOG_FILE and fix sudoers before continuing."
      fi
    fi
  fi

  log "Sudo hardening done."
}

########################################
# 4) Password Policies
########################################
enforce_password_policies() {
  log "=== Password Policy Enforcement ==="

  ensure_pkg "libpam-pwquality" || true
  ensure_pkg "pam_pwquality" || true

  local pwq="/etc/security/pwquality.conf"
  if [[ -f "$pwq" ]]; then
    backup_file "$pwq"
  fi

  local pwq_content=""
  pwq_content+="# pwquality.conf — password quality requirements\n"
  pwq_content+="# These are reasonable baseline settings; tune per policy.\n"
  pwq_content+="minlen = 14\n"
  pwq_content+="dcredit = -1\n"
  pwq_content+="ucredit = -1\n"
  pwq_content+="lcredit = -1\n"
  pwq_content+="ocredit = -1\n"
  pwq_content+="maxrepeat = 3\n"
  pwq_content+="maxclassrepeat = 3\n"
  pwq_content+="difok = 4\n"
  pwq_content+="gecoscheck = 1\n"
  pwq_content+="dictcheck = 1\n"
  pwq_content+="enforcing = 1\n"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY-RUN: would write/update $pwq"
    echo "----- $pwq -----"
    echo -e "$pwq_content"
  else
    mkdir -p /etc/security
    echo -e "$pwq_content" >"$pwq"
    chmod 644 "$pwq"
  fi

  local login_defs="/etc/login.defs"
  if [[ -f "$login_defs" ]]; then
    backup_file "$login_defs"
    set_kv_in_file "$login_defs" "PASS_MAX_DAYS" "90"
    set_kv_in_file "$login_defs" "PASS_MIN_DAYS" "1"
    set_kv_in_file "$login_defs" "PASS_WARN_AGE" "14"
  else
    warn "Missing /etc/login.defs; skipping aging defaults."
  fi

  local profile="/etc/profile"
  if [[ -f "$profile" ]]; then
    backup_file "$profile"
    if ! grep -qE '^\s*umask\s+027\s*$' "$profile"; then
      run "printf '\n# Hardened default umask\numask 027\n' >> '$profile'"
    fi
  fi

  log "Password policy enforcement done."
}

########################################
# 5) Audit / Report
########################################
audit_system_security() {
  log "=== Security Audit Report ==="

  local out=""
  out+="Hardening Toolkit Audit Report\n"
  out+="Generated: $(date -Is)\n"
  out+="Host: $(hostname -f 2>/dev/null || hostname)\n"
  out+="OS: $(grep -E '^(PRETTY_NAME)=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')\n"
  out+="\n"

  out+="[SSH]\n"
  if [[ -f /etc/ssh/sshd_config ]]; then
    out+="sshd_config present: yes\n"
    out+="Port: $(grep -E '^\s*Port\s+' /etc/ssh/sshd_config | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PermitRootLogin: $(grep -E '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PasswordAuthentication: $(grep -E '^\s*PasswordAuthentication\s+' /etc/ssh/sshd_config | tail -n1 | awk '{print $2}' || echo "unknown")\n"
  else
    out+="sshd_config present: no\n"
  fi
  out+="\n"

  out+="[FIREWALL]\n"
  if command -v ufw >/dev/null 2>&1; then
    out+="UFW: $(ufw status 2>/dev/null | head -n1)\n"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    out+="firewalld running: $(systemctl is-active firewalld 2>/dev/null || echo "unknown")\n"
    out+="firewalld rules:\n$(firewall-cmd --list-all 2>/dev/null || echo "unavailable")\n"
  elif command -v iptables >/dev/null 2>&1; then
    out+="iptables policies:\n$(iptables -S 2>/dev/null | head -n 50)\n"
  else
    out+="No firewall tooling detected.\n"
  fi
  out+="\n"

  out+="[SUDO]\n"
  if [[ -f /etc/sudoers.d/99-hardening ]]; then
    out+="Considered hardened sudo file present: yes\n"
  else
    out+="Considered hardened sudo file present: no\n"
  fi
  out+="\n"

  out+="[PASSWORD POLICY]\n"
  if [[ -f /etc/security/pwquality.conf ]]; then
    out+="pwquality.conf present: yes\n"
    out+="minlen: $(grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' || echo "unknown")\n"
  else
    out+="pwquality.conf present: no\n"
  fi
  if [[ -f /etc/login.defs ]]; then
    out+="PASS_MAX_DAYS: $(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PASS_MIN_DAYS: $(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PASS_WARN_AGE: $(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs | tail -n1 | awk '{print $2}' || echo "unknown")\n"
  fi
  out+="\n"

  out+="[HYGIENE CHECKS]\n"
  out+="Open TCP listeners (first 50):\n"
  if command -v ss >/dev/null 2>&1; then
    out+="$(ss -tulpn 2>/dev/null | head -n 50)\n"
  elif command -v netstat >/dev/null 2>&1; then
    out+="$(netstat -tulpn 2>/dev/null | head -n 50)\n"
  else
    out+="(ss/netstat not available)\n"
  fi
  out+="\n"

  out+="World-writable files under /etc (if any):\n"
  out+="$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 50)\n"
  out+="\n"

  out+="SUID binaries (first 50):\n"
  out+="$(find / -xdev -perm -4000 -type f 2>/dev/null | head -n 50)\n"
  out+="\n"

  out+="Failed login attempts (if journal available):\n"
  if command -v journalctl >/dev/null 2>&1; then
    out+="$(journalctl -q -n 100 --no-pager 2>/dev/null | grep -Ei 'failed password|authentication failure|invalid user' | tail -n 30)\n"
  else
    out+="(journalctl not available)\n"
  fi
  out+="\n"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY-RUN: would write report to $REPORT_FILE"
    echo -e "$out"
  else
    echo -e "$out" >"$REPORT_FILE"
    chmod 600 "$REPORT_FILE"
    log "Wrote audit report: $REPORT_FILE"
  fi
}

########################################
# Argument Parsing
########################################
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --ssh-port) SSH_PORT="${2:-}"; [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--ssh-port requires a number"; shift 2;;
    --allow-ssh-from) ALLOW_SSH_FROM="${2:-}"; [[ -n "$ALLOW_SSH_FROM" ]] || die "--allow-ssh-from requires CIDR"; shift 2;;
    --keep-ssh-password) DISABLE_SSH_PASSWORD=0; shift;;
    --permit-ssh-root) DISABLE_SSH_ROOT=0; shift;;
    --no-ssh) NO_SSH=1; shift;;
    --no-firewall) NO_FIREWALL=1; shift;;
    --no-sudo) NO_SUDO=1; shift;;
    --no-password-policy) NO_PW=1; shift;;
    --no-audit) NO_AUDIT=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown option: $1 (use --help)";;
  esac
done

########################################
# Main
########################################
need_root
ensure_log_dir
detect_os

log "Hardening Toolkit starting (dry-run=$DRY_RUN)"
log "Settings: ssh_port=$SSH_PORT allow_ssh_from='${ALLOW_SSH_FROM:-none}' disable_ssh_password=$DISABLE_SSH_PASSWORD disable_ssh_root=$DISABLE_SSH_ROOT"

if [[ "$NO_SSH" -eq 0 ]]; then harden_ssh; else log "Skipping SSH hardening."; fi
if [[ "$NO_FIREWALL" -eq 0 ]]; then configure_firewall; else log "Skipping firewall configuration."; fi
if [[ "$NO_SUDO" -eq 0 ]]; then harden_sudo; else log "Skipping sudo hardening."; fi
if [[ "$NO_PW" -eq 0 ]]; then enforce_password_policies; else log "Skipping password policy enforcement."; fi
if [[ "$NO_AUDIT" -eq 0 ]]; then audit_system_security; else log "Skipping audit/report."; fi

log "Hardening Toolkit complete."
log "Log file: $LOG_FILE"
if [[ "$NO_AUDIT" -eq 0 ]]; then log "Audit report: $REPORT_FILE"; fi
