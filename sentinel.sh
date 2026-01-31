#!/usr/bin/env bash
set -euo pipefail

########################################
# Globals / Defaults
########################################
DRY_RUN=0
CHECK_ONLY=0
FORCE=0
STRICT_CIDR=0

NO_SSH=0
NO_FIREWALL=0
NO_SUDO=0
NO_PW=0
NO_AUDIT=0

FINALIZE_SSH_PORT=0
ENFORCE_PAM_PWQUALITY=0
EMERGENCY_FIREWALL=0

SSH_PORT=22
ALLOW_SSH_FROM=""
DISABLE_SSH_PASSWORD=1
DISABLE_SSH_ROOT=1

LOG_DIR="/var/log/hardening-toolkit"
LOG_FILE=""
REPORT_FILE=""

OS_ID=""
OS_LIKE=""
PKG_MGR=""

########################################
# Helpers
########################################
usage() {
  echo "Sentinel — Automated Linux Server Hardening Toolkit"
  echo
  echo "Options:"
  echo "  --dry-run                  Show what would change, do not modify system"
  echo "  --check-only               Run validations/status checks only; no system changes"
  echo "  --force                    Skip interactive confirmations for risky changes"
  echo "  --ssh-port N               Set SSH port (default: 22)"
  echo "  --allow-ssh-from CIDR      Restrict SSH to a CIDR (e.g., 203.0.113.10/32)"
  echo "  --strict-cidr              Require --allow-ssh-from to validate as a real CIDR (python3 ipaddress)"
  echo "  --finalize-ssh-port        Remove 22/tcp firewall allowance (after verifying new port works)"
  echo "  --keep-ssh-password        Do NOT disable SSH password authentication"
  echo "  --permit-ssh-root          Do NOT disable SSH root login"
  echo "  --enforce-pam-pwquality    Wire pwquality into PAM (careful, distro-specific; may affect logins)"
  echo "  --emergency-firewall       If no ufw/firewalld, apply TEMPORARY nft/iptables firewall fallback (risky)"
  echo "  --no-ssh                   Skip SSH hardening"
  echo "  --no-firewall              Skip firewall configuration"
  echo "  --no-sudo                  Skip sudo hardening"
  echo "  --no-password-policy       Skip password policy enforcement"
  echo "  --no-audit                 Skip audit/report generation"
  echo "  -h, --help                 Show help"
  echo
  echo "Examples:"
  echo "  sudo ./sentinel.sh"
  echo "  sudo ./sentinel.sh --dry-run"
  echo "  sudo ./sentinel.sh --check-only"
  echo "  sudo ./sentinel.sh --ssh-port 2222 --allow-ssh-from 203.0.113.10/32"
  echo "  sudo ./sentinel.sh --ssh-port 2222 --finalize-ssh-port --force"
  echo "  sudo ./sentinel.sh --enforce-pam-pwquality --force"
  echo "  sudo ./sentinel.sh --emergency-firewall --force"
}

timestamp() { date +%F_%H%M%S; }

log() {
  local msg="[*] $*"
  if [[ -n "${LOG_FILE:-}" ]] && [[ -e "$LOG_FILE" ]]; then
    echo "$msg" | tee -a "$LOG_FILE" >/dev/null
  else
    echo "$msg"
  fi
}

warn() {
  local msg="[!] $*"
  if [[ -n "${LOG_FILE:-}" ]] && [[ -e "$LOG_FILE" ]]; then
    echo "$msg" | tee -a "$LOG_FILE" >/dev/null
  else
    echo "$msg" >&2
  fi
}

die() {
  local msg="[X] $*"
  if [[ -n "${LOG_FILE:-}" ]] && [[ -e "$LOG_FILE" ]]; then
    echo "$msg" | tee -a "$LOG_FILE" >/dev/null
  else
    echo "$msg" >&2
  fi
  exit 1
}

is_tty() { [[ -t 0 && -t 1 ]]; }

confirm_or_die() {
  local reason="$1"
  if [[ "$FORCE" -eq 1 ]]; then
    log "Force enabled: proceeding without confirmation. ($reason)"
    return 0
  fi

  warn "$reason"
  warn "This is a risky change. To proceed, type YES (all caps). Anything else aborts."
  if ! is_tty; then
    die "No TTY available for confirmation. Re-run with --force if you accept the risk."
  fi
  read -r ans
  if [[ "$ans" != "YES" ]]; then
    die "Aborted by user."
  fi
}

run_cmd() {
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    if [[ -n "${LOG_FILE:-}" ]] && [[ -e "$LOG_FILE" ]]; then
      printf 'CHECK-ONLY: %q ' "$@" | tee -a "$LOG_FILE" >/dev/null
      echo | tee -a "$LOG_FILE" >/dev/null
    else
      printf 'CHECK-ONLY: %q ' "$@"
      echo
    fi
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ -n "${LOG_FILE:-}" ]] && [[ -e "$LOG_FILE" ]]; then
      printf 'DRY-RUN: %q ' "$@" | tee -a "$LOG_FILE" >/dev/null
      echo | tee -a "$LOG_FILE" >/dev/null
    else
      printf 'DRY-RUN: %q ' "$@"
      echo
    fi
    return 0
  fi

  if [[ -n "${LOG_FILE:-}" ]] && [[ -e "$LOG_FILE" ]]; then
    "$@" >>"$LOG_FILE" 2>&1
  else
    "$@"
  fi
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

ensure_log_dir() {
  local ts
  ts="$(timestamp)"
  LOG_FILE="$LOG_DIR/sentinel_${ts}.log"
  REPORT_FILE="$LOG_DIR/audit_report_${ts}.txt"

  mkdir -p "$LOG_DIR"
  chmod 700 "$LOG_DIR" || true
  : >"$LOG_FILE"
  chmod 600 "$LOG_FILE" || true

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "Dry-run mode: log directory and log file created for safe logging."
  fi
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    log "Check-only mode: will run validations and status checks only."
  fi
}

detect_os() {
  if [[ -r /etc/os-release ]]; then
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
  local b
  b="${f}.bak.$(timestamp)"
  run_cmd cp -a "$f" "$b"
  log "Backup: $f -> $b"
}

set_kv_in_file() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || { warn "set_kv_in_file: file not found: $file"; return 1; }

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would set '${key} ${value}' in $file"
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" '
    BEGIN { found=0 }
    $0 ~ "^[[:space:]]*"k"[[:space:]]+" {
      print k" "v
      found=1
      next
    }
    { print }
    END {
      if (found==0) print k" "v
    }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

cidr_is_valid() {
  local cidr="$1"

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$cidr" >/dev/null 2>&1
import sys, ipaddress
try:
  ipaddress.ip_network(sys.argv[1], strict=False)
  sys.exit(0)
except Exception:
  sys.exit(1)
PY
    return $?
  fi

  if [[ "${STRICT_CIDR:-0}" -eq 1 ]]; then
    return 1
  fi

  [[ "$cidr" == */* ]] && return 0
  return 1
}

cidr_family() {
  local cidr="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$cidr" 2>/dev/null
import sys, ipaddress
n = ipaddress.ip_network(sys.argv[1], strict=False)
print("ipv6" if n.version == 6 else "ipv4")
PY
    return 0
  fi

  if [[ "$cidr" == *:*/* ]]; then
    echo "ipv6"
  elif [[ "$cidr" == *.*/* ]]; then
    echo "ipv4"
  else
    echo "unknown"
  fi
}

ssh_lockout_preflight() {
  if [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_TTY:-}" ]]; then
    if [[ "$DISABLE_SSH_PASSWORD" -eq 1 ]]; then
      confirm_or_die "You appear to be running this over SSH and this will DISABLE SSH password auth. Confirm your key works in a separate session before continuing."
    fi
  fi
}

########################################
# Managed block upsert helper
########################################
upsert_managed_block() {
  # Upsert a delimited block in a text config file.
  local file="$1" begin="$2" end="$3" block="$4"

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would upsert managed block in $file"
    echo "----- $file managed block -----"
    echo "$begin"
    echo -e "$block"
    echo "$end"
    return 0
  fi

  mkdir -p "$(dirname "$file")"

  if [[ -f "$file" ]]; then
    backup_file "$file" || true
  else
    : >"$file"
  fi

  if grep -qF "$begin" "$file"; then
    perl -0777 -i -pe "s/\\Q$begin\\E.*?\\Q$end\\E\\n?//sg" "$file" >>"$LOG_FILE" 2>&1 || true
  fi

  {
    echo
    echo "$begin"
    echo -e "$block"
    echo "$end"
  } >>"$file"
}

########################################
# CHECK-ONLY report
########################################
check_only_report() {
  log "=== CHECK-ONLY MODE: validations + status ==="

  log "OS detection:"
  log "  ID='${OS_ID}' LIKE='${OS_LIKE}' PKG_MGR='${PKG_MGR}'"

  log "SSH effective config (if sshd present):"
  if command -v sshd >/dev/null 2>&1; then
    if sshd -t >>"$LOG_FILE" 2>&1; then
      log "  sshd -t: OK"
    else
      warn "  sshd -t: FAILED (see $LOG_FILE)"
    fi

    local eff
    eff="$(sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|usepam)\b' || true)"
    log "  sshd -T (effective):"
    echo "$eff" | while IFS= read -r line; do log "    $line"; done
  else
    warn "  sshd not found"
  fi

  log "Firewall status:"
  if command -v ufw >/dev/null 2>&1; then
    ufw status verbose 2>/dev/null | while IFS= read -r line; do log "    $line"; done
  elif command -v firewall-cmd >/dev/null 2>&1; then
    log "  firewalld active: $(systemctl is-active firewalld 2>/dev/null || echo unknown)"
    firewall-cmd --list-all 2>/dev/null | while IFS= read -r line; do log "    $line"; done
  elif command -v nft >/dev/null 2>&1; then
    nft list ruleset 2>/dev/null | head -n 60 | while IFS= read -r line; do log "    $line"; done
  elif command -v iptables >/dev/null 2>&1; then
    iptables -S 2>/dev/null | head -n 60 | while IFS= read -r line; do log "    $line"; done
  else
    warn "  No firewall tooling found"
  fi

  log "Password policy status:"
  if [[ -f /etc/security/pwquality.conf ]]; then
    grep -E '^\s*(minlen|dcredit|ucredit|lcredit|ocredit|difok|dictcheck|gecoscheck|enforcing)\s*=' /etc/security/pwquality.conf 2>/dev/null \
      | while IFS= read -r line; do log "    $line"; done
  else
    warn "  /etc/security/pwquality.conf not found"
  fi

  log "Open listeners snapshot:"
  if command -v ss >/dev/null 2>&1; then
    ss -tulpn 2>/dev/null | head -n 50 | while IFS= read -r line; do log "    $line"; done
  fi

  log "CHECK-ONLY complete."
}

########################################
# Package helpers
########################################
pkg_installed() {
  local pkg="$1"
  if command -v dpkg >/dev/null 2>&1; then
    dpkg -s "$pkg" >/dev/null 2>&1
    return $?
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -q "$pkg" >/dev/null 2>&1
    return $?
  fi
  return 1
}

ensure_pkg() {
  local pkg="$1"
  if pkg_installed "$pkg"; then
    return 0
  fi

  [[ -n "$PKG_MGR" ]] || { warn "No package manager detected; cannot install '$pkg'."; return 1; }

  log "Installing package (if available): $pkg"
  case "$PKG_MGR" in
    apt)
      run_cmd apt-get update -y
      run_cmd apt-get install -y "$pkg"
      ;;
    dnf)
      run_cmd dnf install -y "$pkg"
      ;;
    yum)
      run_cmd yum install -y "$pkg"
      ;;
    zypper)
      run_cmd zypper --non-interactive install "$pkg"
      ;;
    *)
      warn "Unknown package manager; cannot install '$pkg'."
      return 1
      ;;
  esac
}

########################################
# Desired-state firewall helpers
########################################
ufw_allow_port() {
  local port="$1"

  if ufw status 2>/dev/null | grep -Eq "(^|[[:space:]])${port}/tcp([[:space:]]|$)"; then
    log "UFW: rule for ${port}/tcp already present."
    return 0
  fi

  run_cmd ufw allow "${port}/tcp"
}

ufw_source_rule_exists() {
  local cidr="$1" port="$2"
  ufw status numbered 2>/dev/null \
    | tr -s ' ' \
    | grep -Eiq "^\[[0-9]+\][[:space:]]+${port}/tcp[[:space:]]+ALLOW IN[[:space:]]+${cidr//\//\\/}"
}

ufw_allow_from_to_port() {
  local cidr="$1" port="$2"

  if ufw_source_rule_exists "$cidr" "$port"; then
    log "UFW: source-restricted rule for ${cidr} -> ${port}/tcp already present."
    return 0
  fi

  run_cmd ufw allow from "$cidr" to any port "$port" proto tcp
}

ufw_delete_allow_port_any_source() {
  local port="$1"

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would delete any UFW allow rules for ${port}/tcp (all sources)"
    return 0
  fi

  while true; do
    local num
    num="$(ufw status numbered 2>/dev/null \
      | tr -s ' ' \
      | awk -v p="${port}/tcp" '$0 ~ p && $0 ~ /ALLOW IN/ { gsub(/^\[|\].*$/,"",$1); print $1; exit }')"

    [[ -n "${num:-}" ]] || break
    run_cmd ufw --force delete "$num" || true
  done
}

firewalld_port_enabled() {
  local port="$1"
  firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | grep -Fxq "${port}/tcp"
}

firewalld_add_port() {
  local port="$1"
  if firewalld_port_enabled "$port"; then
    log "firewalld: port ${port}/tcp already enabled."
    return 0
  fi
  run_cmd firewall-cmd --permanent --add-port="${port}/tcp"
}

firewalld_remove_port() {
  local port="$1"
  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would remove firewalld port ${port}/tcp if present"
    return 0
  fi
  run_cmd firewall-cmd --permanent --remove-port="${port}/tcp" || true
}

firewalld_rich_rule_exists() {
  local rule="$1"
  firewall-cmd --permanent --list-rich-rules 2>/dev/null | grep -Fxq "$rule"
}

firewalld_add_rich_rule() {
  local rule="$1"
  if firewalld_rich_rule_exists "$rule"; then
    log "firewalld: rich rule already present."
    return 0
  fi
  run_cmd firewall-cmd --permanent --add-rich-rule "$rule"
}

firewalld_remove_rich_rule() {
  local rule="$1"
  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would remove firewalld rich rule if present: $rule"
    return 0
  fi
  run_cmd firewall-cmd --permanent --remove-rich-rule "$rule" || true
}

########################################
# SSH Config Management (safer)
########################################
write_sshd_managed_config() {
  local dropin_dir="/etc/ssh/sshd_config.d"
  local dropin_file="${dropin_dir}/10-sentinel.conf"
  local sshd_cfg="/etc/ssh/sshd_config"

  local managed=""
  managed+="# Managed by sentinel.sh\n"
  managed+="# Time: $(date -Is)\n"
  managed+="Port ${SSH_PORT}\n"
  managed+="PermitRootLogin $([[ "$DISABLE_SSH_ROOT" -eq 1 ]] && echo "no" || echo "yes")\n"
  if [[ "$DISABLE_SSH_PASSWORD" -eq 1 ]]; then
    managed+="PasswordAuthentication no\n"
    managed+="KbdInteractiveAuthentication no\n"
    managed+="ChallengeResponseAuthentication no\n"
  else
    managed+="PasswordAuthentication yes\n"
  fi
  managed+="PermitEmptyPasswords no\n"
  managed+="X11Forwarding no\n"
  managed+="AllowTcpForwarding no\n"
  managed+="ClientAliveInterval 300\n"
  managed+="ClientAliveCountMax 2\n"
  managed+="MaxAuthTries 3\n"
  managed+="LoginGraceTime 30\n"
  managed+="UseDNS no\n"

  if [[ -d "$dropin_dir" || "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "Using sshd drop-in config: $dropin_file"
    if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
      log "DRY-RUN/CHECK-ONLY: would write $dropin_file"
      echo "----- $dropin_file -----"
      echo -e "$managed"
    else
      mkdir -p "$dropin_dir"
      backup_file "$dropin_file" || true
      echo -e "$managed" >"$dropin_file"
      chmod 600 "$dropin_file"
    fi
    return 0
  fi

  [[ -f "$sshd_cfg" ]] || { warn "sshd_config not found; cannot manage SSH config."; return 1; }

  log "sshd_config.d not available; inserting managed block into $sshd_cfg (before first Match if present)."
  backup_file "$sshd_cfg"

  local begin="# BEGIN sentinel.sh managed block"
  local end="# END sentinel.sh managed block"

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would upsert managed block in $sshd_cfg"
    echo "----- managed block -----"
    echo "$begin"
    echo -e "$managed"
    echo "$end"
    return 0
  fi

  if grep -qF "$begin" "$sshd_cfg"; then
    perl -0777 -i -pe "s/\\Q$begin\\E.*?\\Q$end\\E\\n?//sg" "$sshd_cfg" >>"$LOG_FILE" 2>&1 || true
  fi

  if grep -nE '^[[:space:]]*Match[[:space:]]+' "$sshd_cfg" >/dev/null 2>&1; then
    local tmp
    tmp="$(mktemp)"
    awk -v begin="$begin" -v end="$end" -v block="$managed" '
      BEGIN { inserted=0 }
      /^[[:space:]]*Match[[:space:]]+/ && inserted==0 {
        print begin
        printf "%s", block
        if (block !~ /\n$/) print ""
        print end
        inserted=1
      }
      { print }
      END {
        if (inserted==0) {
          print begin
          printf "%s", block
          if (block !~ /\n$/) print ""
          print end
        }
      }
    ' "$sshd_cfg" >"$tmp"
    mv "$tmp" "$sshd_cfg"
  else
    {
      echo
      echo "$begin"
      echo -e "$managed"
      echo "$end"
    } >>"$sshd_cfg"
  fi
}

########################################
# 1) Firewall Configuration
########################################
configure_firewall() {
  log "=== Firewall Configuration ==="

  if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
    warn "SSH port is set to $SSH_PORT."
    warn "Staged rollout: firewall will allow BOTH 22/tcp and ${SSH_PORT}/tcp to reduce lockout risk."
    warn "After confirming access on ${SSH_PORT}, re-run with --finalize-ssh-port to remove 22/tcp."
  fi

  if [[ "$FINALIZE_SSH_PORT" -eq 1 && "$SSH_PORT" -eq 22 ]]; then
    warn "--finalize-ssh-port was set but --ssh-port is 22. Nothing to finalize."
    return 0
  fi

  if command -v ufw >/dev/null 2>&1; then
    log "Using UFW (non-destructive; desired-state rules)."

    run_cmd ufw default deny incoming
    run_cmd ufw default allow outgoing

    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      ufw_allow_from_to_port "$ALLOW_SSH_FROM" "$SSH_PORT"
      if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
        ufw_allow_from_to_port "$ALLOW_SSH_FROM" 22
      fi
    else
      ufw_allow_port "$SSH_PORT"
      if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
        ufw_allow_port 22
      fi
    fi

    if ufw status 2>/dev/null | head -n1 | grep -qi inactive; then
      run_cmd ufw --force enable
    fi

    if [[ "$FINALIZE_SSH_PORT" -eq 1 && "$SSH_PORT" -ne 22 ]]; then
      confirm_or_die "Finalizing SSH port transition will REMOVE 22/tcp from the firewall. Ensure you can SSH on port ${SSH_PORT} first."
      ufw_delete_allow_port_any_source 22
      log "Finalize complete (UFW): removed any allow rules for 22/tcp."
    fi

    run_cmd ufw status verbose
    log "Firewall configured (UFW)."
    return 0
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -qE '^firewalld\.service'; then
    log "Using firewalld (non-destructive; idempotent port/rich rules)."
    run_cmd systemctl enable --now firewalld
    run_cmd firewall-cmd --set-default-zone=public

    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      local fam
      fam="$(cidr_family "$ALLOW_SSH_FROM")"
      if [[ "$fam" == "ipv4" ]]; then
        local rule_v4
        rule_v4="rule family=ipv4 source address=${ALLOW_SSH_FROM} port port=${SSH_PORT} protocol=tcp accept"
        firewalld_add_rich_rule "$rule_v4"
        if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
          firewalld_add_rich_rule "rule family=ipv4 source address=${ALLOW_SSH_FROM} port port=22 protocol=tcp accept"
        fi
      elif [[ "$fam" == "ipv6" ]]; then
        local rule_v6
        rule_v6="rule family=ipv6 source address=${ALLOW_SSH_FROM} port port=${SSH_PORT} protocol=tcp accept"
        firewalld_add_rich_rule "$rule_v6"
        if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
          firewalld_add_rich_rule "rule family=ipv6 source address=${ALLOW_SSH_FROM} port port=22 protocol=tcp accept"
        fi
      else
        warn "ALLOW_SSH_FROM not recognized as IPv4/IPv6 CIDR. Using port allowances instead."
        firewalld_add_port "$SSH_PORT"
        if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
          firewalld_add_port 22
        fi
      fi
    else
      firewalld_add_port "$SSH_PORT"
      if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
        firewalld_add_port 22
      fi
    fi

    if [[ "$FINALIZE_SSH_PORT" -eq 1 && "$SSH_PORT" -ne 22 ]]; then
      confirm_or_die "Finalizing SSH port transition will REMOVE 22/tcp from the firewall. Ensure you can SSH on port ${SSH_PORT} first."
      firewalld_remove_port 22
      if [[ -n "$ALLOW_SSH_FROM" ]]; then
        local fam2
        fam2="$(cidr_family "$ALLOW_SSH_FROM")"
        if [[ "$fam2" == "ipv4" ]]; then
          firewalld_remove_rich_rule "rule family=ipv4 source address=${ALLOW_SSH_FROM} port port=22 protocol=tcp accept"
        elif [[ "$fam2" == "ipv6" ]]; then
          firewalld_remove_rich_rule "rule family=ipv6 source address=${ALLOW_SSH_FROM} port port=22 protocol=tcp accept"
        fi
      fi
      log "Finalize complete (firewalld): attempted removal of 22/tcp."
    fi

    run_cmd firewall-cmd --reload
    run_cmd firewall-cmd --list-all
    log "Firewall configured (firewalld)."
    return 0
  fi

  warn "No UFW/firewalld detected."

  if [[ "$EMERGENCY_FIREWALL" -eq 0 ]]; then
    warn "Skipping fallback firewall. If you want a TEMPORARY emergency fallback, rerun with --emergency-firewall --force."
    warn "Note: emergency nftables/iptables rules may not persist and may conflict with distro firewalls."
    return 0
  fi

  confirm_or_die "Emergency firewall fallback will apply TEMPORARY rules (non-persistent). This is for short-lived recovery use only."

  if command -v nft >/dev/null 2>&1; then
    warn "Using nftables emergency fallback (TEMPORARY). Consider persisting rules via distro tooling after validation."
    run_cmd nft list ruleset || true

    run_cmd nft add table inet sentinel 2>/dev/null || true
    run_cmd nft 'add chain inet sentinel input { type filter hook input priority 0; policy drop; }' 2>/dev/null || true

    run_cmd nft add rule inet sentinel input iif lo accept 2>/dev/null || true
    run_cmd nft add rule inet sentinel input ct state established,related accept 2>/dev/null || true

    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      local fam3
      fam3="$(cidr_family "$ALLOW_SSH_FROM")"
      if [[ "$fam3" == "ipv4" ]]; then
        run_cmd nft add rule inet sentinel input ip saddr "$ALLOW_SSH_FROM" tcp dport "$SSH_PORT" accept 2>/dev/null || true
        if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
          run_cmd nft add rule inet sentinel input ip saddr "$ALLOW_SSH_FROM" tcp dport 22 accept 2>/dev/null || true
        fi
      elif [[ "$fam3" == "ipv6" ]]; then
        run_cmd nft add rule inet sentinel input ip6 saddr "$ALLOW_SSH_FROM" tcp dport "$SSH_PORT" accept 2>/dev/null || true
        if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
          run_cmd nft add rule inet sentinel input ip6 saddr "$ALLOW_SSH_FROM" tcp dport 22 accept 2>/dev/null || true
        fi
      else
        warn "ALLOW_SSH_FROM not recognized as CIDR; allowing SSH ports without source restriction in emergency mode."
        run_cmd nft add rule inet sentinel input tcp dport "$SSH_PORT" accept 2>/dev/null || true
        if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
          run_cmd nft add rule inet sentinel input tcp dport 22 accept 2>/dev/null || true
        fi
      fi
    else
      run_cmd nft add rule inet sentinel input tcp dport "$SSH_PORT" accept 2>/dev/null || true
      if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
        run_cmd nft add rule inet sentinel input tcp dport 22 accept 2>/dev/null || true
      fi
    fi

    run_cmd nft list table inet sentinel || true
    log "Emergency firewall configured (nftables, TEMPORARY)."
    return 0
  fi

  if command -v iptables >/dev/null 2>&1; then
    warn "Using iptables emergency fallback (TEMPORARY). On many systems nftables is the backend; persistence is not guaranteed."

    run_cmd iptables -P INPUT DROP
    run_cmd iptables -P FORWARD DROP
    run_cmd iptables -P OUTPUT ACCEPT
    run_cmd iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || run_cmd iptables -A INPUT -i lo -j ACCEPT
    run_cmd iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || run_cmd iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    if [[ -n "$ALLOW_SSH_FROM" ]]; then
      run_cmd iptables -C INPUT -p tcp -s "$ALLOW_SSH_FROM" --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || run_cmd iptables -A INPUT -p tcp -s "$ALLOW_SSH_FROM" --dport "$SSH_PORT" -j ACCEPT
      if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
        run_cmd iptables -C INPUT -p tcp -s "$ALLOW_SSH_FROM" --dport 22 -j ACCEPT 2>/dev/null || run_cmd iptables -A INPUT -p tcp -s "$ALLOW_SSH_FROM" --dport 22 -j ACCEPT
      fi
    else
      run_cmd iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || run_cmd iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
      if [[ "$SSH_PORT" -ne 22 && "$FINALIZE_SSH_PORT" -eq 0 ]]; then
        run_cmd iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || run_cmd iptables -A INPUT -p tcp --dport 22 -j ACCEPT
      fi
    fi

    run_cmd iptables -S
    log "Emergency firewall configured (iptables, TEMPORARY)."
    return 0
  fi

  warn "No nft/iptables available; skipping firewall fallback."
  return 0
}

########################################
# 2) SSH Hardening
########################################
harden_ssh() {
  log "=== SSH Hardening ==="

  local sshd_cfg="/etc/ssh/sshd_config"
  [[ -f "$sshd_cfg" ]] || { warn "sshd_config not found; skipping SSH hardening."; return 0; }

  warn "SSH changes can lock you out. Ensure you have key auth + an open session before applying remotely."
  warn "Firewall was configured before this step to reduce lockout risk."

  ssh_lockout_preflight

  if [[ "$DISABLE_SSH_PASSWORD" -eq 1 ]]; then
    confirm_or_die "This will DISABLE SSH password auth. Ensure you have working SSH keys before continuing."
  fi
  if [[ "$DISABLE_SSH_ROOT" -eq 1 ]]; then
    warn "Root SSH login will be disabled (recommended)."
  fi

  write_sshd_managed_config || { warn "Failed to write SSH managed config; skipping SSH restart."; return 1; }

  if command -v sshd >/dev/null 2>&1; then
    if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
      log "DRY-RUN/CHECK-ONLY: would validate sshd config (sshd -t) and restart sshd"
    else
      if ! sshd -t >>"$LOG_FILE" 2>&1; then
        die "sshd config validation failed. Check $LOG_FILE and restore backup if needed."
      fi

      if systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service'; then
        run_cmd systemctl restart sshd
      else
        run_cmd systemctl restart ssh
      fi
    fi
  else
    warn "sshd binary not found; skipping validation/restart."
  fi

  log "SSH hardening done."
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

  local content=""
  content+="# 99-hardening — sudo hardening defaults\n"
  content+="# Managed by sentinel.sh\n"
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

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would write $hard_file and create /var/log/sudo-io"
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
# 4) Password Policies (+ optional PAM wiring)
########################################
detect_pam_stack_file() {
  if [[ -f /etc/pam.d/common-password ]]; then
    echo "/etc/pam.d/common-password"
    return 0
  fi
  if [[ -f /etc/pam.d/system-auth ]]; then
    echo "/etc/pam.d/system-auth"
    return 0
  fi
  echo ""
  return 1
}

pam_has_pwquality() {
  local f="$1"
  grep -Eq '^\s*password\s+requisite\s+pam_pwquality\.so' "$f"
}

pam_insert_pwquality() {
  local f="$1"
  [[ -f "$f" ]] || die "PAM file not found: $f"

  if pam_has_pwquality "$f"; then
    log "PAM: pwquality line already present in $f"
    return 0
  fi

  if command -v authselect >/dev/null 2>&1; then
    if authselect current 2>/dev/null | grep -qi 'Profile ID'; then
      warn "authselect detected. Manual edits to $f may be overwritten."
      warn "Consider using authselect custom profiles for persistent PAM changes."
      confirm_or_die "Proceed anyway with manual PAM edit to $f (may be overwritten by authselect)."
    fi
  fi

  confirm_or_die "PAM enforcement will modify $f. Incorrect PAM edits can lock users out."
  backup_file "$f"

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would add pam_pwquality to $f"
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  awk '
    BEGIN { inserted=0 }
    /^[[:space:]]*password[[:space:]]+(sufficient|required|requisite)[[:space:]]+pam_unix\.so/ && inserted==0 {
      print "password requisite pam_pwquality.so retry=3"
      inserted=1
    }
    { print }
    END {
      if (inserted==0) print "password requisite pam_pwquality.so retry=3"
    }
  ' "$f" >"$tmp"
  mv "$tmp" "$f"

  log "PAM: inserted pwquality line into $f"
}

enforce_password_policies() {
  log "=== Password Policy Enforcement ==="

  ensure_pkg "libpam-pwquality" || true
  ensure_pkg "pam_pwquality" || true
  ensure_pkg "libpwquality" || true
  ensure_pkg "pwquality" || true

  local pwq="/etc/security/pwquality.conf"
  local begin_pwq="# BEGIN sentinel.sh managed pwquality"
  local end_pwq="# END sentinel.sh managed pwquality"

  local pwq_block=""
  pwq_block+="# pwquality settings (baseline). Tune per policy.\n"
  pwq_block+="minlen = 14\n"
  pwq_block+="dcredit = -1\n"
  pwq_block+="ucredit = -1\n"
  pwq_block+="lcredit = -1\n"
  pwq_block+="ocredit = -1\n"
  pwq_block+="maxrepeat = 3\n"
  pwq_block+="maxclassrepeat = 3\n"
  pwq_block+="difok = 4\n"
  pwq_block+="gecoscheck = 1\n"
  pwq_block+="dictcheck = 1\n"
  pwq_block+="enforcing = 1\n"

  upsert_managed_block "$pwq" "$begin_pwq" "$end_pwq" "$pwq_block"
  if [[ "$DRY_RUN" -ne 1 && "$CHECK_ONLY" -ne 1 ]]; then
    chmod 644 "$pwq" || true
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

  local umask_file="/etc/profile.d/99-sentinel-umask.sh"
  local umask_content="# Managed by sentinel.sh\numask 027\n"

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would write $umask_file"
    echo "----- $umask_file -----"
    echo -e "$umask_content"
  else
    backup_file "$umask_file" || true
    echo -e "$umask_content" >"$umask_file"
    chmod 644 "$umask_file"
  fi

  if [[ "$ENFORCE_PAM_PWQUALITY" -eq 1 ]]; then
    local pam_file
    pam_file="$(detect_pam_stack_file || true)"
    if [[ -z "$pam_file" ]]; then
      warn "Could not auto-detect PAM password stack file. Skipping PAM enforcement."
      warn "On RHEL-like systems, consider authselect-managed stacks (system-auth/password-auth)."
    else
      warn "PAM enforcement requested. Target file: $pam_file"
      pam_insert_pwquality "$pam_file"
    fi
  else
    warn "Note: pwquality.conf managed block applied, but PAM enforcement is not guaranteed unless --enforce-pam-pwquality is used."
  fi

  log "Password policy enforcement done."
}

########################################
# 5) Audit / Report
########################################
audit_system_security() {
  log "=== Security Audit Report ==="

  local out=""
  out+="Sentinel Audit Report\n"
  out+="Generated: $(date -Is)\n"
  out+="Host: $(hostname -f 2>/dev/null || hostname)\n"
  out+="OS: $(grep -E '^(PRETTY_NAME)=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')\n"
  out+="\n"

  out+="[SSH]\n"
  if [[ -f /etc/ssh/sshd_config ]]; then
    out+="sshd_config present: yes\n"
    out+="Port (base file): $(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PermitRootLogin (base file): $(grep -E '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PasswordAuthentication (base file): $(grep -E '^\s*PasswordAuthentication\s+' /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    if [[ -d /etc/ssh/sshd_config.d ]]; then
      out+="sshd_config.d present: yes\n"
      out+="sshd drop-ins:\n$(find /etc/ssh/sshd_config.d -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort | head -n 50)\n"
    else
      out+="sshd_config.d present: no\n"
    fi
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
  elif command -v nft >/dev/null 2>&1; then
    out+="nftables present: yes\n"
    out+="nft sentinel table:\n$(nft list table inet sentinel 2>/dev/null || echo "none")\n"
  elif command -v iptables >/dev/null 2>&1; then
    out+="iptables present: yes\n"
    out+="iptables rules (head):\n$(iptables -S 2>/dev/null | head -n 50)\n"
  else
    out+="No firewall tooling detected.\n"
  fi
  out+="\n"

  out+="[SUDO]\n"
  if [[ -f /etc/sudoers.d/99-hardening ]]; then
    out+="Hardened sudo drop-in present: yes\n"
  else
    out+="Hardened sudo drop-in present: no\n"
  fi
  out+="\n"

  out+="[PASSWORD POLICY]\n"
  if [[ -f /etc/security/pwquality.conf ]]; then
    out+="pwquality.conf present: yes\n"
    out+="minlen: $(grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' || echo "unknown")\n"
  else
    out+="pwquality.conf present: no\n"
  fi

  out+="PAM pwquality module present (best-effort): "
  if find /lib /usr/lib -maxdepth 4 -type f -name 'pam_pwquality.so' 2>/dev/null | head -n1 | grep -q .; then
    out+="yes\n"
  else
    out+="unknown/no\n"
  fi

  if [[ -f /etc/pam.d/common-password ]]; then
    out+="PAM common-password contains pwquality: "
    if grep -Eq '^\s*password\s+requisite\s+pam_pwquality\.so' /etc/pam.d/common-password; then
      out+="yes\n"
    else
      out+="no\n"
    fi
  fi
  if [[ -f /etc/pam.d/system-auth ]]; then
    out+="PAM system-auth contains pwquality: "
    if grep -Eq '^\s*password\s+requisite\s+pam_pwquality\.so' /etc/pam.d/system-auth; then
      out+="yes\n"
    else
      out+="no\n"
    fi
  fi

  if [[ -f /etc/login.defs ]]; then
    out+="PASS_MAX_DAYS: $(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PASS_MIN_DAYS: $(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs | tail -n1 | awk '{print $2}' || echo "unknown")\n"
    out+="PASS_WARN_AGE: $(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs | tail -n1 | awk '{print $2}' || echo "unknown")\n"
  fi

  if [[ -f /etc/profile.d/99-sentinel-umask.sh ]]; then
    out+="umask profile.d managed file present: yes\n"
  else
    out+="umask profile.d managed file present: no\n"
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
    out+="$(journalctl -q -n 200 --no-pager 2>/dev/null | grep -Ei 'failed password|authentication failure|invalid user' | tail -n 30)\n"
  else
    out+="(journalctl not available)\n"
  fi
  out+="\n"

  if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
    log "DRY-RUN/CHECK-ONLY: would write report to $REPORT_FILE"
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
    --check-only) CHECK_ONLY=1; shift;;
    --force) FORCE=1; shift;;
    --strict-cidr) STRICT_CIDR=1; shift;;

    --ssh-port)
      SSH_PORT="${2:-}"
      [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--ssh-port requires a number"
      [[ "$SSH_PORT" -ge 1 && "$SSH_PORT" -le 65535 ]] || die "--ssh-port must be 1-65535"
      shift 2
      ;;

    --allow-ssh-from)
      ALLOW_SSH_FROM="${2:-}"
      [[ -n "$ALLOW_SSH_FROM" ]] || die "--allow-ssh-from requires CIDR"

      if ! cidr_is_valid "$ALLOW_SSH_FROM"; then
        if [[ "$STRICT_CIDR" -eq 1 ]]; then
          die "--allow-ssh-from must be a valid CIDR (python3 ipaddress). Install python3 or omit --strict-cidr."
        fi
        warn "--allow-ssh-from does not validate as a CIDR on this system (python3 missing or invalid input). Continuing best-effort."
      fi

      shift 2
      ;;

    --finalize-ssh-port) FINALIZE_SSH_PORT=1; shift;;
    --keep-ssh-password) DISABLE_SSH_PASSWORD=0; shift;;
    --permit-ssh-root) DISABLE_SSH_ROOT=0; shift;;
    --enforce-pam-pwquality) ENFORCE_PAM_PWQUALITY=1; shift;;
    --emergency-firewall) EMERGENCY_FIREWALL=1; shift;;
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

log "Sentinel starting (dry-run=$DRY_RUN check-only=$CHECK_ONLY)"
log "Settings: ssh_port=$SSH_PORT allow_ssh_from='${ALLOW_SSH_FROM:-none}' disable_ssh_password=$DISABLE_SSH_PASSWORD disable_ssh_root=$DISABLE_SSH_ROOT finalize_ssh_port=$FINALIZE_SSH_PORT enforce_pam_pwquality=$ENFORCE_PAM_PWQUALITY emergency_firewall=$EMERGENCY_FIREWALL strict_cidr=$STRICT_CIDR"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  check_only_report
  log "Sentinel complete (check-only)."
  log "Log file: $LOG_FILE"
  exit 0
fi

if [[ "$NO_FIREWALL" -eq 0 ]]; then configure_firewall; else log "Skipping firewall configuration."; fi
if [[ "$NO_SSH" -eq 0 ]]; then harden_ssh; else log "Skipping SSH hardening."; fi
if [[ "$NO_SUDO" -eq 0 ]]; then harden_sudo; else log "Skipping sudo hardening."; fi
if [[ "$NO_PW" -eq 0 ]]; then enforce_password_policies; else log "Skipping password policy enforcement."; fi
if [[ "$NO_AUDIT" -eq 0 ]]; then audit_system_security; else log "Skipping audit/report."; fi

log "Sentinel complete."
log "Log file: $LOG_FILE"
if [[ "$NO_AUDIT" -eq 0 ]]; then log "Audit report: $REPORT_FILE"; fi
