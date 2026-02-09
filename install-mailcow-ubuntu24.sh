#!/usr/bin/env bash
set -euo pipefail

# install-mailcow-ubuntu24.sh
# Ziel: Ubuntu 24.04 + SSH-only Admin + automatische Security Updates (+ Reboot) + Docker + mailcow + mailcow Auto-Update per systemd timer
#
# Hinweise:
# - mailcow-Doku warnt bei Docker+Firewall (UFW/firewalld) vor Stolperfallen. Siehe:
#   https://docs.mailcow.email/getstarted/prerequisite-system/
# - mailcow-Doku: Default UI Login nach Installation: admin / moohoo (ändern!)
#   https://docs.mailcow.email/getstarted/install/
# - IPv6: falsch konfiguriertes Docker IPv6 kann Open Relay verursachen. Siehe:
#   https://docs.mailcow.email/post_installation/firststeps-disable_ipv6/

SCRIPT_VERSION="1.0"

MAILCOW_DIR="/opt/mailcow-dockerized"
ADMIN_USER="admin"
ADMIN_USER_FLAG_SET="false"   # true|false (ob --admin-user explizit gesetzt wurde)
TZ_FALLBACK_DEFAULT="UTC"
REBOOT_TIME_DEFAULT="04:00"
MAILCOW_UPDATE_TIME_DEFAULT="03:30"

FQDN=""
TZ="$TZ_FALLBACK_DEFAULT"
TZ_FLAG_SET="false"           # true|false (ob --tz explizit gesetzt wurde)
SSH_PUBKEY=""
ENABLE_UFW="yes"              # yes|no
UFW_FLAG_SET="false"          # true|false (ob --ufw explizit gesetzt wurde)
SSH_ALLOW_CIDR=""             # z.B. "203.0.113.10/32"
AUTO_REBOOT="true"            # true|false
AUTO_REBOOT_FLAG_SET="false"  # true|false (ob --auto-reboot explizit gesetzt wurde)
REBOOT_TIME="$REBOOT_TIME_DEFAULT"
MAILCOW_AUTOUPDATE="true"     # true|false
MAILCOW_AUTOUPDATE_FLAG_SET="false" # true|false (ob --mailcow-autoupdate explizit gesetzt wurde)
MAILCOW_UPDATE_TIME="$MAILCOW_UPDATE_TIME_DEFAULT"
RUN_HELLO_WORLD="false"       # true|false
PASSWORDLESS_SUDO="false"     # true|false
ADMIN_LOGIN_PASSWORD="auto"   # auto|true|false
MAILCOW_BRANCH="stable"
SKIP_PING_CHECK="false"       # true|false (für mailcow update.sh)
NON_INTERACTIVE="false"       # true|false

PURGE_EXISTING="no"           # no|containers|full (full löscht auch data/ -> sehr destruktiv)

log()  { printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }
warn() { printf "[%s] WARN: %s\n" "$(date '+%F %T')" "$*" >&2; }
die()  { printf "[%s] ERROR: %s\n" "$(date '+%F %T')" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
install-mailcow-ubuntu24.sh v$SCRIPT_VERSION

Usage:
  sudo bash install-mailcow-ubuntu24.sh [options]

Required (interactive if missing, außer --non-interactive):
  --fqdn <mail.example.org>                 Mailcow FQDN (MAILCOW_HOSTNAME)
  --ssh-pubkey <path|keyline>              SSH Public Key für admin

Optional:
  --mailcow-dir <dir>                      Default: $MAILCOW_DIR
  --admin-user <name>                      Default: $ADMIN_USER (interaktiv: Enter übernimmt Default)
  --tz <Area/City>                         Default: Server-Timezone (Fallback: $TZ_FALLBACK_DEFAULT)
  --ssh-allow-cidr <CIDR[,CIDR...]>        Optional; 'none' deaktiviert Einschränkung. ACHTUNG: falscher Wert kann SSH-Lockout verursachen
  --ufw yes|no                             Ohne Flag: interaktiv Abfrage (Enter=yes), non-interactive => yes
  --passwordless-sudo true|false           Default: $PASSWORDLESS_SUDO
  --auto-reboot true|false                 Default: $AUTO_REBOOT
  --reboot-time HH:MM                      Default: $REBOOT_TIME_DEFAULT
  --mailcow-autoupdate true|false          Default: $MAILCOW_AUTOUPDATE
  --mailcow-update-time HH:MM              Default: $MAILCOW_UPDATE_TIME_DEFAULT
  --skip-ping-check true|false             Default: $SKIP_PING_CHECK
  --hello-world true|false                 Default: $RUN_HELLO_WORLD
  --branch stable|master|...               Default: $MAILCOW_BRANCH
  --non-interactive                        Keine Prompts; fehlende Pflichtwerte führen zu Fehler
  --purge-existing no|containers|full       Default: $PURGE_EXISTING

Examples:
  sudo bash install-mailcow-ubuntu24.sh \\
    --fqdn mail.example.org \\
    --ssh-pubkey "ssh-ed25519 AAAA... user@local" \\
    --ufw no \\
    --auto-reboot true --reboot-time 04:00 \\
    --mailcow-autoupdate true --mailcow-update-time 03:30

  sudo bash install-mailcow-ubuntu24.sh \\
    --non-interactive \\
    --fqdn mail.example.org \\
    --ssh-pubkey "ssh-ed25519 AAAA... user@local" \\
    --ssh-allow-cidr <DEINE_MANAGEMENT_IP/32>

EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Bitte als root ausführen (oder via sudo)."
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

is_true_or_false() {
  [[ "$1" == "true" || "$1" == "false" ]]
}

prompt_default() {
  local var_name="$1" prompt="$2" def="$3"
  local val=""
  read -r -p "$prompt [$def]: " val || true
  if [[ -z "${val}" ]]; then val="$def"; fi
  printf -v "$var_name" '%s' "$val"
}

trim_value() {
  local in="$1"
  printf '%s' "$in" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

prompt_yes_no() {
  local var_name="$1" prompt="$2" def="$3"
  local val=""
  while true; do
    read -r -p "$prompt [${def}]: " val || true
    [[ -z "$val" ]] && val="$def"
    case "$val" in
      y|Y|yes|YES) printf -v "$var_name" "yes"; return 0;;
      n|N|no|NO)   printf -v "$var_name" "no";  return 0;;
      *) echo "Bitte yes/no eingeben.";;
    esac
  done
}

prompt_true_false() {
  local var_name="$1" prompt="$2" def="$3"
  local val=""
  while true; do
    read -r -p "$prompt [${def}]: " val || true
    [[ -z "$val" ]] && val="$def"
    case "$val" in
      y|Y|yes|YES|true|TRUE)   printf -v "$var_name" "true";  return 0;;
      n|N|no|NO|false|FALSE)   printf -v "$var_name" "false"; return 0;;
      *) echo "Bitte yes/no oder true/false eingeben.";;
    esac
  done
}

validate_hhmm() {
  local t="$1"
  [[ "$t" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]
}

detect_ssh_client_cidr() {
  # SSH_CONNECTION: "<client_ip> <client_port> <server_ip> <server_port>"
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local ip
    ip="$(awk '{print $1}' <<<"${SSH_CONNECTION}")"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "${ip}/32"
      return 0
    elif [[ "$ip" == *:* ]]; then
      echo "${ip}/128"
      return 0
    fi
  fi
  echo ""
}

detect_server_timezone() {
  local tz=""
  local link_target=""

  if have_cmd timedatectl; then
    tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  fi

  if [[ -z "$tz" && -f /etc/timezone ]]; then
    tz="$(head -n1 /etc/timezone 2>/dev/null || true)"
  fi

  if [[ -z "$tz" && -L /etc/localtime ]]; then
    link_target="$(readlink /etc/localtime 2>/dev/null || true)"
    if [[ "$link_target" == */zoneinfo/* ]]; then
      tz="${link_target#*/zoneinfo/}"
    fi
  fi

  tz="$(trim_value "$tz")"
  [[ -n "$tz" && "$tz" != "n/a" ]] || return 1
  echo "$tz"
}

normalize_ssh_allow_cidr_value() {
  local raw="$1"
  local trimmed
  local lower

  trimmed="$(trim_value "$raw")"
  lower="$(printf '%s' "$trimmed" | tr '[:upper:]' '[:lower:]')"

  case "$lower" in
    ""|none|disable|disabled|off|open|any) echo ""; return 0 ;;
  esac

  echo "$trimmed"
}

print_bold_warning() {
  local text="$1"
  if [[ -t 1 ]]; then
    printf '\033[1m%s\033[0m\n' "$text"
  else
    printf '%s\n' "$text"
  fi
}

init_runtime_defaults() {
  if [[ "$TZ_FLAG_SET" == "false" ]]; then
    local detected_tz=""
    detected_tz="$(detect_server_timezone || true)"
    if [[ -n "$detected_tz" ]]; then
      TZ="$detected_tz"
    else
      TZ="$TZ_FALLBACK_DEFAULT"
    fi
  fi
}

validate_cidr() {
  local cidr="$1"
  if [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
    return 0
  fi
  if [[ "$cidr" =~ ^[0-9A-Fa-f:]+/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$ ]]; then
    return 0
  fi
  return 1
}

validate_cidr_list() {
  local input="$1"
  [[ -n "$input" ]] || return 1

  local IFS=','
  local c=""
  for c in $input; do
    c="${c//[[:space:]]/}"
    [[ -n "$c" ]] || return 1
    validate_cidr "$c" || return 1
  done
}

validate_mailcow_dir() {
  [[ -n "$MAILCOW_DIR" ]] || die "--mailcow-dir darf nicht leer sein"
  [[ "$MAILCOW_DIR" == /* ]] || die "--mailcow-dir muss ein absoluter Pfad sein"

  local normalized
  normalized="$(realpath -m -- "$MAILCOW_DIR")"
  [[ "$normalized" != "/" ]] || die "--mailcow-dir darf nicht / sein"
  [[ "$normalized" != "/opt" ]] || die "--mailcow-dir darf nicht /opt sein"
  [[ "$normalized" == /opt/* ]] || die "--mailcow-dir muss aus Sicherheitsgründen unter /opt liegen"

  MAILCOW_DIR="$normalized"
}

validate_admin_user_name() {
  local user="$1"
  [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

user_has_password() {
  local user="$1"
  local pw_state=""
  id "$user" >/dev/null 2>&1 || return 1
  pw_state="$(passwd -S "$user" | awk '{print $2}' || true)"
  [[ "$pw_state" == "P" ]]
}

check_noninteractive_consistency() {
  if [[ "$NON_INTERACTIVE" != "true" ]]; then
    return 0
  fi

  if [[ "$ADMIN_LOGIN_PASSWORD" == "true" ]]; then
    if user_has_password "$ADMIN_USER"; then
      log "non-interactive: bestehendes Login-Passwort für $ADMIN_USER erkannt"
    else
      die "--non-interactive mit Login-Passwort erfordert ein bereits gesetztes Passwort für ${ADMIN_USER}. Alternativen: interaktiv ausführen oder --passwordless-sudo true."
    fi
  fi

  if [[ "$ADMIN_LOGIN_PASSWORD" == "false" && "$PASSWORDLESS_SUDO" != "true" ]]; then
    die "--non-interactive ohne Login-Passwort erfordert --passwordless-sudo true."
  fi
}

validate_ssh_public_key() {
  local key="$1"
  [[ -n "$key" ]] || return 1
  [[ "$key" != *$'\n'* ]] || return 1

  [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]
}

validate_inputs() {
  is_true_or_false "$ADMIN_USER_FLAG_SET" || die "Ungültiger interner Zustand: ADMIN_USER_FLAG_SET=$ADMIN_USER_FLAG_SET"
  is_true_or_false "$TZ_FLAG_SET" || die "Ungültiger interner Zustand: TZ_FLAG_SET=$TZ_FLAG_SET"
  is_true_or_false "$UFW_FLAG_SET" || die "Ungültiger interner Zustand: UFW_FLAG_SET=$UFW_FLAG_SET"
  is_true_or_false "$AUTO_REBOOT_FLAG_SET" || die "Ungültiger interner Zustand: AUTO_REBOOT_FLAG_SET=$AUTO_REBOOT_FLAG_SET"
  is_true_or_false "$MAILCOW_AUTOUPDATE_FLAG_SET" || die "Ungültiger interner Zustand: MAILCOW_AUTOUPDATE_FLAG_SET=$MAILCOW_AUTOUPDATE_FLAG_SET"
  [[ "$ENABLE_UFW" == "yes" || "$ENABLE_UFW" == "no" ]] || die "Ungültig: --ufw $ENABLE_UFW"
  is_true_or_false "$PASSWORDLESS_SUDO" || die "Ungültig: --passwordless-sudo $PASSWORDLESS_SUDO"
  is_true_or_false "$AUTO_REBOOT" || die "Ungültig: --auto-reboot $AUTO_REBOOT"
  is_true_or_false "$MAILCOW_AUTOUPDATE" || die "Ungültig: --mailcow-autoupdate $MAILCOW_AUTOUPDATE"
  is_true_or_false "$RUN_HELLO_WORLD" || die "Ungültig: --hello-world $RUN_HELLO_WORLD"
  is_true_or_false "$SKIP_PING_CHECK" || die "Ungültig: --skip-ping-check $SKIP_PING_CHECK"
  is_true_or_false "$NON_INTERACTIVE" || die "Ungültig: --non-interactive/--interactive Konfiguration"

  if [[ "$AUTO_REBOOT" == "true" ]]; then
    validate_hhmm "$REBOOT_TIME" || die "Ungültige reboot-time: $REBOOT_TIME"
  fi
  if [[ "$MAILCOW_AUTOUPDATE" == "true" ]]; then
    validate_hhmm "$MAILCOW_UPDATE_TIME" || die "Ungültige mailcow-update-time: $MAILCOW_UPDATE_TIME"
  fi

  case "$PURGE_EXISTING" in
    no|containers|full) ;;
    *) die "Ungültig: --purge-existing $PURGE_EXISTING" ;;
  esac

  case "$ADMIN_LOGIN_PASSWORD" in
    auto|true|false) ;;
    *) die "Ungültiger interner Zustand: ADMIN_LOGIN_PASSWORD=$ADMIN_LOGIN_PASSWORD" ;;
  esac

  validate_admin_user_name "$ADMIN_USER" || die "Ungültiger Admin-Username: $ADMIN_USER (erlaubt: [a-z_][a-z0-9_-]{0,31})"
  [[ "$MAILCOW_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Ungültiger Branch-Name: $MAILCOW_BRANCH"
  [[ "$FQDN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Ungültiger FQDN: $FQDN"
  validate_ssh_public_key "$SSH_PUBKEY" || die "Ungültiger --ssh-pubkey. Erwarte eine komplette OpenSSH-Public-Key-Zeile (z.B. ssh-ed25519 AAAA... user@local). Wenn ein Pfad genutzt wird, ist er server-lokal."

  if [[ -n "$SSH_ALLOW_CIDR" ]]; then
    validate_cidr_list "$SSH_ALLOW_CIDR" || die "Ungültig: --ssh-allow-cidr (erwarte CIDR oder CSV-Liste aus CIDRs)"
  fi

  validate_mailcow_dir
}

read_pubkey() {
  local in="$1"
  local key=""
  if [[ -f "$in" ]]; then
    key="$(awk 'NF && $1 !~ /^#/ {print; exit}' "$in")"
    [[ -n "$key" ]] || die "SSH Public Key Datei ist leer/ungültig: $in"
  else
    key="$in"
  fi

  key="$(trim_value "$key")"
  echo "$key"
}

is_ubuntu_2404() {
  [[ -f /etc/os-release ]] || return 1
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]
}

has_ipv6_connectivity() {
  # 1) Default route vorhanden?
  if ! ip -6 route show default >/dev/null 2>&1; then
    return 1
  fi
  # 2) Extern ping (Cloudflare DNS v6)
  if ping -6 -c 1 -W 1 2606:4700:4700::1111 >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

configure_docker_ipv6() {
  local want_ipv6="$1" # true|false
  mkdir -p /etc/docker

  # Bestehende daemon.json sichern, danach gezielt JSON-Merge statt Komplett-Overwrite.
  local daemon="/etc/docker/daemon.json"
  local source_json
  local new_json
  source_json="$(mktemp)"
  new_json="$(mktemp)"
  local ts
  ts="$(date +%s)"

  if [[ -f "$daemon" ]]; then
    cp -a "$daemon" "${daemon}.bak.${ts}" || true
    if ! jq -e . "$daemon" >/dev/null 2>&1; then
      die "Docker daemon.json ist ungültiges JSON: $daemon (Backup erstellt: ${daemon}.bak.${ts})"
    fi
    cp -a "$daemon" "$source_json"
  else
    printf '{}\n' >"$source_json"
  fi

  if [[ "$want_ipv6" == "true" ]]; then
    jq '. + {"ipv6": true, "fixed-cidr-v6": "fd00:dead:beef::/48", "ip6tables": true}' \
      "$source_json" >"$new_json"
  else
    jq 'del(.ipv6, .["fixed-cidr-v6"], .ip6tables)' "$source_json" >"$new_json"
  fi

  install -m 0644 "$new_json" "$daemon"
  rm -f -- "$source_json" "$new_json"

  systemctl restart docker
}

install_base_packages() {
  log "APT: Basis-Pakete installieren"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release git jq gawk coreutils grep iputils-ping \
                     unattended-upgrades apt-listchanges fail2ban
}

create_admin_user() {
  local user="$1"
  log "User: $user (SSH-only) anlegen/konfigurieren"

  if id "$user" >/dev/null 2>&1; then
    log "User existiert bereits: $user (wird aktualisiert)"
  else
    adduser --disabled-password --gecos "" "$user"
  fi
  usermod -aG sudo "$user"

  # SSH Key setzen
  local home_dir
  home_dir="$(getent passwd "$user" | cut -d: -f6)"
  install -d -m 0700 -o "$user" -g "$user" "$home_dir/.ssh"
  printf "%s\n" "$SSH_PUBKEY" >"$home_dir/.ssh/authorized_keys"
  chown "$user:$user" "$home_dir/.ssh/authorized_keys"
  chmod 0600 "$home_dir/.ssh/authorized_keys"

  local sudo_file="/etc/sudoers.d/90-${user}-nopasswd"
  local pw_state

  if [[ "$ADMIN_LOGIN_PASSWORD" == "true" ]]; then
    pw_state="$(passwd -S "$user" | awk '{print $2}')"
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      [[ "$pw_state" == "P" ]] || die "non-interactive: Login-Passwort für ${user} fehlt."
      log "Login-Passwort für $user ist bereits gesetzt (non-interactive)."
    else
      log "Login-Passwort für $user setzen/aktualisieren"
      passwd "$user"
    fi
    passwd -u "$user" >/dev/null 2>&1 || true
  else
    passwd -d "$user" >/dev/null 2>&1 || true
    passwd -l "$user" >/dev/null 2>&1 || true
    log "Login-Passwort für $user ist deaktiviert."
  fi

  if [[ "$PASSWORDLESS_SUDO" == "true" ]]; then
    log "Sudo: Passwortlos für $user aktivieren (NOPASSWD)"
    cat >"$sudo_file" <<EOF
${user} ALL=(ALL) NOPASSWD:ALL
EOF
    chmod 0440 "$sudo_file"
    visudo -cf "$sudo_file" >/dev/null
  else
    rm -f "$sudo_file"
    if [[ "$ADMIN_LOGIN_PASSWORD" != "true" ]]; then
      die "PASSWORDLESS_SUDO=false erfordert ein gesetztes Login-Passwort für ${user}."
    fi
    pw_state="$(passwd -S "$user" | awk '{print $2}')"
    [[ "$pw_state" == "P" ]] || die "Für PASSWORDLESS_SUDO=false muss ein Passwort für ${user} gesetzt sein."
    log "Sudo: Für $user ist Passwort erforderlich (kein NOPASSWD)."
  fi
}

harden_sshd() {
  local user="$1"
  log "SSH: Hardening + AllowUsers ${user}"

  mkdir -p /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/99-mailcow-hardening.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers ${user}
X11Forwarding no
EOF

  sshd -t
  systemctl reload ssh
}

configure_fail2ban() {
  log "Fail2ban: sshd jail aktivieren"
  mkdir -p /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
  systemctl enable --now fail2ban
}

configure_unattended_upgrades() {
  log "Unattended-Upgrades: Auto Updates + Auto-Reboot konfigurieren"
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  # Eigene Datei statt 50unattended-upgrades zu patchen
  cat >/etc/apt/apt.conf.d/52mailcow-auto-reboot <<EOF
Unattended-Upgrade::Automatic-Reboot "${AUTO_REBOOT}";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

  systemctl enable --now unattended-upgrades
}

install_docker() {
  log "Docker: Repo hinzufügen + Docker Engine/Compose Plugin installieren"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  local codename
  # shellcheck disable=SC1091
  . /etc/os-release
  codename="${UBUNTU_CODENAME:-$VERSION_CODENAME}"

  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable
EOF

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker

  if [[ "$RUN_HELLO_WORLD" == "true" ]]; then
    log "Docker: hello-world Test"
    docker run --rm hello-world >/dev/null
  else
    log "Docker: hello-world übersprungen (docker läuft, Version wird geprüft)"
  fi

  local dv
  dv="$(docker --version || true)"
  log "Docker Version: ${dv}"
}

purge_existing_mailcow() {
  [[ -d "$MAILCOW_DIR" ]] || return 0

  case "$PURGE_EXISTING" in
    no)
      die "MAILCOW_DIR existiert bereits: $MAILCOW_DIR (setze --purge-existing containers|full oder wähle anderes --mailcow-dir)"
      ;;
    containers)
      log "Bestehende mailcow Container stoppen (ohne data/ zu löschen)"
      (cd "$MAILCOW_DIR" && docker compose down) || true
      ;;
    full)
      warn "FULL PURGE: Stoppe mailcow + lösche Verzeichnis $MAILCOW_DIR (inkl. data/)."
      [[ "$MAILCOW_DIR" == /opt/* && "$MAILCOW_DIR" != "/opt" ]] || die "Sicherheitsabbruch: unsicheres MAILCOW_DIR für purge: $MAILCOW_DIR"
      (cd "$MAILCOW_DIR" && docker compose down) || true
      rm -rf -- "$MAILCOW_DIR"
      ;;
    *)
      die "Ungültig: --purge-existing $PURGE_EXISTING"
      ;;
  esac
}

install_mailcow() {
  log "mailcow: Installation nach /opt"
  mkdir -p "$(dirname "$MAILCOW_DIR")"

  if [[ ! -d "$MAILCOW_DIR" ]]; then
    (cd "$(dirname "$MAILCOW_DIR")" && umask 0022 && git clone https://github.com/mailcow/mailcow-dockerized "$(basename "$MAILCOW_DIR")")
  fi

  cd "$MAILCOW_DIR"

  # Konfig erzeugen (mailcow-Doku empfiehlt generate_config.sh)
  # Wir setzen FQDN, Branch und TZ vorab, damit weniger interaktiv ist.
  export MAILCOW_HOSTNAME="$FQDN"
  export MAILCOW_BRANCH="$MAILCOW_BRANCH"
  export MAILCOW_TZ="$TZ"

  log "mailcow: generate_config.sh ausführen"
  ./generate_config.sh

  # TZ nachziehen (falls generate_config anders gesetzt hat)
  if grep -qE '^TZ=' mailcow.conf; then
    sed -i "s|^TZ=.*|TZ=${TZ}|" mailcow.conf
  else
    printf "\nTZ=%s\n" "$TZ" >> mailcow.conf
  fi

  # IPv6 in mailcow.conf setzen, je nach echter Host-Konnektivität
  if has_ipv6_connectivity; then
    log "IPv6: Host hat IPv6-Konnektivität -> ENABLE_IPV6=true"
    if grep -qE '^ENABLE_IPV6=' mailcow.conf; then
      sed -i "s|^ENABLE_IPV6=.*|ENABLE_IPV6=true|" mailcow.conf
    else
      printf "\nENABLE_IPV6=true\n" >> mailcow.conf
    fi
  else
    log "IPv6: Keine zuverlässige IPv6-Konnektivität -> ENABLE_IPV6=false"
    if grep -qE '^ENABLE_IPV6=' mailcow.conf; then
      sed -i "s|^ENABLE_IPV6=.*|ENABLE_IPV6=false|" mailcow.conf
    else
      printf "\nENABLE_IPV6=false\n" >> mailcow.conf
    fi
  fi

  log "mailcow: Images ziehen + Stack starten"
  docker compose pull
  docker compose up -d

  log "mailcow: Status (kurz)"
  docker compose ps --format "table {{.Name}}\t{{.State}}\t{{.Ports}}" || true
}

setup_mailcow_autoupdate() {
  if [[ "$MAILCOW_AUTOUPDATE" != "true" ]]; then
    log "mailcow Auto-Update: deaktiviert"
    return 0
  fi

  validate_hhmm "$MAILCOW_UPDATE_TIME" || die "Ungültige mailcow-update-time: $MAILCOW_UPDATE_TIME"

  log "mailcow Auto-Update: systemd timer auf $MAILCOW_UPDATE_TIME einrichten"

  cat >/etc/systemd/system/mailcow-update.service <<EOF
[Unit]
Description=mailcow update (dockerized)
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
WorkingDirectory=${MAILCOW_DIR}
ExecStart=/bin/bash -lc './update.sh --force $( [[ "$SKIP_PING_CHECK" == "true" ]] && echo "--skip-ping-check" )'
TimeoutStartSec=0
EOF

  cat >/etc/systemd/system/mailcow-update.timer <<EOF
[Unit]
Description=Run mailcow update daily at ${MAILCOW_UPDATE_TIME}

[Timer]
OnCalendar=*-*-* ${MAILCOW_UPDATE_TIME}:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now mailcow-update.timer
}

setup_ufw_and_docker_user_rules() {
  # Mailcow Ports (TCP) laut Doku:
  # 25, 80, 110, 143, 443, 465, 587, 993, 995, 4190
  local ports=(25 80 110 143 443 465 587 993 995 4190)

  log "Firewall: UFW aktivieren + SSH einschränken"

  apt-get install -y ufw

  # Für konsistente v4/v6 Regeln UFW IPv6 aktivieren.
  if [[ -f /etc/default/ufw ]]; then
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
  fi

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  if [[ -n "$SSH_ALLOW_CIDR" ]]; then
    local IFS=','
    local cidr=""
    for cidr in $SSH_ALLOW_CIDR; do
      cidr="${cidr//[[:space:]]/}"
      ufw allow from "$cidr" to any port 22 proto tcp
    done
  else
    warn "SSH CIDR Einschränkung ist deaktiviert: SSH (22/tcp) wird global erlaubt."
    ufw allow 22/tcp
  fi

  for p in "${ports[@]}"; do
    ufw allow "${p}/tcp"
  done

  ufw --force enable

  # Docker: DOCKER-USER Regeln, damit nicht alles "ungefiltert" published wird.
  # Achtung: Das ist ein pragmatischer Minimal-Ansatz für "nur mailcow läuft auf dem Host".
  log "Firewall: DOCKER-USER Regeln setzen (IPv4 + IPv6)"
  cat >/usr/local/sbin/mailcow-docker-user-fw.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ports=(25 80 110 143 443 465 587 993 995 4190)

apply_chain_rules() {
  local xt="$1"

  # ensure chain exists (Docker legt sie i.d.R. an)
  "$xt" -N DOCKER-USER 2>/dev/null || true

  # flush our policy (nur DOCKER-USER; Docker eigene Chains bleiben)
  "$xt" -F DOCKER-USER

  # allow established
  "$xt" -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  # allow egress from docker bridges
  "$xt" -A DOCKER-USER -i docker0 -j ACCEPT
  "$xt" -A DOCKER-USER -i br+ -j ACCEPT

  # allow inbound to published mailcow ports
  for p in "${ports[@]}"; do
    "$xt" -A DOCKER-USER -p tcp --dport "$p" -j ACCEPT
  done

  # drop everything else forwarded to containers
  "$xt" -A DOCKER-USER -j DROP
}

command -v iptables >/dev/null 2>&1 && apply_chain_rules iptables
if [[ -f /proc/net/if_inet6 ]] && command -v ip6tables >/dev/null 2>&1; then
  apply_chain_rules ip6tables
fi
EOF
  chmod +x /usr/local/sbin/mailcow-docker-user-fw.sh

  cat >/etc/systemd/system/mailcow-docker-user-fw.service <<'EOF'
[Unit]
Description=Apply DOCKER-USER firewall rules for mailcow
Wants=docker.service
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mailcow-docker-user-fw.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now mailcow-docker-user-fw.service
}

print_external_firewall_instructions() {
  cat <<EOF

--- Externe Netzwerk-Firewall ---
Inbound TCP öffnen (mailcow laut Doku, IPv4 und IPv6 falls IPv6 genutzt wird):
  25   SMTP
  80   HTTP (ACME)
  110  POP3
  143  IMAP
  443  HTTPS (UI)
  465  SMTPS
  587  Submission
  993  IMAPS
  995  POP3S
  4190 Sieve

Empfohlen: Inbound TCP 22 (SSH) nur von deinem Management-CIDR erlauben (z.B. ${SSH_ALLOW_CIDR:-DEINE_IP/32 oder DEIN_IPV6_PREFIX/128})

Wichtig-Hinweis aus mailcow-Doku:
- Zusätzlich kann eine Regel nötig sein, um eingehende TCP ACK und UDP für Ports 1024-65535 zu erlauben.
  (Das betrifft vor allem stateless Filter-Implementierungen.)
- Wenn IPv6 nicht genutzt wird, IPv6 in der externen Firewall vollständig sperren.

EOF
}

final_info() {
  cat <<EOF

--- Fertig ---
SSH Login:
  ssh ${ADMIN_USER}@${FQDN}

Mailcow UI:
  https://${FQDN}/admin
  Default Login: admin / moohoo  (bitte sofort ändern)

Systemd Timer:
  mailcow update:  systemctl status mailcow-update.timer
  unattended-upgrades: systemctl status unattended-upgrades

EOF

  if [[ "$ENABLE_UFW" == "no" ]]; then
    print_external_firewall_instructions
  fi
}

parse_args() {
  local opts
  opts=$(getopt -o h --long \
    help,non-interactive,fqdn:,mailcow-dir:,admin-user:,tz:,ssh-pubkey:,ssh-allow-cidr:,ufw:,passwordless-sudo:,auto-reboot:,reboot-time:,mailcow-autoupdate:,mailcow-update-time:,hello-world:,branch:,purge-existing:,skip-ping-check: \
    -n 'install-mailcow-ubuntu24.sh' -- "$@") || { usage; exit 1; }
  eval set -- "$opts"

  while true; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --non-interactive) NON_INTERACTIVE="true"; shift ;;
      --fqdn) FQDN="$2"; shift 2 ;;
      --mailcow-dir) MAILCOW_DIR="$2"; shift 2 ;;
      --admin-user) ADMIN_USER="$2"; ADMIN_USER_FLAG_SET="true"; shift 2 ;;
      --tz) TZ="$2"; TZ_FLAG_SET="true"; shift 2 ;;
      --ssh-pubkey) SSH_PUBKEY="$(read_pubkey "$2")"; shift 2 ;;
      --ssh-allow-cidr) SSH_ALLOW_CIDR="$(normalize_ssh_allow_cidr_value "$2")"; shift 2 ;;
      --ufw) ENABLE_UFW="$2"; UFW_FLAG_SET="true"; shift 2 ;;
      --passwordless-sudo) PASSWORDLESS_SUDO="$2"; shift 2 ;;
      --auto-reboot) AUTO_REBOOT="$2"; AUTO_REBOOT_FLAG_SET="true"; shift 2 ;;
      --reboot-time) REBOOT_TIME="$2"; shift 2 ;;
      --mailcow-autoupdate) MAILCOW_AUTOUPDATE="$2"; MAILCOW_AUTOUPDATE_FLAG_SET="true"; shift 2 ;;
      --mailcow-update-time) MAILCOW_UPDATE_TIME="$2"; shift 2 ;;
      --skip-ping-check) SKIP_PING_CHECK="$2"; shift 2 ;;
      --hello-world) RUN_HELLO_WORLD="$2"; shift 2 ;;
      --branch) MAILCOW_BRANCH="$2"; shift 2 ;;
      --purge-existing) PURGE_EXISTING="$2"; shift 2 ;;
      --) shift; break ;;
      *) die "Unknown arg: $1" ;;
    esac
  done
}

interactive_missing() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    [[ -n "$FQDN" ]] || die "--non-interactive: --fqdn ist erforderlich"
    [[ -n "$SSH_PUBKEY" ]] || die "--non-interactive: --ssh-pubkey ist erforderlich"

    if [[ "$UFW_FLAG_SET" == "false" ]]; then
      ENABLE_UFW="yes"
    fi

    if [[ -z "$SSH_ALLOW_CIDR" ]]; then
      SSH_ALLOW_CIDR="$(detect_ssh_client_cidr)"
    fi

    SSH_ALLOW_CIDR="$(normalize_ssh_allow_cidr_value "$SSH_ALLOW_CIDR")"
    if [[ "$ADMIN_LOGIN_PASSWORD" == "auto" ]]; then
      if [[ "$PASSWORDLESS_SUDO" == "true" ]]; then
        ADMIN_LOGIN_PASSWORD="false"
      else
        ADMIN_LOGIN_PASSWORD="true"
      fi
    fi

    return 0
  fi

  if [[ "$ADMIN_USER_FLAG_SET" == "false" ]]; then
    while true; do
      prompt_default ADMIN_USER "Admin-Benutzername (Option: <name>, Enter=admin)" "$ADMIN_USER"
      ADMIN_USER="$(trim_value "$ADMIN_USER")"
      [[ -z "$ADMIN_USER" ]] && ADMIN_USER="admin"
      if validate_admin_user_name "$ADMIN_USER"; then
        break
      fi
      echo "Ungültiger Username. Erlaubt: [a-z_][a-z0-9_-]{0,31}"
    done
  fi

  if [[ -z "$FQDN" ]]; then
    while [[ -z "$FQDN" ]]; do
      read -r -p "MAILCOW FQDN (Option: <mail.example.org>): " FQDN || true
      FQDN="$(trim_value "$FQDN")"
    done
    [[ -n "$FQDN" ]] || die "--fqdn ist erforderlich"
  fi

  if [[ -z "$SSH_PUBKEY" ]]; then
    local in=""
    read -r -p "SSH Public Key für admin (Optionen: <Keyline vom lokalen Rechner> oder <Pfad auf Server>): " in || true
    [[ -n "$in" ]] || die "--ssh-pubkey ist erforderlich"
    SSH_PUBKEY="$(read_pubkey "$in")"
  fi

  if [[ "$ADMIN_LOGIN_PASSWORD" == "auto" ]]; then
    prompt_true_false ADMIN_LOGIN_PASSWORD "Passwort für den Admin-Login setzen? (Optionen: yes/no, empfohlen)" "yes"
  fi
  if [[ "$ADMIN_LOGIN_PASSWORD" == "false" && "$PASSWORDLESS_SUDO" == "false" ]]; then
    warn "Ohne Login-Passwort und ohne passwordless sudo wäre kein sudo möglich."
    prompt_true_false PASSWORDLESS_SUDO "passwordless sudo aktivieren, um Lockout zu vermeiden? (Optionen: yes/no)" "yes"
    [[ "$PASSWORDLESS_SUDO" == "true" ]] || die "Abbruch zur Vermeidung eines Lockouts: setze Login-Passwort oder aktiviere passwordless sudo."
  fi

  if [[ -z "$SSH_ALLOW_CIDR" ]]; then
    local detected_cidr input lower confirm
    detected_cidr="$(detect_ssh_client_cidr)"
    print_bold_warning "WARNUNG: Eine falsche SSH-CIDR kann zum kompletten SSH-Lockout führen."
    if [[ -n "$detected_cidr" ]]; then
      echo "Erkannte SSH-Quelladresse: $detected_cidr (mit 'auto' übernehmen)."
    fi
    echo "Optionen: <CIDR[,CIDR...]> | auto | none | ENTER=none"
    while true; do
      read -r -p "SSH erlauben von CIDR: " input || true
      input="$(trim_value "$input")"
      lower="$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]')"
      case "$lower" in
        "")
          SSH_ALLOW_CIDR=""
          break
          ;;
        auto)
          if [[ -n "$detected_cidr" ]]; then
            prompt_yes_no confirm "RISIKO-BESTÄTIGUNG: SSH nur von ${detected_cidr} erlauben? (Lockout möglich bei Fehler/IP-Wechsel)" "no"
            if [[ "$confirm" == "yes" ]]; then
              SSH_ALLOW_CIDR="$detected_cidr"
              break
            fi
            echo "CIDR-Einschränkung nicht übernommen. Bitte erneut wählen."
            continue
          fi
          echo "Keine SSH-Quelle auto-erkannt. Bitte CIDR eingeben oder none/ENTER verwenden."
          ;;
        none|disable|disabled|off|open|any)
          SSH_ALLOW_CIDR=""
          break
          ;;
        *)
          if validate_cidr_list "$input"; then
            prompt_yes_no confirm "RISIKO-BESTÄTIGUNG: SSH nur von ${input} erlauben? (Lockout möglich bei Fehler/IP-Wechsel)" "no"
            if [[ "$confirm" == "yes" ]]; then
              SSH_ALLOW_CIDR="$input"
              break
            fi
            echo "CIDR-Einschränkung nicht übernommen. Bitte erneut wählen."
            continue
          fi
          echo "Ungültig. Erlaubt: CIDR/CSV, auto, none oder ENTER."
          ;;
      esac
    done
  fi

  if [[ "$UFW_FLAG_SET" == "false" ]]; then
    prompt_yes_no ENABLE_UFW "UFW verwenden? (Optionen: yes/no, empfohlen)" "yes"
  fi

  if [[ "$AUTO_REBOOT_FLAG_SET" == "false" ]]; then
    prompt_true_false AUTO_REBOOT "Auto-Reboot aktivieren? (Optionen: yes/no, empfohlen)" "yes"
  fi
  if [[ "$MAILCOW_AUTOUPDATE_FLAG_SET" == "false" ]]; then
    prompt_true_false MAILCOW_AUTOUPDATE "mailcow Auto-Update aktivieren? (Optionen: yes/no, empfohlen)" "yes"
  fi

  prompt_default TZ "Timezone (Option: <Area/City>, z.B. UTC oder Europe/Berlin)" "$TZ"
  if [[ "$AUTO_REBOOT" == "true" ]]; then
    prompt_default REBOOT_TIME "Auto-Reboot Uhrzeit (Option: HH:MM, nur wenn AUTO_REBOOT=true)" "$REBOOT_TIME"
    validate_hhmm "$REBOOT_TIME" || die "Ungültige reboot-time: $REBOOT_TIME"
  fi

  if [[ "$MAILCOW_AUTOUPDATE" == "true" ]]; then
    prompt_default MAILCOW_UPDATE_TIME "mailcow Auto-Update Uhrzeit (Option: HH:MM, nur wenn MAILCOW_AUTOUPDATE=true)" "$MAILCOW_UPDATE_TIME"
    validate_hhmm "$MAILCOW_UPDATE_TIME" || die "Ungültige mailcow-update-time: $MAILCOW_UPDATE_TIME"
  fi
}

normalize_defaults_after_prompt() {
  :
}

main() {
  require_root
  parse_args "$@"
  init_runtime_defaults

  is_ubuntu_2404 || warn "Nicht Ubuntu 24.04 erkannt. Das Skript ist dafür ausgelegt."

  interactive_missing
  normalize_defaults_after_prompt
  validate_inputs
  check_noninteractive_consistency

  log "Konfiguration: FQDN=$FQDN, ADMIN_USER=$ADMIN_USER, TZ=$TZ, UFW=$ENABLE_UFW, BRANCH=$MAILCOW_BRANCH, NON_INTERACTIVE=$NON_INTERACTIVE"
  log "Auto-Reboot: $AUTO_REBOOT @ $REBOOT_TIME; mailcow Auto-Update: $MAILCOW_AUTOUPDATE @ $MAILCOW_UPDATE_TIME"

  install_base_packages
  create_admin_user "$ADMIN_USER"
  harden_sshd "$ADMIN_USER"
  configure_fail2ban
  configure_unattended_upgrades

  install_docker

  # IPv6: nur wenn echte Konnektivität vorhanden, sonst aus (wichtig gegen Fehlkonfig/Open Relay)
  if has_ipv6_connectivity; then
    log "IPv6: Host hat IPv6-Konnektivität -> Docker IPv6 konfigurieren"
    configure_docker_ipv6 "true"
  else
    log "IPv6: keine zuverlässige IPv6-Konnektivität -> Docker IPv6 deaktiviert"
    configure_docker_ipv6 "false"
  fi

  purge_existing_mailcow
  install_mailcow
  setup_mailcow_autoupdate

  if [[ "$ENABLE_UFW" == "yes" ]]; then
    setup_ufw_and_docker_user_rules
  else
    log "UFW: deaktiviert (externe Netzwerk-Firewall empfohlen)"
  fi

  final_info
}

main "$@"
