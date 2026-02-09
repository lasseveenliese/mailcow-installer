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
TZ_DEFAULT="Europe/Berlin"
REBOOT_TIME_DEFAULT="04:00"
MAILCOW_UPDATE_TIME_DEFAULT="03:30"

FQDN=""
TZ="$TZ_DEFAULT"
SSH_PUBKEY=""
ENABLE_UFW="yes"              # yes|no
UFW_FLAG_SET="false"          # true|false (ob --ufw explizit gesetzt wurde)
SSH_ALLOW_CIDR=""             # z.B. "203.0.113.10/32"
AUTO_REBOOT="true"            # true|false
REBOOT_TIME="$REBOOT_TIME_DEFAULT"
MAILCOW_AUTOUPDATE="true"     # true|false
MAILCOW_UPDATE_TIME="$MAILCOW_UPDATE_TIME_DEFAULT"
RUN_HELLO_WORLD="false"       # true|false
PASSWORDLESS_SUDO="false"     # true|false
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
  --admin-user <name>                      Default: $ADMIN_USER
  --tz <Area/City>                         Default: $TZ_DEFAULT
  --ssh-allow-cidr <CIDR[,CIDR...]>        Default: auto-detect from SSH_CONNECTION (falls möglich); ACHTUNG: falscher Wert kann SSH-Lockout verursachen
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

validate_ssh_public_key() {
  local key="$1"
  [[ -n "$key" ]] || return 1
  [[ "$key" != *$'\n'* ]] || return 1

  [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]
}

validate_inputs() {
  is_true_or_false "$UFW_FLAG_SET" || die "Ungültiger interner Zustand: UFW_FLAG_SET=$UFW_FLAG_SET"
  [[ "$ENABLE_UFW" == "yes" || "$ENABLE_UFW" == "no" ]] || die "Ungültig: --ufw $ENABLE_UFW"
  is_true_or_false "$PASSWORDLESS_SUDO" || die "Ungültig: --passwordless-sudo $PASSWORDLESS_SUDO"
  is_true_or_false "$AUTO_REBOOT" || die "Ungültig: --auto-reboot $AUTO_REBOOT"
  is_true_or_false "$MAILCOW_AUTOUPDATE" || die "Ungültig: --mailcow-autoupdate $MAILCOW_AUTOUPDATE"
  is_true_or_false "$RUN_HELLO_WORLD" || die "Ungültig: --hello-world $RUN_HELLO_WORLD"
  is_true_or_false "$SKIP_PING_CHECK" || die "Ungültig: --skip-ping-check $SKIP_PING_CHECK"
  is_true_or_false "$NON_INTERACTIVE" || die "Ungültig: --non-interactive/--interactive Konfiguration"

  validate_hhmm "$REBOOT_TIME" || die "Ungültige reboot-time: $REBOOT_TIME"
  validate_hhmm "$MAILCOW_UPDATE_TIME" || die "Ungültige mailcow-update-time: $MAILCOW_UPDATE_TIME"

  case "$PURGE_EXISTING" in
    no|containers|full) ;;
    *) die "Ungültig: --purge-existing $PURGE_EXISTING" ;;
  esac

  [[ "$MAILCOW_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Ungültiger Branch-Name: $MAILCOW_BRANCH"
  [[ "$FQDN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Ungültiger FQDN: $FQDN"
  validate_ssh_public_key "$SSH_PUBKEY" || die "Ungültiger --ssh-pubkey. Erwarte eine komplette OpenSSH-Public-Key-Zeile (z.B. ssh-ed25519 AAAA... user@local). Wenn ein Pfad genutzt wird, ist er server-lokal."

  if [[ -n "$SSH_ALLOW_CIDR" ]]; then
    validate_cidr_list "$SSH_ALLOW_CIDR" || die "Ungültig: --ssh-allow-cidr (erwarte CIDR oder CSV-Liste aus CIDRs)"
  elif [[ "$ENABLE_UFW" == "yes" ]]; then
    die "UFW ist aktiv, aber --ssh-allow-cidr ist leer und konnte nicht automatisch erkannt werden"
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

  key="$(printf '%s' "$key" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
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
  log "User: $user (SSH-only, ohne Passwort) anlegen/konfigurieren"

  if id "$user" >/dev/null 2>&1; then
    log "User existiert bereits: $user (wird aktualisiert)"
  else
    adduser --disabled-password --gecos "" "$user"
    usermod -aG sudo "$user"
  fi

  # SSH Key setzen
  local home_dir
  home_dir="$(getent passwd "$user" | cut -d: -f6)"
  install -d -m 0700 -o "$user" -g "$user" "$home_dir/.ssh"
  printf "%s\n" "$SSH_PUBKEY" >"$home_dir/.ssh/authorized_keys"
  chown "$user:$user" "$home_dir/.ssh/authorized_keys"
  chmod 0600 "$home_dir/.ssh/authorized_keys"

  local sudo_file="/etc/sudoers.d/90-${user}-nopasswd"

  if [[ "$PASSWORDLESS_SUDO" == "true" ]]; then
    # Kein Passwort nötig: Account-Passwort wird gesperrt, Privilege Escalation nur über SSH-Key-Session.
    passwd -d "$user" >/dev/null 2>&1 || true
    passwd -l "$user" >/dev/null 2>&1 || true

    log "Sudo: Passwortlos für $user aktivieren (NOPASSWD)"
    cat >"$sudo_file" <<EOF
${user} ALL=(ALL) NOPASSWD:ALL
EOF
    chmod 0440 "$sudo_file"
    visudo -cf "$sudo_file" >/dev/null
  else
    rm -f "$sudo_file"
    local pw_state
    pw_state="$(passwd -S "$user" | awk '{print $2}')"
    if [[ "$pw_state" != "P" ]]; then
      if [[ -t 0 ]]; then
        log "Sudo mit Passwort ist aktiv. Bitte jetzt ein lokales Passwort für ${user} setzen (wird NICHT für SSH verwendet)."
        passwd "$user"
      else
        die "PASSWORDLESS_SUDO=false erfordert ein gesetztes Passwort für ${user}. Starte interaktiv oder nutze --passwordless-sudo true."
      fi
    fi
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
  # Wir setzen FQDN und Branch vorab, damit weniger interaktiv ist.
  export MAILCOW_HOSTNAME="$FQDN"
  export MAILCOW_BRANCH="$MAILCOW_BRANCH"

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

  [[ -n "$SSH_ALLOW_CIDR" ]] || die "UFW ist aktiv, aber --ssh-allow-cidr fehlt"

  local IFS=','
  local cidr=""
  for cidr in $SSH_ALLOW_CIDR; do
    cidr="${cidr//[[:space:]]/}"
    ufw allow from "$cidr" to any port 22 proto tcp
  done

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
Empfohlen: SSH nur von deiner IP/CIDR erlauben, alles andere zu.

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

Inbound TCP 22 (SSH): nur von deinem Management-CIDR (z.B. ${SSH_ALLOW_CIDR:-DEINE_IP/32 oder DEIN_IPV6_PREFIX/128})

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
      --admin-user) ADMIN_USER="$2"; shift 2 ;;
      --tz) TZ="$2"; shift 2 ;;
      --ssh-pubkey) SSH_PUBKEY="$(read_pubkey "$2")"; shift 2 ;;
      --ssh-allow-cidr) SSH_ALLOW_CIDR="$2"; shift 2 ;;
      --ufw) ENABLE_UFW="$2"; UFW_FLAG_SET="true"; shift 2 ;;
      --passwordless-sudo) PASSWORDLESS_SUDO="$2"; shift 2 ;;
      --auto-reboot) AUTO_REBOOT="$2"; shift 2 ;;
      --reboot-time) REBOOT_TIME="$2"; shift 2 ;;
      --mailcow-autoupdate) MAILCOW_AUTOUPDATE="$2"; shift 2 ;;
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

    return 0
  fi

  if [[ -z "$FQDN" ]]; then
    prompt_default FQDN "MAILCOW FQDN (z.B. mail.example.org)" ""
    [[ -n "$FQDN" ]] || die "--fqdn ist erforderlich"
  fi

  if [[ -z "$SSH_PUBKEY" ]]; then
    local in=""
    read -r -p "SSH Public Key für admin (Key vom lokalen Rechner einfügen): " in || true
    [[ -n "$in" ]] || die "--ssh-pubkey ist erforderlich"
    SSH_PUBKEY="$(read_pubkey "$in")"
  fi

  if [[ -z "$SSH_ALLOW_CIDR" ]]; then
    SSH_ALLOW_CIDR="$(detect_ssh_client_cidr)"
    if [[ -n "$SSH_ALLOW_CIDR" ]]; then
      prompt_default SSH_ALLOW_CIDR "SSH erlauben von CIDR (CSV möglich)" "$SSH_ALLOW_CIDR"
    else
      while [[ -z "$SSH_ALLOW_CIDR" ]]; do
        read -r -p "SSH erlauben von CIDR (erforderlich, z.B. 203.0.113.10/32): " SSH_ALLOW_CIDR || true
      done
    fi
  fi

  if [[ "$UFW_FLAG_SET" == "false" ]]; then
    prompt_yes_no ENABLE_UFW "UFW verwenden? (empfohlen)" "yes"
  fi

  prompt_default TZ "Timezone" "$TZ"
  prompt_default REBOOT_TIME "Auto-Reboot Uhrzeit (nur wenn AUTO_REBOOT=true)" "$REBOOT_TIME"
  validate_hhmm "$REBOOT_TIME" || die "Ungültige reboot-time: $REBOOT_TIME"

  prompt_default MAILCOW_UPDATE_TIME "mailcow Auto-Update Uhrzeit (nur wenn MAILCOW_AUTOUPDATE=true)" "$MAILCOW_UPDATE_TIME"
  validate_hhmm "$MAILCOW_UPDATE_TIME" || die "Ungültige mailcow-update-time: $MAILCOW_UPDATE_TIME"
}

normalize_defaults_after_prompt() {
  if [[ -z "$SSH_ALLOW_CIDR" ]]; then
    SSH_ALLOW_CIDR="$(detect_ssh_client_cidr)"
  fi
}

main() {
  require_root
  parse_args "$@"

  is_ubuntu_2404 || warn "Nicht Ubuntu 24.04 erkannt. Das Skript ist dafür ausgelegt."

  interactive_missing
  normalize_defaults_after_prompt
  validate_inputs

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
