# mailcow Ubuntu 24.04 Installer (SSH-only Admin)

Dieses Repo enthält ein Bash-Skript, das eine frische Ubuntu 24.04-Installation für mailcow vorbereitet und mailcow installiert.

## Quick Start

```bash
sudo ./install-mailcow-ubuntu24.sh
```

```bash
sudo ./install-mailcow-ubuntu24.sh \
  --non-interactive \
  --ufw yes \
  --fqdn mail.example.org \
  --ssh-pubkey "ssh-ed25519 AAAA... user@local" \
  --admin-user admin \
  --tz UTC \
  --branch stable \
  --passwordless-sudo true \
  --auto-reboot true \
  --reboot-time 04:00 \
  --mailcow-autoupdate true \
  --mailcow-update-time 03:30
```

**WARNUNG:** `--ssh-allow-cidr` begrenzt SSH strikt auf diese Quelle. Ein falscher Wert kann dich vom Server aussperren. Auch bei späterer Änderung deiner eigenen öffentlichen IP kannst du dich aussperren. Diese Flag nur bewusst manuell ergänzen.

Wichtige Flags: `--ufw yes|no`, `--non-interactive`, `--ssh-allow-cidr <CIDR[,CIDR...]>` (nur deine Management-IP/-Netze eintragen), `--passwordless-sudo true|false`, `--branch stable|...`; `--ssh-pubkey` erwartet die komplette Public-Key-Zeile deines lokalen Rechners oder einen Dateipfad auf dem Zielserver.

## Was das Skript macht

* Legt einen Admin-User an (Default: `admin`)

  * Login nur per SSH Public Key (kein Passwort-Login)
  * SSH Hardening (kein Root Login, keine Password Auth, `AllowUsers admin`)
  * Optional: passwortloses sudo (`--passwordless-sudo true`)
  * Default ist `--passwordless-sudo false`: sudo mit lokalem User-Passwort (SSH bleibt weiter key-only)
* Aktiviert Wartung/Sicherheit:

  * unattended-upgrades (Auto Updates) plus optionaler Auto-Reboot (Default: 04:00)
  * fail2ban (sshd)
* Installiert Docker Engine + Docker Compose Plugin
* Installiert mailcow nach Doku:

  * Clone nach `/opt/mailcow-dockerized`
  * Default Branch: `stable` (überschreibbar mit `--branch`)
  * `generate_config.sh`
  * `docker compose pull` und `docker compose up -d`
* IPv6 Handling:

  * IPv6 wird nur aktiviert, wenn echte IPv6-Konnektivität erkannt wird
  * Hintergrund: falsches Docker-IPv6 kann zu Open Relay führen
* mailcow Auto-Update:

  * systemd timer (Default: 03:30) führt `update.sh` aus
* Sichere Defaults:

  * UFW wird ohne --ufw-Flag interaktiv abgefragt (Enter = aktivieren); mit --non-interactive ohne Flag wird UFW aktiviert
  * SSH-Freischaltung erwartet ein konkretes CIDR (auto-detect per SSH_CONNECTION, sonst Abfrage)
  * Für Automation steht `--non-interactive` zur Verfügung (ohne Prompts, mit klaren Fehlern bei fehlenden Pflichtwerten)

## Voraussetzungen

* Ubuntu 24.04
* SSH Zugriff auf den Server
* Ein SSH Public Key für den Admin-User
* DNS/PTR/Deliverability ist nicht Teil des Skripts

Doku:

* Installation: [https://docs.mailcow.email/getstarted/install/](https://docs.mailcow.email/getstarted/install/)
* System/Ports/Firewall: [https://docs.mailcow.email/getstarted/prerequisite-system/](https://docs.mailcow.email/getstarted/prerequisite-system/)
* IPv6 Warnung (Open Relay): [https://docs.mailcow.email/post_installation/firststeps-disable_ipv6/](https://docs.mailcow.email/post_installation/firststeps-disable_ipv6/)
* Updates: [https://docs.mailcow.email/maintenance/update/](https://docs.mailcow.email/maintenance/update/)

## Nach erfolgreicher Installation

* UI: `https://<FQDN>/admin`
* Default UI Login (laut mailcow Doku): `admin / moohoo` (sofort ändern)

## Firewall

Wenn UFW nicht genutzt wird, sollte eine externe Netzwerk-Firewall (z.B. VPS-/Cloud-Firewall) inbound TCP öffnen (IPv4 und IPv6, falls IPv6 genutzt wird):

* 25, 80, 110, 143, 443, 465, 587, 993, 995, 4190
* SSH (22) nur von deiner Management-IP/CIDR

Hinweis: mailcow erwähnt, dass bei manchen (insbesondere stateless) Firewalls zusätzlich eingehende TCP ACK und UDP Ports 1024-65535 nötig sein können (siehe Doku-Link oben). Wenn IPv6 nicht genutzt wird, sollte IPv6 in der externen Firewall komplett gesperrt sein.

## Reset

Wenn im Zielpfad bereits mailcow liegt (Default: `/opt/mailcow-dockerized`), bricht das Skript ohne Reset absichtlich ab.

Reset-Optionen:

1. Container-Reset (Daten bleiben erhalten):

```bash
sudo ./install-mailcow-ubuntu24.sh ... --purge-existing containers
```

2. Vollständiger Reset (destruktiv, löscht auch `data/`):

```bash
sudo ./install-mailcow-ubuntu24.sh ... --purge-existing full
```

Vor `--purge-existing full` unbedingt Backup prüfen, da das Verzeichnis vollständig entfernt wird.
