# mailcow Ubuntu 24.04 Installer (SSH-only Admin)

This repository contains a Bash script that prepares a fresh Ubuntu 24.04 installation for mailcow and installs mailcow.

## What the script does

* Creates an admin user (default: `admin`)

  * SSH public key login only (no password login)
  * SSH hardening (no root login, no password auth, `AllowUsers admin`)
  * Optional passwordless sudo (`--passwordless-sudo true`)
  * Default is `--passwordless-sudo false`: sudo with a local user password (SSH still remains key-only)
* Enables maintenance/security:

  * unattended-upgrades (automatic updates) plus optional auto reboot (default: 04:00)
  * fail2ban (sshd)
* Installs Docker Engine + Docker Compose plugin
* Installs mailcow according to the documentation:

  * clone to `/opt/mailcow-dockerized`
  * default branch: `stable` (override with `--branch`)
  * run `generate_config.sh`
  * run `docker compose pull` and `docker compose up -d`
* IPv6 handling:

  * IPv6 is only enabled when real IPv6 connectivity is detected
  * background: incorrect Docker IPv6 configuration can lead to an open relay
* mailcow auto-update:

  * a systemd timer (default: 03:30) runs `update.sh`
* Secure defaults:

  * UFW is enabled by default (unless disabled via flag)
  * SSH access expects a specific CIDR (auto-detected from `SSH_CONNECTION`, otherwise prompted)
  * `--non-interactive` is available for automation (no prompts, clear errors on missing required values)

## Requirements

* Ubuntu 24.04
* SSH access to the server
* An SSH public key for the admin user
* DNS/PTR/deliverability are not handled by this script

Documentation:

* Installation: [https://docs.mailcow.email/getstarted/install/](https://docs.mailcow.email/getstarted/install/)
* System/Ports/Firewall: [https://docs.mailcow.email/getstarted/prerequisite-system/](https://docs.mailcow.email/getstarted/prerequisite-system/)
* IPv6 warning (open relay): [https://docs.mailcow.email/post_installation/firststeps-disable_ipv6/](https://docs.mailcow.email/post_installation/firststeps-disable_ipv6/)
* Updates: [https://docs.mailcow.email/maintenance/update/](https://docs.mailcow.email/maintenance/update/)

## After successful installation

* UI: `https://<FQDN>/admin`
* Default UI login (according to mailcow docs): `admin / moohoo` (change immediately)

## Firewall

If UFW is not used, an external network firewall (e.g. VPS/cloud firewall) should allow inbound TCP (IPv4 and IPv6 if IPv6 is used):

* 25, 80, 110, 143, 443, 465, 587, 993, 995, 4190
* SSH (22) only from your management IP/CIDR

Note: mailcow mentions that on some firewalls (especially stateless firewalls), incoming TCP ACK and UDP ports 1024-65535 may also be required (see documentation link above). If IPv6 is not used, IPv6 should be fully blocked in the external firewall.

## Reset

Optionally, the script can stop existing mailcow containers or remove the complete directory (including data), which is destructive.

## Local Secret Scan Before Commit

This repository includes a `gitleaks` pre-commit scan that aborts the commit if secrets are detected.
Requirement: `gitleaks` must be installed locally.

Setup (if not active locally yet):

```bash
./scripts/setup-git-hooks.sh
```

Bypass (intentional, one-time):

```bash
git commit --no-verify
# or
SKIP_GITLEAKS=1 git commit -m "..."
```
