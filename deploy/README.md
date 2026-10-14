# Linux service deployment

**Contact:** Stephane Jacob / [jacobstephane@outlook.com](mailto:jacobstephane@outlook.com)

This guide runs Renegade++ as a dedicated, unprivileged system account with systemd. The sample unit is in [`renegade-bbs.service`](renegade-bbs.service). Review its paths, network binding, user, and port before installation.

## Install the executable and assets

Build Renegade++ on Debian or Ubuntu using the commands in the [main README](../README.md). Install the executable and artwork beneath `/opt/renegade`:

```sh
sudo install -d -o root -g root -m 0755 /opt/renegade/bin /opt/renegade/assets
sudo install -o root -g root -m 0755 build/renegade-cpp /opt/renegade/bin/renegade-cpp
sudo cp -a assets/ansi /opt/renegade/assets/
```

Create the service account and writable state directories:

```sh
sudo useradd --system --home-dir /var/lib/renegade --create-home --shell /usr/sbin/nologin renegade
sudo install -d -o renegade -g renegade -m 0750 /var/lib/renegade/data /var/lib/renegade/var /var/lib/renegade/files
sudo -u renegade ssh-keygen -t ed25519 -N '' -f /var/lib/renegade/var/ssh_host_ed25519_key
```

Place the `bulletins/`, `quotes/`, and `taglines/` content directories under `/var/lib/renegade`, or adjust the service's working directory and arguments.

## Configure and start systemd

Copy the sample unit to `/etc/systemd/system/renegade-bbs.service`. Edit the unit to match the installation paths, then enable it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now renegade-bbs
sudo systemctl status renegade-bbs
```

Create the SysOp account by running the CLI as the service user and using the same database path configured in the unit:

```sh
sudo -u renegade /opt/renegade/bin/renegade-cpp user add SYSOP --db /var/lib/renegade/data/renegade.sqlite3
sudo -u renegade /opt/renegade/bin/renegade-cpp user sysop SYSOP on --db /var/lib/renegade/data/renegade.sqlite3
```

Review the [operator and user manual](../OPERATOR-USER-MANUAL.md) for account setup, binding, firewall, backup, and terminal configuration.
