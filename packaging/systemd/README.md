# systemd integration

`pangolin@.service` is a systemd template unit. One instance per
saved portal profile, and thanks to pangolin's per-instance control
sockets you can run several units **in parallel** — e.g. a `work`
tunnel and a `client-a` tunnel side by side, each with its own TUN
device, routes, DNS, and `/run/pangolin/<instance>.sock`.

## Install

```bash
# 1. Install the binary (cargo build --release done first).
sudo install -m 0755 target/release/pgn /usr/local/bin/pgn

# 2. Create at least one portal profile.
#    The profile name is what you'll pass as the systemd instance
#    below, and it must match [A-Za-z0-9_-]{1,32}.
sudo pgn portal add work \
    --url https://vpn.corp.example.com \
    --auth-mode paste \
    --only 10.0.0.0/8 \
    --hip auto \
    --reconnect

# 3. Drop the unit file in place and reload systemd.
sudo install -m 0644 packaging/systemd/pangolin@.service \
    /etc/systemd/system/pangolin@.service
sudo systemctl daemon-reload
```

## Use

The instance name (`%i`) after the `@` is a profile name saved
with `pgn portal add`. Bare URLs are not supported as instance
names — they would collide with systemd's own `%i` escaping rules
and with pangolin's `[A-Za-z0-9_-]{1,32}` validator. Save them as
profiles first.

```bash
# Start the "work" profile and enable it at boot.
sudo systemctl enable --now pangolin@work.service

# Tail the live log.
sudo journalctl -u pangolin@work.service -f

# Stop and disable.
sudo systemctl disable --now pangolin@work.service

# Run a second profile in parallel — fully supported. Each
# instance gets its own /run/pangolin/<name>.sock, its own tun
# device, its own routes, and its own DNS state.
sudo systemctl enable --now pangolin@client-a.service
```

`pgn status` and `pgn disconnect` are instance-aware:

```bash
# List every live instance.
sudo pgn status --all

# Query just one.
sudo pgn status -i work

# Disconnect just one.
sudo pgn disconnect -i work

# Disconnect everything.
sudo pgn disconnect --all
```

With no flags:

* `pgn status` prints a `disconnected` line if nothing is running,
  full details for a single live instance, or the list view if two
  or more are live.
* `pgn disconnect` disconnects a single live instance without
  asking, but **refuses** if two or more are live — pass
  `--instance <name>` or `--all` to be explicit. This is on
  purpose: silently picking a target when the user was ambiguous
  is how you accidentally tear down the wrong tunnel.

## Restart policy

`pangolin@.service` uses `Restart=on-failure` with a 15-second
backoff and a burst limit of 5 restarts per 10 minutes. That's
aggressive enough to recover from a transient network blip while
still backing off if the portal is permanently broken (e.g.
expired credentials).

For longer-term resilience, also pass `--reconnect` (or set
`reconnect = true` in the profile, which is what the install
example above does). That bumps libopenconnect's internal
reconnect budget from 60 seconds to 10 minutes, so brief
outages are handled by the existing tunnel without systemd
needing to restart anything.

## Clean shutdown

The unit intentionally has **no `ExecStop=`**. Systemd sends
`SIGTERM` on `systemctl stop`, pgn's signal handler translates
that into the libopenconnect cmd-pipe path, and the tunnel tears
down on exactly the same code path as `Ctrl-C` in foreground
mode. An `ExecStop=/usr/local/bin/pgn disconnect` line would
race that path because `pgn disconnect` returns as soon as the
IPC server acknowledges the request, not when the tunnel is
actually down.

## Troubleshooting

Common failure modes:

* **`pgn: no portal given and no default profile set`** — the
  instance name doesn't match any saved profile. Run
  `sudo pgn portal list` to see what's saved.
* **`instance name … contains an invalid character`** — the
  instance name isn't `[A-Za-z0-9_-]{1,32}`. Rename the profile.
* **`another pgn instance is already running at /run/pangolin/<name>.sock`**
  — you already have a `pangolin@<name>.service` up (possibly a
  stale one from a previous session). `systemctl status pangolin@<name>`
  to check, or `sudo pgn status --all` to see the live list.
* **`Failed to bind local tun device (TUNSETIFF): Operation
  not permitted`** — the unit started without `User=root`,
  or the install path is wrong. Check `systemctl cat
  pangolin@<name>.service`.
* **Repeated restarts hitting `StartLimitBurst`** — systemd
  has stopped trying. Look at `journalctl -u pangolin@<name>
  --since "5 minutes ago"` to see why the connect failed,
  fix the underlying issue, then `systemctl reset-failed
  pangolin@<name>` before re-enabling.
