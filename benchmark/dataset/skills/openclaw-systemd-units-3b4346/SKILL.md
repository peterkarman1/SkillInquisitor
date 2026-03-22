---
name: systemd-units
description: Write correct systemd unit files for services, timers, and sockets -- covering service types, dependency ordering, restart policies, security hardening, and timer scheduling with OnCalendar syntax.
---

# systemd Units

## Unit Types

systemd manages several unit types. The most commonly authored ones:

- `.service` -- process lifecycle (start, stop, restart, supervision)
- `.timer` -- scheduled activation of a service (replaces cron)
- `.socket` -- socket activation (start service on first connection)
- `.mount` / `.automount` -- filesystem mounts
- `.path` -- watch filesystem paths, trigger service on changes
- `.target` -- logical grouping / synchronization point (no processes)

Unit files live in:
- `/etc/systemd/system/` -- admin overrides (highest priority)
- `/run/systemd/system/` -- runtime units
- `/usr/lib/systemd/system/` -- package-provided units (do not edit directly)

To override a package-provided unit, use `systemctl edit myservice` which creates a drop-in at `/etc/systemd/system/myservice.service.d/override.conf`. Never edit files under `/usr/lib/systemd/system/` directly -- updates will overwrite your changes.

## Service Types

The `Type=` directive controls how systemd decides the service has started. Choosing the wrong type is one of the most common mistakes.

| Type | When systemd considers it "started" | Use for |
|------|--------------------------------------|---------|
| `simple` (default) | Immediately after fork() | Long-running processes that do NOT daemonize |
| `exec` | After execve() succeeds | Like simple, but reports exec failures properly |
| `forking` | After the parent process exits | Traditional daemons that fork into background |
| `oneshot` | After the process exits | Scripts that run once and finish |
| `notify` | When process sends sd_notify(READY=1) | Apps with slow initialization |
| `dbus` | When the specified BusName appears on D-Bus | D-Bus services |

### Common mistake: Type=forking for non-forking processes

If your process does NOT fork/daemonize (most modern software does not), do NOT use `Type=forking`. systemd will wait for the parent to exit, and since the main process IS the parent, it will think the service failed or timed out. Use `Type=simple` or `Type=exec` instead.

```ini
# WRONG -- nginx started with "daemon off" does not fork
[Service]
Type=forking
ExecStart=/usr/sbin/nginx -g "daemon off;"

# CORRECT
[Service]
Type=exec
ExecStart=/usr/sbin/nginx -g "daemon off;"
```

### oneshot with RemainAfterExit

For scripts that run once, use `Type=oneshot`. Without `RemainAfterExit=yes`, the service will show as "dead" after the script finishes, which is confusing:

```ini
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/setup-firewall.sh
```

## Dependencies: Ordering vs. Requirement

systemd separates two concepts that are easy to conflate:

- **Ordering** (`After=`, `Before=`) -- controls startup sequence only
- **Requirement** (`Wants=`, `Requires=`, `BindsTo=`) -- controls whether a unit must be running

These are independent. `Requires=foo.service` without `After=foo.service` starts both in parallel. You almost always need both together:

```ini
[Unit]
Requires=postgresql.service
After=postgresql.service
```

| Directive | Behavior |
|-----------|----------|
| `Wants=` | Weak dependency -- start the other unit, but don't fail if it fails |
| `Requires=` | Hard dependency -- if the other unit fails to start, this unit fails too |
| `BindsTo=` | Like Requires, but also stops this unit if the other stops |
| `PartOf=` | When the other unit is stopped/restarted, stop/restart this unit too |
| `After=` | Start this unit after the named unit finishes starting |
| `Before=` | Start this unit before the named unit |

### Common mistake: After=network.target vs network-online.target

`After=network.target` only means the network management stack has been started -- it does NOT mean the network is actually up. If your service needs working network connectivity:

```ini
[Unit]
After=network-online.target
Wants=network-online.target
```

You need both lines. `After=` sets the order; `Wants=` ensures the network-online target is actually activated.

## Timer Units

Timer units replace cron with better logging, dependency management, and sub-minute granularity. A timer `foo.timer` activates `foo.service` by default.

### OnCalendar syntax

Format: `DayOfWeek Year-Month-Day Hour:Minute:Second`

Every component is optional and `*` means "any":

```ini
# Every day at 3:00 AM
OnCalendar=*-*-* 03:00:00

# Shorthand for the above
OnCalendar=daily

# Every Monday at midnight
OnCalendar=Mon *-*-* 00:00:00

# First Saturday of every month at 18:00
OnCalendar=Sat *-*-1..7 18:00:00

# Every 15 minutes
OnCalendar=*-*-* *:00/15:00

# Weekdays at 22:30 and weekends at 20:00
OnCalendar=Mon..Fri 22:30
OnCalendar=Sat,Sun 20:00
```

Test your expressions with `systemd-analyze calendar`:
```bash
systemd-analyze calendar "Mon *-*-* 03:00:00" --iterations=5
```

### Monotonic timers

Trigger relative to an event rather than wall-clock time:

```ini
[Timer]
OnBootSec=5min          # 5 minutes after boot
OnUnitActiveSec=1h      # 1 hour after last activation
OnUnitInactiveSec=30min # 30 minutes after service finishes
```

### Persistent=true

If the machine was off when the timer should have fired, `Persistent=true` triggers the service immediately on next boot:

```ini
[Timer]
OnCalendar=daily
Persistent=true
```

### Complete timer example

```ini
# /etc/systemd/system/backup.timer
[Unit]
Description=Daily backup

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=600
AccuracySec=1s

[Install]
WantedBy=timers.target
```

Note: `RandomizedDelaySec=` staggers execution to avoid thundering herd when multiple timers fire at the same OnCalendar time (e.g., `daily`). `AccuracySec=` defaults to 1 minute -- set it lower if you need precision.

Enable the timer (not the service):
```bash
systemctl enable --now backup.timer
```

## Socket Activation

The socket unit holds the listening socket; systemd starts the service only on first connection.

```ini
# /etc/systemd/system/myapp.socket
[Unit]
Description=MyApp Socket

[Socket]
ListenStream=8080

[Install]
WantedBy=sockets.target
```

- `Accept=no` (default): one service instance handles all connections. Socket name must match service name (`myapp.socket` -> `myapp.service`).
- `Accept=yes`: systemd spawns a new service instance per connection. Requires a template service `myapp@.service`.

The service must accept the file descriptor passed by systemd (fd 3 by default) rather than opening its own socket.

## Restart Policies

```ini
[Service]
Restart=on-failure     # Restart only on non-zero exit
RestartSec=5           # Wait 5 seconds between restarts
```

| Restart= value | When it restarts |
|-----------------|------------------|
| `no` | Never (default) |
| `on-failure` | Non-zero exit, signal, timeout, watchdog |
| `on-abnormal` | Signal, timeout, watchdog (NOT non-zero exit) |
| `always` | Always, regardless of exit status |

### Rate limiting: StartLimitBurst and StartLimitIntervalSec

By default, systemd allows 5 starts within 10 seconds. After that, the unit enters a "failed" state and stops restarting. These are in the `[Unit]` section (not `[Service]`):

```ini
[Unit]
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Restart=on-failure
RestartSec=5
```

This allows up to 5 restarts per 60 seconds. To allow unlimited restarts:

```ini
[Unit]
StartLimitIntervalSec=0
```

## Environment Variables

```ini
[Service]
# Inline
Environment=NODE_ENV=production PORT=3000

# From file (one VAR=VALUE per line, no quotes needed)
EnvironmentFile=/etc/myapp/env

# Pass through from systemd manager
PassEnvironment=LANG TERM
```

`EnvironmentFile=-/etc/myapp/env` -- the `-` prefix means "don't fail if the file is missing."

## Security Hardening

Apply these progressively. Start with the least restrictive and verify the service still works:

```ini
[Service]
# Run as non-root
User=myapp
Group=myapp

# Or let systemd create a transient user/group
DynamicUser=yes

# Filesystem protection
ProtectSystem=strict      # Mount / read-only (except /dev, /proc, /sys)
ProtectHome=yes           # Hide /home, /root, /run/user
PrivateTmp=yes            # Private /tmp and /var/tmp
ReadWritePaths=/var/lib/myapp

# Privilege escalation prevention
NoNewPrivileges=yes

# Restrict network (if service needs no network)
PrivateNetwork=yes

# Restrict system calls
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

`ProtectSystem=` values:
- `true` -- `/usr` and `/boot` are read-only
- `full` -- like `true` plus `/etc` is read-only
- `strict` -- the entire filesystem is read-only; use `ReadWritePaths=` for exceptions

Check your service's security score:
```bash
systemd-analyze security myservice.service
```

## systemctl and journalctl Essentials

```bash
systemctl daemon-reload          # REQUIRED after editing unit files
systemctl enable --now myapp     # Enable at boot and start immediately
systemctl status myapp           # Status, recent logs, PID
systemctl cat myapp              # Show the effective unit file
systemctl edit myapp             # Create/edit drop-in override
systemctl list-timers            # Show all active timers
```

Always run `systemctl daemon-reload` after editing unit files. Forgetting this is the most common reason for "my changes aren't taking effect."

Query logs with journalctl:
```bash
journalctl -u myapp.service -f        # Follow logs (like tail -f)
journalctl -u myapp.service --since "1 hour ago" -p err
```

