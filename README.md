# Where's Waldo?

Waldo is an OSCP-oriented local enumeration tool that finds anomalies instead
of dumping every known check. It compares the host against conservative stock
baselines, highlights what does not belong, and ranks findings that deserve
manual review.

Waldo is intentionally read-only by default and dependency-free:

- No exploitation
- No brute forcing, credential spraying, or credential validation
- No payload writes
- No service, task, registry, or filesystem modification
- No network scanning

Two bounded exceptions are intentional: the Windows script may make a read-only
LDAP query on a domain-joined host, and both scripts can write operator-selected
output files when you explicitly pass an output path.

## Why Waldo

Most enumeration scripts are additive: they run every check and color the hits.
Waldo is subtractive: it starts with a model of a normal host and surfaces the
user, service, process, writable path, SUID binary, autorun, share, webroot, or
credential-shaped artifact that stands out.

Use Waldo to spot the lead quickly and quietly. Use broader tools such as
WinPEAS or LinPEAS when you want exhaustive coverage after you know where to
look.

## What Waldo Surfaces

Waldo is designed to surface local facts that are unusually useful in an OSCP
style enumeration pass. It does not try to prove exploitation; it identifies
manual-review leads and preserves enough context to decide what to inspect next.

Conceptually, Waldo looks for:

- Identity and privilege context: current user, elevation state, token
  privileges, groups, account policy, local/domain role, and whether the current
  context changes what matters.
- User and session anomalies: admin-like users, service-like users, UID/root or
  administrator outliers, active privileged sessions, readable home/profile
  material, and denied paths worth revisiting after privilege changes.
- Filesystem anomalies: non-stock application/data roots, custom tools,
  scripts, binaries, writable files, writable directories, backup material,
  staged loot, and operator-created artifacts that should not be confused with
  target evidence.
- Execution paths: services, scheduled jobs, timers, cron, startup entries,
  autoruns, shell initialization, WMI/event consumers, service registry/config
  settings, unquoted paths, writable execution targets, missing helpers,
  replaceable helpers, and DLL/library search-order conditions.
- Privilege primitives: writable privileged code paths, interesting SUID/SGID or
  capability-bearing binaries, dangerous sudo/doas rules, token privileges,
  install/persistence policies, service-control opportunities, NFS/export
  mistakes, and other local conditions that may become code execution as a more
  privileged identity.
- Process and network context: listeners, non-standard ports, process owners,
  process paths, service identities, local database listeners, routing facts,
  forwarding state, dual-homed/pivot hints, and saved endpoints that may matter
  only from this host.
- Web and application leads: webroots, served directories, writable served
  content, framework/CMS fingerprints, app configuration, source-code wiring,
  exposed repository metadata, upload/sync paths, application backups, schema
  files, and files that may be remotely reachable because they sit under served
  content.
- Credential-shaped material: config files, environment files, connection
  strings, DB credentials, API keys, tokens, private keys, VPN/RDP/session files,
  shell histories, dotfiles, browser/session vaults, password-manager vaults,
  VNC records, SNMP/community strings, deployment profiles, and files whose names
  imply credentials even when their contents do not match a simple regex.
- Offline credential sources: readable local hash stores, registry hive backups,
  SECURITY/LSA material, domain database copies, backup images, database files,
  credential-store databases, and mounted or already-pulled filesystem roots.
- Provisioning and build artifacts: answer files, guest-agent/cloud-init style
  logs, setup/install traces, deployment leftovers, templated credentials, and
  image-reuse clues.
- Objective files: local/proof/flag-style files, access-denied objectives,
  mounted-root objective discoveries, and coverage facts that distinguish a true
  negative from a partial or denied search.
- Correlated leads: relationships such as credential config plus matching local
  database listener, writable path plus privileged consumer, denied objective
  plus local privilege primitive, saved endpoint plus reachable segment, and
  role-specific evidence that changes lead priority.
- Collection context after elevation: what to collect once admin/root/SYSTEM is
  already obtained, including local secrets, hashes, service credentials, saved
  sessions, DPAPI/session material, tickets, hives, databases, logs, and flags.
- Output quality signals: ranked leads, credential provenance and scope hints,
  duplicate suppression, access-denied accounting, collector skip/error/timeout
  reporting, and optional structured JSON.

## Quick Start

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\waldo.ps1
powershell -ExecutionPolicy Bypass -File .\waldo.ps1 -Light
powershell -ExecutionPolicy Bypass -File .\waldo.ps1 -OutFile C:\Temp\waldo.txt
powershell -ExecutionPolicy Bypass -File .\waldo.ps1 -JsonOut C:\Temp\waldo.json
```

Linux:

```bash
chmod +x waldo.sh
./waldo.sh
./waldo.sh --light
./waldo.sh -o /tmp/waldo.txt
./waldo.sh --json /tmp/waldo.json
```

Remote Linux one-liner:

```bash
ssh user@target 'bash -s -- --only creds,flags' < waldo.sh
```

## Modes

Default mode is full plus deep enumeration.

| Mode | Windows | Linux | Use Case |
|------|---------|-------|----------|
| Full | `-Full` or default | `--full` or default | Best first run, includes deep sweeps |
| Medium | `-Medium` | `--medium` | All classes, skips heavier sweeps |
| Light | `-Light` | `--light` | Quick high-signal triage, skips log mining |

Run subsets with class filters:

```powershell
.\waldo.ps1 -List
.\waldo.ps1 -Only creds,flags
.\waldo.ps1 -Skip logs
```

```bash
./waldo.sh --list
./waldo.sh --only creds,flags
./waldo.sh --skip logs
```

Common check classes:

```text
id users fs services autostart proc privesc creds logs flags collection
```

The Windows build also includes:

```text
ad
```

## Windows Features

`waldo.ps1` covers:

- Host, token, privilege, integrity, and elevation context
- Local users, administrators, active sessions, and account policy
- Domain context and read-only AD outbound-right review
- Non-standard filesystem, app/data, backup, and writable-path anomalies
- Services, service ACLs, unquoted paths, DLL search-order evidence, and
  writable or replaceable execution targets
- Processes, listeners, process owners, route/forwarding facts, and path
  anomalies
- Autoruns, scheduled tasks, startup folders, WMI persistence, IFEO, AppInit,
  and LSA persistence indicators
- Web/app roots, served artifacts, app source/configuration leads, exposed
  repository metadata, upload/sync clues, and web-stack execution identity
- Credential-shaped files, deployment/provisioning artifacts, registry hives,
  domain database copies, saved sessions, VNC artifacts, local DB evidence, and
  credential provenance
- Post-admin/SYSTEM collection guidance for hives, LSA/service secrets, saved
  sessions, local databases, tickets, DPAPI-adjacent material, and flags
- Flag/objective search with coverage reporting
- Optional JSON output with lead, coverage, artifact, and abort metadata

Optional Windows arguments:

```powershell
.\waldo.ps1 -Loot C:\loot
.\waldo.ps1 -Root Z:\
.\waldo.ps1 -AD
.\waldo.ps1 -AD -ADUser corp\user -ADPass '<password>'
.\waldo.ps1 -DecodeLocalSecrets
.\waldo.ps1 -NoContent
.\waldo.ps1 -NoColor
.\waldo.ps1 -LowPriv
```

`-DecodeLocalSecrets` is opt-in and limited to documented reversible local
formats such as supported VNC password records. Waldo does not connect with or
reuse decoded values.

## Linux Features

`waldo.sh` covers:

- Host, identity, sudo, group, and login-user context
- UID 0 accounts, service accounts with shells, and readable hash stores
- Odd filesystem roots, app/data roots, temp drops, backup material, and
  writable paths
- SUID/SGID and capability anomalies against conservative baselines
- systemd units, timers, cron entries, shell startup paths, sourced helpers, and
  writable or replaceable execution targets
- Processes, listeners, non-standard ports, and path anomalies
- Web/app roots, served artifacts, app configs, source-code wiring, exposed
  repository metadata, backup images, and credential-shaped files
- SSH material, shell history, dotfiles, saved endpoints, cloud/tool
  credentials, browser/session vaults, and per-home access mapping
- Local database listener/config correlations, routing/pivot facts, service
  identities, and saved-endpoint relationships
- Mounted-root and loot-folder triage for already-pulled target files, including
  Windows hive/domain-database artifacts and Linux hash/config/secret material
- Optional JSON output with coverage and lead metadata

Optional Linux arguments:

```bash
./waldo.sh --loot ./loot
./waldo.sh --root /mnt/target-c
./waldo.sh --share-hints
./waldo.sh --decode-local-secrets
./waldo.sh --no-content
./waldo.sh --lowpriv
```

## Output

Human output uses these tags:

| Tag | Meaning |
|-----|---------|
| `[!]` | Non-standard or anomalous |
| `[!!]` | Non-standard and writable by the current user |
| `[x]` | Access denied or coverage gap |
| `[i]` | Context or supporting information |

The footer includes ranked leads, credential-artifact scope hints, coverage
status, and any collector skips/errors. JSON output is available with
`-JsonOut` on Windows or `--json` on Linux.

## Baselines

Waldo baselines are versioned in the scripts and tested through the fixtures.
They are deliberately conservative:

- Linux SUID baselines use captured minimal base-image manifests under
  `tests/suid_manifests/`.
- Windows build and role detection are used for ranking context, not broad
  suppression, because stock services and scheduled tasks vary heavily by update
  level and role.

Unknown platforms degrade to lower-confidence findings rather than hiding
anomalies.

## Testing

PowerShell KATs:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\a8_kat.ps1
powershell -ExecutionPolicy Bypass -File .\tests\a9_kat.ps1
powershell -ExecutionPolicy Bypass -File .\tests\b2_kat.ps1
powershell -ExecutionPolicy Bypass -File .\tests\cov_kat.ps1
powershell -ExecutionPolicy Bypass -File .\tests\cov_inject_kat.ps1
powershell -ExecutionPolicy Bypass -File .\tests\dll_kat.ps1
powershell -ExecutionPolicy Bypass -File .\tests\v20_web_prov_kat.ps1
powershell -ExecutionPolicy Bypass -File .\tests\vnc_kat.ps1
```

Linux/release checks:

```bash
bash tests/fixtures.sh
bash tests/release_checks.sh
python3 tests/pty_strict.py
```

The release manifest is stored at:

```text
tests/RELEASE_MANIFEST.sha256
```

## Safety Contract

Waldo reports observations and suggested manual review paths. It does not test,
spray, reuse, exploit, or validate credentials or vulnerabilities. Treat all
findings as leads that require operator judgment and authorization.

## License

MIT License. See `LICENSE`.
