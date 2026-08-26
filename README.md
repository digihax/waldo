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
- Non-standard filesystem locations and writable paths
- Services, service ACLs, unquoted paths, and writable binaries
- Processes, listeners, and process path anomalies
- Autoruns, scheduled tasks, startup folders, WMI persistence, IFEO, AppInit,
  and LSA persistence indicators
- Webroots, web-served artifacts, provisioning logs, unattend files, and app
  configuration leads
- Credential-shaped files, registry hives, saved sessions, VNC artifacts, and
  credential provenance
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
- Odd filesystem roots, `/opt`, `/srv`, temp drops, and writable paths
- SUID/SGID and capability anomalies against conservative baselines
- systemd units, timers, cron entries, and writable execution targets
- Processes, listeners, non-standard ports, and path anomalies
- Webroots, staged artifacts, app configs, and credential-shaped files
- SSH material, shell history, dotfiles, saved endpoints, and per-home access
  mapping
- Mounted-root and loot-folder triage for already-pulled target files
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
