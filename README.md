# Where's Waldo?

Enumeration **by anomaly** for OSCP labs. Read-only, dependency-free.

> **OSCP-safe.** Waldo is an enumeration-only local triage script. It does not
> exploit, modify services/tasks, write payloads, brute force credentials, mass-scan
> the network, reuse/spray discovered credentials, or validate CVEs. Findings are
> local configuration observations that require manual verification.
>
> **Two bounded, accurate exceptions to "no network / no writes":**
> - *Read-only directory query.* On a domain-joined Windows host, default PowerShell
>   enumeration may issue a **read-only LDAP query** to the domain the host already
>   trusts (e.g. to read `userWorkstations`, group membership, delegation flags). It
>   binds with the current context, reads, and never writes to the directory. It does
>   **not** authenticate with any *discovered* credential; supplying `-ADUser` is an
>   explicit, operator-opted authenticated context.
> - *Operator-selected output files.* Waldo writes to the target filesystem **only**
>   at paths you choose on the command line — `-OutFile` / `-JsonOut` (PowerShell),
>   `-o` / `--json` (shell). With none of those, it writes nothing to the target — no
>   implicit temp files: bounded collectors are captured through an in-memory pipe
>   (coproc), so an interrupt has nothing to leave behind.

## The idea

WinPEAS / LinPEAS are **additive** — they run every check they know and color the
hits. Waldo is **subtractive**: it holds a baseline of what a *standard* box looks
like and shows you only what **doesn't belong** — the extra user, the non-stock
service, the odd folder in `C:\` or `/opt`, the SUID that isn't standard, the
autorun/cron whose target you can write to. Then it **peeks inside** anomalous
files for secrets (`password=`, private keys, `net user`, `ConvertTo-SecureString`…).

It is a **scalpel next to PEAS's Swiss-army knife**. Use Waldo to *spot* the
anomaly fast and quietly; use PEAS to deep-dive it. Waldo will not out-coverage
PEAS and doesn't try to.

## Running subsets (check classes)

Default = full run. To run just part of it, use `--only`/`--skip` (bash) or
`-Only`/`-Skip` (PowerShell) with these classes (`--list` / `-List` to print them):

`id users fs services autostart proc privesc creds logs flags collection`

Examples: `waldo.sh --only creds,flags` (post-shell credential + flag sweep),
`waldo.ps1 -Skip logs` (skip the slow log mine). The ranked **leads** and
**credential-artifact rollup** always print, and a minimal host/identity header
always runs. Cross-references (e.g. flagging a tool's usage in history) are richest
on a `full` run, because discovery must run to populate what history is matched against.

## Flags

| tag  | meaning |
|------|---------|
| `[!]`  | non-standard — Waldo spotted it |
| `[!!]` | non-standard **and writable by you** — privesc gold |
| `[x]`  | access denied (gaps are interesting too) |
| `[i]`  | context / info |

## Windows — `waldo.ps1`

```powershell
powershell -ep bypass -f waldo.ps1        # default full + deep run
waldo.ps1 -Medium                         # all classes, skip the heaviest sweeps
waldo.ps1 -Light                          # quick high-signal triage
waldo.ps1 -OutFile C:\Temp\waldo.txt      # tee to file
waldo.ps1 -NoContent                      # skip grepping file contents
```

Checks: host/token/priv context, non-standard `C:\Users` + local admins, odd items
in `C:\`, non-stock Program Files, temp drops, anomalous services (path outside
System32 / unquoted / writable), processes from odd paths, non-standard listening
ports, autoruns (Run keys / Startup folders / scheduled tasks) with writable-target
flagging, writable PATH dirs, web-served scripts/schemas/notes/staged loot under
standard and custom app webroots, and a per-user Desktop/Documents/Downloads access map.
Uses only built-in cmdlets with WMI fallbacks (2008/2012 friendly).

## Linux — `waldo.sh`

```bash
./waldo.sh                 # quick triage
./waldo.sh -d              # --deep: SUID/SGID + world-writable sweeps, config-secret grep, NFS
./waldo.sh -o /tmp/w.txt   # tee to file
./waldo.sh --no-content    # skip grepping file contents
```

Checks: host/id/`sudo -l`, UID-0 accounts that aren't root, login users + service
accounts with shells, readable `/etc/shadow`, odd `/` entries, all of `/opt` & `/srv`,
temp drops, web-served scripts/schemas/notes/staged loot under standard and custom
app webroots, **SUID/SGID vs baseline + capabilities**, non-standard/writable systemd
units & `ExecStart`, processes from odd paths, non-standard ports, cron/timers with
writable targets, writable PATH dirs, and per-home SSH keys/history/dotfiles + access map.

## Baseline governance (not per-box editing)

Waldo's subtractive baseline is a **reviewed stock inventory** (standard users, root-dir
entries, Program Files, ports, SUID list, secret regex), carried in the BASELINE block
near the top of each script and changed through the normal spec/changelog process — *not*
by ad-hoc per-box edits. The tool **detects** the OS build (`ID` + major `VERSION_ID` on
Linux; product/build/role on Windows) and applies it as follows:

- **Linux — captured base-image SUID manifests (ranking context, not `high`).** The generic
  base set is the **empirical cross-image intersection** of six pristine official base images
  (`gpasswd mount newgrp su umount` — the only setuid-root binaries present in *every* captured
  base). Everything else — `sudo`, `pkexec`, `fusermount3`, `chsh/chfn`, `chage`, `passwd`
  (not setuid on `almalinux:9`!), `snap-confine`, … — is **not** in generic, so on an
  unknown/minimal box an unexpected one of those *surfaces*. For a build with its **own** captured,
  digest-pinned manifest (`debian:12`, `ubuntu:22.04/24.04`, `rockylinux:9`, `almalinux:9`,
  `oraclelinux:9` — see `tests/suid_manifests/`) a small per-build delta reconstructs that exact
  image's SUID set, and the fixtures assert the effective set **equals** that manifest (equality,
  not subset). Deltas are **never borrowed across families** — the EL9 images differ (Rocky ships
  `userhelper`; Alma lacks `passwd` and `userhelper`; Oracle lacks `userhelper`), and families with
  no freely-pullable image (`rhel:9`, `centos:9`) carry no delta and fall through to the
  conservative generic set. Because these are *minimal base images*, the baseline is **ranking
  context only** and confidence never claims `high` (it caps at `family-detected`, matching Windows);
  unknown builds fall back to `low`.
- **Windows — generic role-detected baseline, by design.** The build (Win10/11, Server
  2019/2022/2025) and role are **recognized for ranking/context only**; Waldo does **not**
  subtract per-build stock-service/task tables. A default-service inventory is update- and
  role-sensitive, and an over-inclusive table would *suppress* a real anomaly (a false
  negative — the worst failure for a security tool), so Windows confidence stays
  `role-detected` (never `high`) and nothing is subtracted.

Optional server roles (IIS, MSSQL, DHCP, DNS, WDS) are **never** globally subtracted on
either OS — their presence is ranking context, not a stock exemption. Where a build can't be
identified at all, Waldo degrades rather than over-subtracting (which would hide the anomaly).

You *may* append a locally-confirmed stock entry as a convenience while working a box,
but that is a temporary operator override, not the governance model: durable baseline
changes belong in the versioned tables so every future target benefits.

## Behavior contract (read-only, bounded)

**Enumeration only** — no exploitation, no service/task modification, no payload
writes, no credential reuse/spray, no mass scanning. Network and filesystem behavior
is exactly the two bounded exceptions described in the OSCP-safe note above: a
read-only LDAP query on a domain-joined host, and writes only to operator-selected
`-OutFile`/`-JsonOut`/`-o`/`--json` paths. There are **no** implicit/transient target
writes — bounded collectors capture through a pipe, not a temp file. Everything else
is read-only.

## Integrity & tests

Each release ships a detached manifest — `tests/RELEASE_MANIFEST.sha256` — listing the
expected SHA-256 of `waldo.sh` and `waldo.ps1`. Verify your copy against it before
running on an engagement. The `tests/` directory holds the acceptance suite:
`fixtures.sh` (collector/ranker logic), `vnc_kat.ps1` / `dll_kat.ps1` / `a9_kat.ps1` /
`b2_kat.ps1` / `cov_kat.ps1` (Known-Answer Tests that import/mirror the production
regexes, functions, and abort-typing), and `pty_strict.py` (a real PTY sends Ctrl-C at
**each** bounded collector — SUID, SGID, getcap — with `--json`, and requires exit 130,
one footer, valid JSON, and no leftover temp). JSON output records `source_mode` (`file`
vs `stdin`), `script_sha256` (null when streamed via stdin), and `abort_kind`
(`none`/`interrupt`/`error` — interruption and terminating errors are distinct states);
the build identity (`waldo_version`/`schema_version`/`build_date`) is retained either way.
