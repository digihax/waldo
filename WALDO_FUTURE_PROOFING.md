# Waldo Future-Proofing Work

Generated 2026-08-24 after the v2.20 backlog cleanup.

Scope: Waldo only. Keep this separate from command-builder/report-pipeline work.

## Current State

- `waldo.ps1` and `waldo.sh` both report `2.20`.
- Release manifest hashes are current.
- Windows KAT coverage includes v2.20 web/provisioning source-signature checks.
- Linux has parity for the main v2.20 web-served artifact sweep: custom served dirs such as `cmsdocs`, `uploads`, `images`, `static`, plus scripts/schemas/notes/staged loot.
- `cov_inject_kat.ps1` now completes deterministically by testing bounded production collectors only.

## Future-Proofing Backlog

1. Build runtime fixtures for v2.20 web/provisioning checks.
   Current `v20_web_prov_kat.ps1` verifies production signatures and lead identities. A stronger next version should create isolated fake trees and execute collector logic against:
   - served `simulate.ps1`
   - `cmsdocs/images` or `uploads` writable served subdirectory
   - web-served `schema.sql`, `.env`, staged hive/loot filenames
   - Cloudbase/provisioning log with a real credential-shaped line
   - Cloudbase `inject_user_password=true` boolean-only context
   - unattend XML with `AdministratorPassword`
   - readable SAM/SYSTEM-style hive backup filenames

2. Split broad collectors into smaller testable units.
   The `creds` class is intentionally broad and useful in real runs, but hard to exercise in real-injection KATs on a live workstation. Future work should factor web/provisioning/saved-session/DB/hive sub-collectors behind small functions so each can be unit-tested without traversing real `C:\`.

3. Add a fixture-root mode for tests only.
   Consider an internal environment variable such as `WALDO_TEST_ROOT` or `WALDO_TEST_WEBROOTS` so KATs can redirect selected collectors to temporary directories. Do not expose this as an operator feature unless needed; keep normal Waldo behavior unchanged.

4. Keep `waldo.ps1` and `waldo.sh` parity explicit.
   When adding a collector to one side, add a short parity note:
   - Windows-only because it depends on registry/IIS/PowerShell/AD.
   - Linux-only because it depends on SUID/systemd/sudo/NFS.
   - Shared concept implemented on both.

5. Add shell-side KAT coverage for web-served artifacts.
   Mirror the Windows v2.20 KAT for `waldo.sh`, ideally using temp directories and shell functions rather than source-only greps.

6. Revisit mounted-root triage parity.
   Windows `-Root` triage is strong for mounted Windows filesystems. Linux root-triage exists, but future review should confirm mounted Linux filesystems get equivalent treatment for:
   - `/etc/shadow` and shadow backups
   - `/etc/sudoers` / `sudoers.d`
   - web/app roots
   - user homes, SSH keys, shell histories
   - local DB config/data indicators
   - flag search with denied/partial accounting

7. Preserve read-only / enumeration-only guardrails.
   Every future lead should remain descriptive and manual-review only. Waldo must not exploit, spray, validate, crack, modify services/tasks, write payloads, or mass-scan. Output writes remain limited to explicit operator-selected output paths.

8. Keep release integrity boring.
   Any change to `waldo.ps1` or `waldo.sh` must be followed by:
   - parse/syntax check
   - relevant KATs
   - release manifest hash refresh
   - README/backlog update if behavior changed

## Validation Command Set

PowerShell:

```powershell
$tests=@('a8_kat.ps1','a9_kat.ps1','b2_kat.ps1','cov_kat.ps1','cov_inject_kat.ps1','dll_kat.ps1','v20_web_prov_kat.ps1','vnc_kat.ps1')
foreach($t in $tests){
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path 'F:\_oscp_artifacts\waldo\tests' $t)
  if($LASTEXITCODE -ne 0){ exit $LASTEXITCODE }
}
```

PowerShell parse:

```powershell
$tokens=$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile('F:\_oscp_artifacts\waldo\waldo.ps1',[ref]$tokens,[ref]$errors)
$errors
```

Linux shell/release:

```bash
cd /mnt/f/_oscp_artifacts/waldo
bash -n waldo.sh
bash tests/release_checks.sh
```

## Related Files

- `F:\_oscp_artifacts\waldo\waldo.ps1`
- `F:\_oscp_artifacts\waldo\waldo.sh`
- `F:\_oscp_artifacts\waldo\README.md`
- `F:\_oscp_artifacts\waldo\WALDO_BACKLOG.md`
- `F:\_oscp_artifacts\waldo\tests\`
