# Waldo Backlog

Generated 2026-08-24 from the August 23 review transcript, `D:\__improve__today.txt`, the exam backup reports, and the current `waldo.ps1` / `waldo.sh`.

## Status

The Windows enumerator is substantially updated. `waldo.ps1` is `v2.20` and includes the main exam-derived enumeration gaps: webroot/writeability detection, web-served high-signal artifacts, provisioning/unattend/Cloudbase logs, readable hive backups, route and IP-forwarding pivot facts, credential provenance, local DB correlations, duplicate/denied flag accounting, and coverage/JSON hardening.

No separate comprehensive backlog had been saved before this file. This file is the working backlog going forward.

## Remaining Waldo Work

Detailed future-proofing notes are captured in `WALDO_FUTURE_PROOFING.md`.

1. Add deeper runtime fixtures for v2.20 web/provisioning checks.
   `tests/v20_web_prov_kat.ps1` now covers the production signatures and lead identities for `simulate.ps1`-style served scripts, `cmsdocs/images` writable served subdirectories, Cloudbase/unattend leaks, and readable hive backup scoring. A future improvement would create isolated fixture trees and execute the collectors against them instead of using source/logic assertions.

2. Keep Linux parity under review.
   `waldo.sh` now has the same high-level web-served artifact sweep and custom served directory names from the Windows v2.20 additions, plus existing route, DB, provisioning, flag-denied, and history correlation logic. Future parity review should focus on mounted Linux root-triage depth and any new Windows-only collector added later.

3. Keep README and release metadata in sync.
   README now reflects the current PowerShell run modes and both shipped scripts report `2.20`. Re-check this whenever either script changes.

## Already Covered In `waldo.ps1`

- Exposed webroot/app artifacts such as `.env`, `simulate.ps1`, schemas, staged hives, notes, and backups.
- Writable webroots and writable served subdirectories.
- Provisioning, guest-agent, Cloudbase, setup, and unattend evidence.
- Registry hive backups and offline credential material pointers.
- Route-to-non-attached-network and IP-forwarding pivot indicators.
- Credential-named files independent of content regex matches.
- Command/history correlations for flagged custom tools and positional secret-shaped arguments.
- Flag-state accounting for duplicates, denied locations, partial searches, and local-vs-proof objective nudges.
- Local DB listener plus config credential correlation.
- JSON/coverage integrity improvements and release manifest hashes.

## Related Non-Waldo Backlog

These are important but belong to the command-builder/report pipeline, not the local enumeration scripts:

1. Build service summaries as a union of all scan artifacts, not only top-100/service scans.
2. Escalate unknown/custom services and banner evidence such as `whois?` with domain/email strings.
3. Treat backend/pivot scope as first-class and generate reports for every scoped IP.
4. Save pivot state in structured JSON/TSV.
5. Log clean executed commands with exit status/outcome, not just terminal transcripts.
6. Maintain normalized `flags.tsv` and diff captured flags against submitted control-panel flags.
7. Parse saved OffSec control-panel HTML for authoritative target scope and submissions.
8. Generate dependency graphs for credential/hash/source-host/destination-host relationships.
9. Add report completeness checks before final export.
