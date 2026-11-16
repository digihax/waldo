# Validation and release integrity

Run from the repository root. These are synthetic known-answer fixtures: some
import production helpers, others mirror rules or inspect source wiring. Passing
tests do not establish complete end-to-end coverage or a supported platform matrix.

## Linux

```bash
bash -n waldo.sh
bash tests/fixtures.sh
bash tests/release_checks.sh
python3 tests/pty_strict.py
python3 tests/pty_interactive.py
```

Bash fixtures need ordinary Unix utilities; some checks use OpenSSL. Release checks
execute the identity class. Python PTY harnesses execute collection and signals.
Run these in an isolated disposable Linux lab, not on a sensitive host. PTY timing
is environment-dependent. `WALDO_SH` can select another script; the default is
relative to this checkout. Each harness uses a private temporary source copy.
Synthetic command shims delay the chosen collector so interruption remains
reproducible on small filesystems; this does not test the external command itself.
The strict harness checks exit 130; the interactive harness supplements it with
job-control behavior and does not replace the strict exit-status check.

## Windows

Run each in its own Windows PowerShell or PowerShell 7 process:

```powershell
powershell -NoProfile -File .\tests\a8_kat.ps1
powershell -NoProfile -File .\tests\a9_kat.ps1
powershell -NoProfile -File .\tests\b2_kat.ps1
powershell -NoProfile -File .\tests\cov_kat.ps1
powershell -NoProfile -File .\tests\dll_kat.ps1
powershell -NoProfile -File .\tests\v20_web_prov_kat.ps1
```

`vnc_kat.ps1` uses Windows profile APIs and synthetic temporary INI data, but its
copied decoder/classifier logic does not prove production wiring. Use a private
TEMP directory. `cov_inject_kat.ps1` executes production collection with injected
failures and always-on host context; run only on an isolated Windows lab host.

## Detached manifest

Paths are relative to the repository root:

```bash
sha256sum -c tests/RELEASE_MANIFEST.sha256
```

```powershell
Get-FileHash .\waldo.ps1 -Algorithm SHA256
# Compare with its entry in tests/RELEASE_MANIFEST.sha256
```

`.gitattributes` selects CRLF for `waldo.ps1` and LF for `waldo.sh`. Changing line
endings changes hashes. The detached manifest detects accidental byte changes;
it is not a signed authenticity proof. Stdin execution has no stable self-hash.
