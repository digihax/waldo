#!/bin/bash
# Release metadata checks (auditor §5 / B6). Proves:
#  (1) file execution   -> source_mode=file,  script_sha256=<on-disk sha256>, build identity retained
#  (2) stdin execution  -> source_mode=stdin, script_sha256=null,             build identity retained
#  (3) packaged-copy hash equality: the file-run self-hash == the detached RELEASE_MANIFEST.sha256 entry
# Run:  bash waldo/tests/release_checks.sh   (exit 0 = all PASS). Point WALDO_SH at the release copy if elsewhere.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="${WALDO_SH:-$HERE/../waldo.sh}"
MAN="$HERE/RELEASE_MANIFEST.sha256"
pass=0; fail=0
ok(){ pass=$((pass+1)); echo "PASS  $1"; }
no(){ fail=$((fail+1)); echo "FAIL  $1"; }
jget(){ grep -E "\"$1\"" "$2" | head -1 | sed -E 's/.*: *//; s/,$//; s/^"//; s/"$//'; }

# normalize to LF into a temp copy (what actually ships / runs on Linux)
WS=$(mktemp); cp "$SRC" "$WS"; sed -i 's/\r$//' "$WS"
DISK_HASH=$(sha256sum "$WS" | awk '{print $1}')

FJ=$(mktemp); bash "$WS" --only id --json "$FJ" >/dev/null 2>&1
[ "$(jget source_mode "$FJ")" = file ]        && ok "file run: source_mode=file"            || no "file run: source_mode ($(jget source_mode "$FJ"))"
[ "$(jget script_sha256 "$FJ")" = "$DISK_HASH" ] && ok "file run: script_sha256 == on-disk sha256" || no "file run: script_sha256 mismatch"
[ -n "$(jget waldo_version "$FJ")" ]          && ok "file run: build identity retained ($(jget waldo_version "$FJ"))" || no "file run: version missing"

SJ=$(mktemp); cat "$WS" | bash -s -- --only id --json "$SJ" >/dev/null 2>&1
[ "$(jget source_mode "$SJ")" = stdin ]       && ok "stdin run: source_mode=stdin"          || no "stdin run: source_mode ($(jget source_mode "$SJ"))"
[ "$(jget script_sha256 "$SJ")" = null ]      && ok "stdin run: script_sha256=null (no stable on-disk identity)" || no "stdin run: script_sha256 not null ($(jget script_sha256 "$SJ"))"
[ "$(jget waldo_version "$SJ")" = "$(jget waldo_version "$FJ")" ] && ok "stdin run: same build identity as file run" || no "stdin run: version differs"

# packaged-copy hash equality vs detached manifest
if [ -f "$MAN" ]; then
  MAN_HASH=$(grep -E '(^|[[:space:]/])waldo\.sh$' "$MAN" | awk '{print $1}' | head -1)
  [ -n "$MAN_HASH" ] && [ "$MAN_HASH" = "$DISK_HASH" ] && ok "manifest: waldo.sh sha256 matches RELEASE_MANIFEST.sha256" \
    || no "manifest: waldo.sh hash mismatch (manifest=$MAN_HASH disk=$DISK_HASH)"
else
  no "manifest: RELEASE_MANIFEST.sha256 not found at $MAN"
fi

rm -f "$WS" "$FJ" "$SJ"
echo ""; echo "RELEASE CHECKS: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
