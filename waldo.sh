#!/bin/bash
# waldo.sh -- "Where's Waldo?"  Linux enumeration by ANOMALY (ENUMERATION ONLY).
#
# v2.12 adds: active sessions (who/w/last), admin-like accounts, Samba
# signing, host-role inference, smb.conf/TFTP sharing configs, credential cross-match.
# Observe-and-advise only.
# v2.13 adds --root <path>: triage a MOUNTED target share (mount -t cifs //host/C /mnt/c) -- auto-detects a
# WINDOWS tree (case-insensitive) and re-roots the crown jewels: readable hives (RegBack/Windows.old) ->
# offline secretsdump, flags, per-user creds, writable drop-targets. Plus --share-hints (no-mount pull list).
# v2.14 adds full group/member roster (you + every login user + high-value group members) and a [LOCAL]
# lockout/password policy read (login.defs + pam_faillock/tally) -- know rate-limits before brute-forcing.
# v2.15: version-synced with waldo.ps1. The v2.15 batch was Windows/AD/DC-only -- NO Linux-applicable
# changes, so waldo.sh is unchanged in function; the number is bumped only to keep the .ps1/.sh pair aligned.
#
# Philosophy: LinPEAS is ADDITIVE (runs every check it knows). Waldo is
# SUBTRACTIVE: it knows what a STANDARD box looks like and shows only what does
# NOT belong -- the SUID that isn't stock, the UID-0 user that isn't root, the
# service/port/cron/binary that stands out -- then PEEKS INSIDE anomalous files.
#
# v2 adds CORRELATION: high-value findings are scored into a "Top Waldo Leads"
# summary at the end, so   non-stock /opt/app + writable script + root cron runs it
# surfaces as ONE ranked lead instead of three scattered lines.
#
# READ-ONLY enumeration: no target changes, no exploit/attack traffic; writes ONLY to a chosen -o/--json path. bash w/ graceful
# degradation (works in a limited/paste-in shell).
#
# Flag legend:
#   [!]  non-standard        [!!] non-standard AND writable (possible privesc condition)
#   [x]  access denied       [i]  context/info    [*]  section header
#
# Usage:
#   ./waldo.sh                 # DEFAULT = full + deep (everything -- first run, best run)
#   ./waldo.sh --medium        # all classes, skip the heavy sweeps (faster)
#   ./waldo.sh --light         # quick high-signal triage (no deep, no log-mining)
#   ./waldo.sh --only creds,flags   # run only some check classes (--list to see them)
#   ./waldo.sh --skip logs     # run everything except a class
#   ./waldo.sh --loot /path/loot   # offline triage of already-pulled files (no target interaction)
#   ./waldo.sh --root /mnt/c   # triage a MOUNTED target share: sudo mount -t cifs //TARGET/C /mnt/c -o user=..
#                              #   auto-detects a Windows tree under the mount -> crown jewels (hives/flags/creds)
#   ./waldo.sh --share-hints   # no mount: print the smbclient/nxc shopping list for a shared-out C:\ and exit
#   ./waldo.sh --lowpriv       # force writable checks even if elevated (default: suppressed as root)
#   ./waldo.sh -o /tmp/w.txt   # tee to file (color off)
#   ./waldo.sh --no-content    # don't grep file contents
#   ssh user@target 'bash -s' < waldo.sh   # run with no upload artifact
#   ssh user@target 'bash -s -- --only creds' < waldo.sh   # pass args over stdin
#
# Pair with LinPEAS: Waldo to SPOT the anomaly, LinPEAS to deep-dive it.

# =====================================================================
#  ARGS
# =====================================================================
WALDO_VERSION="2.20"; SCHEMA_VERSION="1"; BUILD_DATE="2026-08-23"   # v2.20 build (exam-review enumeration backlog)
DEEP=1; OUTFILE=""; NOCONTENT=0; NOCOLOR=0; LOWPRIV=0; SHOW_OPERATOR=0; ONLY=""; SKIP=""; LOOT=""; ROOT=""; SHARE_HINTS=0; JSONOUT=""; DECODE_SECRETS=0; FLAG_STATE="NOT_CHECKED"; FLAG_SUPERSEDED=false  # DEFAULT = full+deep
# Check classes -- run subsets with --only / --skip (default/full = everything).
CLASSES="id users fs services autostart proc privesc creds logs flags collection"
while [ $# -gt 0 ]; do case "$1" in
  -d|--deep) DEEP=1;;
  -o|--out) shift; OUTFILE="$1";;
  --no-content) NOCONTENT=1;;
  --no-color) NOCOLOR=1;;
  --lowpriv) LOWPRIV=1;;
  --show-operator-leads) SHOW_OPERATOR=1;;
  --only) shift; ONLY="$1";;
  --skip) shift; SKIP="$1";;
  --loot) shift; LOOT="$1";;            # offline triage of an already-pulled loot directory
  --root) shift; ROOT="$1";;            # triage a MOUNTED target filesystem root (Windows share via mount -t cifs //host/C /mnt/c)
  --share-hints) SHARE_HINTS=1;;        # print the no-mount smbclient/nxc shopping list for a shared-out C:\ and exit
  --json) shift; JSONOUT="$1";;         # v2.17 B2: write a machine-readable manifest (leads/coverage/artifacts) to FILE
  --decode-local-secrets) DECODE_SECRETS=1;;  # v2.16 A5b: opt-in offline decode of reversible local secrets (VNC ~/.vnc/passwd)
  --full|full) DEEP=1;;                 # explicit "everything" (== the default)
  --medium) DEEP=0;;                    # all classes, skip the heavy sweeps
  --light) DEEP=0; SKIP="${SKIP:+$SKIP,}logs";;   # quick high-signal triage (no deep, no log-mining)
  --list) echo "check classes: $CLASSES"; exit 0;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; echo; echo "check classes (--only/--skip): $CLASSES"; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; shift; done
# ROOT MODE: alias LOOT so host-enum is skipped; the short-circuit branches to run_root (structured, re-rooted).
if [ -n "$ROOT" ]; then ROOT="${ROOT%/}"; [ -d "$ROOT" ] || { echo "root path not found: $ROOT" >&2; exit 1; }; LOOT="$ROOT"; fi
# want CLASS -> should this section run? (unknown class always runs, as a safety net)
CURRENT_CLASS=""; CURRENT_COLLECTOR=""; COV_DENIALS=""; COV_SKIPS=""; COV_ERRORS=""; COV_ERR_REASONS=""; COV_COLLECTORS=""; _COV_SKIP_SEEN=""; _COV_REC_SEEN=""   # v0.15/v0.27/v0.31 COV: per-class + per-COLLECTOR outcomes
# v0.31 COV registry: record one typed outcome per (class, collector, state). CURRENT_COLLECTOR is set by sub() (each
# sub-section IS a collector), so denied/cov_skip/cov_error attribute to a specific collector -- a non-ok outcome is
# retained with its identity + reason and emitted in the JSON `collectors` array. Deduped per class|collector|state.
cov_record(){ _cr="${CURRENT_CLASS:-?}|${CURRENT_COLLECTOR:-?}|$1"; case " $_COV_REC_SEEN " in *" $_cr "*) return 0;; esac; _COV_REC_SEEN="$_COV_REC_SEEN $_cr"; COV_COLLECTORS="${COV_COLLECTORS}${CURRENT_CLASS:-?}|${CURRENT_COLLECTOR:-?}|$1|$2
"; }
# cov_skip: a sub-collector could NOT RUN (missing tool / unavailable prerequisite) -> class PARTIAL. Deduped per class+reason.
cov_skip(){ case " $_COV_SKIP_SEEN " in *" ${CURRENT_CLASS}:$1 "*) return 0;; esac; _COV_SKIP_SEEN="$_COV_SKIP_SEEN ${CURRENT_CLASS}:$1"; COV_SKIPS="$COV_SKIPS ${CURRENT_CLASS:-?}"; cov_record skipped "$1"; note "  [~] sub-check skipped: $1 -- coverage for '${CURRENT_CLASS:-?}' is PARTIAL, not complete"; }
# cov_error: a collector ERRORED / TIMED OUT / failed a prerequisite -> class PARTIAL, tracked as an ERROR (NOT a tool-absent skip),
# with the reason retained for the footer AND JSON. Deduped per class+reason.
cov_error(){ case " $_COV_SKIP_SEEN " in *" ${CURRENT_CLASS}:E:$1 "*) return 0;; esac; _COV_SKIP_SEEN="$_COV_SKIP_SEEN ${CURRENT_CLASS}:E:$1"; COV_ERRORS="$COV_ERRORS ${CURRENT_CLASS:-?}"; COV_ERR_REASONS="${COV_ERR_REASONS}${CURRENT_CLASS:-?}|$1
"; cov_record error "$1"; note "  [~] collector error/timeout: $1 -- coverage for '${CURRENT_CLASS:-?}' is PARTIAL, not complete"; }
want(){
  [ -n "$LOOT" ] && return 1                 # loot mode: skip all target-side host enumeration
  case " $CLASSES " in *" $1 "*) ;; *) CURRENT_CLASS="$1"; return 0;; esac
  [ -n "$ONLY" ] && { case ",$ONLY," in *",$1,"*) ;; *) return 1;; esac; }
  case ",$SKIP," in *",$1,"*) return 1;; esac
  CURRENT_CLASS="$1"; return 0
}

if [ -n "$OUTFILE" ]; then NOCOLOR=1; exec > >(tee "$OUTFILE") 2>&1; fi

# v2.16 COV: bounded coverage footer + interrupt-safe printing -- a stall never suppresses leads/footer.
print_leads(){
  head_ "TOP WALDO LEADS -- look here first"
  if [ "${#LEADS[@]}" -eq 0 ]; then
    info "No high-confidence privesc leads correlated. Work the [!]/[!!] lines above,"
    info "and run LinPEAS for the checks Waldo doesn't cover."
  else
    _hs=$(printf '%s\n' "${LEADS[@]}" | awk -F"$TAB" '$2 ~ /(\[doc secret\]|Flag file:|Credential store|Secrets in file|Root cron|Non-standard SUID)/' | wc -l)
    [ "${_hs:-0}" -gt 1 ] && say "  ${C_R}>> ${_hs} high-signal flag/cred/doc/privesc leads below -- CONFIRM ALL (don't action one and move on).${C_RST}"
    rank=0
    while IFS="$TAB" read -r sc ti wh fnd val scp cat cs cn pr; do
      [ -z "$sc" ] && continue
      rank=$((rank+1))
      if   [ "$sc" -ge 85 ]; then col="$C_R"; elif [ "$sc" -ge 70 ]; then col="$C_Y"; else col="$C_C"; fi
      say "  ${col}#${rank} [${sc}] ${ti}${C_RST}"
      say "       ${C_GY}why: ${wh}${C_RST}"
      [ -n "$scp" ] && say "       ${C_GY}scope: ${scp}  |  validate: ${val}${C_RST}"
      [ "$rank" -ge 15 ] && { note "...(more leads above in their sections)"; break; }
    done < <(printf '%s\n' "${LEADS[@]}" | sort -t"$TAB" -k1,1 -rn | awk -F"$TAB" '!seen[$7 FS $8 FS $9 FS $10]++')
  fi
}
print_coverage(){
  head_ "Coverage -- classes run this pass"
  local c st
  for c in $CLASSES; do
    if [ -n "$LOOT" ]; then st="skipped (loot/root mode)"
    elif want "$c"; then
      _dc=$(printf '%s\n' $COV_DENIALS | grep -c "^$c$" 2>/dev/null)
      _sk=$(printf '%s\n' $COV_SKIPS  | grep -c "^$c$" 2>/dev/null)
      _er=$(printf '%s\n' $COV_ERRORS | grep -c "^$c$" 2>/dev/null)
      if [ "$_SCAN_COMPLETED" != 1 ]; then st="partial (run interrupted before completion)"
      elif [ "${_dc:-0}" -gt 0 ] || [ "${_sk:-0}" -gt 0 ] || [ "${_er:-0}" -gt 0 ]; then
        _p=""; [ "${_dc:-0}" -gt 0 ] && _p="${_dc} denied"
        [ "${_sk:-0}" -gt 0 ] && { [ -n "$_p" ] && _p="$_p, "; _p="${_p}${_sk} skipped: tool absent"; }
        [ "${_er:-0}" -gt 0 ] && { [ -n "$_p" ] && _p="$_p, "; _p="${_p}${_er} error/timed_out"; }
        st="partial ($_p)"
        # show the retained reason(s) for error/timeout outcomes
        printf '%s\n' "$COV_ERR_REASONS" | grep "^$c|" 2>/dev/null | sed 's/^[^|]*|/        -> /'
      else st="complete"; fi
    else st="skipped (--only/--skip)"; fi
    info "  $(printf '%-11s' "$c"): $st"
  done
  note "  'complete' = every DECLARED collector in a selected class ran to its end with NO denied access, NO tool-absent skip, and NO error/timeout. [x]=access denied, [~]=could-not-run (tool absent) or errored/timed_out (distinct in JSON). A Ctrl-C or a collector over WALDO_DEADLINE marks the class partial (typed timed_out). A best-effort probe that suppresses a non-terminating error (2>/dev/null on an absent/inaccessible artifact) is a clean negative -- the correct read-only outcome -- not a hidden gap."
}
# v2.17 B2: machine-readable manifest (optional --json FILE). Renders existing leads/coverage/artifacts.
jesc(){ printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/ /g' | tr -d '\r\n'; }
lead_scope(){ case "$(lead_category "$1")" in flag) echo host-objective;; credential) echo credential-material;; network-pivot) echo segment;; privesc-*) echo host-local;; *) echo host;; esac; }
lead_category(){ case "$1" in
  *Flag*|*flag*|*[Oo]bjective*) echo flag;;
  *Secret*|*[Cc]redential*|*cred*|*VNC*|*Password*|*passwd*) echo credential;;
  *"sudo ->"*|*GTFOBins*|*SUID*|*capabilit*|*primitive*) echo privesc-primitive;;
  *Route*|*[Dd]ual-homed*|*pivot*|*segment*|*neighbour*) echo network-pivot;;
  *cron*|*service*|*sources*|*[Ww]ritable*|*unit*|*rc.local*) echo privesc-write;;
  *) echo misc;;
esac; }
print_json(){
  [ -z "$JSONOUT" ] && return 0
  local hash host user euid mode c st first sc ti wh cat i
  if [ -f "$0" ] && command -v sha256sum >/dev/null 2>&1; then hash=$(sha256sum "$0" 2>/dev/null | awk '{print $1}'); elif [ -f "$0" ]; then hash="unknown"; else hash="null"; fi
  host=$(hostname 2>/dev/null); user=$(id -un 2>/dev/null); euid=$(id -u 2>/dev/null)
  mode=$([ -n "$LOOT" ] && echo loot || echo host)
  {
    printf '{\n'
    printf '  "waldo_version": "%s",\n  "schema_version": "%s",\n  "build_date": "%s",\n' "$WALDO_VERSION" "$SCHEMA_VERSION" "$BUILD_DATE"
    printf '  "script_sha256": %s,\n  "source_mode": "%s",\n' "$([ "$hash" = null ] && echo null || printf '"%s"' "$hash")" "$([ -f "$0" ] && echo file || echo stdin)"
    printf '  "os": "linux",\n  "baseline_family": "%s",\n  "baseline_profile": "%s",\n  "baseline_confidence": "%s",\n  "host": "%s",\n  "host_id": "%s",\n  "user": "%s",\n  "euid": "%s",\n' "$(jesc "$BASELINE_FAMILY")" "$(jesc "$BASELINE_PROFILE")" "$BASELINE_CONFIDENCE" "$(jesc "$host")" "$(jesc "$( [ -r /etc/machine-id ] && cat /etc/machine-id 2>/dev/null || echo "$host" )")" "$(jesc "$user")" "$euid"
    printf '  "elevated": %s,\n  "mode": "%s",\n' "$([ "$ELEVATED" = 1 ] && echo true || echo false)" "$mode"
    printf '  "flag_state": "%s",\n' "$FLAG_STATE"
    printf '  "flag_superseded_after_reset": %s,\n' "$FLAG_SUPERSEDED"
    printf '  "flag_search_evidence": ['
    _fe_first=1; for _fe in $FLAG_SEARCH_EVIDENCE; do _fer=${_fe%%:*}; _fes=${_fe#*:}; [ "$_fe_first" = 1 ] && _fe_first=0 || printf ','; printf '{"root":"%s","status":"%s"}' "$(jesc "$_fer")" "$(jesc "$_fes")"; done
    printf '],\n'
    printf '  "coverage": {'
    first=1; for c in $CLASSES; do
      _dc=$(printf '%s\n' $COV_DENIALS | grep -c "^$c$" 2>/dev/null); _sk=$(printf '%s\n' $COV_SKIPS | grep -c "^$c$" 2>/dev/null); _er=$(printf '%s\n' $COV_ERRORS | grep -c "^$c$" 2>/dev/null)
      if [ -n "$LOOT" ]; then st=skipped; elif want "$c"; then if [ "$_SCAN_COMPLETED" != 1 ]; then st=partial; elif [ "${_dc:-0}" -gt 0 ] || [ "${_sk:-0}" -gt 0 ] || [ "${_er:-0}" -gt 0 ]; then st=partial; else st=complete; fi; else st=skipped; _dc=0; _sk=0; _er=0; fi
      _rsn=$(printf '%s\n' "$COV_ERR_REASONS" | grep "^$c|" 2>/dev/null | sed 's/^[^|]*|//' | head -1)
      [ "$st" = partial ] && [ -z "$_rsn" ] && [ "$_SCAN_COMPLETED" != 1 ] && { [ "$_INTERRUPTED" = 1 ] && _rsn="run interrupted (SIGINT) before this class completed" || _rsn="run ended before completion (deadline/error upstream)"; }
      [ "$first" = 1 ] && first=0 || printf ','; printf '"%s":{"state":"%s","denied":%d,"skipped":%d,"errors":%d,"error_reason":"%s"}' "$c" "$st" "${_dc:-0}" "${_sk:-0}" "${_er:-0}" "$(jesc "$_rsn")"
    done
    printf '},\n'
    # v0.31 COV: collector-level registry -- every recorded non-ok outcome with its {class, collector, state, reason}
    printf '  "collectors": ['
    _kf=1
    printf '%s\n' "$COV_COLLECTORS" | while IFS='|' read -r _kc _kn _ks _kr; do
      [ -z "$_kc" ] && continue
      [ "$_kf" = 1 ] && _kf=0 || printf ','
      printf '{"class":"%s","collector":"%s","state":"%s","reason":"%s"}' "$(jesc "$_kc")" "$(jesc "$_kn")" "$(jesc "$_ks")" "$(jesc "$_kr")"
    done
    printf '],\n'
    printf '  "credential_artifacts": [\n'
    _ci=0
    for _cr in "${CRED_RECORDS[@]}"; do
      # type|where|principal|secret_b64|scope|confidence|tested  (secret is REDACTED in JSON to a boolean)
      _ct=${_cr%%|*}; _cx=${_cr#*|}; _co=${_cx%%|*}; _cx=${_cx#*|}; _cp=${_cx%%|*}; _cx=${_cx#*|}; _csb=${_cx%%|*}; _cx=${_cx#*|}; _cs=${_cx%%|*}; _cx=${_cx#*|}; _cc=${_cx%%|*}
      [ "$_ci" = 0 ] && _ci=1 || printf ',\n'
      printf '    {"principal":"%s","secret_captured":%s,"type":"%s","origin":"%s","scope":"%s","confidence":"%s","tested":false}' "$(jesc "$_cp")" "$([ -n "$_csb" ] && echo true || echo false)" "$(jesc "$_ct")" "$(jesc "$_co")" "$(jesc "$_cs")" "$(jesc "$_cc")"
    done
    printf '\n  ],\n'
    # v0.42 A5: structured VNC state -- independent typed fields + signature coverage (not just prose in a lead)
    printf '  "vnc": {"role":"%s","activity":"%s","signature_coverage":{"checked":%d,"present":%d,"not_found":%d,"denied":%d},"findings":[' "$(jesc "$VNC_ROLE")" "$(jesc "$VNC_ACTIVITY")" "${VNC_SIG_CHECKED:-0}" "${VNC_SIG_PRESENT:-0}" "${VNC_SIG_NOTFOUND:-0}" "${VNC_SIG_DENIED:-0}"
    _vf1=1; printf '%s\n' "$VNC_FINDINGS" | while IFS='|' read -r _vo _vr _va _vst _vau _vas _vfm _vde; do
      [ -z "$_vo" ] && continue
      [ "$_vf1" = 1 ] && _vf1=0 || printf ','
      printf '{"origin":"%s","role":"%s","activity":"%s","stale_possible":%s,"auth_mode":"%s","artifact_state":"%s","format":"%s","decode_state":"%s"}' "$(jesc "$_vo")" "$(jesc "$_vr")" "$(jesc "$_va")" "$([ "$_vst" = true ] && echo true || echo false)" "$(jesc "$_vau")" "$(jesc "$_vas")" "$(jesc "$_vfm")" "$(jesc "$_vde")"
    done
    printf ']},\n'
    printf '  "leads": [\n'
    i=0
    _mid=$( [ -r /etc/machine-id ] && cat /etc/machine-id 2>/dev/null || echo "$host" )   # B2: stable machine identity for IDs
    while IFS="$TAB" read -r sc ti wh fnd val scp cat cs cn pr; do
      [ -z "$sc" ] && continue
      [ -n "$cat" ] || cat=$(lead_category "$ti")           # B1: use the STORED category; derive only if an old record lacks it
      [ -n "$cs" ] || cs=$(lead_locator "$ti"); [ -n "$cn" ] || cn=host; [ -n "$pr" ] || pr=$cat   # B2 canonical facts (fallback for old records)
      [ "$i" = 0 ] && i=1 || printf ',\n'
      # B2: ID derives from stable machine-id + category + CANONICAL non-secret facts (source|consumer|primitive), NOT the prose title
      _lid=$(printf '%s|%s|%s|%s|%s' "$_mid" "$cat" "$cs" "$cn" "$pr" | cksum 2>/dev/null | awk '{print $1}')
      printf '    {"id":"%s-%s-%s","score":%s,"category":"%s","canonical_source":"%s","consumer":"%s","primitive":"%s","title":"%s","finding":"%s","why":"%s","validate":"%s","scope":"%s"}' "$(jesc "$host")" "$cat" "${_lid:-0}" "$sc" "$cat" "$(jesc "$cs")" "$(jesc "$cn")" "$(jesc "$pr")" "$(jesc "$ti")" "$(jesc "${fnd:-$ti}")" "$(jesc "$wh")" "$(jesc "${val:-confirm manually}")" "$(jesc "${scp:-host}")"
    done < <(printf '%s\n' "${LEADS[@]}" | sort -t"$TAB" -k1,1 -rn | awk -F"$TAB" '!seen[$7 FS $8 FS $9 FS $10]++')
    printf '\n  ]\n}\n'
  } > "$JSONOUT" 2>/dev/null
  note "JSON manifest -> $JSONOUT ($(wc -c < "$JSONOUT" 2>/dev/null) bytes)"
}
_FOOTER_DONE=0; _SCAN_COMPLETED=0; _BG=""; _INTERRUPTED=0
print_footer(){ [ "$_FOOTER_DONE" = 1 ] && return 0; _FOOTER_DONE=1; print_leads; print_coverage; print_json; }
# v0.40 interruption model (PTY-verified -- real Ctrl-C during a bounded collector yields the footer + JSON, exit 130,
#  and NO temp artifact because run_bounded uses a coproc pipe, not a file):
#  Bounded collectors run inside a COPROC that the parent drains with `read`. `read` is reliably interruptible, so
#  Ctrl-C fires the INT trap (whereas a command-substitution `$(...)` collector could get the shell KILLED with no
#  footer). `finalize` kills the in-flight collector and renders the footer exactly once (idempotent guard); INT/TERM
#  finalize then exit 130; EXIT finalizes as the catch-all. Ignoring INT/TERM inside finalize protects the footer's
#  own subprocesses (sort/awk/cksum) from a repeat Ctrl-C.
finalize(){ trap '' INT TERM; [ -n "$_BG" ] && kill "$_BG" 2>/dev/null; _BG=""; print_footer; }
trap 'finalize' EXIT
trap '_INTERRUPTED=1; finalize; exit 130' INT TERM
WALDO_DEADLINE="${WALDO_DEADLINE:-90}"; _DEADLINE_OK=1
case "$WALDO_DEADLINE" in ''|*[!0-9]*) WALDO_DEADLINE=90;; esac   # validate deadline input (positive integer seconds)
command -v timeout >/dev/null 2>&1 || _DEADLINE_OK=0
# run_bounded VAR CMD...: run CMD (soft-deadline bounded) and capture its stdout into VAR. Returns CMD's status;
# 124 = timed_out. Deadline-unavailable when 'timeout' is absent -> runs UNBOUNDED (caller records via _DEADLINE_OK).
# v0.40: capture through a COPROC PIPE, NOT a temp file -- so (a) the release "explicit-output-only" invariant holds
# with zero implicit target writes, and (b) an interrupt cannot leave a stray capture file behind. `read` blocks
# interruptibly, so a real Ctrl-C still reaches the INT trap (a command-substitution `$(...)` collector could get the
# shell KILLED first); on EOF we `wait` the producer for its true status. finalize kills _BG if still in flight.
run_bounded(){ local __v="$1"; shift; local __data="" __rc=0 __rfd
  if [ "$_DEADLINE_OK" = 1 ]; then coproc _RB { timeout "$WALDO_DEADLINE" "$@" 2>/dev/null; }
  else coproc _RB { "$@" 2>/dev/null; }; fi
  _BG=$_RB_PID; __rfd=${_RB[0]}
  IFS= read -r -d '' __data <&"$__rfd" 2>/dev/null   # drain the whole stream (interruptible); EOF ends it
  exec {__rfd}<&- 2>/dev/null                         # close our read end so the coproc name frees for reuse
  wait "$_BG" 2>/dev/null; __rc=$?; _BG=""
  printf -v "$__v" '%s' "$__data"; return "$__rc"; }
[ -t 1 ] || NOCOLOR=1
[ -n "$NO_COLOR" ] && NOCOLOR=1
TAB="$(printf '\t')"

# Elevation detection. As root, "[ -w ]" is trivially true for almost everything and is
# NOT a privesc finding -- so we suppress writable-based leads. The elevated pass is for
# post-exploitation COLLECTION; the low-priv pass is authoritative. (--lowpriv forces on.)
# Use /proc/self/status Uid: real eff saved fsuid -- an euid/suid/fsuid of 0 is elevated
# even when the REAL uid is still 1000 (e.g. after a SUID-root shell / PATH-hijack).
_ruid=$(id -ru 2>/dev/null); _euid=$(id -u 2>/dev/null)
_uidline=$(grep -E '^Uid:' /proc/self/status 2>/dev/null)
_suid=$(printf '%s' "$_uidline" | awk '{print $4}'); _fsuid=$(printf '%s' "$_uidline" | awk '{print $5}')
UIDCTX="ruid=${_ruid:-?} euid=${_euid:-?} suid=${_suid:-?} fsuid=${_fsuid:-?}"
if { [ "${_euid:-1000}" = 0 ] || [ "${_suid:-1000}" = 0 ] || [ "${_fsuid:-1000}" = 0 ]; } && [ "$LOWPRIV" != 1 ]; then ELEVATED=1; else ELEVATED=0; fi
# writability gate: false when elevated so writable-escalation false positives are suppressed
iswrite(){ [ "$ELEVATED" = 1 ] && return 1; [ -w "$1" ]; }
# operator-artifact detection -- files WE (the operator) dropped during exploitation.
OPERATOR_RE='(^|/)(waldo|waldo[_-].*\.(txt|log)|lin(peas|enum)|winpeas|peass?|chisel|ligolo|socat|ncat|netcat|nc|RunasCs|PrintSpoofer|GodPotato|JuicyPotato|SweetPotato|rootbash|rootshell|proofshell|jdwp_relay|revshell|reverse|payload|meterpreter|mimikatz|rubeus|certipy|sharphound|secretsdump|procdump|nanodump|dump[_-]?hives|gp\.(exe|bat)|linux-exploit|shell\.(sh|elf|bin)|sh$|bash$|dash$|rbash$)'
is_operator(){ [ -n "$LOOT" ] && return 1; case "$1" in /tmp/*|/var/tmp/*|/dev/shm/*|*/Downloads/*|*/Desktop/*) printf '%s' "$1" | grep -qiE "$OPERATOR_RE";; *) return 1;; esac; }

# Flagged-binary registry: discovery sections (SUID, services, processes, custom exes) record
# basenames here; history/log mining cross-references them so a known anomaly's USAGE (with any
# args) is surfaced unfiltered. Discovery runs BEFORE history; a final pass reconciles late flags.
FLAGGED_BINS=" "
DB_CRED_HINT=""    # config files where a DB-shaped credential was seen
DB_SUDO=""         # v2.18 C1: DB clients permitted via sudo (psql/mysql) -- part of a DB->root chain
DB_LISTENER=""     # local DB listener ports observed (correlate -> "mine the DB manually")
add_flagged_bin(){ local _b; _b=$(basename -- "$1" 2>/dev/null); [ -n "$_b" ] && case "$FLAGGED_BINS" in *" $_b "*) ;; *) FLAGGED_BINS="$FLAGGED_BINS$_b ";; esac; }
is_flagged_bin(){ case "$FLAGGED_BINS" in *" $1 "*) return 0;; esac; return 1; }
HIST_BUF=""   # buffered "sourcefile<TAB>line" from histories/logs for end-of-run reconciliation
buf_hist(){ HIST_BUF="${HIST_BUF}$1${TAB}$2
"; }
# positional-arg secret heuristic: does a command line invoke a local exe/script followed by a
# high-entropy token (>=8 chars, mixed letters+digits, not a path/flag/common word)?
positional_token(){
  printf '%s' "$1" | grep -oE '(\./|/)?[A-Za-z0-9_.-]+\.(exe|sh|bat|cmd|ps1|py|pl|bin) +[^ ]{8,}' | \
    grep -oE '[^ ]{8,}$' | grep -E '[A-Za-z]' | grep -E '[0-9]' | grep -vqE '^(-|/|password|username|localhost|[0-9.]+$)' && return 0
  return 1
}
# Read a shell-history file: print capped content, and flag (a) any line invoking an
# already-flagged binary -- UNFILTERED, all args -- and (b) local-tool + positional-token creds.
analyze_history(){
  local hf="$1" hu="$2" hl tok tb hit
  [ -f "$hf" ] && [ -r "$hf" ] || return
  sub "history: $hf ($hu)"
  [ "$NOCONTENT" = 1 ] || tail -n 60 "$hf" 2>/dev/null | while IFS= read -r hl; do [ -n "$hl" ] && note "  $(printf '%.180s' "$hl")"; done
  add_cred 'shell history (readable -- review for reused creds/commands)' "$hf"
  while IFS= read -r hl; do
    [ -z "$hl" ] && continue
    buf_hist "$hf" "$hl"
    hit=''
    for tok in $hl; do case "$tok" in */*) tb=$(basename -- "$tok");; *) tb="$tok";; esac; is_flagged_bin "$tb" && { hit="$tb"; break; }; done
    if [ -n "$hit" ]; then
      jack "history runs flagged tool '$hit': $(printf '%.200s' "$hl")"
      add_lead 90 "History runs flagged tool '$hit'" "$hl  ::  a previously-flagged custom binary is invoked -- ANY argument (incl. a positional password) is high-signal. Manual review."
      add_cred '[history-credential] flagged-tool usage' "$hf: $(printf '%.120s' "$hl")"
    elif positional_token "$hl"; then
      jack "history: local tool + high-entropy positional arg: $(printf '%.200s' "$hl")"
      add_lead 82 "Positional credential in history: $hf" "$hl  ::  a local exe/script invoked with a password-shaped positional token. Manual review."
      add_cred '[history-credential] positional token' "$hf: $(printf '%.120s' "$hl")"
    fi
  done < "$hf"
}
# Wildcard-command analysis: a root command using '*' whose expansion dir is writable is an
# option-injection candidate (classic tar --checkpoint-action). No exploit run.
analyze_wildcard(){
  local cl="$1" ctx="$2" wdir
  case "$cl" in *tar\ *\**|*rsync\ *\**|*chown\ *\**|*chmod\ *\**|*' cp '*\**|*' mv '*\**|*7z\ *\**|*zip\ *\**|*run-parts*|*'find '*-exec*) ;; *) return;; esac
  printf '%s' "$cl" | grep -qE '(^| )[^ ]*\*' || return
  wdir=$(printf '%s' "$cl" | grep -oE 'cd +[^ ;&]+' | head -n1 | sed 's/^cd *//')
  [ -z "$wdir" ] && wdir=$(printf '%s' "$cl" | grep -oE '/[A-Za-z0-9_./-]+/' | head -n1)
  if [ -n "$wdir" ] && [ -d "$wdir" ] && iswrite "$wdir"; then
    case "$cl" in
      *tar\ *) jack "$ctx: tar wildcard over WRITABLE $wdir -> --checkpoint-action injection candidate"; add_lead 95 "Root tar wildcard over writable dir $wdir" "$cl  ::  tar expands '*' from a dir you can write -- drop '--checkpoint=1 --checkpoint-action=exec=sh <script>' filenames for root code exec. Manual review (no exploit run)." "" "" "" "" "$wdir" "writable-dir" "tar-wildcard-injection";;
      *) jack "$ctx: wildcard command over WRITABLE $wdir -> option-injection candidate"; add_lead 90 "Root wildcard command over writable dir $wdir" "$cl  ::  '*' expands from a writable dir -- possible option/argument injection. Manual review." "" "" "" "" "$wdir" "writable-dir" "wildcard-injection";;
    esac
  elif [ -n "$wdir" ]; then
    waldo "$ctx: wildcard command references $wdir (writability unknown/denied) -- $(printf '%.120s' "$cl")"
  fi
}
# LOOT MODE: offline triage of an already-pulled loot directory (TFTP/SMB/FTP/web). Enumeration-only --
# reads files you already have, no target interaction. Inventories non-empty configs & greps secrets.
run_loot(){
  local root="$1" f n=0 hits=0
  [ -d "$root" ] || { echo "loot dir not found: $root" >&2; return 1; }
  head_ "LOOT TRIAGE: $root  (offline inventory of pulled files)"
  info "Enumeration-only: reading already-pulled files; no target interaction."
  while IFS= read -r f; do
    [ -f "$f" ] && [ -r "$f" ] && [ -s "$f" ] || continue
    n=$((n+1))
    if printf '%s' "$f" | grep -qE "$INTERESTING_RE|$EXEC_RE"; then
      report "$f" "loot"; hits=$((hits+1))
    elif grep -IiqE "$SECRET_RE" "$f" 2>/dev/null; then
      waldo "loot (secret in oddly-named file): $f"; peek "$f"; hits=$((hits+1))
    fi
  done < <(find "$root" -type f 2>/dev/null | head -n 4000)
  info "loot files inventoried: $n ; interesting/secret-bearing: $hits"
  # auto-detect: is this a full filesystem ROOT (mounted share)? point at the structured sweep
  if [ -e "$root/Windows/System32" ] || _ci_path "$root" Windows System32 >/dev/null 2>&1 || [ -e "$root/etc/passwd" ]; then
    jack "this looks like a full filesystem ROOT (mounted share), not a pile of pulled files."
    info "  -> re-run with  --root '$root'  for the structured crown-jewel sweep (hives/RegBack/Windows.old, flags, per-user creds) instead of this blind recurse."
  fi
}

# case-insensitive path resolution (an SMB/NTFS mount may present WINDOWS or windows)
_ci(){ local parent="$1" name="$2" m; [ -d "$parent" ] || return 1
  if [ -e "$parent/$name" ]; then printf '%s' "$parent/$name"; return 0; fi
  m=$(ls -1a "$parent" 2>/dev/null | grep -ixF -- "$name" | head -n1); [ -n "$m" ] && { printf '%s' "$parent/$m"; return 0; }; return 1; }
_ci_path(){ local p="$1" s; shift; for s in "$@"; do p=$(_ci "$p" "$s") || return 1; done; printf '%s' "$p"; }

# ROOT TRIAGE: point Waldo at a MOUNTED target filesystem root (Windows share via mount -t cifs //host/C /mnt/c,
# or Linux / ). Re-roots the crown-jewel intelligence. Enumeration-only: reads over the mount, writes nothing.
run_root(){
  local root="${1%/}"
  [ -d "$root" ] || { echo "root not found: $root" >&2; return 1; }
  if _ci_path "$root" Windows System32 >/dev/null 2>&1; then _root_windows "$root"; return; fi
  if [ -e "$root/etc/passwd" ] || [ -e "$root/etc/shadow" ]; then _root_linux "$root"; return; fi
  head_ "ROOT TRIAGE: $root"
  info "No recognizable Windows (Windows/System32) or Linux (etc/passwd) tree here -- falling back to generic loot recurse."
  run_loot "$root"
}
_root_windows(){
  local root="$1" writable=0 gothive=0 cfg regback wold ntds users ud f d h hp lab pair users pd ip s sn=0 wr cand wroots=""
  head_ "ROOT TRIAGE (mounted WINDOWS share): $root"
  info "Enumeration-only: reading the REMOTE box's C: over the mount, writing nothing. No shell/root on the TARGET needed."
  iswrite "$root" && writable=1
  [ "$writable" = 1 ] && { jack "the mounted share is WRITABLE -> drop-to-execute targets flagged below (Waldo places nothing)"; add_lead 82 "Writable mounted Windows share: $root" "Share is writable -- re-rooted Startup/service/task paths become drop-to-execute. Manual review (Waldo writes nothing)."; }
  sub "Registry hives (readable = offline secretsdump; live SAM/SYSTEM lock, use RegBack/Windows.old)"
  cfg=$(_ci_path "$root" Windows System32 config); regback=$(_ci_path "$root" Windows System32 config RegBack); wold=$(_ci_path "$root" Windows.old Windows System32 config)
  for pair in "${cfg}|live" "${regback}|RegBack (often unlocked)" "${wold}|Windows.old (unlocked)"; do
    d=${pair%%|*}; lab=${pair#*|}; [ -n "$d" ] && [ -d "$d" ] || continue
    for h in SAM SYSTEM SECURITY SOFTWARE; do
      hp=$(_ci "$d" "$h") || continue
      if head -c1 "$hp" >/dev/null 2>&1; then jack "READABLE hive: $hp  [$lab]"; add_cred "registry hive ($lab)" "$hp"; case "$h" in SAM|SYSTEM|SECURITY) gothive=1;; esac
      else note "hive present but LOCKED: $hp -- try RegBack/Windows.old/VSS"; fi
    done
  done
  if [ "$gothive" = 1 ]; then add_lead 95 "Registry hives readable on the share" "SAM+SYSTEM(+SECURITY) readable over the mount -> secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL (offline). LSA often holds domain/service creds. No cracking needed to pass-the-hash. Manual review." "" "" "" "" "share-registry-hives" "mounted-share" "offline-hash-dump"
  else info "No readable SAM/SYSTEM/SECURITY set (live hives lock even over SMB -- RegBack/Windows.old/VSS are the unlocked options)."; fi
  ntds=$(_ci_path "$root" Windows NTDS ntds.dit)
  [ -n "$ntds" ] && head -c1 "$ntds" >/dev/null 2>&1 && { jack "READABLE ntds.dit: $ntds"; add_lead 98 "NTDS.dit readable (DC disk shared)" "ntds.dit + SYSTEM hive = full DOMAIN hash dump offline (secretsdump -ntds ntds.dit -system SYSTEM LOCAL). Manual review." "" "" "" "" "share-ntds-dit" "mounted-share" "domain-hash-dump"; add_cred 'NTDS.dit (domain hashes, offline)' "$ntds"; }
  users=$(_ci_path "$root" Users)
  if [ -n "$users" ]; then
    sub "Flags on user desktops (incl. Administrator's, unreadable from a shell)"
    while IFS= read -r f; do [ -n "$f" ] && { jack "FLAG: $f"; add_lead 90 "Flag readable on share: $f" "Objective readable over the MOUNT -- this is a mounted copy, NOT submission proof: reopen it on the ORIGINAL target in an interactive shell (cat/type) with identity + IP context."; }; done < <(find "$users" -maxdepth 3 -type f 2>/dev/null | grep -iE '/desktop/(proof|local|flag|root|user)\.txt$')
    sub "Per-user artifacts (.ssh / history / saved sessions / vaults / NTUSER.DAT)"
    while IFS= read -r ud; do
      while IFS= read -r f; do report "$f" "root-user"; done < <(find "$ud" -maxdepth 6 -type f \( -iname 'id_rsa' -o -iname 'id_ed25519' -o -iname 'id_dsa' -o -iname 'ConsoleHost_history.txt' -o -iname 'WinSCP.ini' -o -iname 'sitemanager.xml' -o -iname 'recentservers.xml' -o -iname 'NTUSER.DAT' -o -iname '*.kdbx' -o -iname '*.rdp' -o -iname '*.ppk' -o -iname '*.pem' -o -iname 'Login Data' \) 2>/dev/null | head -n 30)
    done < <(find "$users" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
  fi
  sub "Provisioning / answer files"
  while IFS= read -r f; do report "$f" "root-prov"; done < <(find "$root" -maxdepth 4 -type f \( -iname 'unattend.xml' -o -iname 'autounattend.xml' -o -iname 'sysprep.xml' -o -iname 'setupact.log' \) 2>/dev/null | head -n 20)
  sub "Web app roots & configs"
  for cand in inetpub xampp wamp wamp64 laragon www wwwroot; do d=$(_ci "$root" "$cand"); [ -n "$d" ] && wroots="$wroots $d"; done
  for wr in $wroots; do
    while IFS= read -r f; do report "$f" "root-web"; done < <(find "$wr" -maxdepth 5 -type f \( -iname 'web.config' -o -iname 'wp-config.php' -o -iname 'configuration.php' -o -iname 'config.php' -o -iname 'database.php' -o -iname 'settings.php' -o -iname '.env' -o -iname 'appsettings*.json' \) 2>/dev/null | head -n 40)
  done
  if [ "$writable" = 1 ] && [ -n "$users" ]; then
    sub "Writable Startup drop-targets (share writable -> logon code-exec)"
    while IFS= read -r d; do iswrite "$d" && { jack "WRITABLE Startup: $d"; add_lead 86 "Writable Startup on share: $d" "You can write a Startup folder over the mount -- a dropped exe/lnk runs at that user's next logon (as them). Manual review (Waldo drops nothing)."; }; done < <(find "$users" -maxdepth 5 -type d 2>/dev/null | grep -iE '/start menu/programs/startup$')
  fi
  sub "Bounded secret sweep (Users / ProgramData / inetpub -- skips Windows/ noise)"
  pd=$(_ci "$root" ProgramData); ip=$(_ci "$root" inetpub)
  for s in "$users" "$pd" "$ip"; do
    [ -n "$s" ] && [ -d "$s" ] || continue
    while IFS= read -r f; do report "$f" "root-sweep"; sn=$((sn+1)); done < <(find "$s" -maxdepth 5 -type f -size -5M 2>/dev/null | grep -iE '\.(txt|xml|ini|conf|config|cfg|php|json|ya?ml|env|ps1|bat|cmd|kdbx|rdp|ppk|pem|key)$' | head -n 400)
  done
  info "root triage complete ($sn high-value files swept). Confirm/pull manually -- Waldo touched nothing."
}
_root_linux(){
  local root="$1" f s sn=0
  head_ "ROOT TRIAGE (mounted LINUX filesystem): $root"
  info "Enumeration-only. Light pass (full Linux root parity ships later): shadow/keys/flags/configs."
  for f in "$root/etc/shadow" "$root/etc/master.passwd" "$root/etc/passwd"; do
    [ -f "$f" ] && head -c1 "$f" >/dev/null 2>&1 && { jack "READABLE: $f"; case "$f" in *shadow|*master.passwd) add_lead 95 "Readable hash store on the mount: $f" "Password hashes readable over the mount -> crack offline.";; esac; add_cred "unix cred store" "$f"; }
  done
  while IFS= read -r f; do jack "FLAG: $f"; add_lead 90 "Flag on mount: $f" "Objective readable over the MOUNT -- mounted copy, NOT submission proof: reopen it on the ORIGINAL target in an interactive shell (cat/type) with identity + IP context."; done < <(find "$root/root" "$root/home" -maxdepth 3 -type f 2>/dev/null | grep -iE '/(proof|local|flag|user|root)\.txt$')
  while IFS= read -r f; do report "$f" "root-user"; done < <(find "$root/home" "$root/root" -maxdepth 4 -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '.bash_history' -o -name '.mysql_history' -o -name '*.kdbx' -o -name 'authorized_keys' \) 2>/dev/null | head -n 40)
  for s in "$root/home" "$root/etc" "$root/opt" "$root/srv" "$root/var/www"; do
    [ -d "$s" ] || continue
    while IFS= read -r f; do report "$f" "root-sweep"; sn=$((sn+1)); done < <(find "$s" -maxdepth 5 -type f -size -5M 2>/dev/null | grep -iE '\.(sh|php|conf|cfg|config|ini|env|ya?ml|json|xml|txt|sql|key|pem|kdbx)$|/(id_rsa|\.bash_history|\.my\.cnf|\.pgpass|shadow)$' | head -n 300)
  done
  info "linux root triage (light) complete ($sn files). Full parity ships next."
}
# No-mount shopping list: WHERE to look on a shared-out C:\ (Waldo makes NO connection -- a path list only).
share_hints(){
  head_ "Shared-C: shopping list (NO mount needed -- smbclient/nxc GET these first)"
  info "You see a share exposing C:\\ but have no shell. Pull these over SMB, then triage locally. Waldo makes NO connection."
  printf '%s\n' \
"  hives (unlocked copies -> secretsdump LOCAL, no cracking for pass-the-hash):" \
"    Windows/System32/config/RegBack/{SAM,SYSTEM,SECURITY}" \
"    Windows.old/Windows/System32/config/{SAM,SYSTEM,SECURITY}" \
"  flags:   Users/*/Desktop/proof.txt   Users/*/Desktop/local.txt" \
"  per-user creds:" \
"    Users/*/.ssh/id_rsa" \
"    Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt" \
"    Users/*/AppData/Roaming/WinSCP.ini      Users/*/NTUSER.DAT  (offline DPAPI)" \
"  provisioning/web:" \
"    unattend.xml   autounattend.xml   Windows/Panther/Unattend.xml" \
"    inetpub/wwwroot/web.config   xampp/htdocs/**/config*.php   **/wp-config.php" \
"" \
"  pull examples:" \
"    smbclient //TARGET/SHARE -N -c 'recurse ON; prompt OFF; mget \"Windows\\System32\\config\\RegBack\"'" \
"    nxc smb TARGET -u USER -p PASS --get-file 'Users\\Administrator\\Desktop\\proof.txt' proof.txt" \
"  then:   ./waldo.sh --root ./pulled      (or --loot ./pulled)"
}

# =====================================================================
#  BASELINES -- what "standard" looks like. Governed, versioned data (see spec §4.1) -- NOT ad-hoc per-box edits.
# =====================================================================
STD_ROOT="bin sbin lib lib32 lib64 libx32 usr etc var home root opt srv tmp boot dev proc sys run mnt media snap lost+found initrd.img initrd.img.old vmlinuz vmlinuz.old cdrom swapfile swap.img"

# v0.49 §4.1: the GENERIC set is the EMPIRICAL cross-image INTERSECTION of ALL captured pristine base-image SUID
# manifests (debian:12, ubuntu:22.04/24.04, rockylinux:9, almalinux:9, oraclelinux:9 -- pinned digests in
# tests/suid_manifests/). Only these five are setuid-root on EVERY captured base. NOTE captured differences: passwd is
# NOT setuid on almalinux:9, and chfn/chsh are Debian/Ubuntu-only, so they are NOT generic. Everything else (chage,
# unix_chkpwd, pam_timestamp_check, userhelper, passwd, and all package SUIDs like sudo/pkexec/fusermount3) SURFACES on
# an unknown box and is added back ONLY by a matched, captured per-build delta below.
STD_SUID="gpasswd mount newgrp su umount"

STD_PORTS="22 25 53 68 111 631"

# App/web roots worth a deep look when present (incl. BSD /usr/local/*).
APP_ROOTS="/opt /srv /var/www /var/www/html /usr/local/bin /usr/local/sbin /usr/local/www /usr/local/etc /usr/local/apache2 /usr/local/apache24 /home/www /app /data /transfer /backup"

INTERESTING_RE='\.(sh|py|pl|rb|php|inc|conf|cfg|config|inf|ini|env|ya?ml|toml|json|xml|txt|md|csv|log|bak|old|sql|key|pem|ppk|pfx|p12|jks|keystore|gpg|kdbx|kdb|psafe3|opvault|agilekeychain|walletx|vnc|ovpn|db|sqlite|sqlite3|properties|htpasswd|docx|xlsx|pptx|doc|xls|pdf|zip|7z|rar|tar|gz|tgz)$|(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|\.netrc|\.pgpass|\.my\.cnf|\.npmrc|\.pypirc|\.dockercfg|\.git-credentials|shadow|master\.passwd|credentials|logins\.json|key4\.db|signons\.sqlite|confCons\.xml|wp-config\.php|config\.php|configuration\.php|database\.php|settings\.py|web\.config|local\.settings\.json|\.env)$'
EXEC_RE='\.(sh|py|pl|rb|php|elf|bin|jar)$'

# Secret grep: assignment-style key<sep>value (allowing quotes/=> for PHP/web configs),
# PHP define('KEY_PASS','val'), private keys, AWS keys, and $hash$ shadow format.
# arms: (a) assignment key<sep>value  (b) XML element <secretname>value</  (c) PHP define  (d) private keys/AWS/$hash$
SECRET_RE='(pass(word)?|passwd|pwd|secret|cred(ential)?s?|api[_-]?key|access[_-]?key|secret[_-]?key|token|connection ?string|db_pass|validationKey|decryptionKey|machineKey|auth[_-]?info|reg_identity|realm|registrar|sip_domain)[^[:alnum:]]{0,2}(=>|[:=])[[:space:]]*[^[:space:],;]+|<(pass(word)?|passwd|user(name)?|secret|token|auth([_-]?info)?|realm|registrar|proxy|api[_-]?key|sip_domain|reg_identity)[^>]*>[^<]+<|define\([^)]*(pass|pwd|secret|key|token)[^)]*,[[:space:]]*[^)]+|-----BEGIN ([A-Z]+ )?PRIVATE KEY|AKIA[0-9A-Z]{16}|:[$][0-9a-z][$]'

MAX_PEEK_KB=400
MAX_PEEK_LINES=6
ZONE_FILE_CAP=60

# =====================================================================
#  OUTPUT
# =====================================================================
if [ "$NOCOLOR" = 1 ]; then
  C_RST=""; C_Y=""; C_R=""; C_GY=""; C_C=""; C_M=""; C_DY=""
else
  C_RST=$'\033[0m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_GY=$'\033[90m'
  C_C=$'\033[36m'; C_M=$'\033[35m'; C_DY=$'\033[33;2m'
fi
say(){  printf '%s\n' "$1"; }   # %s not %b: color vars already hold real ESC bytes, and content (e.g. C:\Users) must stay literal
head_(){ CURRENT_COLLECTOR="(class-level)"; say ""; say "${C_M}[*] === $1 ===${C_RST}"; }   # class header resets collector attribution until a sub() names one
sub(){   CURRENT_COLLECTOR="$1"; say "    ${C_C}-- $1${C_RST}"; }   # each sub-section IS a collector (COV registry attribution)
waldo(){ say "  ${C_Y}[!]  $1${C_RST}"; }
jack(){  say "  ${C_R}[!!] $1${C_RST}"; }
denied(){ say "  ${C_GY}[x]  $1${C_RST}"; COV_DENIALS="$COV_DENIALS ${CURRENT_CLASS:-?}"; cov_record denied "$1"; }
info(){  say "  ${C_C}[i]  $1${C_RST}"; }
note(){  say "       ${C_GY}$1${C_RST}"; }

have(){ command -v "$1" >/dev/null 2>&1; }
in_list(){ case " $2 " in *" $1 "*) return 0;; esac; return 1; }

# =====================================================================
#  LEAD ENGINE -- correlated, scored, ranked at the end.
#  NB: lead-raising loops MUST run in the current shell (use  < <(...)  not
#  a pipe), or array appends are lost to the subshell.
# =====================================================================
LEADS=()
# v0.15 B1: lead record carries score|title|why|finding|validate|scope. 3-arg calls default the extra fields;
# collectors MAY pass a distinct raw finding ($4), a bounded validate step ($5), and an explicit scope ($6).
# v0.24 B1: category is a STORED field ($7 supplied by the collector when known, else derived ONCE here) -- not re-derived at render.
# v0.32 B2: extract a STABLE, NON-SECRET locator (canonical_source) from a title -- the path/key/identifier after the
# last ': ' (or the whole title), with secret shapes redacted. IDs derive from canonical facts, not the prose, so
# rewording a title does not change a lead's ID.
# v0.44 B2: derive a STABLE non-secret locator. Prefer the explicit locator after the last ': '; for a no-colon title
# extract the most stable embedded token (an absolute path, else a quoted 'name') so rewording the surrounding prose
# does NOT change the ID. Fall back to the whole title only when neither exists. (High-signal leads pass explicit facts.)
lead_locator(){ _ll="$1"
  case "$_ll" in
    *": "*) _ll="${_ll##*: }";;
    *) # v0.48 §2: only a REAL absolute path (space/start-anchored, >=2 segments) -- NOT a lone slash in prose
       # ("creds/flag" must NOT become "/flag"). Else a quoted token. Else the whole title (an unstable last resort
       # that a scored lead should avoid by passing explicit facts).
       _p=$(printf '%s' " $_ll" | grep -oE '[[:space:]]/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+' | head -1 | sed 's/^[[:space:]]*//')
       if [ -n "$_p" ]; then _ll="$_p"
       else _q=$(printf '%s' "$_ll" | grep -oE "'[^']+'|\"[^\"]+\"" | head -1 | tr -d "'\""); [ -n "$_q" ] && _ll="$_q"; fi ;;
  esac
  redact_for_id "$_ll"; }
# fields: score TAB title TAB why TAB finding TAB validate TAB scope TAB category TAB canonical_source TAB consumer TAB primitive
# ($8 canonical_source, $9 consumer, $10 primitive) -- collectors MAY supply them; else derive (source=locator, consumer=class, primitive=category).
add_lead(){ LEADS+=("$1${TAB}$2${TAB}$3${TAB}${4:-$2}${TAB}${5:-confirm manually before acting; Waldo took no action}${TAB}${6:-$(lead_scope "$2")}${TAB}${7:-$(lead_category "$2")}${TAB}${8:-$(lead_locator "$2")}${TAB}${9:-${CURRENT_CLASS:-host}}${TAB}${10:-$(lead_category "$2")}"); }
# v0.24 B2: strip secret-shaped content from a string BEFORE deriving a stable ID (IDs must never be secret-derived).
# Redact secret-shaped content AND the value after a known short-secret LABEL (community string, passcode, pin, otp, ...),
# so even a short value like 'public' never reaches the ID hash. (Rare: two same-type leads with different secret values
# collapse to one ID -- acceptable vs. leaking; full canonical-field IDs are the deeper remaining item.)
redact_for_id(){ printf '%s' "$1" | sed -E 's/(pass(word)?|pwd|secret|token|api[_-]?key|community|passcode|otp|credential)[^:=]{0,24}[:=][[:space:]]*[^[:space:]]+/\1 <redacted>/Ig; s/[A-Fa-f0-9]{16,}/<hex>/g; s/[A-Za-z0-9+/]{24,}={0,2}/<b64>/g'; }

# Credential-artifact rollup -- a clean handoff list (NO spraying/testing performed).
CRED_ARTIFACTS=(); CRED_RECORDS=()
# v0.42 A5: structured VNC state for JSON (independent typed fields + signature coverage), not just prose in a lead.
VNC_FINDINGS=""; VNC_ROLE=unknown; VNC_ACTIVITY=unknown; VNC_SIG_CHECKED=0; VNC_SIG_PRESENT=0; VNC_SIG_NOTFOUND=0; VNC_SIG_DENIED=0
# v0.15 A11: scope a credential artifact by its type (strict default -- no cross-product, no validation advice).
cred_scope(){ case "$1" in
  *machine?account*|*computer?account*|*'HOST$'*|*'$@'*|*'NT AUTHORITY\SYSTEM'*) echo "machine-account (non-interactive; authenticates as the COMPUTER on the network, not a user logon)";;
  *NTDS*|*domain*|*Domain*|*DA*)                          echo "domain-principal (exact; subject to logon restrictions)";;
  *SSH*|*ssh*|*key*|*shadow*|*SAM*|*hive*|*local*)        echo "origin-host-only";;
  *browser*|*Chrome*|*chrome*|*Firefox*|*firefox*|*login?data*|*vault*|*keepass*|*kdbx*|*WinSCP*|*FileZilla*|*PuTTY*|*RDP*|*rdp*) echo "origin-service-only (bound to the EXACT stored host/service; not portable elsewhere)";;
  *DB*|*db*|*SQL*|*sql*|*postgres*|*mysql*|*Froxlor*)     echo "origin-service-only";;
  *SNMP*|*SIP*|*sip*|*proxy*|*API*|*token*|*VNC*|*app*)   echo "origin-service-only";;
  *provision*|*cloudbase*)                                echo "origin-host-only (until image-reuse evidence)";;
  *)                                                      echo "unknown (do not test until corroborated)";;
esac; }
# v0.24 A11: retain the ACTUAL principal/secret pair when Waldo extracted one ($3=principal, $4=secret);
# confidence reflects what was captured. CRED_RECORDS = type|where|principal|secret_captured|scope|confidence|tested.
add_cred(){ local _sc _cf _pr="${3:-}" _se="${4:-}" _sb=""; _sc=$(cred_scope "$1")
  # v0.32 A11: RETAIN the intact pair internally -- store the secret base64-encoded (so '|' can't corrupt the record).
  # It is shown in the human handoff rollup but REDACTED to a boolean in JSON (never emit secret values in safe output).
  [ -n "$_se" ] && _sb=$(printf '%s' "$_se" | base64 2>/dev/null | tr -d '\n')
  if [ -n "$_se" ] && [ -n "$_pr" ]; then _cf=captured-pair; elif [ -n "$_se" ]; then _cf=secret-observed; elif [ -n "$_pr" ]; then _cf=principal-observed; else _cf=located; fi
  CRED_ARTIFACTS+=("[$1]  $2  {principal=${_pr:-?}; secret=$([ -n "$_se" ] && printf '%s' "$_se" || echo '(none captured)'); scope=$_sc; confidence=$_cf; tested=false}")
  CRED_RECORDS+=("$1|$2|$_pr|$_sb|$_sc|$_cf|false"); }
# v0.15 A8: surface an INLINE credential in a command line / ExecStart / cron action (conservative; placeholders filtered).
# Complements the file-content secret scan -- covers secrets embedded in EXECUTION config, not just env/registry/files.
_INLINE_SEEN=""
scan_inline_cred(){ # $1=text  $2=source-label
  [ -n "$1" ] || return 0
  _hit=$(printf '%s' "$1" | grep -oiE '(password|passwd|--pass|pwd)[[:space:]:=]+[^[:space:];,]{4,}|(api[_-]?key|client[_-]?secret|secret|token|access[_-]?key)[[:space:]:=]+[A-Za-z0-9+/_.-]{8,}' | head -1)
  [ -z "$_hit" ] && _hit=$(printf '%s' "$1" | grep -oE '(-P|/P|/RP)[[:space:]]+[^[:space:];,]*[A-Za-z][^[:space:];,]{3,}' | head -1)
  [ -z "$_hit" ] && return 0
  case "$_hit" in *'%'*|*'$('*|*'${'*|*'<'*|*xxxx*|*changeme*|*placeholder*|*example*) return 0;; esac
  case " $_INLINE_SEEN " in *" $_hit "*) return 0;; esac; _INLINE_SEEN="$_INLINE_SEEN $_hit"
  jack "inline credential in $2 : $_hit"
  add_lead 84 "Inline credential in $2" "An execution-config value exposes an inline secret ($2): '$_hit'. Preserve the EXACT principal/secret pair with this origin; do NOT recombine across sources. Manual review -- Waldo does not test it." "" "" "" "" "$2" "execution-config" "inline-credential"
  _iprin=$(printf '%s' "$1" | grep -oiE '(user[ _]?id|username|uid)[[:space:]]*[:=][[:space:]]*"?[^[:space:]";,]+' | head -1 | sed -E 's/.*[:=][[:space:]]*"?//')
  add_cred "inline credential ($2)" "$2" "$_iprin" "$_hit"
}
# Classify a secret sample by hash/cred type so the handoff says HOW to use it.
classify_secret(){
  case "$1" in
    *'$DCC2$'*)      echo 'DCC2 (crack-only)';;
    *'$krb5tgs$'*)   echo 'Kerberoast TGS (crack-only)';;
    *'$krb5asrep$'*) echo 'AS-REP (crack-only)';;
    *'$2a$'*|*'$2b$'*|*'$2y$'*) echo 'bcrypt (crack-only)';;
    *'$6$'*|*'$5$'*|*'$1$'*)    echo 'unix crypt (crack-only)';;
    *) if printf '%s' "$1" | grep -qE '[a-fA-F0-9]{32}:[a-fA-F0-9]{32}|:[a-fA-F0-9]{32}:::'; then echo 'NTLM (pass-the-hash OR crack)'; else echo 'possible cleartext (scope=unknown, tested=false -- do not reuse until corroborated)'; fi;;
  esac
}

# Pull candidate script/binary paths out of a command line (cron/unit ExecStart).
extract_targets(){
  printf '%s' "$1" | grep -oE '/[A-Za-z0-9_.@/+-]+' | sort -u
}

# v2.16 A3: follow ONE level of sourced/called scripts inside a privileged, readable-but-unwritable
# script; a writable include is a root-code-exec chain. Never executes anything. (Process-sub keeps
# add_lead in the current shell.)
follow_sourced(){
  local parent="$1" ctx="$2" inc d n=0
  [ -r "$parent" ] || return 0
  while IFS= read -r inc; do
    [ -z "$inc" ] && continue
    n=$((n+1)); [ "$n" -gt 12 ] && break                              # cap children per parent
    case "$inc" in /*) ;; *) inc="$(dirname "$parent")/$inc";; esac   # resolve same-dir / relative includes
    [ "$inc" = "$parent" ] && continue                                # simple loop guard
    if [ -e "$inc" ] && iswrite "$inc"; then
      jack "$ctx: root-run $parent sources/calls WRITABLE $inc"
      add_lead 95 "Root script sources a writable helper: $inc" "$ctx runs $parent (root-owned/unwritable) which sources/calls WRITABLE $inc -- append your payload to the included file for root code exec. Manual review (Waldo executes nothing)."
    else
      d=$(dirname "$inc")
      if [ ! -e "$inc" ] && [ -d "$d" ] && iswrite "$d"; then
        jack "$ctx: root-run $parent calls MISSING $inc in WRITABLE dir $d"
        add_lead 90 "Root script calls a missing include in a writable dir: $inc" "$ctx runs $parent which includes/calls $inc (absent) but its directory $d is writable -- create it for root code exec. Manual review."
      elif [ -e "$inc" ] && [ -d "$d" ] && iswrite "$d"; then
        # v0.15 A3: child exists and is NOT writable, but its PARENT DIR is -- you may be able to replace it (create/rename over)
        jack "$ctx: root-run $parent calls $inc (not writable) but its DIR $d is WRITABLE"
        add_lead 85 "Root helper replaceable via writable dir: $inc (dir $d)" "$ctx runs $parent which sources/calls $inc -- the file itself is not writable, but its directory $d is, so you may be able to replace it (create a new file and rename over it) for root code exec. Confirm you can unlink/recreate in $d. Manual review."
      fi
    fi
  done < <( { grep -oE '^[[:space:]]*(\.|source)[[:space:]]+[^[:space:];&|<>]+' "$parent" 2>/dev/null | sed -E 's/^[[:space:]]*(\.|source)[[:space:]]+//';
              grep -oE '(^|[[:space:]])(bash|sh|dash|ksh|zsh|python[0-9.]*|perl|ruby|php)[[:space:]]+[^-][^[:space:];&|<>]*' "$parent" 2>/dev/null | sed -E 's/.*(bash|sh|dash|ksh|zsh|python[0-9.]*|perl|ruby|php)[[:space:]]+//';
              grep -oE '(^|[[:space:]])\.{1,2}/[^[:space:];&|<>]+' "$parent" 2>/dev/null | sed -E 's/^[[:space:]]*//';
              # A3: a plain static ABSOLUTE child command invoked in command position (line start or after ; && || ` $( )
              grep -oE '(^[[:space:]]*|;[[:space:]]*|&&[[:space:]]*|\|\|[[:space:]]*|`|\$\([[:space:]]*)/(usr|opt|srv|home|tmp|var|bin|sbin|etc)/[A-Za-z0-9._/-]+' "$parent" 2>/dev/null | sed -E 's#^[^/]*/#/#'; } | sort -u )
}

# v2.16 A5b: decode a reversible VNC secret (fixed-key DES). Key {23,82,107,6,35,78,88,7} bit-reversed = e84ad660c4721ae0.
# Uses openssl (DES-ECB); degrades gracefully if openssl is unavailable. KAT-validated (see waldo/tests/vnc_kat.ps1).
_OSSL_LEGACY=""
if have openssl; then printf '' | openssl enc -des-ecb -nopad -K 0000000000000000 -provider legacy -provider default >/dev/null 2>&1 && _OSSL_LEGACY="-provider legacy -provider default"; fi
vnc_decode_block(){  # $1 = file, $2 = byte offset (0 or 8) -> decoded printable plaintext (or empty)
  have openssl || { cov_skip "openssl absent: VNC/secret DES decode not run (pull the blob and decode offline)"; return 1; }
  dd if="$1" bs=1 skip="$2" count=8 2>/dev/null | openssl enc -d -des-ecb -nopad -K e84ad660c4721ae0 $_OSSL_LEGACY 2>/dev/null | tr -d '\000' | tr -cd '[:print:]'
}

# v0.15 C3: compute the network address for a.b.c.d[/prefix] from the actual prefix (default /24 when absent).
ip_net(){
  local ip="${1%/*}" pfx o1 o2 o3 o4 rest ipnum mask n
  case "$1" in */*) pfx="${1#*/}";; *) pfx=24;; esac
  o1=${ip%%.*}; rest=${ip#*.}; o2=${rest%%.*}; rest=${rest#*.}; o3=${rest%%.*}; o4=${rest##*.}
  case "$o1$o2$o3$o4" in *[!0-9]*|'') return 1;; esac
  ipnum=$(( (o1<<24)|(o2<<16)|(o3<<8)|o4 ))
  if [ "$pfx" -ge 32 ] 2>/dev/null; then mask=4294967295; elif [ "$pfx" -le 0 ] 2>/dev/null; then mask=0; else mask=$(( 4294967295 ^ ((1<<(32-pfx))-1) )); fi
  n=$(( ipnum & mask ))
  printf '%d.%d.%d.%d/%d\n' $(( (n>>24)&255 )) $(( (n>>16)&255 )) $(( (n>>8)&255 )) $(( n&255 )) "$pfx"
}

# v0.15 C3: is IP $1 inside network CIDR $2 (a.b.c.d/pfx)? Uses the NETWORK's real prefix -- no /24 assumption
# (so a neighbour 10.10.5.3 is correctly seen as inside an attached 10.10.0.0/16).
ip_in_net(){ case "$2" in */*) ;; *) return 1;; esac; [ "$(ip_net "$1/${2#*/}")" = "$(ip_net "$2")" ]; }

# C1 local role evidence: echo a matched privileged DB-role token from a config file, else empty.
# Gates the DB->root chain on LOCAL evidence the credential is a superuser/sa, not just a listener.
db_priv_role(){
  [ -r "$1" ] || return 0
  # Skip comment lines; require the privileged role as a bounded VALUE (not a prefix like admin_readonly), and require
  # a superuser/sysadmin ATTRIBUTE to be positively enabled (superuser=true), so 'superuser=false' / a comment never counts.
  grep -hvE '^[[:space:]]*(#|;|--)' "$1" 2>/dev/null | grep -hoiE '(user[ _]?id|username|uid|user|role)[[:space:]]*[:=][[:space:]]*"?(sa|root|postgres|superuser|sysadmin)"?([^A-Za-z0-9_]|$)|(is[_ ]?)?(superuser|sysadmin)[[:space:]]*[:=][[:space:]]*(true|yes|on|1)([^A-Za-z0-9_]|$)' | head -1
}

# cheap per-type text extraction from a flagged office/pdf doc (no admin/Office needed).
# docx/xlsx/pptx are zips -> read the text XML parts & strip tags. pdf -> pdftotext else strings.
extract_doc_text(){
  local f="$1" ext sz
  sz=$(wc -c < "$f" 2>/dev/null || echo 0); [ "${sz:-0}" -gt 8388608 ] && return
  ext=$(printf '%s' "$f" | grep -oiE '\.[a-z0-9]+$' | tr 'A-Z' 'a-z')
  case "$ext" in
    .docx|.xlsx|.pptx)
      have unzip || { cov_skip "unzip absent: office-doc (docx/xlsx/pptx) text extraction not run"; return; }
      unzip -p "$f" 'word/document.xml' 'xl/sharedStrings.xml' 'ppt/slides/slide*.xml' 'docProps/core.xml' 2>/dev/null | sed -E 's/<[^>]+>/ /g; s/[[:space:]]+/ /g'
      ;;
    .pdf)
      if have pdftotext; then pdftotext "$f" - 2>/dev/null; else strings -n 5 "$f" 2>/dev/null; fi
      ;;
  esac
}

# Grep a file for secrets. Prints hits, returns 0 if any found (and leads).
peek(){
  [ "$NOCONTENT" = 1 ] && return 1
  local f="$1"
  [ -f "$f" ] && [ -r "$f" ] || return 1
  # operator artifact (our own tool/output, incl. waldo's own source) -- don't grep its contents as "creds"
  if is_operator "$f" && [ "$SHOW_OPERATOR" != 1 ]; then note "operator artifact (content peek skipped): $f"; return 1; fi
  # office/pdf docs -- Waldo already flagged the file; extract text & grep it
  case "$f" in
    *.docx|*.DOCX|*.xlsx|*.XLSX|*.pptx|*.PPTX|*.pdf|*.PDF)
      local dt; dt=$(extract_doc_text "$f")
      [ -z "$dt" ] && return 1
      printf '%s' "$dt" | grep -qiE "$SECRET_RE" || return 1
      sub "doc text extracted: $f"
      printf '%s' "$dt" | grep -oiE "$SECRET_RE" | head -n "$MAX_PEEK_LINES" | while IFS= read -r m; do say "         ${C_R}> doc secret? $(printf '%.160s' "$m")${C_RST}"; done
      add_lead 86 "[doc secret] $f" "Text extracted from a flagged document contains credential-shaped content -- read the file. Manual review." "" "" "" "" "$f" "filesystem" "document-secret"
      add_cred "[doc secret]" "$f"
      return 0
      ;;
  esac
  local kb; kb=$(( $(wc -c < "$f" 2>/dev/null || echo 0) / 1024 ))
  [ "$kb" -gt "$MAX_PEEK_KB" ] && return 1
  grep -IiqE "$SECRET_RE" "$f" 2>/dev/null || return 1
  local sample; sample=$(grep -IinE "$SECRET_RE" "$f" 2>/dev/null | head -n "$MAX_PEEK_LINES")
  printf '%s\n' "$sample" | while IFS= read -r line; do
    [ -z "$line" ] && continue; line=$(printf '%.180s' "$line"); say "         ${C_R}> creds? ${line}${C_RST}"
  done
  case "$f" in *.log) return 0;; esac
  # DB-credential hint (for the "you have creds + a local DB" correlation)
  printf '%s %s' "$f" "$sample" | grep -qiE 'db_pass|database|mysql|postgre|pgsql|mssql|jdbc|data source|connection ?string|wp-config|configuration\.php' && DB_CRED_HINT="$DB_CRED_HINT $f"
  local ctype; ctype=$(classify_secret "$sample")
  # context-aware scoring: a commented stock /etc example must not outrank a real custom-root secret.
  local score=70 tag='' noncomment
  noncomment=$(printf '%s\n' "$sample" | sed -E 's/^[0-9]+://' | grep -cvE '^\s*(#|;|//|\*|/\*|$)')
  if is_operator "$f"; then
    score=40; tag='[operator] '
  elif printf '%s' "$sample" | grep -qiE '(=>|[:=])[[:space:]]*["'"'"']?(changeme|change_me|password|passwd|secret|example|foo|bar|test|xxx+|placeholder|yourpassword)["'"'"']?[[:space:]]*$'; then
    score=45; tag='[placeholder] '
  else case "$f" in
    /etc/*|/usr/share/*|/usr/lib/*|/snap/*|/usr/local/lib/*)
      if [ "${noncomment:-0}" -eq 0 ]; then score=45; tag='[commented-example] '; else score=58; tag='[stock-config] '; fi;;
    /opt/*|/srv/*|/var/www/*|/home/*|/usr/local/www/*|/app/*|/data/*|/transfer/*|/backup/*|/tmp/*)
      score=85; tag='[custom-root] ';;
    *) score=70;;
  esac; fi
  # high-signal filenames float regardless of dir
  case "$f" in *wp-config.php|*configuration.php|*database.php|*.env|*web.config|*.my.cnf|*.pgpass|*id_rsa|*.ppk|*.kdbx|*.ovpn|*unattend.xml) [ "$score" -lt 78 ] && score=78;; esac
  if [ "$tag" = '[operator] ' ] && [ "$SHOW_OPERATOR" != 1 ]; then
    note "operator artifact (secret grep): $f  [capped -- --show-operator-leads to rank]"
  fi
  add_lead "$score" "${tag}Secrets in file: $f" "Grep hit credential-shaped lines -- type: $ctype. Manual review." "" "" "" "" "$f" "filesystem" "file-secret"
  add_cred "$ctype" "$f"
  return 0
}

# Report a path, flag by writability, then peek if a file.
report(){
  local p="$1" label="$2" tag
  tag="${label:+$label -> }$p"
  if iswrite "$p"; then jack "$tag   [WRITABLE by you]"
  elif [ ! -r "$p" ] && [ ! -x "$p" ]; then denied "$tag   [no access]"
  else waldo "$tag"; fi
  if [ -f "$p" ]; then peek "$p"; fi
  # v0.15 A6: credential-SEMANTIC basename -- surface regardless of content grammar (outside stock/template paths)
  if [ -f "$p" ] && printf '%s' "$(basename -- "$p")" | grep -qiE '^(credentials?|creds|passwords?|secrets?|logins?|accounts?)\.(txt|md|csv|ini|cfg|conf|ya?ml|json|xlsx?|docx?|pptx?|ods|odt|kdbx?)$'; then
    case "$p" in */[Ss]amples/*|*/[Ee]xamples/*|*/[Tt]emplates/*) ;; *)
      jack "credential-named file: $p"
      add_lead 86 "[credential-named] $p" "Filename is credential-semantic ($(basename -- "$p")) -- read it regardless of format (lines like 'HOST: value' carry creds and won't match a password= regex). Manual review." "" "" "" "" "$p" "filesystem" "credential-named-file"
      add_cred 'credential-named file (review)' "$p" ;;
    esac
  fi
}

# Deep look at a directory: surface scripts/configs, flag writable, peek text.
scan_zone(){
  local root="$1" label="$2" count=0 f ext
  [ -d "$root" ] || return
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if printf '%s' "$f" | grep -qE "$INTERESTING_RE|$EXEC_RE"; then :; else continue; fi
    if [ "$count" -ge "$ZONE_FILE_CAP" ]; then note "   ...(zone scan capped at $ZONE_FILE_CAP files in $root)"; break; fi
    count=$((count+1))
    if iswrite "$f"; then
      jack "$label $f   [WRITABLE]"
      add_lead 68 "Writable file in custom/app path: $f" "This file under $root is writable by you -- possible code-execution condition if a privileged process runs/sources it. Manual review."
      printf '%s' "$f" | grep -qE "$EXEC_RE|\.(exe|jar)$" && add_flagged_bin "$f"
    elif printf '%s' "$f" | grep -qE "$EXEC_RE"; then
      waldo "$label script: $f"; add_flagged_bin "$f"
    else
      waldo "$label $f"
    fi
    [ "$NOCONTENT" = 1 ] || { printf '%s' "$f" | grep -qE "$INTERESTING_RE" && peek "$f"; }
  done < <(find "$root" -maxdepth 4 -type f 2>/dev/null)
}

# =====================================================================
#  BANNER
# =====================================================================
say ""
say "${C_DY}          .---------------------------------------.${C_RST}"
say "${C_Y}          |  W H E R E ' S   W A L D O ?  (Linux)  |${C_RST}"
say "${C_DY}          '---------------------------------------'${C_RST}"
say "${C_GY}   Enumeration by anomaly. Read-only. Correlates anomalies into ranked leads.${C_RST}"
say "${C_GY}   Legend: [!]=nonstandard  [!!]=nonstandard+WRITABLE  [x]=denied  [i]=info${C_RST}"
say "${C_GY}   lab-safe: enumeration-only local triage. Does NOT exploit, modify services/${C_RST}"
say "${C_GY}   tasks, write payloads, brute force, scan the network, or validate CVEs. Every${C_RST}"
say "${C_GY}   finding is a local observation that requires manual verification.${C_RST}"
if [ "$ELEVATED" = 1 ]; then
  say ""
  say "${C_R}   *** MODE: ELEVATED ($UIDCTX) -- writable-escalation findings SUPPRESSED ***${C_RST}"
  say "${C_R}   (writability is trivially true as root). This pass = post-exploitation collection${C_RST}"
  say "${C_R}   & visibility (all users' keys/history/creds, shadow, previously-denied areas).${C_RST}"
  say "${C_R}   Re-run as the LOW-PRIV user for authoritative privesc findings. (--lowpriv overrides.)${C_RST}"
else
  say "${C_GY}   MODE: standard user -- writable checks active (authoritative for privesc).${C_RST}"
fi

# LOOT / ROOT / SHARE-HINTS short-circuit: triage, then jump to the ranked summaries.
[ "$SHARE_HINTS" = 1 ] && { share_hints; [ -z "$ROOT" ] && exit 0; }
if [ -n "$ROOT" ]; then run_root "$ROOT"; elif [ -n "$LOOT" ]; then run_loot "$LOOT"; fi

# =====================================================================
#  0. HOST FACTS + CURRENT CONTEXT
# =====================================================================
if [ -z "$LOOT" ]; then
head_ "Host & current context"
info "Host   : $(hostname 2>/dev/null)"
info "Kernel : $(uname -a 2>/dev/null)"
[ -r /etc/os-release ] && info "Distro : $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
# v0.15 §4.1: baseline family SELECTION + honest confidence. Detecting the family is not enough -- we must SELECT the
# family-specific standard set so the subtraction is calibrated; confidence only reaches 'high' when a profile is applied.
BASELINE_FAMILY="unknown"; BASELINE_CONFIDENCE="low"; BASELINE_PROFILE="generic"
_bvers=""
if [ -r /etc/os-release ]; then
  _bid=$(. /etc/os-release 2>/dev/null; printf '%s %s' "${ID:-}" "${VERSION_ID%%.*}")
  case "$_bid" in ' '|'') ;; *[A-Za-z]*) BASELINE_FAMILY=$(printf '%s' "$_bid" | tr -s ' ');; esac
  _bvers=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID%%.*}")
fi
_bfam=$(printf '%s' "$BASELINE_FAMILY" | awk '{print tolower($1)}')
# v0.44 §4.1: REVIEWED per-version stock SUID tables. baseline_stock_suid() returns the authoritative default SUID
# basename set for a specific reviewed OS build. When the detected id+major matches a reviewed row, that set is
# unioned into the stock set and confidence rises to 'high' (we know EXACTLY what ships, so an extra SUID is a
# definite anomaly and no stock item false-flags). Non-reviewed families keep the CONSERVATIVE GENERIC base at
# 'family-detected'; unknown builds fall back 'low'. Optional-package SUIDs remain visible unless a reviewed table
# lists them for that build. Tables are validated by per-family stock-negative fixtures (tests/fixtures.sh).
baseline_stock_suid(){ # $1=family $2=major  -> the per-build DELTA over the generic intersection, from a CAPTURED
  # pristine base-image SUID manifest (tests/suid_manifests/*.txt, each pinned to an image digest). generic ∪ delta
  # EXACTLY equals that captured manifest (fixtures assert EQUALITY, not subset). These are the MINIMAL base-image
  # flavors; a box with extra packages (sudo, pkexec, ...) will show those as non-stock -- by design, since they are
  # not in the pinned reference. Because these reflect a base image rather than every deployed flavor, they are used
  # for RANKING context only and do NOT elevate confidence to 'high' (see the confidence block).
  # v0.49 §4.1 (auditor fix): a delta is returned ONLY for a family+major with its OWN captured, digest-pinned manifest
  # (generic ∪ delta EXACTLY equals that image's SUID set). Families WITHOUT a captured image (rhel-9, centos-9 -- not
  # freely pullable) return "" -> conservative generic fallback (family-detected), never a borrowed delta. The EL9
  # derivatives are NOT identical -- rocky ships 'userhelper', alma lacks 'passwd' AND 'userhelper', oracle lacks
  # 'userhelper' -- so each carries its own delta from its own manifest.
  case "$1-$2" in
    debian-12|ubuntu-22|ubuntu-24) echo "chfn chsh passwd" ;;                          # + generic = debian:12/ubuntu base
    rocky-9)                       echo "chage pam_timestamp_check passwd unix_chkpwd userhelper" ;;  # rockylinux:9
    almalinux-9)                   echo "chage pam_timestamp_check unix_chkpwd" ;;      # almalinux:9 (no passwd, no userhelper)
    ol-9)                          echo "chage pam_timestamp_check passwd unix_chkpwd" ;;             # oraclelinux:9 (no userhelper)
    *) echo "" ;;
  esac
}
_rev_suid=$(baseline_stock_suid "$_bfam" "$_bvers")
if [ -n "$_rev_suid" ]; then
  # v0.48 §4.1: a captured base-image delta matched. Union it for a tighter subtraction, BUT keep confidence at
  # 'family-detected' -- the manifest is a pinned MINIMAL base image, not every deployed flavor, so we do NOT claim
  # 'high' / 'no false-flags' (a real box with sudo/pkexec/... will legitimately show those, by design).
  STD_SUID="$STD_SUID $_rev_suid"
  BASELINE_PROFILE="${_bfam}-${_bvers} (base-image SUID manifest applied -- ranking context; extra-package SUIDs still surface)"
  BASELINE_CONFIDENCE="family-detected"
else
  case "$_bfam" in
    debian|ubuntu|kali|raspbian|linuxmint|pop|devuan)      BASELINE_PROFILE="debian-family (generic base stock; optional-package SUIDs NOT subtracted)"; BASELINE_CONFIDENCE="family-detected";;
    rhel|centos|fedora|rocky|almalinux|ol|amzn|scientific) BASELINE_PROFILE="rhel-family (generic base stock; optional-package SUIDs NOT subtracted)"; BASELINE_CONFIDENCE="family-detected";;
    arch|manjaro|endeavouros)                              BASELINE_PROFILE="arch-family (generic base stock)"; BASELINE_CONFIDENCE="family-detected";;
    suse|opensuse*|sles)                                   BASELINE_PROFILE="suse-family (generic base stock)"; BASELINE_CONFIDENCE="family-detected";;
    alpine)                                                BASELINE_PROFILE="alpine-family (busybox -- minimal SUID)"; BASELINE_CONFIDENCE="family-detected";;
    '')  BASELINE_PROFILE="generic (family unknown)"; BASELINE_CONFIDENCE="low";;
    *)   BASELINE_PROFILE="generic (family '$_bfam' detected, no specialized profile)"; BASELINE_CONFIDENCE="detected-generic";;
  esac
fi
info "Baseline : family=$BASELINE_FAMILY profile=$BASELINE_PROFILE confidence=$BASELINE_CONFIDENCE"
case "$BASELINE_CONFIDENCE" in
  low)               info "         (unknown family -- CONSERVATIVE GENERIC base stock only; 'non-standard' flags may include family-stock items -- read with caution)";;
  detected-generic)  info "         (family known but no profile -- 'non-standard' flags may include this distro's stock items; verify against a clean box)";;
  family-detected)   info "         (family used for RANKING context only; the GENERIC base-stock set is subtracted and OPTIONAL-package SUIDs are NOT -- an unexpected mount.nfs/Xorg/etc. still surfaces; 'high' is reserved for a fixture-validated per-version stock table)";;
  high)              info "         (REVIEWED per-version stock table for this exact build applied -- the default SUID set is known, so any EXTRA SUID is a definite anomaly and no stock item false-flags)";;
esac
info "You    : $(id 2>/dev/null)"
if [ "${_ruid:-0}" != "${_euid:-0}" ] || [ "${_fsuid:-$_euid}" != "${_euid:-0}" ]; then
  info "UIDs   : $UIDCTX  <- real/effective differ (SUID-root context: effective privilege is what matters)"
fi
sub "sudo -l (non-interactive; blank = no cached creds / not allowed)"
# Binaries with a documented GTFOBins sudo->root path. Interpreting sudo -l is the win.
# v2.16 A1/A2: capability taxonomy -- rank shell > write > read; annotate read-only primitives.
GTFO_BINS="vim vi view rvim nano pico ed less more most man find awk gawk sed perl python python2 python3 ruby lua tar zip unzip gzip bzip2 bash sh dash zsh ksh csh env printenv nmap docker lxc ctr runc systemctl service journalctl mount umount make cmake gdb ftp tftp socat nc ncat wget curl fetch scp ssh sftp git rsync borg cpulimit ionice nohup timeout xargs flock taskset watch tee dd cp install mv chmod chown chroot apt apt-get dpkg yum dnf rpm snap pip pip3 gem node npm mysql mysqldump psql sqlite3 tmux screen byobu ansible-playbook emacs crontab at strace ltrace busybox php base64 openssl xxd zip7 7z tar bsdtar cpio pkexec ip ss nsenter unshare capsh setpriv cat tac nl head tail od hexdump base32 basenc strings truncate"
# Primitive class for a matched binary: shell (best) > write > read (weakest). Default = shell.
# v0.42 A1: authoritative per-binary taxonomy. Each row stores class|score|caveat matched to the binary's ACTUAL
# documented sudo primitive (shell = arbitrary command exec, write = controlled root write, read = arbitrary read).
# An unlisted/unknown binary defaults to REVIEW (no proven primitive registered) -- never a blind shell assertion.
gtfo_class(){ case "$1" in
    # --- SHELL: the sudo invocation yields arbitrary command execution / a root shell ---
    bash|sh|dash|zsh|ksh|csh|busybox)              echo "shell|96|spawns a root shell directly";;
    ip)                                            echo "shell|96|ip netns add + netns exec <ns> <shell> -> root shell";;
    nsenter|unshare|capsh|setpriv|chroot)          echo "shell|96|namespace/privilege helper -> root shell";;
    pkexec)                                        echo "shell|96|pkexec runs the target program as root";;
    docker|lxc|ctr|runc)                           echo "shell|96|container runtime -> host root (privileged exec / host mount)";;
    find)                                          echo "shell|95|find -exec <cmd> \; -> root command exec";;
    vim|vi|view|rvim|emacs)                        echo "shell|95|editor shell escape (:!cmd / -c / --eval) -> root command exec";;
    perl|python|python2|python3|ruby|lua|php|node) echo "shell|95|interpreter os.system/exec -> root command exec";;
    env|nohup|timeout|xargs|flock|taskset|watch|cpulimit|ionice) echo "shell|94|wrapper executes an arbitrary command as root";;
    awk|gawk)                                      echo "shell|94|awk BEGIN{system(\"...\")} -> root command exec";;
    gdb)                                           echo "shell|94|gdb -ex '!cmd' / python -> root command exec";;
    systemctl|service)                             echo "shell|94|unit ExecStart / pager -> root command exec";;
    less|more|most|man)                            echo "shell|93|pager shell escape (!cmd) -> root command exec";;
    socat|nc|ncat)                                 echo "shell|93|EXEC/-e <shell> -> root command exec";;
    tar|bsdtar)                                    echo "shell|93|tar --checkpoint-action=exec=<cmd> -> root command exec";;
    tmux|screen|byobu)                             echo "shell|92|multiplexer new-window/command -> root shell";;
    sed)                                           echo "shell|92|GNU sed 'e' command -> root command exec";;
    make|cmake)                                    echo "shell|92|make -f - with a shell recipe -> root command exec";;
    apt|apt-get)                                   echo "shell|92|APT::Update::Pre-Invoke / dpkg::Pre-Invoke -> root command exec";;
    ed|nano|pico)                                  echo "shell|90|editor command/escape -> root command exec (build-dependent)";;
    ssh|scp|sftp)                                  echo "shell|90|ssh -oProxyCommand / scp -S <cmd> -> root command exec";;
    rsync)                                         echo "shell|90|rsync -e/--rsh <cmd> -> root command exec";;
    git)                                           echo "shell|90|git -c core.pager / hooks / -p PAGER -> root command exec";;
    strace|ltrace)                                 echo "shell|90|strace -f <cmd> runs an arbitrary command as root";;
    ansible-playbook)                              echo "shell|90|ansible shell/command module -> root command exec";;
    yum|dnf)                                       echo "shell|90|package-manager plugin/spec -> root command exec";;
    ftp|tftp)                                      echo "shell|88|ftp '!cmd' -> root command exec";;
    nmap)                                          echo "shell|88|nmap --interactive/--script (legacy) -> root command exec";;
    crontab|at)                                    echo "shell|88|scheduled job body runs as root";;
    journalctl)                                    echo "shell|88|pager shell escape (!cmd) -> root command exec";;
    mysql|psql|sqlite3)                            echo "shell|88|db client shell escape (\\\\! / .shell / os cmd) -> root command exec";;
    snap)                                          echo "shell|88|malicious snap install hook -> root command exec";;
    zip)                                           echo "shell|84|zip -T -TT '<cmd>' (test command) -> root command exec";;
    gem|pip|pip3)                                  echo "shell|84|package build hook (setup.py/extconf.rb) -> root command exec";;
    dpkg|rpm)                                      echo "shell|84|package pager / maintainer script -> root command exec";;
    npm)                                           echo "shell|84|npm preinstall script -> root command exec";;
    # --- WRITE: controlled root file write/modify (needs a privileged target/consumer) ---
    tee|dd|cp|install|mv|xxd|truncate)             echo "write|90|controlled root file write/modify -- needs a privileged target";;
    chmod|chown)                                   echo "write|90|change perms/owner of a target as root -> privesc";;
    cpio)                                          echo "write|86|cpio -i extract into a privileged path -> controlled root write";;
    openssl)                                       echo "write|82|openssl enc -in/-out reads and writes files as root (engine .so can exec)";;
    wget|curl|fetch)                               echo "write|82|writes (-o/-O) or reads (file://) a root path; wget --use-askpass can exec -- confirm the exact flags";;
    unzip)                                         echo "write|82|unzip extracts into a privileged path -> controlled root write";;
    # --- READ: arbitrary root file read (empty output does NOT prove an absent file) ---
    cat|tac|nl|head|tail|base32|base64|basenc|od|hexdump|strings)  echo "read|82|reads an arbitrary file as root -- empty output does NOT prove an absent file";;
    ss)                                            echo "read|82|ss -F <file> filter-file read -- empty output does NOT prove an absent file";;
    mysqldump)                                     echo "read|80|dumps the DB / reads files as root";;
    gzip|bzip2|borg|7z|zip7)                       echo "read|78|compress/extract a privileged path (read/write, no direct shell) -- confirm target";;
    mount|umount)                                  echo "read|76|mount/bind exposes a privileged path (no direct sudo shell primitive)";;
    printenv)                                      echo "read|72|reads the root environment only";;
    # --- UNKNOWN: no authoritative rule -> MANUAL capability review, NO proven primitive registered ---
    *)                                             echo "review|70|MANUAL capability review -- no authoritative primitive rule for this binary; check GTFOBins for the exact sudo technique before asserting shell/write/read";;
  esac; }
# v0.15 A4: register a local privilege PRIMITIVE from ANY source (sudo GTFObin, SUID, capability, root cron, writable
# service) so the C5 denied-objective->primitive relationship and the elevation note cite a SPECIFIC primitive, not
# just sudo. First writer per class wins (keeps the earliest concrete citation). class = shell|write|read.
reg_prim(){ case "$1" in shell) ROOT_PRIM_SHELL="${ROOT_PRIM_SHELL:-$2}";; write) ROOT_PRIM_WRITE="${ROOT_PRIM_WRITE:-$2}";; read) ROOT_PRIM_READ="${ROOT_PRIM_READ:-$2}";; esac; }
# v0.15 A1: a sudo GTFObin capability applies only to the PERMITTED invocation. Classify the argument constraint:
# any = bare binary (any args -> full capability); wildcard = fixed prefix + '*'; pinned = fixed args; noargs = "".
# In sudoers, a command with NO args permits ANY args; a command WITH fixed args requires an exact match (wildcards
# allowed) -- so a pinned/noargs rule usually BLOCKS the standard GTFObin technique (which needs its own arguments).
sudo_arg_mode(){ # $1=rule line  $2=binary name (lowercased)
  _after=$(printf '%s' "$1" | sed -E "s#^.*[ /]${2}([ ].*)?\$#\1#I")
  [ "$_after" = "$1" ] && { echo any; return; }            # sed did not reduce -> could not parse -> assume any (never downgrade blindly)
  _after=$(printf '%s' "$_after" | sed -E 's/^[[:space:]]+//')
  case "$_after" in
    '""'|"''") echo noargs;;
    '') echo any;;
    *'*'*) echo wildcard;;
    *) echo pinned;;
  esac
}
if have sudo; then
  _alt=$(printf '%s' "$GTFO_BINS" | tr ' ' '|')
  while IFS= read -r l; do
    [ -z "$l" ] && continue
    jack "$l"
    hitbin=$(printf '%s' "$l" | grep -woiE "($_alt)" | head -n1)
    danger=""
    case "$l" in *--rsh*|*" -e "*|*--checkpoint-action*|*-exec*|*--eval*|*ProxyCommand*|*LD_PRELOAD*|*PYTHONPATH*) danger=" [dangerous option -> command/arg injection]";; esac
    case "$l" in *SETENV*|*env_keep*) danger="$danger [SETENV/env_keep -> LD_PRELOAD/PYTHONPATH abuse]";; esac
    if [ -n "$hitbin" ]; then
      _lc=$(printf '%s' "$hitbin" | tr 'A-Z' 'a-z')
      _ci=$(gtfo_class "$_lc"); _cls=${_ci%%|*}; _rest=${_ci#*|}; _scr=${_rest%%|*}; _adv=${_rest#*|}
      _warn=""; [ "$_cls" = read ] && _warn=" [read-only: absence of output != absence of file]"
      # v0.15 A1: argument-aware. A pinned rule blocks a SHELL technique (it needs its own exec args), but a READ/WRITE
      # primitive still operates ON the pinned target (e.g. `ss -F <file>` IS the read primitive). Only shell downgrades;
      # a wildcard is a CANDIDATE (does not prove the pattern permits the technique) and is NOT registered as proven.
      _amode=$(sudo_arg_mode "$l" "$_lc"); _argnote=""; _reg=0
      [ -n "$danger" ] && _reg=1
      if [ -n "$danger" ]; then :
      else
        case "$_cls" in
          shell)
            case "$_amode" in
              any) _reg=1;;
              wildcard) _argnote=" (ARG WILDCARD: fixed prefix + '*' -- CANDIDATE: assess whether the allowed pattern permits the shell technique; not counted as a proven primitive)";;
              pinned|noargs) [ "$_scr" -gt 55 ] && _scr=55; _argnote=" (ARG-CONSTRAINED [$_amode]: pins arguments -- the standard shell GTFObin invocation likely does NOT apply; assess THIS exact arg set)";;
            esac;;
          read|write)
            _reg=1   # the primitive acts on whatever target the rule allows -- pinning constrains the target, it does not disable the primitive
            case "$_amode" in
              any) ;;
              wildcard) _argnote=" (the $_cls primitive applies within the allowed '*' pattern)";;
              pinned|noargs) _argnote=" (constrained: the $_cls primitive operates on the PINNED target/pattern only -- still usable within that constraint)";;
            esac;;
          review)
            # v0.42 A1: no authoritative rule -> a manual-review CANDIDATE, never a proven primitive (never reg_prim).
            _reg=0; _argnote=" (no authoritative primitive rule -- assess the exact invocation manually; not counted as a proven shell/write/read)";;
        esac
      fi
      add_lead "$_scr" "sudo -> $hitbin (GTFOBins/$_cls${_argnote:+; $_amode})$danger$_warn" "$l  ::  $_adv.$_argnote$danger" "" "" "" "" "sudo:$hitbin" "sudo-gtfobin" "gtfo-$_cls"
      [ "$_reg" = 1 ] && reg_prim "$_cls" "sudo $hitbin ($l)"
      case "$_lc" in psql|mysql|mysqldump) DB_SUDO="$DB_SUDO $_lc";; esac
    else
      case "$l" in *NOPASSWD*|*"(ALL"*|*"(root)"*) add_lead 90 "sudo -> manual capability review: $l" "Runs as root, but this binary is NOT in the known primitive table -- do NOT assume a shell/write/read primitive. Manually assess whether the permitted invocation (note any pinned arguments) yields command exec, a file write, or a file read; check GTFObins for this exact binary. Manual review.";; esac
    fi
  done < <(sudo -n -l 2>/dev/null | grep -vE '^\s*$')
fi
# doas (OpenBSD & minimal Linux) -- the sudo alternative people forget to check
for _dc in /etc/doas.conf /usr/local/etc/doas.conf; do
  [ -r "$_dc" ] || continue
  sub "doas config: $_dc"
  while IFS= read -r l; do
    case "$l" in \#*|'') continue;; esac
    jack "$l"
    case "$l" in
      *nopass*) add_lead 93 "doas nopass rule: $l" "Passwordless doas elevation -- check the permitted command via GTFOBins.";;
      permit*)  add_lead 88 "doas rule: $l" "doas elevation rule -- check the permitted command via GTFOBins.";;
    esac
  done < "$_dc"
done
if have doas; then
  doas -n id 2>/dev/null | grep -q 'uid=0' && { jack "doas -n id returned uid=0 (passwordless)"; add_lead 96 "doas returns uid=0 without a password" "'doas -n id' returned uid=0 -- possible passwordless root via doas. Manual review." "" "" "" "" "doas-nopasswd" "doas-config" "privesc-doas"; }
fi
fi   # end host-context (skipped in loot mode)

# =====================================================================
#  NETWORK -- interfaces, routes, DUAL-HOMED (pivot indicator)
# =====================================================================
if want id; then
head_ "Network -- interfaces & routes (dual-homed = pivot)"
_wips=""
if have ip; then
  while IFS= read -r _a; do [ -n "$_a" ] && { _wips="$_wips $_a"; info "iface: $_a"; }; done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2" "$4}')
elif have ifconfig; then
  while IFS= read -r _a; do [ -n "$_a" ] && { _wips="$_wips $_a"; info "iface ip: $_a"; }; done < <(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -vE '^127\.')
fi
_wnets=$(for a in $_wips; do case "$a" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) ip_net "$a";; esac; done | sort -u)
_wn=$(printf '%s\n' "$_wnets" | grep -c .)
# COV: the interface collector declares an outcome -- an empty result is a real gap (no ip/ifconfig, or no global-scope addr), not a silent 'complete'
if [ -z "$(printf '%s' "$_wips" | tr -d ' ')" ]; then cov_error "no IPv4 interface enumerated (ip/ifconfig absent or no global-scope address) -- network picture incomplete"; fi
if [ "${_wn:-0}" -ge 2 ]; then
  jack "DUAL-HOMED: $_wn network segments here -> $(printf '%s ' $_wnets)"
  add_lead 95 "Dual-homed host ($_wn segments)" "Box bridges networks -- tunnel (chisel/ligolo/ssh -D SOCKS) and pivot to the other segment, then re-run the whole methodology there. Flagless boxes are often the pivot." "" "" "" "" "dual-homed" "network-topology" "pivot-multihomed"
elif [ "${_wn:-0}" -eq 1 ]; then
  info "Single segment ($_wnets) -- no obvious pivot from here."
fi
sub "routes toward internal ranges (extra reachable segments)"
# v2.16 C3: score a route to a network we are NOT directly attached to (pivot lead even on a single NIC).
_wnets_sp=$(printf '%s' "$_wnets" | tr '\n' ' ')
_routed_extra=0
while IFS= read -r r; do
  [ -z "$r" ] && continue
  waldo "route -> $r"
  _rnet=$(printf '%s' "$r" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | head -n1)
  [ -z "$_rnet" ] && continue
  _rnetn=$(ip_net "$_rnet") || continue
  # v0.34 C3: CONTAINMENT suppression (not exact equality) -- a more-specific route (e.g. 10.10.5.0/24) wholly inside
  # an attached network (10.10.0.0/16) is ATTACHED, not a pivot. Check the route's network address against every attached CIDR.
  _rip=${_rnetn%%/*}; _contained=0
  printf '%s\n' "$_wnets" | grep -qxF "$_rnetn" && _contained=1
  [ "$_contained" = 0 ] && for _aw in $_wnets; do ip_in_net "$_rip" "$_aw" && { _contained=1; break; }; done
  [ "$_contained" = 1 ] && continue   # route is within/equal to an attached network -> not an anomaly
  _rif=$(printf '%s' "$r" | grep -oE 'dev [^ ]+' | awk '{print $2}')
  _rmet=$(printf '%s' "$r" | grep -oE 'metric [0-9]+' | awk '{print $2}')   # C3: route preference (lower = active path)
  _rvia=$(printf '%s' "$r" | grep -oE 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
  _routed_extra=1
  add_lead 80 "Route to non-attached network: $_rnet${_rif:+ (dev $_rif)}${_rmet:+ [metric $_rmet]}" "This host reaches $_rnet, not one of its own subnets -- a pivot lead even from a single NIC.${_rvia:+ Next-hop gateway $_rvia.}${_rmet:+ Route metric $_rmet (lower = the preferred active path).} Tunnel (chisel/ligolo/ssh -D SOCKS) from here and re-run; an unowned gateway may already forward. Source: this host${_rif:+/$_rif}."
done < <( { ip route 2>/dev/null || route -n 2>/dev/null; } | grep -E '(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | grep -viE 'default|^0\.0\.0\.0' )
# v0.15 C3: IP forwarding = this host actively ROUTES between segments (stronger than merely being multi-homed)
_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [ "$_fwd" = 1 ]; then
  # v0.15 C3: forwarding is only a "router between segments" claim when a SECOND segment/route is actually observed.
  # ip_forward=1 alone is a common default (containers/VMs) and does NOT prove the host bridges anything.
  if [ "${_wn:-0}" -ge 2 ] || [ "$_routed_extra" = 1 ]; then
    jack "IP forwarding ENABLED (net.ipv4.ip_forward=1) + a second segment/route observed -- this host routes between segments"
    add_lead 84 "IP forwarding enabled + multi-segment -- host is a router between segments" "net.ipv4.ip_forward=1 AND a second segment/non-attached route is present: this box forwards between its networks, so traffic you send may already reach the far segment THROUGH it (peer static route or masquerade). A tunnel here is a first-class pivot; the adjacent segment may be reachable with no tunnel at all. Manual review." "" "" "" "" "ip-forwarding-router" "network-topology" "pivot-router"
  else
    note "net.ipv4.ip_forward=1, but only one attached segment and no non-attached route observed -- forwarding is enabled yet nothing to bridge from here (common container/VM default). Not scored as a pivot."
  fi
fi
if [ "${_wn:-0}" -ge 2 ] || [ "$_routed_extra" = 1 ]; then
  note "attack-position: you hold a LAN-adjacent vantage onto the segment(s) above -- timing-sensitive (heap-groom/race) or auth-walled attacks may behave differently launched from here than across the VPN."
fi
# v0.34 C3: read-only local FIREWALL context (default policy / rule presence) -- affects which listeners are actually reachable and whether a reverse shell egresses. No changes made.
sub "Local firewall context (read-only -- affects reachability & egress)"
if have ufw && ufw status 2>/dev/null | grep -qiE 'Status: active'; then note "ufw ACTIVE: $(ufw status 2>/dev/null | grep -iE 'Status:|Default:' | tr '\n' ' ')"
elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then note "firewalld RUNNING (zones: $(firewall-cmd --get-active-zones 2>/dev/null | tr '\n' ' '))"
elif have nft && [ -n "$(nft list ruleset 2>/dev/null)" ]; then note "nftables ruleset present ($(nft list ruleset 2>/dev/null | grep -c 'chain ') chain(s)) -- review INPUT/OUTPUT policy for reachability/egress"
elif have iptables; then _ipt=$(iptables -S 2>/dev/null); [ -n "$_ipt" ] && note "iptables: INPUT policy $(printf '%s' "$_ipt" | grep -m1 '^-P INPUT' | awk '{print $3}'), OUTPUT policy $(printf '%s' "$_ipt" | grep -m1 '^-P OUTPUT' | awk '{print $3}'), $(printf '%s' "$_ipt" | grep -c '^-A') rule(s) -- affects listener reachability & reverse-shell egress" || note "iptables present but no readable rules at this privilege"
else note "no readable local firewall (ufw/firewalld/nft/iptables) -- listeners likely reachable as shown; confirm egress for reverse shells"; fi
sub "ARP / neighbours (live hosts to hit after pivoting)"
# C3: classify each neighbour against the ATTACHED nets (real prefix) + surface link state; an off-segment neighbour is a live host reachable only via the pivot.
{ ip neigh 2>/dev/null || arp -an 2>/dev/null; } | grep -E '(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | while IFS= read -r n; do
  _nip=$(printf '%s' "$n" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  _nstate=$(printf '%s' "$n" | grep -oiE '(REACHABLE|STALE|DELAY|PROBE|PERMANENT|FAILED|INCOMPLETE)' | head -n1)
  _natt=0; for _aw in $_wnets; do ip_in_net "$_nip" "$_aw" && { _natt=1; break; }; done
  if [ -n "$_nip" ] && [ "$_natt" = 0 ]; then
    waldo "$n  <- live host on a NON-attached segment (reachable via the pivot)${_nstate:+ [$_nstate]}"
  else
    waldo "$n${_nstate:+ [$_nstate]}"
  fi
done
sub "hosts file & DNS (internal DNS server often = the DC)"
grep -vE '^\s*#|^\s*$' /etc/hosts 2>/dev/null | while IFS= read -r l; do note "$l"; done
grep -i '^nameserver' /etc/resolv.conf 2>/dev/null | while IFS= read -r l; do note "$l"; done

# =====================================================================
#  1. USERS
# =====================================================================
fi
if want users; then
head_ "Users -- accounts that stand out"
sub "UID 0 accounts (should be ONLY root)"
while IFS= read -r u; do
  if [ "$u" = root ]; then note "root (expected)"
  else jack "UID 0 account: $u   [root-equivalent!]"; add_lead 88 "Non-root UID-0 account: $u" "A second superuser account -- if you can authenticate as it (or it has a weak/known password), it is root-equivalent. Manual review."; fi
done < <(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
sub "Login-capable users (UID>=1000 with a real shell)"
awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false|sync)$/ {print $1"  (uid="$3", shell="$7", home="$6")"}' /etc/passwd 2>/dev/null |
  while IFS= read -r l; do waldo "$l"; done
sub "Service accounts that HAVE a shell (unusual)"
awk -F: '$3<1000 && $3!=0 && $7 ~ /(bash|sh|zsh)$/ {print $1"  ("$7")"}' /etc/passwd 2>/dev/null |
  while IFS= read -r l; do waldo "$l"; done
if [ -r /etc/shadow ]; then jack "/etc/shadow is READABLE by you -> dump & crack"; add_lead 95 "/etc/shadow readable" "You can read password hashes directly -- crack offline for any account incl. root."; peek /etc/shadow; fi
# BSD equivalent (FreeBSD/OpenBSD store hashes in master.passwd)
if [ -r /etc/master.passwd ]; then jack "/etc/master.passwd is READABLE (BSD shadow) -> dump & crack"; add_lead 95 "/etc/master.passwd readable" "BSD hash store readable -- crack offline (hashcat -m 1800/500 depending on format)."; peek /etc/master.passwd; fi
id 2>/dev/null | grep -qiE '\((wheel|sudo|admin|operator)\)' && info "you are in a privileged group (wheel/sudo/admin) -> su/doas to root if you have/crack the pass"
# membership in high-value groups explains WHY later sections are reachable (score it)
_grp=$(id 2>/dev/null)
case "$_grp" in
  *'(docker)'*) jack "you are in group 'docker' -> mount host / run privileged container"; add_lead 90 "docker group membership" "Members of 'docker' can start a container mounting the host FS -> read/write as root. Manual review." "" "" "" "" "group:docker" "current-user-groups" "privesc-group-docker";;
esac
case "$_grp" in
  *'(lxd)'*|*'(lxc)'*) jack "you are in group 'lxd/lxc' -> privileged container -> host root"; add_lead 90 "lxd/lxc group membership" "Members of 'lxd' can launch a privileged container mounting the host -> root. Manual review." "" "" "" "" "group:lxd-lxc" "current-user-groups" "privesc-group-lxd";;
esac
case "$_grp" in
  *'(adm)'*|*'(systemd-journal)'*) info "you are in a LOG-READER group (adm/systemd-journal)"; add_lead 60 "Log-reader group (adm/systemd-journal)" "You can read system/journal logs -- provisioning/guest-agent/cloud-init logs often leak creds & flag paths here. See the Logs section. Manual review." "" "" "" "" "group:adm-systemd-journal" "current-user-groups" "log-read-group";;
esac
# Full group roster -- note-taking capture: your groups, every login user's groups, high-value group members
sub "Group membership (full roster)"
info "you: $_grp"
for lu in $(awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false|sync)$/ {print $1}' /etc/passwd 2>/dev/null); do
  gl=$(id "$lu" 2>/dev/null); [ -n "$gl" ] && { if printf '%s' "$gl" | grep -qiE '\((sudo|wheel|admin|docker|lxd|lxc|adm|disk|shadow)\)'; then waldo "$lu: $(printf '%s' "$gl" | sed 's/^[^ ]* //')"; else note "$lu: $(printf '%s' "$gl" | sed 's/^[^ ]* //')"; fi; }
done
# members of high-value groups (from /etc/group) -- who else can escalate/read
for hg in sudo wheel admin docker lxd lxc adm disk shadow systemd-journal backup; do
  gm=$(getent group "$hg" 2>/dev/null | cut -d: -f4); [ -n "$gm" ] && waldo "group '$hg' members: $gm"
done
# Local lockout & password policy -- know before you brute SSH (the Linux analog of net accounts)
sub "Account lockout & password policy [LOCAL] (posture fact -- Waldo does not brute/spray)"
if [ -r /etc/login.defs ]; then
  grep -E '^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' /etc/login.defs 2>/dev/null | while IFS= read -r l; do note "login.defs: $(printf '%s' "$l" | tr -s ' ')"; done
fi
_deny=""
for fc in /etc/security/faillock.conf /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/sshd; do
  [ -r "$fc" ] || continue
  d=$(grep -hoE 'pam_(faillock|tally2?)\.so.*deny=[0-9]+' "$fc" 2>/dev/null | grep -oE 'deny=[0-9]+' | head -n1)
  [ -n "$d" ] && { _deny="$d"; waldo "lockout enforced ($fc): pam_faillock/tally $d"; break; }
done
if [ -n "$_deny" ]; then
  n=${_deny#deny=}; add_lead 45 "[LOCAL] SSH/login lockout after ${n} tries" "pam_faillock/tally locks local accounts after ${n} failed logins -- posture fact only; Waldo does not brute/guess/spray. Any credential testing is your manual decision." "" "" "" "" "local-login-lockout" "pam-policy" "posture-lockout"
else
  note "no pam_faillock/pam_tally lockout found -- local login attempts likely NOT rate-locked (still your manual call; watch auth.log)."
fi
# backup copies of the password DB (the Linux analog of SAM/SYSTEM hive backups)
sub "Password-DB backups (readable copy = crack offline, no root needed)"
for sb in /etc/shadow- /etc/shadow.bak /etc/gshadow- /etc/master.passwd- /etc/passwd- /var/backups/shadow.bak /var/backups/gshadow.bak /var/backups/passwd.bak; do
  [ -f "$sb" ] && [ -r "$sb" ] && { jack "READABLE credential backup: $sb"; add_lead 90 "Readable password-DB backup: $sb" "A backup of the shadow/passwd database is readable -- crack hashes offline (no root needed). Manual review."; peek "$sb"; }
done
# active sessions -- who else is logged on (situational awareness; no session touched)
sub "Active sessions (who else is here -- session untouched)"
_me=$(id -un 2>/dev/null)
if command -v who >/dev/null 2>&1; then
  while IFS= read -r sl; do
    [ -z "$sl" ] && continue
    su=$(printf '%s' "$sl" | awk '{print $1}')
    [ -z "$su" ] && continue
    if [ "$su" = "$_me" ]; then note "session: $sl (you)"
    else
      pv=""
      groups "$su" 2>/dev/null | grep -qiE '(^| )(sudo|wheel|admin|root)( |$)' && pv=" [privileged group]"
      [ "$(id -u "$su" 2>/dev/null)" = 0 ] && pv="$pv [UID 0]"
      if [ -n "$pv" ]; then jack "session: $sl$pv"; add_lead 70 "Privileged user session present: $su" "Another privileged user ($su) is logged on$pv. Situational awareness only -- if you gain root their creds/agent sockets may be reachable. Waldo touches nothing."
      else waldo "session: $sl (other user)"; fi
    fi
  done < <(who 2>/dev/null)
fi
command -v last >/dev/null 2>&1 && last -n 5 2>/dev/null | grep -vE '^$|^wtmp|^reboot' | while IFS= read -r ll; do note "last: $ll"; done
# admin-like-named login accounts -- often the intended credential target
sub "Admin-like-named accounts (svc/deploy/backup/etc)"
while IFS= read -r au; do
  [ -z "$au" ] && continue
  waldo "admin-like account: $au"
  add_lead 50 "Admin-like account: $au" "Account name suggests a service/admin/deploy role -- often the credential target on lab boxes. Look for its creds in configs/history/keys. Manual review."
done < <(awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1}' /etc/passwd 2>/dev/null | grep -iE '^(svc|backup|deploy|ansible|operator|adm[-_]|jenkins|gitlab|sql|web(admin|svc)|helpdesk|automation)')

# =====================================================================
#  2. / ROOT
# =====================================================================
fi
if want fs; then
head_ "/ root -- items that don't belong"
while IFS= read -r e; do
  n=$(basename -- "$e")
  in_list "$n" "$STD_ROOT" && continue
  report "$e" "$( [ -d "$e" ] && echo dir || echo file )"
done < <(for x in /*; do echo "$x"; done)

# =====================================================================
#  3. APP / WEB ROOTS -- custom software (scripts, configs, writable)
# =====================================================================
fi
if want fs; then
head_ "App/web roots -- scripts, configs, writable files"
for base in $APP_ROOTS; do
  [ -d "$base" ] || continue
  sub "$base"
  scan_zone "$base" "   |-"
done
sub "Writable webroots (served web dir you can write to)"
_WEBROOTS="/var/www /var/www/html /usr/local/www /usr/local/www/apache24/data /srv/http /srv/www"
_WEBROOTS="$_WEBROOTS $(ls -d /opt/*/htdocs /opt/*/www 2>/dev/null)"
_WEBROOTS="$_WEBROOTS $(find /opt /srv /var/www -maxdepth 4 -type d \( -iname htdocs -o -iname www -o -iname wwwroot -o -iname webroot -o -iname public_html -o -iname public -o -iname html -o -iname cmsdocs -o -iname uploads -o -iname upload -o -iname files -o -iname images -o -iname static \) 2>/dev/null | head -n 40)"
for wr in $(printf '%s\n' $_WEBROOTS | awk 'NF && !seen[$0]++'); do
  [ -d "$wr" ] || continue
  if iswrite "$wr"; then jack "WRITABLE webroot: $wr"; add_lead 88 "Writable webroot: $wr" "A served web directory is writable by you -- possible code-execution condition (writable web content would run as the web user). Manual review." "" "" "" "" "$wr" "writable-webroot" "writable-webroot"
  else note "webroot (not writable): $wr"; fi
done
sub "Web-served interesting files (scripts, schemas, notes, staged loot)"
_SERVED_RE='\.(sh|py|pl|rb|php|inc|sql|bak|old|save|hiv|hive|log|txt|md|csv|env|ini|conf|cfg|config|json|ya?ml|zip|7z|rar)$|/(SAM|SYSTEM|SECURITY|NTDS\.dit)$'
_SERVED_HOT='simulate|schema|credential|creds|password|secret|backup|dump|hive|sam|system|security|ntds|local|proof|admin|config|database|users?'
_served_n=0
for wr in $(printf '%s\n' $_WEBROOTS | awk 'NF && !seen[$0]++'); do
  [ -d "$wr" ] || continue
  while IFS= read -r wf; do
    [ -f "$wf" ] || continue
    _served_n=$((_served_n+1))
    if printf '%s\n' "$wf" | grep -qiE "$_SERVED_HOT"; then
      jack "web-served high-signal file: $wf"
      add_lead 82 "Web-served high-signal file: $wf" "A file under a served web/app directory has a credential/schema/loot/objective-shaped name. Directory listings or app routes may expose it remotely; read it locally first and preserve source provenance. Manual review -- Waldo does not request it over HTTP." "" "" "" "" "$wf" "web-served-high-signal-file" "web-served-artifact"
      add_cred 'web-served high-signal artifact' "$wf"
    else
      waldo "web-served file: $wf"
    fi
    [ "$NOCONTENT" = 0 ] && peek "$wf"
    _wd=$(dirname -- "$wf")
    if iswrite "$_wd"; then
      add_lead 76 "Writable served subdirectory: $_wd" "A web-served subdirectory containing interesting files is writable by you. This is a write-to-served-content condition; Waldo writes nothing. Manual review." "" "" "" "" "$_wd" "writable-served-subdirectory" "writable-served-subdirectory"
    fi
  done < <(find "$wr" -maxdepth 5 -type f -size -20M 2>/dev/null | grep -Ei "$_SERVED_RE" | head -n 80)
done
[ "$_served_n" -ge 80 ] && info "web-served artifact sweep capped at 80 file(s) per root -- coverage may be partial for large webroots."
sub "Web-app source wiring (DB / object-storage / upload-sync)"
_WIRE='S3Client|use_path_style_endpoint|[^a-z](endpoint|bucket)[^a-z].{0,40}[:=]|SaveAs|move_uploaded_file|file_put_contents|new mysqli|PDO\(|mysql_connect|AKIA[0-9A-Z]{16}|secret[_-]?key|access[_-]?key'
while IFS= read -r sf; do
  [ -f "$sf" ] && [ -r "$sf" ] || continue
  h=$(grep -IiaEn "$_WIRE" "$sf" 2>/dev/null | head -n 3)
  [ -z "$h" ] && continue
  jack "app source wiring: $sf"
  printf '%s\n' "$h" | while IFS= read -r hl; do say "         ${C_R}> $(printf '%.150s' "$hl")${C_RST}"; done
  add_lead 84 "App source reveals backend wiring: $sf" "Web source references DB / object-storage / upload-sync / hardcoded keys -- read it for endpoint/bucket/creds and object->webroot writes. Manual review."
  add_cred 'app source (DB/S3/keys wiring)' "$sf"
done < <(find /var/www /usr/local/www /srv $(ls -d /opt/*/htdocs /opt/*/www 2>/dev/null) -maxdepth 5 -type f \( -name '*.php' -o -name '*.inc' -o -name '*.py' -o -name '*.rb' -o -name '*.env' -o -name '*.ini' \) 2>/dev/null | head -n 80)
sub "Exposed .git in web/app roots (dump history -- removed creds often recoverable)"
while IFS= read -r g; do
  [ -z "$g" ] && continue
  jack ".git repo in web/app root: $g"
  add_lead 84 "Exposed .git metadata: $g" "Deployed .git -- reconstruct history (git log / checkout old revs); credentials removed in later commits are often recoverable. Manual review."
  add_cred 'git history (removed creds often recoverable)' "$g"
done < <(find /var/www /usr/local/www /srv $APP_ROOTS -maxdepth 4 -type d -name '.git' 2>/dev/null | head -n 8)
sub "Backup images / archives in web/app/backup roots (staged hives & creds)"
while IFS= read -r im; do
  [ -z "$im" ] && continue
  jack "backup image/archive: $im"
  add_lead 78 "Backup image/archive: $im" "May contain staged configs / DB dumps / credential files. Exfil & inspect offline. Manual review."
  add_cred 'backup image/archive' "$im"
done < <(find /var/www /srv /backup /opt /transfer $APP_ROOTS -maxdepth 4 -type f \( -name '*.vhd' -o -name '*.vhdx' -o -name '*.vmdk' -o -name '*.ova' -o -name '*.ovf' -o -name '*.7z' -o -name '*.zip' -o -name '*.bak' -o -name '*.old' -o -name '*.tar' -o -name '*.gz' \) 2>/dev/null | head -n 12)

# =====================================================================
#  4. WORLD-WRITABLE TEMP + dropped files
# =====================================================================
fi
if want fs; then
head_ "Temp / world-writable dirs -- dropped files"
for t in /tmp /var/tmp /dev/shm; do
  [ -d "$t" ] || continue
  sub "$t"
  while IFS= read -r f; do report "$f" "tmp"; done < <(find "$t" -maxdepth 1 -type f 2>/dev/null | grep -EI "$INTERESTING_RE|$EXEC_RE" | head -n 40)
done

# =====================================================================
#  5. SUID / SGID / capabilities
# =====================================================================
fi
if want privesc; then
head_ "SUID / SGID / capabilities -- non-standard = check GTFOBins"
sub "SUID root binaries"
# capture with a soft deadline so a huge tree cannot hold the foreground indefinitely; inspect the timeout status
# (process substitution would hide it). here-string keeps the loop in the MAIN shell so add_lead/reg_prim persist.
run_bounded _suid find / -xdev -perm -4000 -type f; _src=$?
[ "$_src" = 124 ] && cov_error "SUID scan timed_out at ${WALDO_DEADLINE}s -- SUID enumeration INCOMPLETE (results truncated)"
[ "$_DEADLINE_OK" = 0 ] && cov_error "no 'timeout' binary -- SUID/getcap scans ran UNBOUNDED (deadline guarantee unavailable)"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  b=$(basename -- "$f")
  if in_list "$b" "$STD_SUID"; then note "std: $f"
  elif iswrite "$f"; then jack "SUID $f   [and WRITABLE]"; add_lead 82 "Writable SUID binary: $f" "SUID-root and writable by you -- possible privesc condition. Manual review." "" "" "" "" "$f" "setuid-root" "writable-suid-binary"; reg_prim shell "writable SUID-root binary $f"
  else
    # score by LOCATION: a custom/user-path SUID is far more likely the intended privesc
    case "$f" in
      /home/*|/opt/*|/srv/*|/tmp/*|/var/tmp/*|/dev/shm/*|/var/www/*|/usr/local/*|/app/*|/data/*|/transfer/*|/backup/*) suscore=92; suloc='custom/user path';;
      *) suscore=55; suloc='system path';;
    esac
    # NAME suggests a lab action -> boost
    case "$b" in *[Rr][Ee][Ss][Ee][Tt]*|*[Pp][Aa][Ss][Ss][Ww]*|*backup*|*admin*|*monitor*|*service*|*update*|*script*) [ "$suscore" -lt 90 ] && suscore=90; sunote=' (action-name)';; *) sunote='';; esac
    [ -g "$f" ] && { suscore=$((suscore+3)); sunote="$sunote +SGID"; }   # SUID and SGID
    [ "$suscore" -gt 95 ] && suscore=95
    waldo "SUID $f"; add_flagged_bin "$f"
    add_lead "$suscore" "Non-standard SUID: $f$sunote" "SUID-root under $suloc -- check GTFOBins; possible custom privesc. Manual review." "" "" "" "" "$f" "setuid-root" "non-standard-suid"
    # C5: a non-standard SUID is a CANDIDATE, not a proven escape -- it must NOT register as an available primitive
    # (that would let the denied-objective->primitive relationship assert an escape that isn't confirmed). Surfaced as a lead above only.
    # light version annotation where the filename exposes a version
    ver=$(printf '%s' "$b" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
    [ -n "$ver" ] && info "   ^ '$b' exposes version $ver -- check for known local-privesc issues affecting this exact version. Manual review."
    case "$b" in screen-4.5.*) add_lead 90 "SUID screen $ver (version-flagged)" "SUID screen $ver present -- check for known local-root issues affecting this exact version. Manual review (no exploit run)." "" "" "" "" "suid-screen:$ver" "setuid-root" "version-flagged-suid";; esac
    # strings triage on smallish SUID -- exec API + unqualified command = PATH-hijack signature.
    # Case-SENSITIVE (C APIs/commands are lowercase) to avoid SH/System dupes. The HIGH lead is
    # gated to CUSTOM-PATH SUIDs -- a system tool (e.g. kismet) legitimately calls execve+sh.
    if have strings && [ -r "$f" ]; then
      susz=$(wc -c < "$f" 2>/dev/null || echo 0)
      if [ "${susz:-0}" -lt 2000000 ]; then
        sust=$(strings -n 4 "$f" 2>/dev/null)
        suapi=$(printf '%s' "$sust" | grep -oE '\b(system|popen|execlp|execvp|execve|setuid|setgid)\b' | sort -u | tr '\n' ',' | sed 's/,$//')
        sucmd=$(printf '%s' "$sust" | grep -oE '\b(chpasswd|passwd|useradd|usermod|tar|zip|bash|sh|python[23]?|perl|ruby|curl|wget|nc|ncat|chmod|chown|service|systemctl)\b' | sort -u | tr '\n' ',' | sed 's/,$//')
        if [ -n "$suapi" ] && [ -n "$sucmd" ] && [ "$suscore" -ge 90 ]; then
          jack "   strings: exec API [$suapi] + unqualified cmd [$sucmd] -> possible PATH-hijack/injection"
          add_lead 94 "Custom SUID likely PATH-hijackable: $f" "Contains exec API ($suapi) and unqualified command(s) ($sucmd) -- possible PATH-hijack/command-injection to root. Verify manually (no exploit run)."
          reg_prim shell "PATH-hijackable custom SUID $f (exec API + unqualified cmd)"
        elif [ -n "$suapi" ] && [ -n "$sucmd" ]; then
          info "   strings: exec API [$suapi] + cmd [$sucmd] (system-path binary -- likely legit; inspect if custom). Manual review."
        fi
      fi
    fi
  fi
done <<< "$_suid"
if [ "$DEEP" = 1 ]; then
  sub "SGID binaries (non-standard)"
  run_bounded _sgid find / -xdev -perm -2000 -type f; [ "$?" = 124 ] && cov_error "SGID scan timed_out at ${WALDO_DEADLINE}s -- SGID enumeration INCOMPLETE (results truncated)"
  while IFS= read -r f; do [ -z "$f" ] && continue; b=$(basename -- "$f"); in_list "$b" "$STD_SUID" || waldo "SGID $f"; done <<< "$_sgid"
fi
if have getcap; then
  sub "File capabilities (getcap)"
  # capture with a soft deadline so a huge tree cannot hold the foreground indefinitely; timeout -> timed_out outcome
  run_bounded _gcaps getcap -r /; _gcrc=$?
  [ "$_gcrc" = 124 ] && cov_error "getcap timed_out at ${WALDO_DEADLINE}s -- capability enumeration INCOMPLETE (raise WALDO_DEADLINE or run getcap manually)"
  # here-string (not a pipe) so add_lead/reg_prim run in the MAIN shell and persist
  while IFS= read -r l; do
    [ -z "$l" ] && continue
    case "$l" in
      *cap_setuid*|*cap_dac_*|*cap_sys_admin*|*cap_sys_ptrace*)
        jack "$l"; add_lead 85 "Dangerous capability: $l" "This capability has a documented privesc path (setuid/dac/ptrace/sys_admin)."
        case "$l" in *cap_setuid*|*cap_sys_admin*) reg_prim shell "file capability $l";; *) reg_prim read "file capability $l (dac/ptrace read primitive)";; esac;;
      *) waldo "$l";;
    esac
  done <<< "$_gcaps"
fi
sub "Versions of privesc-sensitive binaries (compare vs known issues -- manual review)"
for vb in sudo pkexec screen dbus-daemon exim4 lxc; do
  if have "$vb"; then
    v=$("$vb" --version 2>&1 | head -n1)
    [ -n "$v" ] && info "$vb: $v"
  fi
done

# =====================================================================
#  5b. LOCAL SERVICE CONFIGS -- SNMP extend, FTP key stores
# =====================================================================
fi
if want services; then
head_ "Local service configs -- SNMP extend & FTP key stores"
# SNMP: extend/pass directives can run local scripts as the snmpd user; community strings enable remote reads
if pgrep -x snmpd >/dev/null 2>&1 || printf '%s' "$LP" 2>/dev/null | grep -q ':161 ' || { have ss && ss -ulnp 2>/dev/null | grep -q ':161 '; }; then
  sub "snmpd present -- inspecting config"
  for sc in /etc/snmp/snmpd.conf /var/lib/snmp/snmpd.conf /usr/local/etc/snmp/snmpd.conf; do
    [ -f "$sc" ] || continue
    if [ -r "$sc" ]; then
      while IFS= read -r sl; do
        case "$sl" in \#*|'') continue;; esac
        case "$sl" in
          *extend*|*pass_persist*|*'pass '*)
            tgt=$(printf '%s' "$sl" | grep -oE '/[A-Za-z0-9_./-]+' | head -n1)
            jack "SNMP $sc: $sl"
            if [ -n "$tgt" ] && [ -e "$tgt" ]; then add_lead 90 "SNMP extend/pass runs $tgt" "snmpd runs this local script/binary; if it's SUID/custom or writable it's a privesc, and it's exposed via SNMP. Manual review." "" "" "" "" "$tgt" "snmp-service" "snmp-extend-exec"; else add_lead 80 "SNMP extend/pass directive" "$sl -- snmpd executes a local command. Manual review." "" "" "" "" "snmp-extend-directive" "snmp-service" "snmp-extend-exec"; fi;;
          *rwcommunity*) jack "SNMP $sc: $sl"; add_lead 80 "SNMP rwcommunity (write)" "$sl -- writable SNMP community. Manual review." "" "" "" "" "snmp-rwcommunity" "snmp-service" "credential-snmp-write";;
          *rocommunity*|*com2sec*) waldo "SNMP $sc: $sl"; add_lead 70 "SNMP community string" "$sl -- readable SNMP community (enumerate remotely). Manual review." "" "" "" "" "snmp-community" "snmp-service" "credential-snmp";;
        esac
      done < "$sc"
    else
      denied "snmpd config present but not readable: $sc"; add_lead 65 "SNMP config denied: $sc" "snmpd running with a config you can't read yet -- revisit when elevated. Manual review."
    fi
  done
fi
# FTP: if an FTP daemon is running, FTP roots often stage SSH keys reused for login
if pgrep -xE 'vsftpd|proftpd|pure-ftpd' >/dev/null 2>&1 || printf '%s' "$LP" 2>/dev/null | grep -q ':21 '; then
  sub "FTP daemon present -- checking FTP roots for keys/creds"
  for fr in /srv/ftp /var/ftp /home/ftp /home/vsftpd; do
    [ -d "$fr" ] || continue
    while IFS= read -r kf; do
      [ -z "$kf" ] && continue
      report "$kf" "ftp"
      case "$kf" in *id_rsa|*id_ed25519|*.ppk|*.pem)
        add_lead 88 "FTP root exposes SSH private key: $kf" "A private key served over FTP -- preserve it as an exact key/principal pair (its owner may match the key path/comment). Any use is your manual decision; Waldo does not test/reuse."
        add_cred 'SSH private key (FTP-exposed)' "$kf";;
      esac
    done < <(find "$fr" -maxdepth 4 \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.ppk' -o -name '*.pem' -o -name 'authorized_keys' -o -name '*.kdbx' -o -name '*.env' \) -type f 2>/dev/null | head -n 10)
  done
fi
# Samba config (signing posture + guest/writable shares) -- read-only local facts
if [ -r /etc/samba/smb.conf ] || pgrep -xE 'smbd|nmbd' >/dev/null 2>&1; then
  sub "Samba config (smb.conf -- signing, guest/writable shares)"
  if [ -r /etc/samba/smb.conf ]; then
    if grep -qiE '^[[:space:]]*server signing[[:space:]]*=[[:space:]]*(auto|disabled|no)' /etc/samba/smb.conf; then
      waldo "Samba server signing not mandatory"; add_lead 60 "Samba signing not required" "smb.conf does not mandate SMB signing -- posture fact (relay-relevant). Manual review." "" "" "" "" "samba-signing-not-required" "smb-posture" "posture-relay-candidate"
    fi
    _shr="(global)"
    while IFS= read -r sl; do
      _l=$(printf '%s' "$sl" | tr 'A-Z' 'a-z')
      case "$_l" in
        \[*\]) _shr="$sl";;
        *guest\ ok*=*yes*|*guest\ account*) jack "Samba guest-ok share $_shr"; add_lead 66 "Samba guest-accessible share: $_shr" "smb.conf allows guest access to $_shr -- unauthenticated read may expose configs/keys/backups. Manual review.";;
        *writable*=*yes*|*writeable*=*yes*|*read\ only*=*no*) waldo "Samba writable share $_shr"; add_lead 58 "Samba writable share: $_shr" "smb.conf marks $_shr writable -- content you can drop is served over SMB. Manual review.";;
        *path*=*) note "  $_shr : $sl";;
      esac
    done < <(grep -vE '^[[:space:]]*(#|;|$)' /etc/samba/smb.conf 2>/dev/null)
  else
    denied "smbd running but /etc/samba/smb.conf not readable -- revisit when elevated"
  fi
fi
# TFTP root -- often anonymous/world-writable
if pgrep -xE 'in.tftpd|tftpd|tftpd-hpa' >/dev/null 2>&1 || { printf '%s' "$LP" 2>/dev/null | grep -q ':69 '; }; then
  for tr in /srv/tftp /var/lib/tftpboot /tftpboot; do
    [ -d "$tr" ] || continue
    if iswrite "$tr"; then jack "TFTP root WRITABLE: $tr"; add_lead 70 "Writable TFTP root: $tr" "TFTP server root is writable (often served unauthenticated) -- drop/read files without auth. Manual review."
    else note "TFTP root: $tr"; fi
  done
fi

# =====================================================================
#  5c. KERNEL & LOCAL-PRIVESC-RELEVANT CAPABILITIES (generic -- no exploit named)
# =====================================================================
fi
if want privesc; then
head_ "Kernel & local-privesc-relevant capabilities"
_kver=$(uname -r 2>/dev/null)
info "kernel: $(uname -a 2>/dev/null)"
_kcaps=""
for _cap in gcc cc clang make pkexec newuidmap newgidmap unshare nsenter docker lxc lxd; do have "$_cap" && _kcaps="$_kcaps $_cap"; done
[ -n "$_kcaps" ] && info "privesc-relevant local tools present:$_kcaps"
add_lead 60 "Kernel $_kver + local capabilities" "Kernel $_kver.${_kcaps:+ Tools present:$_kcaps (build tools help compile, others are common local-privesc primitives).} Check for any public local-privesc exploits matching this exact kernel/config -- manual review (no specific exploit named, no exploit run)." "" "" "" "" "kernel:$_kver" "kernel" "kernel-exploit-surface"
# v0.15 C2: non-standard privileged local broker (PackageKit) + reachability/namespace facts (descriptive, no CVE)
# NB: pkexec belongs to polkit and is NOT PackageKit -- require actual PackageKit evidence (daemon/binary/package).
_pkg_present=0
pgrep -x packagekitd >/dev/null 2>&1 && _pkg_present=1
{ [ -x /usr/libexec/packagekitd ] || [ -x /usr/lib/packagekit/packagekitd ]; } && _pkg_present=1
dpkg-query -W packagekit >/dev/null 2>&1 && _pkg_present=1
rpm -q PackageKit >/dev/null 2>&1 && _pkg_present=1
if [ "$_pkg_present" = 1 ]; then
  _pkver=$(dpkg-query -W -f='${Version}' packagekit 2>/dev/null || rpm -q --qf '%{VERSION}' PackageKit 2>/dev/null)
  _pkstate=$(pgrep -x packagekitd >/dev/null 2>&1 && echo running || echo installed)
  _pkdbus=$(ls /usr/share/dbus-1/system.d/org.freedesktop.PackageKit*.conf /etc/dbus-1/system.d/org.freedesktop.PackageKit*.conf 2>/dev/null | head -n1)
  _pkreach=$(have pkcon && echo "pkcon client present" || echo "no pkcon client")
  # RootDirectory added -- a chroot (like PrivateTmp) changes which staging paths the consumer resolves
  _pkbound=$(systemctl show -p User -p PrivateTmp -p ProtectSystem -p ReadWritePaths -p RootDirectory packagekit.service 2>/dev/null | tr '\n' ' ')
  # v0.15 C2: EVALUATE the D-Bus policy for the CURRENT user. System bus default-denies unless a policy ALLOWS
  # send_destination. Associate the allow with its ENCLOSING <policy> block (not anywhere-in-file), then decide
  # reachability by context/user/group -- verifying actual group membership for a group policy.
  _me=$(id -un 2>/dev/null); _mygroups=$(id -nG 2>/dev/null); _pksend="unknown (no readable policy)"; _pkreach_self=0
  if [ -n "$_pkdbus" ] && [ -r "$_pkdbus" ]; then
    # emit the <policy...> open-tag of every block that CONTAINS a PackageKit send-allow (awk tracks the enclosing block across lines)
    _pkpolicies=$(awk '
      /<policy[^>]*>/ { if (match($0, /<policy[^>]*>/)) { ctx=substr($0,RSTART,RLENGTH) } }
      /<allow[^>]*send_destination="[^"]*PackageKit/ { if (ctx!="") print ctx }
      /<\/policy>/ { ctx="" }
    ' "$_pkdbus" 2>/dev/null)
    if [ -z "$_pkpolicies" ]; then _pksend="no send-allow associated with any policy block (system-bus default deny -- unprivileged calls likely blocked)"
    else
      _pksend="send allowed under a policy block, but your context does not match it"
      # evaluate each associated policy block against the current user (last match wins -- approximates deny/override ordering)
      while IFS= read -r _pp; do
        [ -z "$_pp" ] && continue
        case "$_pp" in
          *'context="default"'*) _pksend="default-context send ALLOWED for this block (any local user can address the broker)"; _pkreach_self=1;;
          *"user=\"$_me\""*)     _pksend="a policy block for user '$_me' allows send -- you CAN address it"; _pkreach_self=1;;
          *group=*)
            _pg=$(printf '%s' "$_pp" | sed -nE 's/.*group="([^"]+)".*/\1/p')
            if printf ' %s ' "$_mygroups" | grep -q " $_pg "; then _pksend="a GROUP policy (group='$_pg') allows send AND you ARE in that group -- you CAN address it"; _pkreach_self=1
            else _pksend="a GROUP policy (group='$_pg') allows send but you are NOT in '$_pg' -- not reachable as you"; fi;;
        esac
      done <<EOF
$_pkpolicies
EOF
    fi
  fi
  # polkit default for the install/refresh action: does an ACTIVE local session drive it WITHOUT a password?
  _pkpol=$(grep -lRIE 'org\.freedesktop\.packagekit\.(package-install|system-sources-refresh|package-install-untrusted)' /usr/share/polkit-1/actions 2>/dev/null | head -n1)
  _pkauth="unknown"
  [ -r "$_pkpol" ] && _pkauth=$(grep -m1 -A4 -iE 'action id="org\.freedesktop\.packagekit\.package-install' "$_pkpol" 2>/dev/null | grep -m1 -i allow_active | sed -E 's/<[^>]*>//g; s/^[[:space:]]*//; s/[[:space:]]*$//')
  # C2: allow_active applies ONLY to an ACTIVE, LOCAL (non-remote) polkit session. An SSH session satisfies send+role but
  # is Remote=yes and does NOT qualify -- so prove an active local seat session for the current user before lifting to 74.
  _pkactive_local=0; _pkses="unknown"
  if command -v loginctl >/dev/null 2>&1; then
    _sid="${XDG_SESSION_ID:-$(loginctl --no-legend 2>/dev/null | awk -v u="$_me" '$3==u{print $1; exit}')}"
    if [ -n "$_sid" ]; then
      _si=$(loginctl show-session "$_sid" -p Active -p Remote 2>/dev/null)
      case "$_si" in *Active=yes*Remote=no*|*Remote=no*Active=yes*) _pkactive_local=1; _pkses="active local (Active=yes, Remote=no)";; *Remote=yes*) _pkses="REMOTE session (Remote=yes) -- allow_active does NOT apply here";; *) _pkses="present but not active-local";; esac
    fi
  fi
  # only lift to self-drivable (74) with PROVEN reachability (matched policy block) AND polkit allow_active=yes AND an active LOCAL session
  _pkscore=62; { [ "$_pkreach_self" = 1 ] && [ "$_pkactive_local" = 1 ] && printf '%s' "$_pkauth" | grep -qi '^yes$'; } && _pkscore=74
  # v0.42 C2: actually COLLECT + COMPARE the consumer's mount-namespace/path view vs the producer (you). A namespace
  # mismatch is asserted ONLY when a concrete difference is proven: differing mnt-ns inode, PrivateTmp=yes (a private
  # /tmp), or a non-'/' RootDirectory (chroot). Otherwise the consumer shares your filesystem view -> no mismatch.
  _pkpid=$(pgrep -x packagekitd 2>/dev/null | head -1)
  _prod_ns=$(readlink /proc/self/ns/mnt 2>/dev/null); _cons_ns=""; [ -n "$_pkpid" ] && _cons_ns=$(readlink "/proc/$_pkpid/ns/mnt" 2>/dev/null)
  _pkns_mismatch=0
  if [ -n "$_prod_ns" ] && [ -n "$_cons_ns" ] && [ "$_prod_ns" != "$_cons_ns" ]; then
    _pkns_mismatch=1; _pkns_reason="MISMATCH PROVEN: consumer mount namespace ($_cons_ns) differs from yours ($_prod_ns) -- a path you control may not be the path it resolves (confused-deputy/TOCTOU surface)"
  elif printf '%s' "$_pkbound" | grep -qi 'PrivateTmp=yes'; then
    _pkns_mismatch=1; _pkns_reason="MISMATCH PROVEN: consumer PrivateTmp=yes -- it sees a PRIVATE /tmp and /var/tmp, so a /tmp path you write is NOT the one it resolves"
  elif printf '%s' "$_pkbound" | grep -qiE 'RootDirectory=/[^ ]' ; then
    _pkns_mismatch=1; _pkns_reason="MISMATCH PROVEN: consumer has a RootDirectory (chroot) -- its filesystem root differs from yours"
  elif [ -n "$_cons_ns" ]; then
    _pkns_reason="no mismatch: consumer shares your mount namespace ($_cons_ns) and declares no PrivateTmp/RootDirectory -- same filesystem view (lower-confidence: no confused-deputy path condition proven)"
  else
    _pkns_reason="mismatch NOT proven: consumer namespace unreadable from your context (root-owned /proc) and no PrivateTmp/RootDirectory declared"
  fi
  # a proven mismatch is the concrete privesc surface -> ensure the card scores at least the reachable-broker floor
  [ "$_pkns_mismatch" = 1 ] && [ "$_pkscore" -lt 70 ] && _pkscore=70
  waldo "PackageKit broker present ($_pkstate${_pkver:+, version $_pkver})"
  # v0.34 C2: a scored CANDIDATE card requires PROVEN current-user reachability (matched D-Bus send-allow for your context).
  # Stock tooling present with NO caller reachability emits NOTHING (a note only) -- not a scored lead (stock-negative rule).
  if [ "$_pkreach_self" = 1 ]; then
    add_lead "$_pkscore" "PackageKit privileged broker present + reachable as you ($_pkstate)$([ "$_pkns_mismatch" = 1 ] && echo ' [namespace mismatch proven]')" "PackageKit${_pkver:+ $_pkver} is a non-standard PRIVILEGED local broker on D-Bus${_pkdbus:+ (policy: $_pkdbus)} AND your context can address it. Client: $_pkreach. D-Bus send (your context '$_me'): $_pksend. polkit install allow_active=${_pkauth:-unknown} (yes = an active LOCAL session drives it with NO password). Your session: $_pkses. Service sandbox: ${_pkbound:-unknown}. Producer/consumer path view: ${_pkns_reason}. CANDIDATE privileged consumer -- check known local issues for THIS exact version. Descriptive facts only; Waldo runs no exploit and validates no CVE." "" "" "" "" "packagekit-broker" "packagekit:$_pkstate" "privileged-broker-reachable"
  else
    note "PackageKit present ($_pkstate) but NOT reachable from your context ($_pksend) -- stock tooling with no caller reachability is not scored. Re-check if you obtain a matching D-Bus policy context / active local session."
  fi
fi

# =====================================================================
#  6. SERVICES / init -- non-stock root units (shown even if not writable)
# =====================================================================
fi
if want services; then
head_ "Services -- non-standard units, ExecStart, writable configs"
for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/init.d; do
  [ -d "$d" ] || continue
  # v0.34 A3: /etc/init.d holds EXECUTABLE SysV scripts (no .service extension) -- iterate those, not *.service.
  while IFS= read -r u; do
    [ -f "$u" ] || continue
    case "$d" in
      */init.d)
        # SysV init script -- runs as ROOT at boot/service start. Check writability + the writable-helper chain.
        if iswrite "$u"; then jack "writable init.d script: $u"; add_lead 93 "Writable init.d script (root): $u" "A SysV init script under /etc/init.d runs as root at boot/service start and is writable by you -- edit it for root code exec. Manual review."; reg_prim shell "writable init.d script $u (runs as root)"
        else waldo "init.d script: $(basename -- "$u")"; follow_sourced "$u" "init.d $(basename -- "$u")"; fi
        continue;;
    esac
    exe=$(grep -m1 -E '^\s*ExecStart=' "$u" 2>/dev/null | sed -E 's/^\s*ExecStart=-?//')
    binp=$(printf '%s' "$exe" | awk '{print $1}')
    scan_inline_cred "$exe" "systemd unit $(basename -- "$u") ExecStart"
    # v0.34 A3: parse User= before asserting a ROOT service -- a User=<nonroot> unit runs as THAT user, not root.
    _uuser=$(grep -m1 -E '^\s*User=' "$u" 2>/dev/null | sed -E 's/^\s*User=//' | tr -d '[:space:]')
    { [ -z "$_uuser" ] || [ "$_uuser" = root ] || [ "$_uuser" = 0 ]; } && _runas=root || _runas="$_uuser"
    # un-pathed ExecStart command (bare name, no absolute path) = PATH-hijackable if a writable dir is early on PATH
    case "$binp" in /*|''|-*) ;; *) waldo "un-pathed ExecStart '$binp' in $(basename -- "$u") (runs as $_runas)"; add_lead 76 "Un-pathed service command: $binp ($(basename -- "$u"), as $_runas)" "ExecStart calls a bare command (no absolute path) -> PATH-resolved as $_runas. If a writable dir precedes the system dirs on the service PATH, you can shadow it. Cross-check the PATH section. Manual review.";; esac
    if iswrite "$u"; then
      jack "writable unit: $u  -> ${exe:-?} (as $_runas)"; add_lead $([ "$_runas" = root ] && echo 95 || echo 80) "Writable systemd unit: $u (runs as $_runas)" "Edit the unit's ExecStart to your command; on start/restart it runs as $_runas$([ "$_runas" != root ] && echo ' -- NOT root; value is scoped to that user'). Manual review." "" "" "" "" "$u" "service:$(basename -- "$u")" "writable-unit-file"; [ "$_runas" = root ] && reg_prim shell "writable systemd unit $u (edit ExecStart -> runs as root)"
    elif printf '%s' "$binp" | grep -qE '^(/opt|/srv|/home|/tmp|/var/www|/usr/local)'; then
      waldo "non-stock unit: $(basename -- "$u")  -> ${exe:-?} (as $_runas)"; [ -n "$binp" ] && add_flagged_bin "$binp"
      if [ -n "$binp" ] && [ -f "$binp" ] && iswrite "$binp"; then
        add_lead $([ "$_runas" = root ] && echo 95 || echo 80) "Service ($_runas) runs writable binary: $binp" "$(basename -- "$u") ExecStart is a file you can overwrite -- code runs as $_runas." "" "" "" "" "$binp" "service:$(basename -- "$u")" "writable-service-binary"
        jack "   ExecStart target WRITABLE: $binp"; [ "$_runas" = root ] && reg_prim shell "writable ExecStart target $binp (root service $(basename -- "$u"))"
      elif [ -n "$binp" ] && [ -f "$binp" ]; then
        follow_sourced "$binp" "service $(basename -- "$u")"
      fi
    elif [ -n "$binp" ] && [ -f "$binp" ] && iswrite "$binp"; then
      jack "$(basename -- "$u") ExecStart WRITABLE -> $binp (as $_runas)"; add_lead $([ "$_runas" = root ] && echo 95 || echo 80) "Service ($_runas) runs writable binary: $binp" "Overwrite the ExecStart target -- runs as $_runas." "" "" "" "" "$binp" "service:$(basename -- "$u")" "writable-service-binary"; [ "$_runas" = root ] && reg_prim shell "writable ExecStart target $binp (service $(basename -- "$u"))"
    fi
  done < <( case "$d" in */init.d) find "$d" -maxdepth 2 -type f -perm -u+x 2>/dev/null;; *) find "$d" -maxdepth 2 -type f -name '*.service' 2>/dev/null;; esac )
done
iswrite /etc/rc.local && { jack "/etc/rc.local is WRITABLE"; add_lead 90 "/etc/rc.local writable" "Runs as root at boot -- append your command."; reg_prim shell "writable /etc/rc.local (runs as root at boot)"; }
[ -f /etc/rc.local ] && ! iswrite /etc/rc.local && follow_sourced /etc/rc.local "rc.local"

# =====================================================================
#  7. PROCESSES -- real exe via /proc/<pid>/exe
# =====================================================================
fi
if want proc; then
head_ "Processes -- running from non-standard locations"
while IFS="$TAB" read -r owner exe; do
  case "$exe" in /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/snap/*) continue;; esac
  add_flagged_bin "$exe"
  if [ -f "$exe" ] && iswrite "$exe"; then jack "proc ($owner) WRITABLE binary: $exe"
  else waldo "proc ($owner): $exe"; fi
done < <( { for pd in /proc/[0-9]*; do
    exe=$(readlink "$pd/exe" 2>/dev/null) || continue
    exe=${exe% (deleted)}; [ -n "$exe" ] || continue
    owner=$(stat -c '%U' "$pd" 2>/dev/null)
    printf '%s\t%s\n' "$owner" "$exe"
  done; } | sort -u )
# v0.15 A8: scan process command lines for an inline secret (e.g. a service launched with -p <pass>). Bounded, read-only; deduped by value.
for pd in /proc/[0-9]*; do
  cl=$(tr '\0' ' ' < "$pd/cmdline" 2>/dev/null); [ -n "$cl" ] || continue
  scan_inline_cred "$cl" "process cmdline (pid $(basename "$pd"))"
done

# =====================================================================
#  8. LISTENING PORTS
# =====================================================================
fi
if want proc; then
head_ "Listening ports -- non-standard (PID -> user -> exe -> cmdline)"
if have ss; then LP=$(ss -tlnp 2>/dev/null); elif have netstat; then LP=$(netstat -tlnp 2>/dev/null); else LP=""; fi
while IFS= read -r l; do
  [ -z "$l" ] && continue
  addr=$(printf '%s' "$l" | grep -oE '[0-9.:*]+:[0-9]+' | head -n1)
  port=${addr##*:}; ip=${addr%:*}
  case "$port" in ''|*[!0-9]*) continue;; esac
  in_list "$port" "$STD_PORTS" && continue
  case "$port" in 3306|5432|1433|1521|27017|6379|5984) DB_LISTENER="$DB_LISTENER ${port}(${ip})";; esac
  pid=$(printf '%s' "$l" | grep -oE 'pid=[0-9]+' | head -n1 | cut -d= -f2)
  pname=$(printf '%s' "$l" | grep -oE 'users:\(\("[^"]+' | head -n1 | sed 's/.*"//')
  cmd=''; owner=''; exe=''
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//')
    owner=$(stat -c '%U' "/proc/$pid" 2>/dev/null)
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
  fi
  linfo="port $port  ($ip)  pid=${pid:-?} user=${owner:-?}${pname:+ proc=$pname}${cmd:+ cmd=$(printf '%.140s' "$cmd")}"
  loop=0; case "$ip" in 127.*|::1|'[::1]') loop=1;; esac
  sig=''; lscore=0
  case "$cmd" in
    *-Xrunjdwp*|*jdwp*|*transport=dt_socket*) sig='root-owned JDWP debug listener'; [ "$owner" = root ] && lscore=95 || lscore=85;;
    *--inspect*|*debugpy*|*werkzeug*|*' pdb'*) sig='debug listener'; lscore=85;;
  esac
  if [ -z "$sig" ] && [ "$loop" = 1 ] && [ "$owner" = root ]; then
    case "$exe" in /opt/*|/srv/*|/home/*|/tmp/*|/var/www/*|/usr/local/*) sig='root localhost listener from custom path'; lscore=90;; *) sig='root localhost listener'; lscore=75;; esac
  fi
  if [ -n "$sig" ]; then
    jack "$linfo   [$sig]"
    add_lead "$lscore" "$sig on $ip:$port${pname:+ ($pname)}" "Local listener: ${cmd:-cmdline not visible at this priv}.$( case "$sig" in *JDWP*) echo ' Forward the port and validate with jdb/jdwp tooling.';; esac) Manual review (no exploit run)." "" "" "" "" "listener:$ip:$port" "network-listener" "notable-listener"
  elif [ "$loop" = 1 ] && [ -z "$owner" ]; then
    waldo "$linfo   [localhost-only, owner not visible]"
    add_lead 80 "Non-standard localhost listener :$port (owner unknown at this priv)" "Localhost-only listener; owner/cmdline hidden at current privilege -- re-check when elevated. Manual review." "" "" "" "" "localhost-listener:$port" "network-listener" "local-listener-unknown-owner"
  else
    waldo "$linfo"
  fi
done < <(printf '%s\n' "$LP" | grep -E 'LISTEN')

# =====================================================================
#  9. CRON / AUTOSTART -- non-stock root jobs (shown even if not writable)
# =====================================================================
fi
if want autostart; then
head_ "Cron & autostart -- root jobs & writable targets"
sub "System cron"
for cf in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
  [ -f "$cf" ] || continue
  if iswrite "$cf"; then jack "writable cron file: $cf"; add_lead 93 "Writable cron file: $cf" "Runs as root on schedule -- add your command."; reg_prim shell "writable root cron file $cf"; fi
  scan_inline_cred "$(grep -vE '^\s*(#|$)' "$cf" 2>/dev/null)" "cron file $cf"
  while IFS= read -r p; do
    [ -f "$p" ] || continue
    if iswrite "$p"; then jack "cron ($cf) runs WRITABLE script: $p"; add_lead 93 "Root cron runs writable script: $p" "Scheduled as root and you can edit the script -- code runs as root at next tick."; reg_prim shell "writable script $p run by root cron ($cf)"
    else case "$p" in /opt/*|/home/*|/tmp/*|/var/*|/usr/local/*) waldo "cron ($cf) -> $p (non-stock, not writable)";; esac; follow_sourced "$p" "cron $cf"; fi
  done < <(extract_targets "$(cat "$cf" 2>/dev/null)")
  analyze_wildcard "$(grep -vE '^\s*(#|$)' "$cf" 2>/dev/null | tr '\n' ';')" "cron $cf"
done
sub "User crontabs"
for c in /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$c" ] && report "$c" "crontab"; done
sub "Readable scheduler logs -- concrete root commands (the .157 miss)"
for lg in /var/log/syslog /var/log/cron /var/log/cron.log /var/log/auth.log /var/log/messages; do
  [ -r "$lg" ] || continue
  while IFS= read -r cl; do
    [ -z "$cl" ] && continue
    jack "cron log: root CMD -> $(printf '%.200s' "$cl")"
    add_lead 88 "Readable cron log shows root command" "$cl  ::  root runs this on schedule (from $lg). Check its targets/dirs for write access. Manual review." "" "" "" "" "cron-log-root-command" "cron-log" "info-leak-cron"
    analyze_wildcard "$cl" "cron-log root cmd"
    while IFS= read -r p; do [ -f "$p" ] && iswrite "$p" && { jack "   -> writable target: $p"; add_lead 93 "Root cron target writable: $p" "Root scheduler runs $p which you can edit. Manual review."; }; done < <(extract_targets "$cl")
  done < <(grep -hoE 'CRON.*\(root\) CMD \(.*\)' "$lg" 2>/dev/null | sed -E 's/.*CMD \((.*)\)\s*$/\1/' | sort -u | head -n 20)
done
if have journalctl; then
  while IFS= read -r cl; do
    [ -z "$cl" ] && continue
    jack "journal cron root CMD -> $(printf '%.180s' "$cl")"; add_lead 88 "journalctl shows root cron command" "$cl  ::  root scheduled command. Check targets/dirs. Manual review." "" "" "" "" "journal-root-cron" "journal-log" "info-leak-cron"; analyze_wildcard "$cl" "journal cron root cmd"
  done < <(journalctl _COMM=cron --no-pager 2>/dev/null | grep -oE '\(root\) CMD \(.*\)' | sed -E 's/.*CMD \((.*)\)\s*$/\1/' | sort -u | head -n 20)
fi
if have systemctl; then
  sub "systemd timers (non-standard)"
  systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $NF}' |
    grep -vE '^(anacron|apt-daily|fstrim|logrotate|man-db|motd|systemd-|e2scrub|fwupd|snapd|dpkg|phpsessionclean|certbot|update-notifier)' | grep '\.timer' |
    while IFS= read -r tm; do waldo "$tm"; done
fi
[ -f /etc/rc.local ] && report /etc/rc.local "rc.local"

# =====================================================================
#  10. PATH
# =====================================================================
fi
if want proc; then
head_ "PATH -- composition, ordering & hijack surface"
info "PATH = $PATH"
# ORDER MATTERS: a non-standard/writable dir that precedes the system dirs wins name resolution.
_pos=0; _seen_writable_early=""
while IFS= read -r d; do
  _pos=$((_pos+1))
  [ -z "$d" ] && { jack "EMPTY element #$_pos in PATH (= current dir)"; add_lead 72 "Empty/'.' element in PATH (pos $_pos)" "Current dir on PATH -- a binary you drop in \$PWD can shadow a command. Manual review."; continue; }
  case "$d" in .|./*|../*) jack "relative entry #$_pos in PATH: $d"; add_lead 72 "Relative PATH entry (pos $_pos): $d" "Current-dir-relative on PATH -- plant a spoofed binary. Manual review."; continue;; esac
  [ -d "$d" ] || { waldo "PATH dir #$_pos missing: $d (a writable parent lets you create it)"; continue; }
  # non-standard entry (not a normal system bin dir)?
  case "$d" in /usr/bin|/bin|/usr/sbin|/sbin|/usr/local/bin|/usr/local/sbin|/usr/local/games|/usr/games|/snap/bin) _std=1;; *) _std=0;; esac
  if iswrite "$d"; then
    if [ "$_std" = 0 ]; then _seen_writable_early="$d"; fi
    jack "WRITABLE PATH dir #$_pos: $d"
    add_lead 74 "Writable PATH dir (pos $_pos): $d" "On PATH and writable -- plant a binary to shadow a command another user/service invokes. Earlier position = wins resolution. Manual review."
  elif [ "$_std" = 0 ]; then
    waldo "non-standard PATH dir #$_pos: $d"
  fi
done < <(printf '%s' "$PATH" | tr ':' '\n')
[ -n "$_seen_writable_early" ] && add_lead 78 "Writable non-system dir on PATH: $_seen_writable_early" "A writable/non-standard dir sits on PATH -- if it precedes the system dirs, an unpathed command call resolves to your planted binary. Cross-check with un-pathed commands in services/cron/scripts. Manual review."

# =====================================================================
#  11. HOME DIRS -- keys, history, secrets, access map
# =====================================================================
fi
if want creds; then
head_ "Home dirs -- keys, history, secrets, access map"
# v2.16 A5: VNC secret files -- presence/role flag (A5a) + reversible decode (A5b, opt-in --decode-local-secrets)
sub "VNC secret files (A5a state model; decode with --decode-local-secrets)"
_vnc_any=0
# v0.34 A5: full role model -- server / server_unattributed / viewer / installed_only / unknown, with local
# process/listener attribution and hypothesis-only handling for an unattributed port. Read-only; Waldo never connects.
# A5: only a RUNNING/attributed server proves activity. A passwd file with no live server is activity=unknown,
# stale_possible=true (it may be a leftover from a prior config, not an authoritative running service).
_vsrv=0; _vview=0; _vinst=0; _vlisten=0; _vlisten_attr=0
pgrep -xE 'Xvnc|vncserver|x11vnc|Xtigervnc|Xtightvnc' >/dev/null 2>&1 && _vsrv=1
pgrep -xE 'vncviewer|vinagre|remmina|ssvncviewer|xtightvncviewer' >/dev/null 2>&1 && _vview=1
for _vb in vncserver x11vnc Xvnc vncviewer tigervncserver; do command -v "$_vb" >/dev/null 2>&1 && _vinst=1; done
# Listener attribution on the VNC port range (5900-5906). ss shows the owning pid/prog only with privilege;
# a listener with no attributable process is a HYPOTHESIS, not proof of a server here.
if have ss; then
  while IFS= read -r _ln; do
    [ -n "$_ln" ] || continue; _vlisten=1
    case "$_ln" in *users:\(*) _vlisten_attr=1; _lprog=$(printf '%s' "$_ln" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p'); info "VNC listener attributed -> ${_lprog:-?} ($(printf '%s' "$_ln" | awk '{print $4}'))" ;;
      *) add_lead 58 "VNC listener not attributed to a local process" "A VNC-range listener is open ($(printf '%s' "$_ln" | awk '{print $4}')) but Waldo could not tie it to an owning local process (insufficient rights or a namespaced listener). HYPOTHESIS ONLY -- possible server pending manual attribution; Waldo does not connect. Manual review." "" "" "" "" "vnc-listener-unattributed" "network-listener" "hypothesis-vnc" ;;
    esac
  done <<EOF
$(ss -ltnH 2>/dev/null | awk '{n=split($4,a,":"); p=a[n]; if(p>=5900 && p<=5906) print $0}')
EOF
fi
# A5 declared enums (fact vs hypothesis kept SEPARATE): role in {server, client, unknown}; activity in
# {active, installed_only, unknown}. An unattributed listener does NOT claim a server role -- it stays role/activity
# unknown here and is carried by the separate hypothesis-only lead above. This classifier is the SINGLE source of
# truth for role/activity (the test suite imports it -- see tests/fixtures.sh -- so tests can't drift from production).
# $1=server_active(proc/svc) $2=viewer $3=installed $4=listener_attributed -> echoes "<role> <activity>".
vnc_role_activity(){
  if [ "$1" = 1 ] || [ "$4" = 1 ]; then echo "server active"
  elif [ "$2" = 1 ]; then echo "client unknown"
  elif [ "$3" = 1 ]; then echo "unknown installed_only"
  else echo "unknown unknown"; fi
}
_vra=$(vnc_role_activity "$_vsrv" "$_vview" "$_vinst" "$_vlisten_attr"); _vrole=${_vra%% *}; _vact=${_vra##* }
_vstale=$([ "$_vact" = active ] && echo false || echo true)
_dstate=$([ "$DECODE_SECRETS" = 1 ] && echo requested || echo not_requested)
_vsig_checked=0; _vsig_present=0; _vsig_denied=0; _vsig_notfound=0
for _vp in /root/.vnc/passwd /home/*/.vnc/passwd /etc/vnc/passwd /etc/tigervnc/*passwd*; do
  case "$_vp" in *'*'*) continue;; esac   # unexpanded glob = no such path
  _vsig_checked=$((_vsig_checked+1))
  if [ -e "$_vp" ] && [ ! -r "$_vp" ]; then _vsig_denied=$((_vsig_denied+1)); denied "$_vp  [VNC secret present but unreadable]"; continue; fi
  [ -f "$_vp" ] || { _vsig_notfound=$((_vsig_notfound+1)); continue; }
  _vsig_present=$((_vsig_present+1))
  _vnc_any=1; _pt=""; _pt2=""
  _vsz=$(wc -c < "$_vp" 2>/dev/null)
  # v0.15 A5a: validate length -> format BEFORE labeling reversible; emit the 6-field lead ALWAYS (malformed too)
  case "$_vsz" in 8|16) _fmt=reversible_supported; _fsc=78;; *) _fmt=unknown_format; _fsc=55;; esac
  jack "VNC password file: $_vp ($_vsz bytes; format=$_fmt)"
  # v0.42 A5: structured record (pipe-delimited): origin|role|activity|stale|auth|artifact_state|format|decode
  VNC_FINDINGS="${VNC_FINDINGS}${_vp}|${_vrole}|${_vact}|${_vstale}|vnc_password|present|${_fmt}|${_dstate}
"
  add_lead "$_fsc" "VNC password file present ($_fmt): $_vp" "role=$_vrole activity=$_vact stale_possible=$_vstale auth_mode=vnc_password artifact_state=present format=$_fmt decode_state=$_dstate. $([ "$_fmt" = reversible_supported ] && echo '8=primary, 16=primary+view-only fixed-key DES.' || echo "$_vsz bytes is not a supported 8/16-byte fixed-key file -- NOT decoded.")$([ "$_vstale" = true ] && echo ' No running VNC server observed -- this secret may be stale (verify it maps to a live service before relying on it).') Waldo does not test/reuse." "VNC artifact at $_vp" "confirm the record; decode only supported reversible records with --decode-local-secrets" "credential-material" "credential" "$_vp" "vnc-passwd-file" "vnc-secret-$_fmt"
  if [ "$_fmt" = reversible_supported ] && [ "$DECODE_SECRETS" = 1 ] && [ -r "$_vp" ]; then
    _pt=$(vnc_decode_block "$_vp" 0)
    if [ -n "$_pt" ]; then jack "  VNC decode (primary): $([ "$NOCONTENT" = 1 ] && echo '[--no-content]' || printf '%s' "$_pt")"; add_lead 84 "[!!] VNC secret decoded: $_vp (primary)" "origin=$_vp scope=VNC-server-primary transformation=fixed-key-local-decode UNTESTED -- Waldo does not connect/reuse. Value: $([ "$NOCONTENT" = 1 ] && echo '[hidden]' || printf '%s' "$_pt")"; add_cred 'VNC primary (untested)' "$_vp"; fi
    if [ "$_vsz" = 16 ]; then
      _pt2=$(vnc_decode_block "$_vp" 8)
      [ -n "$_pt2" ] && { add_lead 82 "[!!] VNC secret decoded: $_vp (view-only)" "origin=$_vp scope=VNC-server-viewonly transformation=fixed-key-local-decode UNTESTED. Value: $([ "$NOCONTENT" = 1 ] && echo '[hidden]' || printf '%s' "$_pt2")"; add_cred 'VNC view-only (untested)' "$_vp"; }
    fi
    [ -z "$_pt" ] && ! have openssl && info "  (openssl not present -- pull $_vp and decode offline: DES-ECB, key e84ad660c4721ae0)"
  fi
done
[ "$_vnc_any" = 0 ] && info "No ~/.vnc/passwd VNC secret files found."
info "VNC role=$_vrole activity=$_vact signature-coverage: checked=$_vsig_checked present=$_vsig_present not_found=$_vsig_notfound denied=$_vsig_denied (empty = asserted absence across the checked paths, not an unrun probe)"
# v0.42 A5: publish observed role/activity + structured signature coverage for the JSON manifest.
VNC_ROLE=$_vrole; VNC_ACTIVITY=$_vact; VNC_SIG_CHECKED=$_vsig_checked; VNC_SIG_PRESENT=$_vsig_present; VNC_SIG_NOTFOUND=$_vsig_notfound; VNC_SIG_DENIED=$_vsig_denied
for h in /root /home/*; do
  [ -d "$h" ] || continue
  u=$(basename -- "$h")
  if [ ! -r "$h" ] || [ ! -x "$h" ]; then denied "$h  [no access]"; continue; fi
  info "$h  [readable]"
  for k in "$h"/.ssh/id_* "$h"/.ssh/*.pem "$h"/.ssh/authorized_keys "$h"/.putty/sessions/*; do
    [ -f "$k" ] || continue
    report "$k" "ssh"
    case "$k" in *.pub|*authorized_keys|*known_hosts) ;; */.ssh/id_*|*.pem) add_cred 'SSH private key' "$k";; */.putty/*) add_cred 'PuTTY saved session' "$k";; esac
  done
  for f in "$h"/.netrc "$h"/.pgpass "$h"/.git-credentials "$h"/.aws/credentials "$h"/.config/*/credentials* "$h"/.docker/config.json; do
    [ -f "$f" ] || continue
    report "$f" ""
    case "$f" in *.pgpass|*.netrc|*/credentials|*/.git-credentials) add_lead 78 "Credential store found: $f" "Stored creds/tokens -- read them; preserve each as an exact pair with its origin scope (see the credential-artifact rollup). Waldo does not test/reuse."; add_cred 'saved credential/token' "$f";; esac
  done
  for hf in "$h"/.bash_history "$h"/.zsh_history "$h"/.mysql_history "$h"/.psql_history "$h"/.ash_history "$h"/.sh_history; do analyze_history "$hf" "$u"; done
  while IFS= read -r kf; do [ -f "$kf" ] && { report "$kf" "$u"; add_lead 80 "Credential store: $kf" "Password-manager / browser / session vault -- exfil & crack (KeePass/PwSafe/1Password/Firefox/Chrome/mRemoteNG). Manual review."; add_cred 'password vault / saved session' "$kf"; }; done < <(find "$h" -maxdepth 4 \( -name '*.kdbx' -o -name '*.kdb' -o -name '*.psafe3' -o -name '*.opvault' -o -name '*.agilekeychain' -o -name '*.walletx' -o -name '*.env' -o -name 'logins.json' -o -name 'key4.db' -o -name 'signons.sqlite' -o -name 'confCons.xml' \) -type f 2>/dev/null | head -n 10)
  for sub in Desktop Documents Downloads; do
    p="$h/$sub"; [ -d "$p" ] || continue
    if [ -r "$p" ]; then n=$(ls -1A "$p" 2>/dev/null | wc -l); info "$u/$sub ($n items)"; else denied "$u/$sub [access denied]"; fi
  done
done

# =====================================================================
#  12. DEEP EXTRAS
# =====================================================================
if [ "$DEEP" = 1 ]; then
  head_ "Deep extras (-d)"
  sub "World-writable files under /etc /opt /usr/local /var/www"
  while IFS= read -r f; do jack "world-writable: $f"; done < <(find /etc /opt /usr/local /var/www -xdev -type f -perm -0002 2>/dev/null | head -n 60)
  sub "Config/secret files with grep hits"
  while IFS= read -r f; do
    if grep -IiqE "$SECRET_RE" "$f" 2>/dev/null; then waldo "$f"; peek "$f"; fi
  done < <(find /etc /opt /var/www /srv -xdev -type f \( -name '*.conf' -o -name '*.config' -o -name '*.ini' -o -name '*.env' -o -name '*.php' -o -name '*.py' \) 2>/dev/null | head -n 200)
  sub "NFS exports (no_root_squash = privesc)"
  if [ -r /etc/exports ]; then
    while IFS= read -r l; do case "$l" in *no_root_squash*) jack "$l"; add_lead 84 "NFS no_root_squash: $l" "Mount from your box, drop a SUID-root binary -- run it back on the target.";; *) waldo "$l";; esac; done < <(grep -vE '^\s*(#|$)' /etc/exports 2>/dev/null)
  fi
fi

# =====================================================================
#  LOGS / PROVISIONING EVIDENCE -- guest-agent, cloud-init, journal
# =====================================================================
fi
if want logs; then
head_ "Logs & provisioning evidence -- creds/flags leak into these"
_LOGPAT='guest-exec|qemu-ga|qemu-guest|cloud-init|cloudbase|waagent|sshpass|plink|proof\.txt|local\.txt|password[[:space:]]*[:=]'
sub "/var/log & provisioning files"
while IFS= read -r lf; do
  [ -f "$lf" ] && [ -r "$lf" ] || continue
  hits=$(grep -IiaE "$_LOGPAT" "$lf" 2>/dev/null | head -n 4)
  [ -z "$hits" ] && continue
  jack "log hit: $lf"
  printf '%s\n' "$hits" | while IFS= read -r hl; do say "         ${C_R}> $(printf '%.180s' "$hl")${C_RST}"; done
  add_lead 80 "Provisioning/log leak: $lf" "Guest-agent/cloud-init/setup log contains credential- or flag-shaped lines. Manual review."
  add_cred 'provisioning log secret' "$lf"
done < <(ls -1 /var/log/*.log /var/log/syslog /var/log/messages /var/log/auth.log /var/log/cloud-init*.log /var/lib/cloud/instance/*.log /var/log/qemu-ga.log /var/log/waagent.log 2>/dev/null | sort -u)
if have journalctl; then
  sub "journalctl search (capped, read-only)"
  jl=$(journalctl --no-pager 2>/dev/null | grep -IiaE "$_LOGPAT" | head -n 8)
  if [ -n "$jl" ]; then
    printf '%s\n' "$jl" | while IFS= read -r jhl; do jack "journal: $(printf '%.180s' "$jhl")"; done
    add_lead 80 "journalctl leaks creds/flag evidence" "systemd journal contains guest-agent/cloud-init/cred/flag lines. Manual review." "" "" "" "" "journal-cred-leak" "journal-log" "info-leak-journal"
    add_cred 'journal secret/flag reference' 'journalctl --no-pager'
  fi
fi

# =====================================================================
#  FLAG HUNT -- local.txt / proof.txt / flag.txt (the objective)
# =====================================================================
fi
if want flags; then
head_ "Flag hunt -- local.txt / proof.txt / flag.txt"
# v0.15 B5: STRUCTURED per-root search evidence -- record each declared search root's readability so 'not found'
# is backed by exactly WHERE Waldo looked (and where it could not). This drives the state; absence != asserted absence.
# v0.32 B5: per-root search with FULL bounds accounting -- depth, cap, cap-hit (TRUNCATED), recursive permission-denials,
# and status. `find ... 2>ERR` captures denials DEEP in the tree (not just root readability). A root is only 'complete'
# if it was readable, hit no recursive denial, and was not truncated at the cap. absence != asserted absence.
_flag_depth=6; _flag_cap=200; FLAG_SEARCH_EVIDENCE=""; _flag_partial=0
_btime=$(awk '/^btime/{print $2}' /proc/stat 2>/dev/null)   # system boot epoch -- for SUPERSEDED_AFTER_RESET reasoning
_ff_found=0; _flaglist=""
for _r in /root /home /opt /srv /var/www /usr/local/www /tmp; do
  if [ ! -d "$_r" ]; then FLAG_SEARCH_EVIDENCE="$FLAG_SEARCH_EVIDENCE ${_r}:absent"; continue; fi
  if [ ! -r "$_r" ] || [ ! -x "$_r" ]; then FLAG_SEARCH_EVIDENCE="$FLAG_SEARCH_EVIDENCE ${_r}:denied(root-unreadable)"; _flag_partial=1; continue; fi
  # v0.40: single-pass, NO temp file -- merge find's stdout (hits, ending in a flag name) and stderr (denials) into
  # one stream, then separate by content. Keeps the release invariant (no implicit target writes).
  # v0.41 COV: soft per-root DEADLINE (parity with the PowerShell flag search). A root that exceeds WALDO_DEADLINE is
  # recorded searched(...,TIMED_OUT) and flips the class to partial -- absence is never asserted from a truncated scan.
  if [ "$_DEADLINE_OK" = 1 ]; then
    _combined=$(timeout "$WALDO_DEADLINE" find "$_r" -maxdepth "$_flag_depth" \( -name 'local.txt' -o -name 'proof.txt' -o -name 'flag.txt' -o -name 'root.txt' -o -name 'user.txt' \) -type f 2>&1); _frc=$?
  else
    _combined=$(find "$_r" -maxdepth "$_flag_depth" \( -name 'local.txt' -o -name 'proof.txt' -o -name 'flag.txt' -o -name 'root.txt' -o -name 'user.txt' \) -type f 2>&1); _frc=0
  fi
  _res=$(printf '%s\n' "$_combined" | grep -E '/(local|proof|flag|root|user)\.txt$')
  _dn=$(printf '%s\n' "$_combined" | grep -ci 'permission denied')
  _cnt=$(printf '%s\n' "$_res" | grep -c .)
  _caphit=0; if [ "${_cnt:-0}" -gt "$_flag_cap" ]; then _caphit=1; _res=$(printf '%s\n' "$_res" | head -n "$_flag_cap"); fi
  _st="searched(d${_flag_depth},cap${_flag_cap}"; [ "${_dn:-0}" -gt 0 ] && { _st="${_st},recursive-denied:${_dn}"; _flag_partial=1; }; [ "$_caphit" = 1 ] && { _st="${_st},TRUNCATED"; _flag_partial=1; }; [ "$_frc" = 124 ] && { _st="${_st},TIMED_OUT"; _flag_partial=1; }; _st="${_st})"
  FLAG_SEARCH_EVIDENCE="$FLAG_SEARCH_EVIDENCE ${_r}:${_st}"
  [ -n "$_res" ] && _flaglist="$_flaglist
$_res"
done
_res=$(find / -maxdepth 1 \( -name 'local.txt' -o -name 'proof.txt' -o -name 'flag.txt' -o -name 'root.txt' -o -name 'user.txt' \) -type f 2>/dev/null)
FLAG_SEARCH_EVIDENCE="$FLAG_SEARCH_EVIDENCE /:searched(d1)"
[ -n "$_res" ] && _flaglist="$_flaglist
$_res"
_flaglist=$(printf '%s\n' "$_flaglist" | grep -v '^$' | sort -u)
while IFS= read -r ff; do
  [ -z "$ff" ] && continue
  _ff_found=1
  if [ -r "$ff" ]; then
    FLAG_STATE="FOUND_READABLE"
    jack "FLAG: $ff  (size $(wc -c < "$ff" 2>/dev/null))"
    add_lead 99 "Flag file: $ff" "The objective -- Waldo shows the value below, but capture the submission proof yourself: cat it in an interactive shell and screenshot with 'id' + 'ip a' in the same frame."
    note "   -> $(head -c 80 "$ff" 2>/dev/null)"
    # B5 SUPERSEDED_AFTER_RESET reasoning: report the flag's mtime vs boot so a value you noted BEFORE the file was (re)written is known-stale
    _fmt=$(stat -c %Y "$ff" 2>/dev/null)
    if [ -n "$_fmt" ] && [ -n "$_btime" ]; then
      if [ "$_fmt" -ge "$_btime" ]; then FLAG_SUPERSEDED=true; note "   mtime=$(date -d "@$_fmt" 2>/dev/null || echo "$_fmt"): written THIS boot -- any value you recorded before this is SUPERSEDED_AFTER_RESET (re-read). [structured: flag_superseded_after_reset=true]"
      else note "   mtime=$(date -d "@$_fmt" 2>/dev/null || echo "$_fmt"): predates boot -- baked into the image (stable across this boot)."; fi
    fi
  else
    [ "$FLAG_STATE" = "FOUND_READABLE" ] || FLAG_STATE="FOUND_DENIED"
    denied "FLAG (present, no read): $ff  [elevate or get a cred first]"
    _prim="${ROOT_PRIM_SHELL:-${ROOT_PRIM_WRITE:-$ROOT_PRIM_READ}}"
    _pkind=$([ -n "$ROOT_PRIM_SHELL" ] && echo shell || { [ -n "$ROOT_PRIM_WRITE" ] && echo write || echo read; })
    [ -n "$_prim" ] && add_lead 93 "Denied flag + local elevation primitive ($_pkind): $ff" "$ff is unreadable now, but a discovered local root primitive is available -- rule $_prim ($_pkind). Elevate with it (prefer shell > write > read), then read the flag. $([ "$_pkind" = read ] && echo 'NOTE: a read-only primitive can collect the flag but CANNOT prove absence.' || echo 'A read-only primitive cannot prove absence.')"
  fi
done <<EOF
$_flaglist
EOF
info "Flag search evidence:$FLAG_SEARCH_EVIDENCE"
if [ "$_ff_found" = 0 ]; then
  if [ "$_flag_partial" = 1 ]; then
    FLAG_STATE="SEARCH_PARTIAL"; info "Flag state: SEARCH_PARTIAL -- at least one root was denied at the root, hit a recursive permission-denial, or was TRUNCATED at the cap (see per-root evidence). Absence CANNOT be asserted; revisit after elevation or widen scope."
  else
    FLAG_STATE="NOT_FOUND_IN_DECLARED_SEARCH_SCOPE"; info "Flag state: NOT_FOUND_IN_DECLARED_SEARCH_SCOPE -- EVERY declared root completed within recorded bounds (depth $_flag_depth, cap $_flag_cap, no recursive denials, not truncated) + / (depth 1), no hit. denied != absent."
  fi
fi
# duplicate / case-variant grouping (e.g. /home/jack vs /home/Jack) -- treat as one objective
while IFS= read -r g; do
  [ -z "$g" ] && continue
  waldo "duplicate/case-variant flag paths: $g"
  add_lead 55 "Duplicate/case-variant flag paths" "$g -- likely one objective under case-variant/duplicate paths; treat as a single flag (compare size/hash if readable)." "" "" "" "" "duplicate-flag-paths" "flag-hunt" "flag-duplicate"
done < <(printf '%s' "$_flaglist" | awk 'NF{lc=tolower($0); grp[lc]=grp[lc]"  "$0; cnt[lc]++} END{for(k in cnt) if(cnt[k]>1){sub(/^  /,"",grp[k]); print grp[k]}}')
# denied accounting -- user areas we can't read (a flag may be owed there)
_owed=""
for h in /root /home/*; do
  [ -d "$h" ] || continue
  u=$(basename -- "$h")
  for d in "$h" "$h/Desktop" "$h/Documents"; do
    [ -e "$d" ] && [ ! -r "$d" ] && _owed="$_owed ${u}/$(basename -- "$d")"
  done
done
[ -n "$_owed" ] && { denied "PENDING (denied -- flag may be owed):$_owed"; add_lead 50 "Flags PENDING in denied areas" "Cannot read:$_owed -- denied != cleared; revisit after elevation or with a cred." "" "" "" "" "flags-pending-denied" "flag-hunt" "flag-denied"; }

# =====================================================================
fi
#  RECONCILIATION -- re-check buffered history/log lines vs the FINAL flagged-binary set
#  (catches a binary flagged AFTER its usage line was already read)
# =====================================================================
if [ -n "$HIST_BUF" ] && [ -n "$(printf '%s' "$FLAGGED_BINS" | tr -d ' ')" ]; then
  head_ "Late correlation -- flagged tools used in earlier history/logs"
  _rec=0
  while IFS="$TAB" read -r hsrc hline; do
    [ -z "$hline" ] && continue
    for tok in $hline; do case "$tok" in */*) tb=$(basename -- "$tok");; *) tb="$tok";; esac
      is_flagged_bin "$tb" && { _rec=1; jack "[$hsrc] runs flagged '$tb': $(printf '%.180s' "$hline")"; add_lead 88 "Flagged tool '$tb' used (reconciled from $hsrc)" "$hline -- a binary flagged elsewhere this run is invoked here; any argument (positional password) is high-signal. Manual review."; break; }
    done
  done < <(printf '%s' "$HIST_BUF")
  [ "$_rec" = 0 ] && info "No buffered history/log line referenced a flagged binary."
fi

# v2.18 C1: DB credential + local DB listener + local privilege primitive -> one chain card (Waldo never connects/dumps)
if [ -n "$DB_CRED_HINT" ] && [ -n "$DB_LISTENER" ]; then
  head_ "DB access correlation -- creds + a local database"
  jack "DB credential(s) in config + local DB listener present"
  add_lead 86 "DB creds + local DB listener -> mine the DB manually" "Config(s) with DB creds:$DB_CRED_HINT ; local DB listener(s):$DB_LISTENER. You hold creds AND a reachable local DB -- connect and enumerate it manually (users / password / hash / token columns). If the DB role is a superuser, engine features (Postgres COPY ... PROGRAM / extension load, MySQL UDF) are a documented local-privesc path. Manual review -- no exploit run, Waldo does not connect." "" "" "" "" "db-creds-local-listener" "local-database" "credential-store-local-db"
  # v0.34 C1: the strong chain REQUIRES all four local facts -- listener + matching DB SERVICE IDENTITY (a live local
  # DB process) + locally-evidenced privileged role + local primitive. A missing service identity drops to the weaker card.
  _dbrole=""; for _hf in $DB_CRED_HINT; do _dbrole=$(db_priv_role "$_hf"); [ -n "$_dbrole" ] && break; done
  _pg_svc=$(pgrep -x postgres >/dev/null 2>&1 && echo "postgres (process)" || { pgrep -f 'bin/postgres' >/dev/null 2>&1 && echo "postgres (process)"; })
  _my_svc=$(pgrep -xE 'mysqld|mariadbd' >/dev/null 2>&1 && echo "$(pgrep -xE 'mysqld|mariadbd' | head -1 | xargs -r ps -o comm= -p 2>/dev/null) (process)")
  case "$DB_LISTENER" in
    *5432*) if printf '%s' "$DB_SUDO" | grep -q psql; then
              if [ -n "$_dbrole" ] && [ -n "$_pg_svc" ]; then add_lead 90 "PostgreSQL -> root chain (listener + service $_pg_svc + superuser cred + sudo psql)" "Local PostgreSQL listener + a LIVE local postgres service ($_pg_svc) + config credential naming a PRIVILEGED role ($_dbrole) + NOPASSWD sudo psql ($DB_SUDO). Documented chain: DB SUPERUSER -> 'COPY ... FROM PROGRAM' as the postgres service user -> NOPASSWD sudo psql escapes to root (\\! sh). Manual review -- Waldo does not connect." "" "" "" "" "postgres-root-chain" "postgres-service" "privesc-db-chain"
              else add_lead 72 "PostgreSQL: listener + sudo psql (chain needs: $([ -z "$_pg_svc" ] && echo 'a live local postgres service; ')$([ -z "$_dbrole" ] && echo 'superuser role evidence')confirm locally)" "Local PostgreSQL listener + NOPASSWD sudo psql, but the strong chain REQUIRES a matching LIVE postgres service identity AND a locally-evidenced superuser role. Missing: $([ -z "$_pg_svc" ] && echo 'service-identity ')$([ -z "$_dbrole" ] && echo 'superuser-role'). Establish those locally first. Manual review -- Waldo does not connect."; fi
            fi;;
    *3306*) if printf '%s' "$DB_SUDO" | grep -qE 'mysql'; then
              if [ -n "$_dbrole" ] && [ -n "$_my_svc" ]; then add_lead 88 "MySQL/MariaDB -> root chain (listener + service $_my_svc + privileged cred + sudo mysql)" "Local MySQL listener + a LIVE local $_my_svc + config credential naming a PRIVILEGED role ($_dbrole) + NOPASSWD sudo mysql ($DB_SUDO). With FILE/SUPER (or root@localhost), a UDF or 'sudo mysql' shell escape (\\! sh) is a documented root path. Manual review -- Waldo does not connect." "" "" "" "" "mysql-root-chain" "mysql-service" "privesc-db-chain"
              else add_lead 72 "MySQL: listener + sudo mysql (chain needs a live mysqld service + FILE/SUPER/root role)" "Local MySQL listener + NOPASSWD sudo mysql, but the strong chain REQUIRES a matching LIVE mysqld/mariadbd service AND a privileged DB role. Missing: $([ -z "$_my_svc" ] && echo 'service-identity ')$([ -z "$_dbrole" ] && echo 'privileged-role'). Establish those locally first. Manual review -- Waldo does not connect."; fi
            fi;;
  esac
fi

# v0.34 C5: DATA-DRIVEN relationship vocabulary -- each row fires ONLY when its REQUIRED TYPED facts all exist (no
# hypothesis-only cards). Typed facts computed once below; the _c5 rule table evaluates each vocabulary row.
_ncred=${#CRED_RECORDS[@]}
_seg2=$({ [ "${_wn:-0}" -ge 2 ] || [ "${_routed_extra:-0}" = 1 ]; } && echo 1 || echo 0)
_prim="${ROOT_PRIM_SHELL:-${ROOT_PRIM_WRITE:-$ROOT_PRIM_READ}}"
_wprim="$ROOT_PRIM_WRITE"                          # execution-setting write primitive (writable service/cron/unit target)
# saved-endpoint FACT: a saved session / known-host / client config that references a REMOTE host (NOT just any credential)
_saved=$(printf '%s\n' "${CRED_RECORDS[@]}" 2>/dev/null | grep -ciE '^[^|]*(saved.?session|known.?hosts|ssh.?config|\.rdp|winscp|putty|filezilla|remote.?server|sitemanager|recentservers)')
_c5(){ [ "$1" = 1 ] && [ "$2" = 1 ] && add_lead "$3" "$4" "$5" "" "" "" "" "$(printf '%s' "$4" | sed 's/^relationship: //')" "c5-relationship-engine" "typed-relationship"; }
# vocabulary row: SAVED ENDPOINT -> newly reachable segment (narrowed from the old any-credential+any-segment join)
_c5 "$([ "${_saved:-0}" -gt 0 ] && echo 1 || echo 0)" "$_seg2" 64 "relationship: saved endpoint -> newly reachable segment" "You hold $_saved SAVED-ENDPOINT artifact(s) (saved session / known-host / client config referencing a REMOTE host) AND this box reaches another segment -- those endpoints likely live on the adjacent segment. Preserve each exact pair with its origin scope, tunnel from here, and re-run Waldo from a foothold there. Waldo tests nothing."
# vocabulary row: EXECUTION SETTING -> writable referenced path -> effective ACL (a write primitive on a root-run target)
_c5 "$([ -n "$_wprim" ] && echo 1 || echo 0)" 1 63 "relationship: execution setting -> writable path -> root exec" "A root-run execution setting references a path you can WRITE ($_wprim) -- the effective ACL grants you write, so replacing/appending that path runs as root at its next trigger. Confirm the trigger; Waldo writes nothing."
# C5: fire ONLY on an actual match -- a DB-credential config (DB_CRED_HINT) paired with a local DB listener, not any cred + any listener.
# C5: type BOTH sides by ENGINE and require a MATCH -- a MySQL cred config must not pair with a PostgreSQL/MSSQL listener.
_dbc_eng=""; for _hf in $DB_CRED_HINT; do [ -r "$_hf" ] || continue
  grep -qiE 'mysql|mariadb|:3306|jdbc:mysql' "$_hf" 2>/dev/null && _dbc_eng="$_dbc_eng mysql"
  grep -qiE 'postgres|pgsql|:5432|jdbc:postgresql' "$_hf" 2>/dev/null && _dbc_eng="$_dbc_eng postgres"
  grep -qiE 'mssql|sqlserver|sql server|:1433|data source=' "$_hf" 2>/dev/null && _dbc_eng="$_dbc_eng mssql"
done
_dbl_eng=""; case "$DB_LISTENER" in *3306*) _dbl_eng="$_dbl_eng mysql";; esac; case "$DB_LISTENER" in *5432*) _dbl_eng="$_dbl_eng postgres";; esac; case "$DB_LISTENER" in *1433*) _dbl_eng="$_dbl_eng mssql";; esac
_dbmatch=0; _dbe=""; for _e in $_dbc_eng; do case " $_dbl_eng " in *" $_e "*) _dbmatch=1; _dbe="$_e"; break;; esac; done
_c5 "$_dbmatch" 1 60 "relationship: $_dbe credential config -> matching local $_dbe listener" "A config with $_dbe credentials AND a local $_dbe listener (same engine) are BOTH present -- read the DB locally (it often holds crackable creds) before any remote guessing. Waldo does not connect."
_c5 "$([ "$FLAG_STATE" = FOUND_DENIED ] && echo 1 || echo 0)" "$([ -n "$_prim" ] && echo 1 || echo 0)" 66 "relationship: denied objective -> available privilege primitive" "A flag is present-but-denied AND a local root primitive was found ($_prim) -- elevate with it, then read the flag. Waldo runs nothing."
_c5 "${_routed_extra:-0}" 1 62 "relationship: route -> non-attached network" "This host routes to a non-attached network -- tunnel and re-run Waldo from a foothold on that segment. Waldo does not scan."
# vocabulary row: PRODUCER PATH -> CONSUMER NAMESPACE VISIBILITY (confused-deputy). v0.46 §7 (auditor fix): DEMOTED to
# UNSCORED CONTEXT. A scored C5 relationship requires an EXACT controlled producer path AND local evidence that the
# named privileged consumer resolves/uses that same path. Waldo does not collect that path/use fact safely, so
# "reachable broker shares your view + some unrelated write primitive" is a hypothesis-only join -- which C5 forbids as
# a SCORED lead. It is surfaced as CONTEXT only (a note, no score) until the exact path+use fact is collectable.
_c5_consumer_visible=$({ [ "${_pkreach_self:-0}" = 1 ] && [ "${_pkns_mismatch:-0}" = 0 ] && [ -n "${_cons_ns:-}" ]; } && echo 1 || echo 0)
if [ "$_c5_consumer_visible" = 1 ] && [ -n "$_wprim" ]; then
  note "context (NOT a scored relationship): a reachable privileged broker shares your filesystem view and you hold a write primitive ($_wprim). IF you can identify an EXACT path that broker reads/writes which you also control, that is a confused-deputy path -- but Waldo has NOT proven that exact path+use, so this stays context, not a scored lead."
fi

# host-role inference -- name what this box is for
if [ -z "$LOOT" ]; then
  _roles=""; _ev=""
  { pgrep -xE 'apache2|httpd|nginx' >/dev/null 2>&1 || [ -d /var/www ]; } && { _roles="$_roles web-server"; _ev="$_ev http"; }
  { pgrep -xE 'mysqld|mariadbd' >/dev/null 2>&1 || printf '%s' "$LP" 2>/dev/null | grep -q ':3306 '; } && { _roles="$_roles mysql-db"; _ev="$_ev 3306"; }
  { pgrep -x postgres >/dev/null 2>&1 || printf '%s' "$LP" 2>/dev/null | grep -q ':5432 '; } && { _roles="$_roles postgres-db"; _ev="$_ev 5432"; }
  pgrep -xE 'postfix|dovecot|exim4|exim|sendmail' >/dev/null 2>&1 && { _roles="$_roles mail"; _ev="$_ev smtp/imap"; }
  pgrep -x smbd >/dev/null 2>&1 && { _roles="$_roles samba-fileserver"; _ev="$_ev smbd"; }
  { pgrep -x nfsd >/dev/null 2>&1 || [ -r /etc/exports ]; } && { _roles="$_roles nfs-server"; _ev="$_ev exports"; }
  pgrep -x named >/dev/null 2>&1 && { _roles="$_roles dns"; _ev="$_ev named"; }
  pgrep -xE 'dockerd|containerd|lxd' >/dev/null 2>&1 && { _roles="$_roles container-host"; _ev="$_ev docker/lxd"; }
  if [ -n "$_roles" ]; then
    head_ "Host role inference (what this box is for)"
    info "Inferred role(s):$_roles   [evidence:$_ev]"
    add_lead 48 "Host role:$_roles" "Evidence:$_ev. Role tells you which local files matter most (web configs / DB dumps / mail stores / exports). Manual review." "" "" "" "" "host-role" "host" "host-role-inference"
  fi
  # credential cross-match -- does a discovered secret name a REAL local account?
  _lu=$(awk -F: '$3>=1000 && $3<65534 && $1!="nobody" {print $1}' /etc/passwd 2>/dev/null)
  if [ "${#CRED_ARTIFACTS[@]}" -gt 0 ] && [ -n "$_lu" ]; then
    _xm=""
    for u in $_lu; do
      [ "${#u}" -ge 3 ] || continue
      if printf '%s\n' "${CRED_ARTIFACTS[@]}" | grep -iwqF "$u"; then _xm="$_xm $u"; fi
    done
    if [ -n "$_xm" ]; then
      head_ "Credential cross-match (discovered secret <-> real local account)"
      info "Correlation only -- Waldo tests nothing."
      for u in $_xm; do jack "a discovered secret references local user '$u'"; done
      add_lead 74 "Credential cross-match (secret names a real local account)" "Discovered secret(s) name real local account(s):$_xm. Preserve each as an exact principal/secret pair with its origin scope; corroborate before crossing scope. Waldo tests/reuses nothing." "" "" "" "" "credential-cross-match" "local-account" "credential-corroboration"
    fi
  fi
fi

# =====================================================================
#  CREDENTIAL ARTIFACTS -- clean handoff list (NO spraying/testing done)
# =====================================================================
head_ "Credential artifacts -- collect + crack offline; each tagged with scope + tested=false (Waldo never sprays/validates)"
if [ "${#CRED_ARTIFACTS[@]}" -eq 0 ]; then
  info "None surfaced from here."
else
  info "Handoff by type: NTLM -> pass-the-hash OR crack; DCC2/TGS/AS-REP/bcrypt/unix-crypt -> crack-only; cleartext -> scope=unknown until corroborated (Waldo does not spray/test)."
  printf '%s\n' "${CRED_ARTIFACTS[@]}" | sort -u | while IFS= read -r ca; do say "  ${C_C}* ${ca}${C_RST}"; done
fi

# =====================================================================
#  TOP WALDO LEADS + COVERAGE (v2.16 COV) -- interrupt-safe footer
# =====================================================================
_SCAN_COMPLETED=1
print_footer

head_ "Done"
info "Leads are ranked guesses -- confirm each manually. Run LinPEAS alongside for full coverage."
if [ -n "$OUTFILE" ]; then _ofsz=$( (wc -c < "$OUTFILE" 2>/dev/null) | tr -d ' ' ); say "${C_C}Saved -> $OUTFILE (${_ofsz:-0} bytes -- confirm non-zero before you retrieve/move on)${C_RST}"; fi
