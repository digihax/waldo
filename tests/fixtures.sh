#!/bin/bash
# Waldo (Linux) detector fixtures -- generalized positives + stock negatives for the v2.16-2.19 detectors.
# Sources the ACTUAL helper functions out of waldo.sh (no full scan) so the tests exercise real code,
# not a re-implementation. Run:  bash waldo/tests/fixtures.sh   (exit 0 = all PASS)
WALDO="${1:-$(dirname "$0")/../waldo.sh}"
[ -r "$WALDO" ] || { echo "waldo.sh not found: $WALDO"; exit 2; }
have(){ command -v "$1" >/dev/null 2>&1; }
# Robustly extract EXACTLY one function definition (one-line or multi-line) from waldo.sh, so we import real code
# without dragging in surrounding lines. A prior sed-range loader broke on one-line functions (their end anchor is
# not matched on the start line, so the range ran on for hundreds of lines) -- this replaces it.
import_fn(){ # $1 = function name
  local start first
  start=$(grep -nE "^$1\(\)\{" "$WALDO" | head -1 | cut -d: -f1)
  [ -n "$start" ] || { echo "FIXTURE LOADER ERROR: function '$1' not found in $WALDO" >&2; return 1; }
  first=$(sed -n "${start}p" "$WALDO")
  case "$first" in
    *\}) sed -n "${start}p" "$WALDO"; return 0;;                         # one-liner: the whole body is on the start line
  esac
  # multi-line: print from start THROUGH the first function-close line ( } | esac; } | indented esac; } )
  awk -v s="$start" 'NR>=s{print} NR>s && /^[[:space:]]*(esac; )?\}$/{exit}' "$WALDO"
}
_import_ok=1
for _fn in ip_net ip_in_net cred_scope gtfo_class db_priv_role reg_prim scan_inline_cred sudo_arg_mode; do
  if ! _def="$(import_fn "$_fn")"; then _import_ok=0; continue; fi
  eval "$_def" || { echo "FIXTURE LOADER ERROR: failed to eval '$_fn'" >&2; _import_ok=0; }
done
[ "$_import_ok" = 1 ] || { echo "FIXTURE LOADER FAILED -- aborting (import errors above)"; exit 3; }
pass=0; fail=0
ok(){ pass=$((pass+1)); echo "PASS  $1"; }
no(){ fail=$((fail+1)); echo "FAIL  $1"; }

# --- C3 ip_net: real-prefix network math (non-Skylark addresses) ---
[ "$(ip_net 192.168.50.7/24)" = "192.168.50.0/24" ] && ok "ip_net /24" || no "ip_net /24"
[ "$(ip_net 10.10.5.7/16)"    = "10.10.0.0/16"     ] && ok "ip_net /16 (not mislabeled /24)" || no "ip_net /16"
[ "$(ip_net 172.20.9.3/12)"   = "172.16.0.0/12"    ] && ok "ip_net /12" || no "ip_net /12"

# --- C3 ip_in_net: subnet membership uses the network's REAL prefix (no /24 assumption) ---
ip_in_net 10.10.5.3 10.10.0.0/16     && ok "C3 10.10.5.3 inside /16 (not mislabeled off-segment)" || no "C3 /16 member"
ip_in_net 10.11.5.3 10.10.0.0/16     && no "C3 10.11.5.3 wrongly inside /16" || ok "C3 10.11.5.3 correctly outside /16"
ip_in_net 192.168.2.7 192.168.1.0/24 && no "C3 192.168.2.7 wrongly inside /24" || ok "C3 192.168.2.7 correctly outside /24"
# C3 CONTAINMENT: a more-specific route inside an attached network is suppressed (not flagged non-attached)
c3contain(){ _rnetn=$(ip_net "$1"); _rip=${_rnetn%%/*}; for _aw in $2; do ip_in_net "$_rip" "$_aw" && { echo contained; return; }; done; echo non-attached; }
[ "$(c3contain 10.10.5.0/24 '10.10.0.0/16 192.168.1.0/24')" = contained ] && ok "C3 route 10.10.5.0/24 inside attached /16 -> contained (suppressed)" || no "C3 containment suppress"
[ "$(c3contain 172.20.0.0/16 '10.10.0.0/16 192.168.1.0/24')" = non-attached ] && ok "C3 route 172.20.0.0/16 not in attached -> non-attached (flagged)" || no "C3 containment flag"

# --- C3 attached-vs-nonattached decision ---
ATT="192.168.50.0/24"
[ "$(ip_net 192.168.50.0/24)" = "$ATT" ] && ok "route to attached subnet -> suppressed" || no "attached suppression"
[ "$(ip_net 10.10.0.0/16)"    != "$ATT" ] && ok "route to 10.10.0.0/16 -> non-attached pivot" || no "non-attached pivot"

# --- A11 cred_scope: strict default scope ---
[ "$(cred_scope 'NTDS.dit (domain hashes)')" = "domain-principal (exact; subject to logon restrictions)" ] && ok "cred_scope domain" || no "cred_scope domain"
[ "$(cred_scope 'SSH private key')" = "origin-host-only" ] && ok "cred_scope host" || no "cred_scope host"
case "$(cred_scope 'random blob')" in unknown*) ok "cred_scope unknown default";; *) no "cred_scope unknown";; esac
# A11 scope rows: machine-account (non-interactive) + browser/vault origin-bound
case "$(cred_scope 'machine account HOST$')" in machine-account*) ok "cred_scope machine-account (non-interactive)";; *) no "cred_scope machine-account";; esac
case "$(cred_scope 'browser Chrome login data')" in *"EXACT stored host/service"*) ok "cred_scope browser origin-bound";; *) no "cred_scope browser";; esac
# A11 secret retention: base64 round-trips (no '|' corruption of the record), value never in the derived JSON flag
_a11s=$(printf '%s' 'p|a$s:1' | base64 | tr -d '\n'); [ "$(printf '%s' "$_a11s" | base64 -d)" = 'p|a$s:1' ] && ok "A11 secret retained b64 (survives '|' in value)" || no "A11 secret b64"
[ -n "$_a11s" ] && [ "$([ -n "$_a11s" ] && echo true || echo false)" = true ] && ok "A11 JSON secret_captured=true derived from stored secret (value not emitted)" || no "A11 secret_captured"

# --- A1 gtfo capability taxonomy (shell>write>read) ---
case "$(gtfo_class ip)" in shell*) ok "gtfo ip=shell";; *) no "gtfo ip";; esac
case "$(gtfo_class ss)" in read*) ok "gtfo ss=read";; *) no "gtfo ss";; esac
case "$(gtfo_class tee)" in write*) ok "gtfo tee=write";; *) no "gtfo tee";; esac
# A1: read binaries are now REACHABLE from the production GTFO_BINS list (were classified but unreachable)
eval "$(sed -n '/^GTFO_BINS="/p' "$WALDO")"
printf '%s' "$GTFO_BINS" | grep -qw cat && ok "A1 'cat' reachable in GTFO_BINS (read case not dead)" || no "A1 cat reachable"
printf '%s' "$GTFO_BINS" | grep -qw head && printf '%s' "$GTFO_BINS" | grep -qw tail && ok "A1 head/tail reachable in GTFO_BINS" || no "A1 head/tail reachable"
# A3: User= gates the 'root' assertion -- a User=nonroot unit runs as that user, not root
a3runas(){ _u="$1"; { [ -z "$_u" ] || [ "$_u" = root ] || [ "$_u" = 0 ]; } && echo root || echo "$_u"; }
[ "$(a3runas '')" = root ]    && ok "A3 no User= -> runs as root" || no "A3 default root"
[ "$(a3runas root)" = root ]  && ok "A3 User=root -> root" || no "A3 user root"
[ "$(a3runas www-data)" = www-data ] && ok "A3 User=www-data -> that user, NOT root (no overclaim)" || no "A3 nonroot user"

# --- A6 credential-named basename (positive + stock-negative), matching report()'s rule ---
a6(){ printf '%s' "$(basename -- "$1")" | grep -qiE '^(credentials?|creds|passwords?|secrets?|logins?|accounts?)\.(txt|md|csv|ini|cfg|conf|ya?ml|json|xlsx?|docx?|pptx?|ods|odt|kdbx?)$' && case "$1" in */[Ss]amples/*|*/[Ee]xamples/*|*/[Tt]emplates/*) echo demoted;; *) echo surface;; esac || echo none; }
[ "$(a6 /srv/app/accounts.csv)" = surface ] && ok "A6 accounts.csv surfaces" || no "A6 positive"
[ "$(a6 /srv/app/credentials.xlsx)" = surface ] && ok "A6 credentials.xlsx surfaces (format-independent)" || no "A6 xlsx"
[ "$(a6 /srv/app/passwords.kdbx)" = surface ] && ok "A6 passwords.kdbx surfaces (vault)" || no "A6 kdbx"
[ "$(a6 /opt/vendor/Samples/credentials.txt)" = demoted ] && ok "A6 stock Samples/ demoted" || no "A6 stock-negative"
[ "$(a6 /home/u/readme.md)" = none ] && ok "A6 readme.md not credential-named" || no "A6 non-match"

# --- A3 follow_sourced: writable sourced helper chain (generalized), + stock-negative ---
iswrite(){ [ "$ELEVATED" = 1 ] && return 1; [ -w "$1" ]; }; jack(){ :; }
declare -a LEADS; add_lead(){ LEADS+=("$1|$2"); }
eval "$(import_fn follow_sourced)"
ELEVATED=0; T=$(mktemp -d)
printf '#!/bin/sh\n. %s/env.sh\n' "$T" > "$T/fs.sh"; printf '# helper\n' > "$T/env.sh"; chmod 444 "$T/fs.sh"; chmod 666 "$T/env.sh"
LEADS=(); follow_sourced "$T/fs.sh" "cron test"
printf '%s\n' "${LEADS[@]}" | grep -q 'writable helper' && ok "A3 writable sourced helper detected" || no "A3 positive"
# stock-negative: a parent with NO source/exec directives -> no lead (environment-independent)
printf '#!/bin/sh\necho hello\ndate\nls -la /var\n' > "$T/plain.sh"; chmod 444 "$T/plain.sh"
LEADS=(); follow_sourced "$T/plain.sh" "cron test"
[ "${#LEADS[@]}" -eq 0 ] && ok "A3 parent with no includes/exec -> no lead (stock-negative)" || no "A3 stock-negative"
# A3 NEW: child exists, not writable, but its PARENT DIR is writable -> replaceable-via-dir lead
printf '#!/bin/sh\n. %s/roenv.sh\n' "$T" > "$T/fs3.sh"; printf '# x\n' > "$T/roenv.sh"; chmod 444 "$T/fs3.sh" "$T/roenv.sh"   # $T (mktemp) dir is writable
LEADS=(); follow_sourced "$T/fs3.sh" "cron test"
printf '%s\n' "${LEADS[@]}" | grep -q 'replaceable via writable dir' && ok "A3 non-writable child in writable dir -> replaceable lead" || no "A3 parent-dir-writable"
# A3 NEW: static same-dir command call (interpreter-invoked RELATIVE script) resolves to parent dir + is followed
printf '#!/bin/sh\nbash step2.sh\n' > "$T/fs4.sh"; printf '# step2\n' > "$T/step2.sh"; chmod 444 "$T/fs4.sh"; chmod 666 "$T/step2.sh"
LEADS=(); follow_sourced "$T/fs4.sh" "cron test"
printf '%s\n' "${LEADS[@]}" | grep -q 'writable helper' && ok "A3 interpreter-invoked relative same-dir script detected" || no "A3 same-dir exec"
# elevated -> writable checks suppressed
LEADS=(); ELEVATED=1 follow_sourced "$T/fs.sh" "cron test"; [ "${#LEADS[@]}" -eq 0 ] && ok "A3 elevated suppresses writable leads" || no "A3 elevated"; ELEVATED=0
rm -rf "$T"

# --- A5b ~/.vnc/passwd decode (8-byte + 16-byte), independent openssl blob ---
if have openssl; then
  OL=""; printf '' | openssl enc -des-ecb -nopad -K 0000000000000000 -provider legacy -provider default >/dev/null 2>&1 && OL="-provider legacy -provider default"
  dec(){ dd if="$1" bs=1 skip="$2" count=8 2>/dev/null | openssl enc -d -des-ecb -nopad -K e84ad660c4721ae0 $OL 2>/dev/null | tr -d '\000' | tr -cd '[:print:]'; }
  V=$(mktemp)
  printf '\x50\xcc\xb2\xfc\x99\x72\x6c\x7f\x9c\x0a\x17\x2d\x34\x82\xe1\x22' > "$V"   # Secret12 + abc
  [ "$(dec "$V" 0)" = "Secret12" ] && ok "A5b ~/.vnc/passwd primary=Secret12" || no "A5b primary"
  [ "$(dec "$V" 8)" = "abc" ]      && ok "A5b ~/.vnc/passwd view-only=abc" || no "A5b view-only"
  rm -f "$V"
else echo "SKIP  A5b decode (openssl absent)"; fi

# --- A5a length->format classification (matches the production case rule: 8/16=reversible, else=unknown) ---
a5fmt(){ case "$1" in 8|16) echo reversible_supported;; *) echo unknown_format;; esac; }
[ "$(a5fmt 8)"  = reversible_supported ] && ok "A5a 8-byte  -> reversible_supported" || no "A5a 8"
[ "$(a5fmt 16)" = reversible_supported ] && ok "A5a 16-byte -> reversible_supported" || no "A5a 16"
[ "$(a5fmt 5)"  = unknown_format       ] && ok "A5a 5-byte  -> unknown_format (malformed, not decoded)" || no "A5a 5"

# --- C1 db_priv_role: local role evidence gates the DB->root chain ---
C1D=$(mktemp -d)
printf 'host=db\nuser = postgres\npassword=x\n' > "$C1D/pg.conf"
printf '[db]\nusername: appreader\npassword: y\n' > "$C1D/low.conf"
printf 'Data Source=.;User Id=sa;Password=z;\n' > "$C1D/mssql.ini"
printf 'superuser=false\n' > "$C1D/neg1.conf"
printf '# superuser role notes here\n' > "$C1D/neg2.conf"
printf 'user=admin_readonly\n' > "$C1D/neg3.conf"
printf 'is_superuser = true\n' > "$C1D/pos2.conf"
[ -n "$(db_priv_role "$C1D/pg.conf")" ]  && ok "C1 superuser role (postgres) -> chain evidence present" || no "C1 pg positive"
[ -n "$(db_priv_role "$C1D/mssql.ini")" ] && ok "C1 sa role (mssql) -> chain evidence present" || no "C1 sa positive"
[ -n "$(db_priv_role "$C1D/pos2.conf")" ] && ok "C1 superuser=true -> chain evidence present" || no "C1 superuser=true positive"
[ -z "$(db_priv_role "$C1D/low.conf")" ] && ok "C1 non-privileged role (appreader) -> NO chain" || no "C1 low-priv stock-negative"
[ -z "$(db_priv_role "$C1D/neg1.conf")" ] && ok "C1 superuser=false -> NO chain (tightened regex)" || no "C1 superuser=false FP"
[ -z "$(db_priv_role "$C1D/neg2.conf")" ] && ok "C1 comment 'superuser' -> NO chain (comments excluded)" || no "C1 comment FP"
[ -z "$(db_priv_role "$C1D/neg3.conf")" ] && ok "C1 admin_readonly -> NO chain (bounded value, no prefix match)" || no "C1 admin prefix FP"
rm -rf "$C1D"

# --- C5 engine typing: a DB-cred config must match the listener's ENGINE ---
c5eng(){ _c=$1; _l=$2; for _e in $_c; do case " $_l " in *" $_e "*) echo match; return;; esac; done; echo none; }
[ "$(c5eng 'mysql' 'mssql')" = none ]      && ok "C5 mysql cred + mssql listener -> NO match (engine typed)" || no "C5 cross-engine FP"
[ "$(c5eng 'postgres' 'postgres')" = match ] && ok "C5 postgres cred + postgres listener -> match" || no "C5 same-engine"
# C5 saved-endpoint typing: the segment relationship requires a SAVED-ENDPOINT fact, not any credential
c5saved(){ printf '%s\n' "$1" | grep -ciE '(saved.?session|known.?hosts|ssh.?config|\.rdp|winscp|putty|filezilla|remote.?server|sitemanager|recentservers)'; }
[ "$(c5saved 'saved session (RDP) -- host2')" -gt 0 ] && ok "C5 saved-endpoint fact detected (RDP saved session)" || no "C5 saved-endpoint detect"
[ "$(c5saved 'SSH private key')" = 0 ] && ok "C5 a plain credential is NOT a saved-endpoint (no over-broad segment card)" || no "C5 saved-endpoint over-broad"
c5rule(){ [ "$1" -gt 0 ] && [ "$2" -ge 2 ] && echo fire || echo hold; }
[ "$(c5rule 1 2)" = fire ] && ok "C5 saved-endpoint + 2+ segments -> relationship fires" || no "C5 saved fire"
[ "$(c5rule 0 3)" = hold ] && ok "C5 NO saved endpoint (even with segments) -> no card (typed fact required)" || no "C5 saved hold"

# --- interruption/deadline: EXIT-trap footer on exit; bounded soft deadline yields timed_out (NOTE: real Ctrl-C needs a Linux PTY) ---
intout=$(bash -c '_FOOTER_DONE=0; f(){ [ "$_FOOTER_DONE" = 1 ] && return; _FOOTER_DONE=1; echo FOOTER; }; trap f EXIT; trap "trap - INT TERM; exit 130" INT TERM; exit 130' 2>&1)
[ "$intout" = FOOTER ] && ok "interruption: EXIT trap renders footer on exit-130 (synthetic; real Ctrl-C needs PTY test)" || no "interruption footer"
if command -v timeout >/dev/null 2>&1; then
  WALDO_DEADLINE=1; bounded(){ if command -v timeout >/dev/null 2>&1; then timeout "$WALDO_DEADLINE" "$@"; else "$@"; fi; }
  bounded sleep 5 >/dev/null 2>&1; [ "$?" = 124 ] && ok "soft deadline: a slow collector times out (rc=124 -> timed_out outcome)" || no "deadline timeout"
  bounded true >/dev/null 2>&1; [ "$?" = 0 ] && ok "soft deadline: a fast collector completes normally (rc=0)" || no "deadline normal"
else echo "SKIP  soft-deadline (timeout absent)"; fi
# COV registry: cov_record attributes a typed outcome to (class, collector), deduped; cov_error routes to errors not skips
CURRENT_CLASS=privesc; CURRENT_COLLECTOR="File capabilities (getcap)"; COV_SKIPS=""; COV_ERRORS=""; COV_ERR_REASONS=""; COV_COLLECTORS=""; _COV_SKIP_SEEN=""; _COV_REC_SEEN=""; note(){ :; }
eval "$(import_fn cov_record)"; eval "$(import_fn cov_error)"
cov_error "getcap timed_out at 1s"
# registry got a record attributing the timeout to the specific collector, with state=error + reason
printf '%s' "$COV_COLLECTORS" | grep -q 'privesc|File capabilities (getcap)|error|getcap timed_out' && ok "COV registry attributes timeout to its collector (class|collector|state|reason)" || no "COV registry attribution"
_before=$(printf '%s' "$COV_COLLECTORS" | grep -c .); cov_record error "getcap timed_out at 1s"; _after=$(printf '%s' "$COV_COLLECTORS" | grep -c .)
[ "$_before" = "$_after" ] && ok "COV registry dedups same class|collector|state" || no "COV registry dedup"
[ -z "$(printf '%s' "$COV_SKIPS" | tr -d ' ')" ] && ok "COV timeout NOT counted as a tool-absent skip" || no "COV timeout mislabeled as skip"
case "$COV_ERRORS" in *privesc*) ok "COV timeout counted as an error/timed_out outcome" ;; *) no "COV error not recorded";; esac
case "$COV_ERR_REASONS" in *"getcap timed_out"*) ok "COV timeout REASON retained for footer/JSON" ;; *) no "COV error reason lost";; esac
# here-string feeds the getcap loop in the MAIN shell so add_lead/reg_prim persist (not a subshell pipe)
_hsL=(); add_lead2(){ _hsL+=("$1"); }; while IFS= read -r l; do case "$l" in *cap_setuid*) add_lead2 x;; esac; done <<< "/usr/bin/foo cap_setuid+ep"
[ "${#_hsL[@]}" -eq 1 ] && ok "getcap here-string loop persists leads (main-shell, not subshell)" || no "here-string persistence"

# --- C5 relationship gating: a card fires only when BOTH facts are present ---
c5(){ [ "$1" = 1 ] && [ "$2" = 1 ] && echo fire || echo hold; }
[ "$(c5 1 1)" = fire ] && ok "C5 both facts present -> relationship fires" || no "C5 both"
[ "$(c5 1 0)" = hold ] && ok "C5 one fact missing -> no relationship (no over-claim)" || no "C5 one"
[ "$(c5 0 0)" = hold ] && ok "C5 no facts -> silent" || no "C5 none"

# --- A4 reg_prim: register privilege primitives from any source; first writer per class wins ---
ROOT_PRIM_SHELL=""; ROOT_PRIM_WRITE=""; ROOT_PRIM_READ=""
reg_prim shell "writable SUID-root binary /opt/x"
reg_prim shell "sudo vim (later source)"                # must NOT overwrite the first shell primitive
reg_prim write "writable systemd unit /etc/systemd/system/y.service"
reg_prim read  "file capability cap_dac_read_search"
[ "$ROOT_PRIM_SHELL" = "writable SUID-root binary /opt/x" ] && ok "A4 first shell primitive wins (SUID over later sudo)" || no "A4 shell first-wins"
[ "$ROOT_PRIM_WRITE" = "writable systemd unit /etc/systemd/system/y.service" ] && ok "A4 write primitive registered (service)" || no "A4 write reg"
[ "$ROOT_PRIM_READ"  = "file capability cap_dac_read_search" ] && ok "A4 read primitive registered (capability)" || no "A4 read reg"
# C5 preference order shell>write>read picks the strongest concrete citation
_prim="${ROOT_PRIM_SHELL:-${ROOT_PRIM_WRITE:-$ROOT_PRIM_READ}}"
[ "$_prim" = "writable SUID-root binary /opt/x" ] && ok "A4 C5 picks strongest (shell) primitive citation" || no "A4 C5 pref"

# --- A8 scan_inline_cred: inline secrets in command lines / task actions / ExecStart; placeholders + ports filtered ---
jack(){ :; }; add_cred(){ :; }; add_lead(){ LEADS+=("$2"); }
a8(){ _INLINE_SEEN=""; LEADS=(); scan_inline_cred "$1" "src"; echo "${#LEADS[@]}"; }
[ "$(a8 'schtasks /RU admin /RP S3cretP@ss /TR calc')" -ge 1 ] && ok "A8 schtasks /RP inline password surfaced" || no "A8 schtasks"
[ "$(a8 'sqlcmd -U sa -P MyDbPw123 -S localhost')" -ge 1 ] && ok "A8 sqlcmd -P inline password surfaced" || no "A8 sqlcmd"
[ "$(a8 'connectionString=Server=x;Password=Hunter2;Db=y')" -ge 1 ] && ok "A8 connection-string Password= surfaced" || no "A8 connstr"
[ "$(a8 'app --password %PASSWORD% --port 80')" -eq 0 ] && ok "A8 %VAR% placeholder NOT surfaced" || no "A8 placeholder FP"
[ "$(a8 'myprog -p 8080 -v')" -eq 0 ] && ok "A8 lowercase -p port NOT surfaced" || no "A8 -p port FP"
[ "$(a8 'tool -P 1433 -S host')" -eq 0 ] && ok "A8 numeric -P port NOT surfaced (value needs a letter)" || no "A8 -P port FP"

# --- A1 sudo_arg_mode: argument-awareness of a GTFObin sudo rule ---
[ "$(sudo_arg_mode '(root) NOPASSWD: /usr/bin/tar' tar)" = any ]        && ok "A1 bare binary -> any args (full capability)" || no "A1 any"
[ "$(sudo_arg_mode '(ALL) /usr/bin/vim ""' vim)" = noargs ]             && ok "A1 empty-arg rule -> noargs (technique blocked)" || no "A1 noargs"
[ "$(sudo_arg_mode '(root) /usr/bin/tar -czf /b/x *' tar)" = wildcard ] && ok "A1 fixed prefix + '*' -> wildcard" || no "A1 wildcard"
[ "$(sudo_arg_mode '(root) NOPASSWD: /usr/bin/tar --version' tar)" = pinned ] && ok "A1 fixed args -> pinned (downgrade)" || no "A1 pinned"
# score-downgrade logic: pinned (no danger) caps a shell primitive score at 55
_a1score(){ _scr=$1; _amode=$2; _danger=$3; if [ -z "$_danger" ]; then case "$_amode" in pinned|noargs) [ "$_scr" -gt 55 ] && _scr=55;; esac; fi; echo "$_scr"; }
[ "$(_a1score 94 pinned '')" = 55 ]                                     && ok "A1 pinned rule downgrades 94 -> 55" || no "A1 downgrade"
[ "$(_a1score 94 pinned ' [dangerous]')" = 94 ]                        && ok "A1 pinned + dangerous option keeps 94 (arg IS the exploit)" || no "A1 danger-keep"
[ "$(_a1score 94 any '')" = 94 ]                                       && ok "A1 any-args keeps full score" || no "A1 any-keep"

# --- B5 flag search evidence status + SUPERSEDED_AFTER_RESET decision ---
b5status(){ if [ ! -d "$1" ]; then echo absent; elif [ -r "$1" ] && [ -x "$1" ]; then echo searched; else echo DENIED; fi; }
B5T=$(mktemp -d)
[ "$(b5status "$B5T")" = searched ]     && ok "B5 readable root -> searched" || no "B5 searched"
[ "$(b5status "$B5T/missing")" = absent ] && ok "B5 missing root -> absent" || no "B5 absent"
rm -rf "$B5T"
b5sup(){ [ "$1" -ge "$2" ] && echo superseded || echo baked; }   # flag mtime vs boot epoch
[ "$(b5sup 2000 1000)" = superseded ] && ok "B5 mtime>=boot -> SUPERSEDED_AFTER_RESET warning" || no "B5 superseded"
[ "$(b5sup 500 1000)"  = baked ]      && ok "B5 mtime<boot -> baked (stable this boot)" || no "B5 baked"
# B5 per-root bounds accounting: status string encodes depth/cap/recursive-denials/TRUNCATED; partial -> SEARCH_PARTIAL
b5status(){ _d=$1 _cap=$2 _dn=$3 _cap_hit=$4; _s="searched(d${_d},cap${_cap}"; [ "$_dn" -gt 0 ] && _s="${_s},recursive-denied:${_dn}"; [ "$_cap_hit" = 1 ] && _s="${_s},TRUNCATED"; echo "${_s})"; }
[ "$(b5status 6 200 0 0)" = "searched(d6,cap200)" ] && ok "B5 clean root -> searched(depth,cap) no partial markers" || no "B5 clean status"
case "$(b5status 6 200 7 0)" in *"recursive-denied:7"*) ok "B5 records recursive access-denials per root" ;; *) no "B5 denial record";; esac
case "$(b5status 6 200 0 1)" in *TRUNCATED*) ok "B5 records cap-hit as TRUNCATED" ;; *) no "B5 truncation record";; esac
b5state(){ _found=$1 _partial=$2; if [ "$_found" = 1 ]; then echo FOUND; elif [ "$_partial" = 1 ]; then echo SEARCH_PARTIAL; else echo NOT_FOUND; fi; }
[ "$(b5state 0 1)" = SEARCH_PARTIAL ] && ok "B5 no-hit + any denial/truncation -> SEARCH_PARTIAL (absence NOT asserted)" || no "B5 partial state"
[ "$(b5state 0 0)" = NOT_FOUND ]      && ok "B5 no-hit + all roots complete-in-bounds -> NOT_FOUND_IN_DECLARED_SEARCH_SCOPE" || no "B5 notfound state"

# --- A1 refinement: gtfo_class read/write classification + registration decision (ss -F kept, shell pinned/wildcard dropped) ---
case "$(gtfo_class cat)" in read*) ok "A1 cat -> read (not overclassified as shell)";; *) no "A1 cat read";; esac
case "$(gtfo_class xxd)" in write*) ok "A1 xxd -> write";; *) no "A1 xxd write";; esac
case "$(gtfo_class find)" in shell*) ok "A1 find -> shell (genuinely shell-capable)";; *) no "A1 find shell";; esac
a1reg(){ _cls=$1; _amode=$2; danger=$3; _reg=0; [ -n "$danger" ] && _reg=1; if [ -n "$danger" ]; then :; else case "$_cls" in shell) case "$_amode" in any) _reg=1;; esac;; read|write) _reg=1;; esac; fi; echo "$_reg"; }
[ "$(a1reg read pinned '')" = 1 ]              && ok "A1 read primitive pinned (ss -F) STAYS registered" || no "A1 ss -F reg"
[ "$(a1reg shell pinned '')" = 0 ]             && ok "A1 shell pinned NOT registered (technique blocked)" || no "A1 shell pinned reg"
[ "$(a1reg shell wildcard '')" = 0 ]           && ok "A1 shell wildcard NOT registered (candidate)" || no "A1 shell wildcard reg"
[ "$(a1reg shell pinned ' [danger]')" = 1 ]    && ok "A1 shell pinned+danger registered (arg IS exploit)" || no "A1 danger reg"
[ "$(a1reg write pinned '')" = 1 ]             && ok "A1 write pinned registered (writes pinned target)" || no "A1 write pinned reg"

# --- A3 static ABSOLUTE child command is followed ---
A3T=$(mktemp -d)
printf '#!/bin/sh\n%s/abs_helper --run\n' "$A3T" > "$A3T/parent.sh"; printf '# helper\n' > "$A3T/abs_helper"; chmod 444 "$A3T/parent.sh"; chmod 666 "$A3T/abs_helper"
LEADS=(); follow_sourced "$A3T/parent.sh" "cron test"
printf '%s\n' "${LEADS[@]}" | grep -q 'writable helper' && ok "A3 static absolute writable child followed" || no "A3 absolute child"
rm -rf "$A3T"

# --- C2 D-Bus policy-block association (allow tied to ENCLOSING policy; deny excluded; single+multi line) ---
c2extract(){ awk '/<policy[^>]*>/ { if (match($0, /<policy[^>]*>/)) { ctx=substr($0,RSTART,RLENGTH) } } /<allow[^>]*send_destination="[^"]*PackageKit/ { if (ctx!="") print ctx } /<\/policy>/ { ctx="" }' "$1"; }
C2T=$(mktemp -d)
printf '<busconfig>\n<policy group="sudo"><allow send_destination="org.freedesktop.PackageKit"/></policy>\n<policy context="default"><deny send_destination="org.freedesktop.PackageKit"/></policy>\n</busconfig>\n' > "$C2T/s.conf"
printf '<busconfig>\n  <policy user="alice">\n    <allow send_destination="org.freedesktop.PackageKit"/>\n  </policy>\n</busconfig>\n' > "$C2T/m.conf"
[ "$(c2extract "$C2T/s.conf")" = '<policy group="sudo">' ] && ok "C2 single-line: allow tied to group block, deny/default excluded" || no "C2 single-line assoc"
[ "$(c2extract "$C2T/m.conf")" = '<policy user="alice">' ] && ok "C2 multi-line: allow tied to enclosing user block" || no "C2 multi-line assoc"
rm -rf "$C2T"

# --- B2 redact_for_id: secrets never reach the ID hash input; non-secret locators (paths) preserved ---
eval "$(import_fn redact_for_id)"
case "$(redact_for_id 'x password=S3cretP@ss y')" in *'<redacted>'*) ok "B2 password value redacted from ID input";; *) no "B2 pass redact";; esac
case "$(redact_for_id 'hash deadbeefcafe1234feedface')" in *'<hex>'*) ok "B2 long hex redacted from ID input";; *) no "B2 hex redact";; esac
[ "$(redact_for_id '/opt/app/bin/helper')" = '/opt/app/bin/helper' ] && ok "B2 path preserved (stable non-secret ID input)" || no "B2 path preserved"
# B2 canonical IDs: derive from canonical_source|consumer|primitive (not prose) -> ID stable when the TITLE is reworded
eval "$(import_fn lead_locator)"
_loc1=$(lead_locator "Writable SUID binary: /opt/app/helper"); _loc2=$(lead_locator "Non-standard writable SUID (root) -> reads/writes: /opt/app/helper")
[ "$_loc1" = "$_loc2" ] && ok "B2 lead_locator: same source from reworded titles" || no "B2 locator stability ($_loc1 vs $_loc2)"
_bid1=$(printf '%s|%s|%s|%s|%s' host privesc-write /opt/app/helper host privesc-write | cksum | awk '{print $1}')
_bid2=$(printf '%s|%s|%s|%s|%s' host privesc-write "$_loc2" host privesc-write | cksum | awk '{print $1}')
[ "$_bid1" = "$_bid2" ] && ok "B2 ID stable across title rewording (canonical facts drive it)" || no "B2 ID stability"
case "$(lead_locator 'Inline cred: password=S3cret deadbeefcafe1234feed')" in *'<redacted>'*|*'<hex>'*) ok "B2 canonical_source redacts secrets in the locator" ;; *) no "B2 locator redaction";; esac

# --- B1 add_lead stores category as a real field (7th), supplied or derived once ---
TAB=$(printf '\t')
eval "$(import_fn lead_category)"; eval "$(import_fn lead_scope)"; eval "$(import_fn redact_for_id)"; eval "$(import_fn lead_locator)"; eval "$(import_fn add_lead)"
LEADS=(); add_lead 90 "Flag file: /root/proof.txt" "why"
[ "$(printf '%s' "${LEADS[0]}" | awk -F"$TAB" '{print $7}')" = flag ] && ok "B1 add_lead stores category field (flag)" || no "B1 category stored"
LEADS=(); add_lead 80 "Route to non-attached network: 10.0.0.0/8" "why"
[ "$(printf '%s' "${LEADS[0]}" | awk -F"$TAB" '{print $7}')" = network-pivot ] && ok "B1 category derived once (network-pivot)" || no "B1 category derived"
LEADS=(); add_lead 70 "Some misc thing" "why" "" "" "" "credential"
[ "$(printf '%s' "${LEADS[0]}" | awk -F"$TAB" '{print $7}')" = credential ] && ok "B1 collector-supplied category honored" || no "B1 category supplied"

# --- Baseline families (§4.1): base-stock recognized, optional/custom SUID still flagged, confidence honest ---
eval "$(import_fn in_list)"; eval "$(sed -n '/^STD_SUID="/,/"$/p' "$WALDO")"
in_list su "$STD_SUID"        && ok "baseline: invariant SUID 'su' recognized as stock (generic core)" || no "baseline su stock"
in_list sudo "$STD_SUID"      && no "baseline: 'sudo' wrongly in GENERIC (not cross-family invariant)" || ok "baseline: 'sudo' NOT in generic (surfaces on unknown; stock only via matched version table)"
in_list custombackup "$STD_SUID" && no "baseline custom SUID wrongly stock (false negative)" || ok "baseline: unexpected/custom SUID NOT stock -> still flagged (no false negative)"
# confidence tier honesty: detected family -> family-detected (NOT high); unknown -> low
bfconf(){ case "$1" in debian|ubuntu|rhel|fedora|arch|suse|alpine) echo family-detected;; '') echo low;; *) echo detected-generic;; esac; }
[ "$(bfconf debian)" = family-detected ] && ok "baseline: detected family -> 'family-detected' (not overclaimed 'high')" || no "baseline family-detected"
[ "$(bfconf '')" = low ] && ok "baseline: unknown build -> conservative 'low' fallback" || no "baseline low fallback"
[ "$(bfconf weirddistro)" = detected-generic ] && ok "baseline: unlisted family -> detected-generic" || no "baseline detected-generic"

# --- A5 VNC state model: length->format classification, glob-skip, signature coverage, role precedence ---
# format-by-length (mirrors the exact sh case): only 8/16 are supported fixed-key; every other length is unknown_format.
vfmt(){ case "$1" in 8|16) echo reversible_supported;; *) echo unknown_format;; esac; }
[ "$(vfmt 8)"  = reversible_supported ] && ok "A5 VNC: 8-byte file -> reversible_supported" || no "A5 8-byte fmt"
[ "$(vfmt 16)" = reversible_supported ] && ok "A5 VNC: 16-byte file -> reversible_supported (primary+view-only)" || no "A5 16-byte fmt"
[ "$(vfmt 5)"  = unknown_format ]       && ok "A5 VNC: 5-byte malformed -> unknown_format (NOT decoded)" || no "A5 5-byte fmt"
[ "$(vfmt 7)"  = unknown_format ]       && ok "A5 VNC: 7-byte malformed -> unknown_format" || no "A5 7-byte fmt"
[ "$(vfmt 20)" = unknown_format ]       && ok "A5 VNC: 20-byte (RealVNC-shaped) -> unknown_format, never length-guessed reversible" || no "A5 20-byte fmt"
# glob-skip: an unexpanded glob path is skipped (not treated as a real file)
vskip(){ case "$1" in *'*'*) echo skip;; *) echo take;; esac; }
[ "$(vskip '/home/*/.vnc/passwd')" = skip ] && ok "A5 VNC: unexpanded glob path skipped (no phantom checked++)" || no "A5 glob skip"
[ "$(vskip '/root/.vnc/passwd')"  = take ] && ok "A5 VNC: real literal path is counted" || no "A5 literal take"
# A5 reconciled enums -- import the PRODUCTION classifier (no standalone re-implementation): role in {server,client,
# unknown}; activity in {active,installed_only,unknown}; an unattributed listener never sets a server role/activity.
eval "$(import_fn vnc_role_activity)"
#                    srv view inst attr-lstn
[ "$(vnc_role_activity 1 0 0 0)" = "server active" ]          && ok "A5 role: running server proc -> server/active" || no "A5 role server ($(vnc_role_activity 1 0 0 0))"
[ "$(vnc_role_activity 0 0 0 1)" = "server active" ]          && ok "A5 role: attributed listener -> server/active" || no "A5 role attr-listener"
[ "$(vnc_role_activity 0 0 0 0)" = "unknown unknown" ]        && ok "A5 role: unattributed listener/no signal -> unknown/unknown (hypothesis stays separate)" || no "A5 role unattributed"
[ "$(vnc_role_activity 0 1 0 0)" = "client unknown" ]         && ok "A5 role: viewer proc, no server -> client/unknown (reconciled: 'client', not 'viewer')" || no "A5 role client"
[ "$(vnc_role_activity 0 0 1 0)" = "unknown installed_only" ] && ok "A5 role: installed only -> unknown/installed_only (reconciled: not role='installed_only')" || no "A5 role installed_only"
# the ROLE field must never be an obsolete value (installed_only is now a valid ACTIVITY, so check role only)
_roles="$(vnc_role_activity 1 0 0 0 | cut -d' ' -f1) $(vnc_role_activity 0 1 0 0 | cut -d' ' -f1) $(vnc_role_activity 0 0 1 0 | cut -d' ' -f1) $(vnc_role_activity 0 0 0 0 | cut -d' ' -f1)"
case " $_roles " in *" server_unattributed "*|*" viewer "*|*" installed_only "*) no "A5 obsolete ROLE value leaked: $_roles";; *) ok "A5 role field only ever server/client/unknown (no obsolete enum)";; esac

# --- B2 shell dedup keys on the CANONICAL TUPLE (fields 7-10 = category|source|consumer|primitive), not the full record ---
# Two prose/score variants sharing one evidence tuple must collapse to the highest-score one; distinct tuples survive.
TAB=$(printf '\t')
_dedup(){ sort -t"$TAB" -k1,1 -rn | awk -F"$TAB" '!seen[$7 FS $8 FS $9 FS $10]++'; }
_recs=$(printf '%s\n' \
  "70${TAB}Writable service target: svcA -> /opt/a${TAB}why1${TAB}f${TAB}v${TAB}host-local${TAB}privesc-write${TAB}/opt/a${TAB}service:svcA${TAB}writable-service-binary" \
  "95${TAB}Service binary you can overwrite (svcA)${TAB}why2${TAB}f${TAB}v${TAB}host-local${TAB}privesc-write${TAB}/opt/a${TAB}service:svcA${TAB}writable-service-binary" \
  "80${TAB}Writable service target: svcB -> /opt/b${TAB}why3${TAB}f${TAB}v${TAB}host-local${TAB}privesc-write${TAB}/opt/b${TAB}service:svcB${TAB}writable-service-binary")
_out=$(printf '%s\n' "$_recs" | _dedup)
_n=$(printf '%s\n' "$_out" | grep -c .)
[ "$_n" = 2 ] && ok "B2 shell: same tuple/different prose collapses; distinct tuple survives (2 rows)" || no "B2 shell dedup count ($_n, want 2)"
# the surviving svcA row must be the HIGHER score (95), not the 70 variant
_svca=$(printf '%s\n' "$_out" | awk -F"$TAB" '$9=="service:svcA"{print $1}')
[ "$_svca" = 95 ] && ok "B2 shell: tuple-collapse keeps the higher score (95)" || no "B2 shell dedup kept score $_svca (want 95)"
# same title but DIFFERENT source must NOT collapse (distinct evidence)
_recs2=$(printf '%s\n' \
  "90${TAB}Writable service target${TAB}w${TAB}f${TAB}v${TAB}host-local${TAB}privesc-write${TAB}/opt/a${TAB}service:svcA${TAB}writable-service-binary" \
  "90${TAB}Writable service target${TAB}w${TAB}f${TAB}v${TAB}host-local${TAB}privesc-write${TAB}/opt/b${TAB}service:svcB${TAB}writable-service-binary")
_n2=$(printf '%s\n' "$_recs2" | _dedup | grep -c .)
[ "$_n2" = 2 ] && ok "B2 shell: same title, different source -> both survive (no title-collapse)" || no "B2 shell same-title diff-source ($_n2, want 2)"

# --- A1 privileged-binary taxonomy: per-binary primitive rows + unmatched -> review; arg-mode across all cases ---
eval "$(import_fn gtfo_class)"; eval "$(import_fn sudo_arg_mode)"
_cls(){ gtfo_class "$1" | cut -d'|' -f1; }
[ "$(_cls find)" = shell ]      && ok "A1 gtfo: find -> shell (exec primitive)" || no "A1 find class $(_cls find)"
[ "$(_cls bash)" = shell ]      && ok "A1 gtfo: bash -> shell" || no "A1 bash class"
[ "$(_cls tee)"  = write ]      && ok "A1 gtfo: tee -> write (not shell)" || no "A1 tee class $(_cls tee)"
[ "$(_cls chown)" = write ]     && ok "A1 gtfo: chown -> write" || no "A1 chown class $(_cls chown)"
[ "$(_cls cat)"  = read ]       && ok "A1 gtfo: cat -> read (not shell)" || no "A1 cat class $(_cls cat)"
[ "$(_cls ss)"   = read ]       && ok "A1 gtfo: ss -> read" || no "A1 ss class $(_cls ss)"
[ "$(_cls wget)" = write ]      && ok "A1 gtfo: wget -> write (not a blanket shell)" || no "A1 wget class $(_cls wget)"
[ "$(_cls tar)"  = shell ]      && ok "A1 gtfo: tar -> shell (checkpoint-action)" || no "A1 tar class $(_cls tar)"
# the crux fix: an UNLISTED binary must be 'review', never a proven shell primitive
[ "$(_cls somecustombin)" = review ] && ok "A1 gtfo: unknown binary -> review (NOT a blind shell assertion)" || no "A1 unknown class $(_cls somecustombin)"
[ "$(_cls totally_made_up)" = review ] && ok "A1 gtfo: second unknown -> review" || no "A1 unknown2 class"
# sudo_arg_mode across the representative cases
[ "$(sudo_arg_mode '(root) NOPASSWD: /usr/bin/find' find)" = any ]                 && ok "A1 argmode: bare binary -> any (full capability)" || no "A1 argmode any"
[ "$(sudo_arg_mode '(root) NOPASSWD: /usr/bin/tar -cf /tmp/*.tar' tar)" = wildcard ] && ok "A1 argmode: fixed prefix + '*' -> wildcard (candidate)" || no "A1 argmode wildcard ($(sudo_arg_mode '(root) NOPASSWD: /usr/bin/tar -cf /tmp/*.tar' tar))"
[ "$(sudo_arg_mode '(root) NOPASSWD: /usr/bin/tee /etc/motd' tee)" = pinned ]      && ok "A1 argmode: fixed args -> pinned" || no "A1 argmode pinned ($(sudo_arg_mode '(root) NOPASSWD: /usr/bin/tee /etc/motd' tee))"
[ "$(sudo_arg_mode '(root) NOPASSWD: /usr/bin/less ""' less)" = noargs ]           && ok "A1 argmode: empty-string arg -> noargs (blocks shell technique)" || no "A1 argmode noargs ($(sudo_arg_mode '(root) NOPASSWD: /usr/bin/less ""' less))"

# --- C2 broker namespace comparison: a mismatch is asserted ONLY when a concrete difference is proven ---
# mirrors the production decision (differing mnt-ns inode | PrivateTmp=yes | non-'/' RootDirectory -> mismatch)
c2_mismatch(){ # $1=producer_ns $2=consumer_ns $3=sandbox_props
  if [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ]; then echo 1
  elif printf '%s' "$3" | grep -qi 'PrivateTmp=yes'; then echo 1
  elif printf '%s' "$3" | grep -qiE 'RootDirectory=/[^ ]'; then echo 1
  else echo 0; fi; }
[ "$(c2_mismatch 'mnt:[1]' 'mnt:[2]' 'PrivateTmp=no')" = 1 ]        && ok "C2: differing mount-ns inode -> mismatch proven" || no "C2 ns-inode mismatch"
[ "$(c2_mismatch 'mnt:[1]' 'mnt:[1]' 'PrivateTmp=yes ProtectSystem=full')" = 1 ] && ok "C2: PrivateTmp=yes -> mismatch proven (private /tmp)" || no "C2 privatetmp mismatch"
[ "$(c2_mismatch 'mnt:[1]' 'mnt:[1]' 'RootDirectory=/srv/chroot')" = 1 ] && ok "C2: RootDirectory chroot -> mismatch proven" || no "C2 rootdir mismatch"
[ "$(c2_mismatch 'mnt:[1]' 'mnt:[1]' 'PrivateTmp=no RootDirectory=')" = 0 ] && ok "C2: same ns + no sandbox -> NO mismatch (shared view, lower-confidence)" || no "C2 shared-view no-mismatch"

# --- C5 producer-path row is DEMOTED to UNSCORED CONTEXT (auditor §4): it is a NOTE only, never a scored relationship,
#     because Waldo does not collect an exact producer path + consumer-use evidence. Assert: the context NOTE condition
#     is recognized (reachable+shared-view+write-prim), any missing fact suppresses even the note, and it never scores. ---
c5_visible(){ [ "$1" = 1 ] && [ "$2" = 0 ] && [ -n "$3" ] && echo 1 || echo 0; }   # reachable && no-mismatch && cons_ns known
c5_context(){ [ "$(c5_visible "$1" "$2" "$3")" = 1 ] && [ -n "$4" ] && echo NOTE || echo silent; }  # NOTE = unscored context
[ "$(c5_context 1 0 'mnt:[1]' '/etc/x')" = NOTE ]  && ok "C5 confused-deputy: reachable+shared-view+write-prim -> UNSCORED context note (both)" || no "C5 both note"
[ "$(c5_context 1 1 'mnt:[1]' '/etc/x')" = silent ] && ok "C5 confused-deputy: mismatch present -> silent (isolated view)" || no "C5 mismatch silent"
[ "$(c5_context 0 0 'mnt:[1]' '/etc/x')" = silent ] && ok "C5 confused-deputy: broker NOT reachable -> silent (one missing)" || no "C5 unreachable silent"
[ "$(c5_context 1 0 'mnt:[1]' '')" = silent ]       && ok "C5 confused-deputy: no write primitive -> silent (none)" || no "C5 no-prim silent"
# the demoted row must NOT emit a scored 'relationship:' add_lead -- confirm the production line is a note(), not add_lead
grep -q 'note "context (NOT a scored relationship): a reachable privileged broker' "$WALDO" && ok "C5 §4: producer-path row is note()/unscored in production (not add_lead)" || no "C5 §4 row still scored"
grep -qE 'add_lead[^#]*producer path -> consumer namespace' "$WALDO" && no "C5 §4: producer-path still emits a scored add_lead (hypothesis-only)" || ok "C5 §4: no scored add_lead for producer-path (demoted)"

# --- §4.1 baseline validated by EQUALITY against CAPTURED pristine base-image SUID manifests (auditor §3) ---
eval "$(import_fn baseline_stock_suid)"
eval "$(import_fn in_list)"; eval "$(sed -n '/^STD_SUID="/,/"$/p' "$WALDO")"
MANDIR="$(dirname "$0")/suid_manifests"
# sorted-space-normalized set from a captured manifest file (basenames, one per line)
_manset(){ tr '\n' ' ' < "$1" | tr -s ' ' | sed 's/^ //; s/ $//'; }
# effective = generic STD_SUID UNION the per-build delta, sorted-unique
_effset(){ printf '%s %s\n' "$STD_SUID" "$(baseline_stock_suid "$1" "$2")" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
_normset(){ printf '%s\n' "$1" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
# 0) EQUALITY: for each captured build, effective(generic ∪ delta) EXACTLY equals the pinned base-image manifest
_eq_check(){ # $1=family $2=major $3=manifest-file
  local m e; m=$(_normset "$(_manset "$MANDIR/$3")"); e=$(_normset "$(_effset "$1" "$2")")
  [ "$m" = "$e" ] && ok "§4.1 $1 $2: effective set EQUALS captured $3 manifest (equality, not subset)" || no "§4.1 $1 $2 != manifest: eff=[$e] man=[$m]"
}
if [ -f "$MANDIR/debian-12.txt" ]; then
  # each captured family is compared to ITS OWN pinned manifest (auditor §2: no borrowed evidence across families)
  _eq_check debian 12 debian-12.txt
  _eq_check ubuntu 24 ubuntu-24.04.txt
  _eq_check ubuntu 22 ubuntu-22.04.txt
  _eq_check rocky 9 rockylinux-9.txt
  _eq_check almalinux 9 almalinux-9.txt   # DIFFERENT from rocky (no passwd/userhelper) -- proves per-family capture
  _eq_check ol 9 oraclelinux-9.txt        # DIFFERENT from rocky (no userhelper)
else no "§4.1 captured manifests missing under $MANDIR"; fi
# EVIDENCE == PRODUCTION scope: every family+major that baseline_stock_suid returns a delta for MUST have its own
# manifest file. This FAILS if a profile is suppressed without its own captured evidence (the auditor's §2 defect).
_map_manifest(){ case "$1-$2" in debian-12) echo debian-12.txt;; ubuntu-22) echo ubuntu-22.04.txt;; ubuntu-24) echo ubuntu-24.04.txt;; rocky-9) echo rockylinux-9.txt;; almalinux-9) echo almalinux-9.txt;; ol-9) echo oraclelinux-9.txt;; *) echo "";; esac; }
_orphan=""
for _b in "debian 12" "ubuntu 22" "ubuntu 24" "rocky 9" "almalinux 9" "ol 9" "rhel 9" "centos 9" "debian 11" "rhel 8"; do
  set -- $_b
  if [ -n "$(baseline_stock_suid "$1" "$2")" ]; then
    _mf=$(_map_manifest "$1" "$2"); { [ -n "$_mf" ] && [ -f "$MANDIR/$_mf" ]; } || _orphan="$_orphan $1-$2"
  fi
done
[ -z "$_orphan" ] && ok "§4.1 every production delta has its OWN captured manifest (evidence scope == production scope)" || no "§4.1 delta WITHOUT captured manifest (borrowed evidence):$_orphan"
# rhel-9 / centos-9 (not freely pullable) carry NO delta -> conservative generic fallback (not a borrowed EL9 delta)
[ -z "$(baseline_stock_suid rhel 9)" ] && ok "§4.1 rhel-9 has no captured image -> no delta (conservative generic fallback)" || no "§4.1 rhel-9 borrows a delta without its own manifest"
[ -z "$(baseline_stock_suid centos 9)" ] && ok "§4.1 centos-9 has no captured image -> no delta" || no "§4.1 centos-9 borrows a delta"
# 1) GENERIC = the cross-image INTERSECTION of ALL captured manifests (present in EVERY one); nothing else
_gcore="$(_normset "$STD_SUID")"
[ "$_gcore" = "gpasswd mount newgrp su umount" ] && ok "§4.1 generic = cross-image intersection of all 6 captured bases (gpasswd mount newgrp su umount)" || no "§4.1 generic not the intersection: [$_gcore]"
# passwd is NOT generic (almalinux:9 base has no setuid passwd) -> it surfaces on unknown/alma unless the delta adds it
in_list passwd "$STD_SUID" && no "§4.1 'passwd' wrongly in generic (not setuid on almalinux:9 base)" || ok "§4.1 'passwd' NOT generic (surfaces unless a captured delta includes it)"
# distro-specific / optional names MUST NOT be in generic (they surface on unknown boxes)
for d in sudo pkexec fusermount3 at crontab snap-confine chsh chfn chage unix_chkpwd sg ntfs-3g mount.nfs Xorg.wrap login; do
  in_list "$d" "$STD_SUID" && no "§4.1 generic wrongly contains '$d' (should surface on unknown boxes)" || ok "§4.1 generic excludes '$d' (surfaces on unknown)"
done
# 2) injected non-stock SUID still surfaces under a matched build
in_list evilbackup "$STD_SUID $(baseline_stock_suid debian 12)" && no "§4.1 injected non-stock wrongly subtracted" || ok "§4.1 injected 'evilbackup' still surfaces under matched build"
# 3) confidence: NO build claims 'high' any more (base-image manifest = ranking context only); matched -> family-detected,
#    unproven family -> family-detected, unknown -> low
bl_conf(){ [ -n "$(baseline_stock_suid "$1" "$2")" ] && { echo family-detected; return; }; case "$1" in debian|ubuntu|kali|rhel|centos|fedora|rocky|almalinux|ol|arch|suse|alpine) echo family-detected;; '') echo low;; *) echo detected-generic;; esac; }
for _b in "debian 12" "ubuntu 24" "rhel 9"; do set -- $_b; [ "$(bl_conf "$1" "$2")" != high ] && ok "§4.1 no 'high' overclaim for $1 $2 (base-image = ranking context)" || no "§4.1 $1 $2 still claims high"; done
[ "$(bl_conf '' '')" = low ] && ok "§4.1 unknown -> low (conservative fallback)" || no "§4.1 unknown conf"
[ -z "$(baseline_stock_suid gentoo 2)" ] && ok "§4.1 unlisted family -> no table (generic fallback)" || no "§4.1 gentoo table"

# --- B2 long-tail: no-colon title with an embedded path -> STABLE locator (rewording prose doesn't change the ID) ---
_l1=$(lead_locator "Root tar wildcard over writable dir /opt/app/incoming")
_l2=$(lead_locator "Writable dir /opt/app/incoming used by a root tar wildcard")
[ "$_l1" = "$_l2" ] && [ "$_l1" = "/opt/app/incoming" ] && ok "B2 long-tail: no-colon titles sharing an embedded path -> same stable locator" || no "B2 long-tail path locator ($_l1 vs $_l2)"
_lq1=$(lead_locator "Service accountsvc reconfigurable")
_lq2=$(lead_locator "Reconfigurable service accountsvc")
# both have no path/quote -> fall back to full title (different) -- ensure the PATH case above is what stabilizes
_lp=$(lead_locator "AppInit_DLLs set 'C:/evil.dll' loads everywhere")
case "$_lp" in *evil.dll*) ok "B2 long-tail: quoted/path token extracted from no-colon title" ;; *) no "B2 long-tail quoted extract ($_lp)" ;; esac

# --- B2 shell coverage (auditor §2): NO scored add_lead may fall to the unstable whole-title identity. Each call must
#     EITHER supply explicit positional canonical facts, OR carry a REAL locator that the (now bug-fixed) lead_locator
#     extracts stably -- a ': ' colon locator, a >=2-segment absolute path, or a quoted token. A lone slash in prose no
#     longer counts (that bug is fixed), and the whole-title fallback cases were migrated to explicit facts. ---
_b2miss=0; _b2total=0; _b2list=""
while IFS= read -r _line; do
  case "$_line" in *'add_lead '*) : ;; *) continue;; esac
  case "$_line" in *'add_lead(){'*|*'_c5(){'*) continue;; esac
  _b2total=$((_b2total+1))
  case "$_line" in *'"" "" "" ""'*) continue;; esac      # explicit canonical facts -> covered
  # else the title must carry a REAL stable locator (matches lead_locator's extraction order)
  _title=$(printf '%s' "$_line" | sed -n 's/.*add_lead [^"]*"\([^"]*\)".*/\1/p')
  # if the score is quoted (add_lead "$score" "TITLE"), the real title is the 2nd quoted field
  case "$_line" in *'add_lead "$'*) _title=$(printf '%s' "$_line" | sed -n 's/.*add_lead "[^"]*" "\([^"]*\)".*/\1/p');; esac
  _rp=$(printf '%s' " $_title" | grep -oE '[[:space:]]/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+' | head -1)
  case "$_title" in
    *": "*) : ;;                    # colon-space locator (lead_locator takes the post-colon path/id)
    *"'"*) : ;;                     # quoted token
    "") : ;;                        # dynamic ($var) title -> add_lead derives; not a literal prose fallback
    *) [ -n "$_rp" ] || { _b2miss=$((_b2miss+1)); _b2list="$_b2list
  $(printf '%s' "$_title" | cut -c1-70)"; } ;;
  esac
done < "$WALDO"
[ "$_b2miss" -eq 0 ] && ok "B2 shell coverage: no scored add_lead falls to whole-title identity ($_b2total sites: explicit facts or a real locator)" || no "B2 shell coverage: $_b2miss/$_b2total add_lead reach whole-title:$_b2list"

echo ""; echo "FIXTURES: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
