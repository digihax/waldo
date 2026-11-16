#!/usr/bin/env python3
# STRICT interruption test -- reproduces the auditor's direct-TTY methodology.
# For each bounded collector (SUID / SGID / getcap) it: runs waldo.sh under a PTY with --json, waits for THAT
# collector's marker in the live output, sends a real Ctrl-C (\x03), then asserts:
#   exit 130, footer presence, valid requested JSON written, NO leftover temp file in a private TMPDIR.
import os, pty, time, select, sys, subprocess, glob, tempfile, json, signal

from pathlib import Path
import atexit
import shlex
import shutil
_SOURCE = Path(os.environ.get("WALDO_SH", str(Path(__file__).resolve().parents[1] / "waldo.sh"))).expanduser().resolve(strict=True)
_WORK = tempfile.TemporaryDirectory(prefix="waldo_pty_source_")
atexit.register(_WORK.cleanup)
_SCRIPT = Path(_WORK.name) / "waldo.sh"
_SCRIPT.write_bytes(_SOURCE.read_bytes().replace(b"\r\n", b"\n"))

# Synthetic dependency delay makes cancellation deterministic even on tiny lab filesystems.
# This checks the real collector/trap path, not find/getcap detection correctness.
_BIN = Path(_WORK.name) / "bin"
_BIN.mkdir()
for _command in ("find", "getcap"):
    _real = shutil.which(_command) or "/bin/true"
    _shim = _BIN / _command
    _rule = ('case "$WALDO_PTY_CASE:$*" in SUID:*"-perm -4000"*|SGID:*"-perm -2000"*) sleep 5;; esac' if _command == 'find' else '[ "$WALDO_PTY_CASE" != getcap ] || sleep 5')
    _shim.write_text("#!/bin/bash\n" + _rule + "\nexec " + shlex.quote(_real) + ' "$@"\n')
    _shim.chmod(0o700)


CASES = [
    ("SUID",   "SUID root binaries"),
    ("SGID",   "SGID binaries"),
    ("getcap", "File capabilities (getcap)"),
]

def run_case(label, marker):
    tmpdir = tempfile.mkdtemp(prefix="waldo_str_")
    jpath  = os.path.join(tmpdir, "out.json")
    env = dict(os.environ, TMPDIR=tmpdir, WALDO_DEADLINE="120", PATH=str(_BIN)+os.pathsep+os.environ.get("PATH", os.defpath), WALDO_PTY_CASE=label)  # long deadline so the collector is still running
    pid, fd = pty.fork()
    if pid == 0:
        os.execve("/bin/bash", ["bash", str(_SCRIPT), "--only", "privesc", "--json", jpath], env)
    out = b""; sent = False; start = time.time()
    while True:
        try:
            r, _, _ = select.select([fd], [], [], 0.2)
        except OSError:
            break
        if fd in r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
            if (not sent) and (marker.encode() in out):
                time.sleep(0.25)          # let the collector actually enter its work
                os.write(fd, b"\x03")     # real Ctrl-C to the PTY foreground group
                sent = True
        if time.time() - start > 60:
            try: os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            break
    try:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
    except ChildProcessError:
        code = None
    os.close(fd)
    text = out.decode(errors="replace")
    # footer markers rendered by print_footer / print_leads / print_coverage / print_json
    footer = ("Coverage" in text) or ("LEADS" in text.upper()) or ("No high-signal leads" in text)
    # JSON validity
    jvalid = False
    if os.path.exists(jpath):
        try:
            with open(jpath) as fh: json.load(fh); jvalid = True
        except Exception: jvalid = False
    leftovers = [p for p in glob.glob(os.path.join(tmpdir, "*")) if p != jpath]
    # cleanup
    for p in glob.glob(os.path.join(tmpdir, "*")):
        try: os.remove(p)
        except OSError: pass
    try: os.rmdir(tmpdir)
    except OSError: pass
    ok = (code == 130) and footer and jvalid and (len(leftovers) == 0) and sent
    print(f"[{label}] sent_at_marker={sent} exit={code} footer={footer} json_valid={jvalid} leftovers={leftovers} -> {'PASS' if ok else 'FAIL'}")
    return ok

if __name__ == "__main__":
    results = [run_case(l, m) for (l, m) in CASES]
    print("=== STRICT RESULT:", "PASS" if all(results) else "FAIL")
    sys.exit(0 if all(results) else 1)
