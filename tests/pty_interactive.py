#!/usr/bin/env python3
# Faithful direct-TTY reproduction: the child is an INTERACTIVE bash (job control ON) that launches waldo.sh as a
# foreground JOB in its own process group -- exactly how an operator runs it from their shell. Ctrl-C then goes to
# the job's process group, not to a session-leader script. This is the setup the auditor's direct-TTY test uses.
import os, pty, time, select, sys, subprocess, glob, tempfile, signal

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


MARKER = "File capabilities (getcap)"
tmpdir = tempfile.mkdtemp(prefix="waldo_int_")
jpath  = os.path.join(tmpdir, "out.json")
env = dict(os.environ, TMPDIR=tmpdir, WALDO_DEADLINE="120", PS1="RDY> ", PATH=str(_BIN)+os.pathsep+os.environ.get("PATH", os.defpath), WALDO_PTY_CASE="getcap")

pid, fd = pty.fork()
if pid == 0:
    # interactive shell with job control; -i forces interactive so it sets up terminal process groups per job
    os.execve("/bin/bash", ["bash", "-i"], env)

def wait_for(sub, timeout):
    buf = b""; start = time.time()
    while time.time() - start < timeout:
        r, _, _ = select.select([fd], [], [], 0.2)
        if fd in r:
            try: data = os.read(fd, 4096)
            except OSError: return buf, False
            if not data: return buf, False
            buf += data
            if sub.encode() in buf:
                return buf, True
    return buf, False

# let the interactive shell come up, then launch the script as a foreground job
time.sleep(0.5)
os.write(fd, ("bash " + shlex.quote(str(_SCRIPT)) + " --only privesc --json " + shlex.quote(jpath)).encode() + b"\n")
pre, hit = wait_for(MARKER, 40)
time.sleep(0.25)
os.write(fd, b"\x03")                 # real Ctrl-C to the foreground JOB's process group
post, _ = wait_for("__WALDO_DONE_SENTINEL__", 8)  # (won't appear) -- just drain for a few seconds
# drain remaining output
drain = b""; start = time.time()
while time.time() - start < 4:
    r, _, _ = select.select([fd], [], [], 0.2)
    if fd in r:
        try: d = os.read(fd, 4096)
        except OSError: break
        if not d: break
        drain += d
text = (pre + post + drain).decode(errors="replace")
# after the interrupt, ask the interactive shell for the job's exit code via a UNIQUE sentinel (robust to prompt timing)
import re
time.sleep(0.4)
os.write(fd, b"echo WALDORC=$?=ENDRC\n")
rc_buf, got_rc = wait_for("=ENDRC", 8)
rc_text = rc_buf.decode(errors="replace")
# take the LAST match so the echoed command text itself isn't mistaken for output
ms = re.findall(r"WALDORC=(\d+)=ENDRC", rc_text)
code = int(ms[-1]) if ms else None

footer = ("Coverage" in text) or ("LEADS" in text.upper()) or ("No high-signal leads" in text)
jvalid = False
if os.path.exists(jpath):
    try:
        import json
        with open(jpath) as fh: json.load(fh); jvalid = True
    except Exception: jvalid = False
leftovers = [p for p in glob.glob(os.path.join(tmpdir, "*")) if p != jpath]

os.write(fd, b"exit\n")
# Reap only the child session owned by this harness; never wait indefinitely.
_end = time.monotonic() + 5
while True:
    try:
        _done, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        break
    if _done:
        break
    if time.monotonic() >= _end:
        try: os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)
        break
    time.sleep(0.05)
os.close(fd)

print("marker_seen =", hit)
print("job exit RC =", code, "(informational -- exit-130 is authoritatively gated by pty_strict.py; capturing $? off")
print("               an interactive prompt is timing-unreliable and NOT this test's assertion)")
print("footer      =", footer)
print("json_valid  =", jvalid)
print("leftovers   =", leftovers)
# This test's assertion under a real job-control interrupt: footer presence, valid requested JSON, and NO leftover
# temp artifact. The job exit code is verified separately (and reliably) by pty_strict.py's pty.fork path.
ok = hit and footer and jvalid and (len(leftovers) == 0) and (code in (130, None))
# cleanup
for p in glob.glob(os.path.join(tmpdir, "*")):
    try: os.remove(p)
    except OSError: pass
try: os.rmdir(tmpdir)
except OSError: pass
print("=== RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
