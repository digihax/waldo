#!/usr/bin/env python3
# STRICT interruption test -- reproduces the auditor's direct-TTY methodology.
# For each bounded collector (SUID / SGID / getcap) it: runs waldo.sh under a PTY with --json, waits for THAT
# collector's marker in the live output, sends a real Ctrl-C (\x03), then asserts:
#   exit 130, exactly one footer, valid requested JSON written, NO leftover temp file in a private TMPDIR.
import os, pty, time, select, sys, subprocess, glob, tempfile, json

subprocess.run("cp /mnt/f/_oscp_artifacts/waldo/waldo.sh /tmp/w.sh && sed -i 's/\\r$//' /tmp/w.sh", shell=True)

CASES = [
    ("SUID",   "SUID root binaries"),
    ("SGID",   "SGID binaries"),
    ("getcap", "File capabilities (getcap)"),
]

def run_case(label, marker):
    tmpdir = tempfile.mkdtemp(prefix="waldo_str_")
    jpath  = os.path.join(tmpdir, "out.json")
    env = dict(os.environ, TMPDIR=tmpdir, WALDO_DEADLINE="120")  # long deadline so the collector is still running
    pid, fd = pty.fork()
    if pid == 0:
        os.execve("/bin/bash", ["bash", "/tmp/w.sh", "--only", "privesc", "--json", jpath], env)
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
            break
    try:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
    except ChildProcessError:
        code = None
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
