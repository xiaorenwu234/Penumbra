#!/bin/bash
# Smoke test for try: commit / discard / deferred commit semantics as root.
#
# IMPORTANT (measured): `try commit` must be given an ABSOLUTE sandbox path.
# Upstream try-commit(C) walks the upperdir with fts, which chdir()s; a
# relative sandbox path makes the rename() src resolve against the wrong
# cwd and fail with ENOENT ("couldn't commit ... (rename)"). TryEngine
# always passes absolute paths for this reason.
#
# Root note: this script only touches /tmp, which works under root as-is.
# Sandboxes that must reach files OWNED BY OTHER UIDS (e.g. /home/xht/**)
# fail inside try's user namespace when try runs as root (only uid 0 is
# mapped -> EACCES/exit 126); TryEngine installs an unshare shim for that.
# For the full engine-level check (shim included):
#   sudo python3 run_baseline.py --smoke --engine try
set -u
TRY_BIN=/home/xht/桌面/penumbra-work/RQ2/try-osdi26-ae/try
export PATH=/home/xht/桌面/penumbra-work/RQ2/try-osdi26-ae/utils:$PATH
SB=/tmp/try-smoke
rm -rf "$SB"; mkdir -p "$SB"; cd "$SB"

echo "=== 1) try -y: commit mode ==="
"$TRY_BIN" -y 'echo committed > c.txt'
if [ -f c.txt ] && grep -q committed c.txt; then echo "[PASS] -y commits to live"; else echo "[FAIL] -y commit"; fi

echo "=== 2) try -D dir: quiet discard mode ==="
mkdir -p "$SB/sb2"
"$TRY_BIN" -D "$SB/sb2" 'echo discarded > d.txt'
if [ ! -e d.txt ]; then echo "[PASS] -D keeps live unchanged"; else echo "[FAIL] -D leaked d.txt"; fi
if [ -f "$SB/sb2/upperdir/tmp/try-smoke/d.txt" ]; then echo "[PASS] effect stored in sandbox upperdir"; else echo "[FAIL] no upperdir effect"; fi

echo "=== 3) deferred commit of existing sandbox (absolute path) ==="
"$TRY_BIN" commit "$SB/sb2"
if [ -f d.txt ] && grep -q discarded d.txt; then echo "[PASS] commit DIR applies effect"; else echo "[FAIL] deferred commit"; fi

echo "=== 4) summary of sb2 after commit (should be empty) ==="
"$TRY_BIN" summary "$SB/sb2"; echo "summary rc=$?"

echo "=== 5) exit code propagation ==="
mkdir -p sb3 sb4 sb5
"$TRY_BIN" -D "$SB/sb3" 'exit 7' 2>/dev/null; echo "rc=$? (expect 7)"
true
"$TRY_BIN" -D "$SB/sb4" 'true'; echo "rc=$? (expect 0)"

echo "=== 6) command output capture ==="
OUT=$("$TRY_BIN" -D "$SB/sb5" 'echo hello-stdout; echo err-stderr >&2')
echo "out=[$OUT]"

echo "=== 7) nested dirs + file creation under /tmp workspace ==="
mkdir -p ws "$SB/sb6" && cd ws
"$TRY_BIN" -D "$SB/sb6" 'mkdir -p sub; echo A > sub/a.txt; echo B > b.txt'
if [ ! -e b.txt ] && [ ! -e sub ]; then echo "[PASS] nested effects isolated"; else echo "[FAIL] leak"; fi
"$TRY_BIN" commit "$SB/sb6"
if [ -f b.txt ] && [ -f sub/a.txt ]; then echo "[PASS] nested commit applied"; else echo "[FAIL] nested commit"; fi

echo "=== 8) timing of a full cycle (host-side) ==="
cd "$SB"
mkdir -p sb7
S=$(date +%s%N)
"$TRY_BIN" -D "$SB/sb7" 'true' >/dev/null 2>&1
E=$(date +%s%N)
echo "try -D true: $(( (E-S)/1000000 )) ms"
S=$(date +%s%N)
"$TRY_BIN" -y 'true' >/dev/null 2>&1
E=$(date +%s%N)
echo "try -y true: $(( (E-S)/1000000 )) ms"
S=$(date +%s%N)
"$TRY_BIN" commit "$SB/sb7" >/dev/null 2>&1
E=$(date +%s%N)
echo "try commit (empty sandbox): $(( (E-S)/1000000 )) ms"

echo "ALL DONE"
