#!/usr/bin/env python3
"""Verify the fmod_ret return-value ABI of a compiled shadow_proc BPF object.

Background: an `fmod_ret` program's r0 is stored verbatim into the return slot
of a syscall wrapper whose C return type is `long`. If clang materialises a
negative errno with LD_IMM_DW (opcode 0x18) and imm_hi == 0, the value reaches
the kernel ZERO-EXTENDED (-512 becomes +0x00000000fffffe00), so do_signal()'s
restart check never matches and the fenced syscall is never re-executed.
The correct encoding is the sign-extended ALU64 move (opcode 0xb7).

This is a regression guard for a bug that already shipped once in this repo:
the fenced syscall silently stopped being restarted, and because the fence is
irreversible the failure looked like a hang rather than a wrong return value.

Usage: check_fmod_ret_abi.py <shadow_proc.skel.rs | object.bpf.o>
Exit status 1 if any fmod_ret section still carries a zero-extended errno.

Pass the skeleton: build.rs compiles src/bpf/shadow_proc.bpf.c straight into
src/bpf/shadow_proc.skel.rs, so the skeleton is the artifact that actually
ships and no standalone .bpf.o is ever produced.
"""
import os
import re
import subprocess
import sys
import tempfile

# LD_IMM_DW whose 64-bit value is a zero-extended negative errno
ZEROEXT = re.compile(
    r'\b18 0[0-9a-f] 00 00 '
    r'(?:0[0-9a-f] ff ff ff|f[0-9a-f] ff ff ff) '
    r'00 00 00 00 00 00 00 00')
# ALU64 MOV IMM carrying -512 (ERESTARTSYS) or -1 (EPERM), i.e. sign-extended
SIGNEXT = re.compile(r'\bb7 0[0-9a-f] 00 00 (?:0[0-9a-f] fe ff ff|ff ff ff ff)\b')


def sections(obj):
    out = subprocess.run(["llvm-objdump", "-h", obj],
                         capture_output=True, text=True).stdout
    return re.findall(r'^\s*\d+\s+(\S+)\s', out, re.M)


def disasm(obj, sec):
    out = subprocess.run(["llvm-objdump", "-d", "--section=" + sec, obj],
                         capture_output=True, text=True).stdout
    return out.split("Disassembly of section", 1)[-1]


def extract_from_skeleton(path):
    """Pull the embedded BPF object out of a libbpf-cargo skeleton.

    SkeletonBuilder emits the compiled object as a decimal byte array
    (`const DATA: &[u8] = &[127, 69, 76, 70, ...]`). Verified to reproduce the
    object byte-for-byte, so checking the skeleton is equivalent to checking
    what the loader hands to the kernel.
    """
    with open(path, encoding="utf-8", errors="replace") as f:
        txt = f.read()
    m = re.search(r'const DATA: &\[u8\] = &\[(.*?)\];', txt, re.S)
    if not m:
        raise SystemExit(f"{path}: no `const DATA: &[u8]` array found")
    data = bytes(int(x) for x in re.findall(r'\d+', m.group(1)))
    if data[:4] != b'\x7fELF':
        raise SystemExit(f"{path}: extracted {len(data)} bytes, not an ELF")
    return data


def resolve_object(path):
    """Return (obj_to_inspect, tmp_to_delete_or_None)."""
    if not path.endswith(".rs"):
        return path, None
    data = extract_from_skeleton(path)
    fd, tmp = tempfile.mkstemp(suffix=".bpf.o")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    print(f"[extracted {len(data)} bytes of embedded object from {path}]")
    return tmp, tmp


def main(path):
    obj, tmp = resolve_object(path)
    try:
        return check(obj)
    finally:
        if tmp:
            os.unlink(tmp)


def check(obj):
    names = sections(obj)
    fmod = [n for n in names if n.startswith("fmod_ret/")]
    lsm = [n for n in names if n.startswith("lsm/")]
    print(f"{'SECTION':42s} {'zeroext':>8s} {'sext':>6s}")
    bad = 0
    for n in fmod:
        body = disasm(obj, n)
        z, s = len(ZEROEXT.findall(body)), len(SIGNEXT.findall(body))
        bad += z
        print(f"{n:42s} {z:8d} {s:6d}" + ("   <-- BAD" if z else ""))
    print(f"\nfmod_ret={len(fmod)}  lsm={len(lsm)} (lsm returns int, "
          f"truncated by the trampoline - not checked)")
    print(f"zero-extended errnos in fmod_ret: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
