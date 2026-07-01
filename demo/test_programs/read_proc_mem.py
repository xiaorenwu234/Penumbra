#!/usr/bin/env python3
"""
read_proc_mem.py - Read a value from /proc/<pid>/mem at a given address.

Usage:
    python3 read_proc_mem.py <pid> <hex_address> <type>

Types:
    int   - Read 4 bytes as little-endian int32
    str   - Read up to 64 bytes as null-terminated string

Examples:
    python3 read_proc_mem.py 1234 0x55a3b4c00000 int
    python3 read_proc_mem.py 1234 0x55a3b4c00040 str
"""

import struct
import sys


def read_proc_mem(pid: int, addr: int, size: int) -> bytes:
    """Read `size` bytes from /proc/<pid>/mem at virtual address `addr`."""
    mem_path = f"/proc/{pid}/mem"
    with open(mem_path, "rb") as f:
        f.seek(addr)
        return f.read(size)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    pid = int(sys.argv[1])
    addr = int(sys.argv[2], 16)
    value_type = sys.argv[3]

    try:
        if value_type == "int":
            data = read_proc_mem(pid, addr, 4)
            value = struct.unpack("<i", data)[0]
            print(value)
        elif value_type == "str":
            data = read_proc_mem(pid, addr, 64)
            # Find null terminator
            null_idx = data.find(b'\x00')
            if null_idx >= 0:
                data = data[:null_idx]
            print(data.decode("utf-8", errors="replace"))
        else:
            print(f"Unknown type: {value_type}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
