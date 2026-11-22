#!/usr/bin/env python3
"""pahole wrapper for kernels < 6.0 (used as PAHOLE=... by vm/build-kernel.sh
and by "make oldk-privsim").

pahole >= 1.24 emits BTF that 5.x kernels reject ("Invalid btf_info
kind_flag"): ENUM64, DECL_TAG and the kind_flag that marks signed enums.
pahole is run with --skip_encoding_btf_{enum64,decl_tag}, then kind_flag is
cleared on the ENUMs in the .BTF section of the output file (same size, edited
in place). All other arguments are passed through unchanged.
"""
import os
import struct
import subprocess
import sys

PAHOLE = os.environ.get("REAL_PAHOLE", "/usr/bin/pahole")
BTF_KIND_ENUM = 6
# extra bytes after the 12-byte header, per kind (vlen = number of members)
EXTRA = {1: lambda v: 4, 3: lambda v: 12, 4: lambda v: 12 * v, 5: lambda v: 12 * v,
         6: lambda v: 8 * v, 13: lambda v: 8 * v, 14: lambda v: 4, 15: lambda v: 12 * v,
         17: lambda v: 4, 19: lambda v: 12 * v}


def btf_section(f):
    f.seek(0)
    eh = f.read(64)
    if eh[:4] != b"\x7fELF" or eh[4] != 2:
        return None
    shoff, = struct.unpack_from("<Q", eh, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", eh, 0x3A)
    shdrs = []
    for i in range(shnum):
        f.seek(shoff + i * shentsize)
        name, _, _, _, off, size = struct.unpack("<IIQQQQ", f.read(40))
        shdrs.append((name, off, size))
    stroff = shdrs[shstrndx][1]
    for name, off, size in shdrs:
        f.seek(stroff + name)
        if f.read(5) == b".BTF\x00":
            return off, size
    return None


def fix(path):
    with open(path, "r+b") as f:
        sec = btf_section(f)
        if not sec:
            return 0
        base, _ = sec
        f.seek(base)
        magic, _, _, hdr_len, type_off, type_len = struct.unpack("<HBBIII", f.read(16))
        if magic != 0xEB9F:
            return 0
        start = base + hdr_len + type_off
        f.seek(start)
        data = bytearray(f.read(type_len))
        pos = fixed = 0
        while pos + 12 <= len(data):
            info, = struct.unpack_from("<I", data, pos + 4)
            kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
            if kind == BTF_KIND_ENUM and info & 0x80000000:
                struct.pack_into("<I", data, pos + 4, info & 0x7FFFFFFF)
                fixed += 1
            pos += 12 + EXTRA.get(kind, lambda v: 0)(vlen)
        f.seek(start)
        f.write(data)
        return fixed


def main():
    args = sys.argv[1:]
    if "-J" in args or "--btf_encode" in args:
        args = ["--skip_encoding_btf_enum64", "--skip_encoding_btf_decl_tag"] + args
        rc = subprocess.call([PAHOLE] + args)
        if rc == 0:
            fix(args[-1])
        return rc
    return subprocess.call([PAHOLE] + args)


if __name__ == "__main__":
    sys.exit(main())
