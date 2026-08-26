#!/usr/bin/env python3
"""Measure compiled code size against Coldcard Mk4's flash budget.

Sums allocatable PROGBITS sections across every member of each release .rlib.
Necessary because `llvm-size` reads only the first member of a multi-member ar
archive, and because LTO leaves code as bitcode until link time -- so this must
run against a build with LTO disabled to see real numbers:

    CARGO_PROFILE_RELEASE_LTO=false cargo build --release
    python3 tools/measure-flash.py

FLASH_TEXT is 1392K at 0x08024000 (stm32/COLDCARD_MK4/layout.ld:17).
"""
import collections
import glob
import os
import re
import struct
import sys

FLASH_TEXT = 1392 * 1024  # bytes; COLDCARD_MK4/layout.ld:17
SHT_PROGBITS, SHF_ALLOC, SHF_EXECINSTR = 1, 0x2, 0x4

# Attributed to the C libsecp256k1 static lib, which ships ~1.1MB of
# precomputed ECMULT tables. See PLAN.md 2.2.
CSECP = ('secp256k1_sys', 'libsecp256k1-')
BITCOIN = ('libbitcoin', 'libbech32', 'libbase58ck', 'libhex_')


def ar_members(data):
    """Yield (name, blob) per archive member, resolving GNU long names."""
    if not data.startswith(b'!<arch>\n'):
        return
    off, longnames = 8, b''
    while off + 60 <= len(data):
        hdr = data[off:off + 60]
        raw = hdr[0:16].rstrip()
        try:
            size = int(hdr[48:58].decode().strip())
        except ValueError:
            return
        body = data[off + 60:off + 60 + size]
        if raw == b'//':
            longnames = body
        elif raw not in (b'/', b'__.SYMDEF', b'__.SYMDEF SORTED'):
            name = raw.decode('utf-8', 'replace')
            if name.startswith('/') and name[1:].isdigit() and longnames:
                start = int(name[1:])
                end = longnames.find(b'/\n', start)
                if end < 0:
                    end = longnames.find(b'\n', start)
                name = longnames[start:end].decode('utf-8', 'replace')
            yield name.rstrip('/'), body
        off += 60 + size + (size & 1)


def elf_alloc_bytes(blob):
    """Return (text, rodata) allocatable PROGBITS bytes for one ELF32 object."""
    if len(blob) < 52 or blob[:4] != b'\x7fELF' or blob[4] != 1:
        return 0, 0
    e_shoff, = struct.unpack_from('<I', blob, 32)
    e_shentsize, e_shnum, _ = struct.unpack_from('<HHH', blob, 46)
    if not e_shoff or not e_shnum:
        return 0, 0
    text = rodata = 0
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        if o + 40 > len(blob):
            break
        _, sh_type, sh_flags, _, _, sh_size = struct.unpack_from('<IIIIII', blob, o)
        if sh_type == SHT_PROGBITS and sh_flags & SHF_ALLOC:
            if sh_flags & SHF_EXECINSTR:
                text += sh_size
            else:
                rodata += sh_size
    return text, rodata


def main():
    pattern = sys.argv[1] if len(sys.argv) > 1 else \
        'target/thumbv7em-none-eabihf/release/deps/*.rlib'
    paths = sorted(glob.glob(pattern))
    if not paths:
        sys.exit(f'no rlibs matched {pattern!r} -- build first, LTO disabled')

    sizes = collections.OrderedDict()
    for path in paths:
        with open(path, 'rb') as fh:
            data = fh.read()
        t = r = 0
        for _, blob in ar_members(data):
            a, b = elf_alloc_bytes(blob)
            t += a
            r += b
        if t + r:
            sizes[os.path.basename(path)] = (t, r)

    if not sizes:
        sys.exit('no allocatable sections found -- was LTO left enabled?')

    print(f"{'crate':<44}{'.text':>10}{'.rodata':>10}{'total':>10}")
    print('-' * 74)
    for name, (t, r) in sorted(sizes.items(), key=lambda kv: -sum(kv[1])):
        print(f'{name:<44}{t:>10,}{r:>10,}{t + r:>10,}')

    def group(keys):
        return sum(t + r for n, (t, r) in sizes.items()
                   if any(k in n for k in keys))

    total = sum(t + r for t, r in sizes.values())
    c_secp = group(CSECP)
    btc = group(BITCOIN)
    rest = total - c_secp - btc

    print('-' * 74)
    print(f'\nFLASH_TEXT budget: {FLASH_TEXT:,} bytes\n')
    for label, val in (
        ('C secp256k1-sys (precomputed tables)', c_secp),
        ('rust-bitcoin + encodings', btc),
        ('frostsnap + pure-Rust crypto', rest),
        ('ALL, as built', total),
        ('without C secp256k1-sys', btc + rest),
        ('without C secp256k1 and rust-bitcoin', rest),
    ):
        pct = val / FLASH_TEXT * 100
        flag = '  <-- DOES NOT FIT' if pct > 100 else ''
        print(f'  {label:<38}{val:>10,}  {pct:5.1f}%{flag}')


if __name__ == '__main__':
    main()
