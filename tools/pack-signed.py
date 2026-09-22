#!/usr/bin/env python3
"""ELF -> signed Mk4 artifact, in one command, with every byte accounted for.

    python3 tools/pack-signed.py [--elf PATH] [--out DIR] [--fw-version 6.0.0cs]

Produces target/pack/firmware-signed.bin (raw, 0x08020000) and
target/pack/coldsnap-<ver>.dfu (what a human hands to `ckcc upgrade`).
NOTHING IS FLASHED and nothing is written outside --out.

Needs an interpreter with signit.py's two deps (`ecdsa`, `click`):

    python3 -m venv target/pack-venv
    target/pack-venv/bin/pip install ecdsa click

This script re-execs itself into target/pack-venv automatically if it exists.

Why it is shaped this way (all of it measured, see PLAN.md / README.md):
  * The 128-byte header at 0x08023f80 is NOT emitted by our build. `link.x`
    shrinks FLASH_ISR to 0x3f80 so nothing can grow into the slot, and
    `cli/signit.py` builds all ten header fields itself at pack time. So this
    tool's "did the emitter leave the slot alone" check is a check that NO
    section covers the slot -- if one ever does, signit would either drop it
    (-r path, signit.py:275-276) or refuse to sign (-b path, signit.py:292).
  * Two objcopy calls, never one whole-ELF dump: the 16 KiB hole between
    .vector_table and .text would come out zero-filled, where signit's own
    padding is 0xff.
  * A flat file is NOT the sum of its section sizes. .rodata's alignment is 8
    and .text ends at 0x080728a4, so four bytes of alignment padding are
    legitimate and objcopy is right to emit them. The check is validated
    flash-load geometry -- max(lma+size) - min(lma), with every gap required to
    be exactly the next section's alignment padding -- not a sum. See geometry().
  * Flash placement is by LMA, never VMA. .data lives at VMA 0x20008010 (RAM)
    and LMA 0x08080bc4 (flash); an ELF section header has no LMA field, so it
    comes from the PT_LOAD that contains the section. See sections().
  * Reproducible: the header format demands a BCD timestamp, so we freeze it to
    the ELF's mtime (override with --epoch / SOURCE_DATE_EPOCH), and we force
    RFC6979 deterministic ECDSA so two runs of the same ELF give the same bytes.
"""
import argparse
import collections
import contextlib
import datetime
import io
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLDCARD = os.environ.get('COLDCARD_TREE',
                          os.path.join(os.path.dirname(REPO), 'coldcard-firmware'))
VENV_PY = os.path.join(REPO, 'target', 'pack-venv', 'bin', 'python3')
DEFAULT_ELF = os.path.join(REPO, 'target', 'thumbv7em-none-eabihf', 'release',
                           'coldsnap_firmware')
OBJCOPY = os.environ.get('OBJCOPY', '/opt/homebrew/opt/llvm/bin/llvm-objcopy')
READELF = os.environ.get('READELF', '/opt/homebrew/opt/llvm/bin/llvm-readelf')

# firmware/link.x:25,148-149 -- the reserved header slot, flash addresses.
SLOT_START, SLOT_END = 0x0802_3F80, 0x0802_4000
FLASH_ORIGIN = 0x0802_0000
# hal/src/lib.rs:181 (memmap::FLASH_FS_BASE) == link.x:47's FLASH_TEXT end. The
# littlefs region. An image reaching it would be erased by the filesystem.
FLASH_FS_BASE = 0x0818_0000
# The only sections that may carry flash-resident content. An unexpected one is
# an abort, not a warning: it would be silently dropped from the artifact.
BODY_SECTIONS = ['.text', '.rodata', '.data']
VECTOR_SECTIONS = ['.vector_table']
# Two fills, two owners, and they are NOT interchangeable. Inter-section
# alignment padding inside one -j group is emitted by llvm-objcopy, which fills
# 0x00 (we pass --gap-fill 0 rather than trust the default). Everything signit
# adds -- the vector/header gap and the post-body alignment -- is 0xff, matching
# erased flash (shared/sigheader.py:11-12). verify.c hashes both.
GAP_FILL, PAD_FILL = 0x00, 0xFF
ADDR_BITS = 32

# One row per ELF section. `vma` is where it is USED, `lma` is where its bytes
# LIVE in flash; for .data those differ (RAM VMA, flash LMA) and only the LMA
# places bytes in the artifact. `off`/`size` locate the bytes in the ELF file,
# `align` is what forces (and therefore explains) any gap in front of it.
Sec = collections.namedtuple('Sec', 'name type vma lma off size align flags')


class Abort(Exception):
    pass


def say(fmt, *a):
    print(fmt % a if a else fmt, flush=True)


def quoted(signit, argv):
    """Run a signit subcommand in-process, echoing its output indented."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        signit.main(argv, standalone_mode=False)   # asserts propagate as Abort
    for line in buf.getvalue().splitlines():
        say('    | %s', line)
    return buf.getvalue()


def need(path, what):
    if not os.path.exists(path):
        raise Abort('%s not found at %s' % (what, path))
    return path


def run(cmd):
    say('    $ %s', ' '.join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise Abort('%s exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s'
                    % (cmd[0], p.returncode, p.stdout, p.stderr))
    return p.stdout


def sections(elf):
    """[Sec] from llvm-readelf's JSON -- both addresses, not a column parse.

    An ELF section header has no LMA field, so the flash address comes from the
    PT_LOAD segment that contains the section's file range:

        lma = p_paddr + (sh_offset - p_offset)

    For everything but .data that equals the VMA. For .data it does not, and
    using the VMA there would place 36 bytes at 0x20008010 -- RAM, 384 MiB past
    the end of the artifact.
    """
    out = run([READELF, '--elf-output-style=JSON', '--pretty-print',
               '--sections', '--program-headers', elf])
    try:
        doc = json.loads(out)[0]
        rows = [s['Section'] for s in doc['Sections']]
        loads = [p['ProgramHeader'] for p in doc['ProgramHeaders']
                 if p['ProgramHeader']['Type']['Name'] == 'PT_LOAD']
    except (ValueError, KeyError, IndexError) as e:
        raise Abort('could not read %s as llvm-readelf JSON (%s: %s) -- output format '
                    'changed?' % (elf, type(e).__name__, e))
    rv = []
    for s in rows:
        flags = frozenset(f['Name'] for f in s['Flags']['Flags'])
        typ = s['Type']['Name'].removeprefix('SHT_')
        sec = Sec(s['Name']['Name'], typ, s['Address'], s['Address'], s['Offset'],
                  s['Size'], s['AddressAlignment'], flags)
        if typ == 'PROGBITS' and 'SHF_ALLOC' in flags and sec.size:
            seg = [p for p in loads
                   if p['FileSize'] and p['Offset'] <= sec.off
                   and sec.off + sec.size <= p['Offset'] + p['FileSize']]
            if len(seg) != 1:
                raise Abort('%s is flash-resident but %d PT_LOAD segments contain its '
                            'file range [0x%x,0x%x): its load address is undecidable, '
                            'so refusing to guess where its bytes belong.'
                            % (sec.name, len(seg), sec.off, sec.off + sec.size))
            sec = sec._replace(lma=seg[0]['PhysicalAddress'] + (sec.off - seg[0]['Offset']))
        rv.append(sec)
    if not rv:
        raise Abort('parsed no sections out of %s -- readelf output format changed?' % elf)
    return rv


def align_up(n, a):
    return n if a <= 1 else -(-n // a) * a


def geometry(secs, names, what):
    """Validated flash-load geometry of one `objcopy -j` group.

    Returns (group, base, span, gaps): the sections in load order, the flash
    address the flat file starts at, the exact byte count objcopy must emit, and
    every inter-section gap it will fill as (lo, hi, alignment-that-forced-it).

    This is what replaces "the file size equals the sum of the section sizes".
    That assumption is wrong for any group whose members are not contiguous, and
    the linked image is not: .rodata's section alignment is 8 while .text ends at
    0x080728a4, so four bytes of alignment padding are legitimate and objcopy is
    right to emit them. The sum is not the geometry; max(lma+size) - min(lma) is.

    A gap is accepted ONLY when it is exactly the padding the next section's
    alignment requires. Anything else is a hole nothing accounts for, and the
    "every emitted byte is attributed" rule says refuse it rather than ship it.
    """
    grp = sorted((s for s in secs if s.name in names), key=lambda s: s.lma)
    if not grp:
        raise Abort('no flash-resident section matched the %s group %s' % (what, names))
    for s in grp:
        if s.lma + s.size > 1 << ADDR_BITS:
            raise Abort('%s: LMA 0x%x + %d B overruns %d-bit flash addressing'
                        % (s.name, s.lma, s.size, ADDR_BITS))
    gaps, end = [], grp[0].lma + grp[0].size
    for s in grp[1:]:
        if s.lma < end:
            raise Abort('%s at 0x%08x OVERLAPS the section before it, which ends at '
                        '0x%08x. Two sections cannot own the same flash byte; one '
                        'would be written over the other.' % (s.name, s.lma, end))
        if s.lma > end:
            want = align_up(end, s.align)
            if s.lma != want:
                raise Abort('%d B hole at 0x%08x..0x%08x in front of %s is NOT '
                            'alignment padding: align %d would put it at 0x%08x. '
                            'Refusing to emit bytes nothing accounts for.'
                            % (s.lma - end, end, s.lma, s.name, s.align, want))
            gaps.append((end, s.lma, s.align))
        end = s.lma + s.size
    return grp, grp[0].lma, end - grp[0].lma, gaps


def header_slot_occupants(secs):
    """Sections whose FLASH bytes land in the reserved 128-byte header slot.

    By LMA, deliberately: a section with a RAM VMA can still have a flash LMA
    inside the slot, and the VMA test used to miss exactly that case.
    """
    return [s.name for s in secs if s.lma < SLOT_END and s.lma + s.size > SLOT_START]


def image_bounds(base, total):
    """Refuse an image that wraps the address space or reaches into FLASH_FS."""
    if base + total > 1 << ADDR_BITS:
        raise Abort('image 0x%08x + %d B overruns %d-bit flash addressing'
                    % (base, total, ADDR_BITS))
    if base + total > FLASH_FS_BASE:
        raise Abort('image 0x%08x..0x%08x (%s B) reaches into FLASH_FS at 0x%08x '
                    '(hal/src/lib.rs:181, link.x:47). littlefs owns that region and '
                    'would erase the tail of the firmware.'
                    % (base, base + total, f'{total:,}', FLASH_FS_BASE))
    return base + total


def attribute(blob, base, grp, elf_bytes, gaps, label):
    """Prove each byte of one flat group: ELF section content, or gap fill."""
    for s in grp:
        at = s.lma - base
        if blob[at:at + s.size] != elf_bytes[s.off:s.off + s.size]:
            raise Abort('%s: %s (%s B at LMA 0x%08x, artifact offset 0x%05x) does not '
                        'match the ELF bytes at file offset 0x%05x'
                        % (label, s.name, f'{s.size:,}', s.lma, at, s.off))
    for lo, hi, al in gaps:
        seen = set(blob[lo - base:hi - base])
        if seen != {GAP_FILL}:
            raise Abort('%s: the %d B align-%d gap at 0x%08x..0x%08x is not all '
                        '0x%02x (saw %s)'
                        % (label, hi - lo, al, lo, hi, GAP_FILL,
                           ' '.join('0x%02x' % b for b in sorted(seen)[:8])))


def utc(epoch):
    """Naive UTC datetime; utcfromtimestamp() is deprecated on 3.12+."""
    return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) \
                            .replace(tzinfo=None)


def bcd_timestamp(when):
    """8-byte BCD YYMMDDHHMMSS0000. Same conversion as cli/signit.py:30-45."""
    f = when.strftime('%y%m%d%H%M%S0000').encode('ascii')
    rv = bytes([((f[i] & 0xf) << 4) | (f[i + 1] & 0xf) for i in range(0, 16, 2)])
    if len(rv) != 8 or rv[0] >= 0x40:
        raise Abort('bad BCD timestamp %r (verify.c:214 needs byte0 < 0x40)' % rv)
    return rv


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--elf', default=DEFAULT_ELF)
    ap.add_argument('--out', default=os.path.join(REPO, 'target', 'pack'))
    ap.add_argument('--fw-version', default='6.0.0cs',
                    help='<8 chars, major >= 3 or the installer calls it a downgrade')
    ap.add_argument('--pubkey-num', type=int, default=0)
    ap.add_argument('--epoch', type=int, default=os.environ.get('SOURCE_DATE_EPOCH'),
                    help='UTC epoch seconds for the header timestamp (default: ELF mtime)')
    ap.add_argument('--no-dfu', action='store_true')
    args = ap.parse_args()

    elf = os.path.abspath(args.elf)
    outdir = os.path.abspath(args.out)
    ver = args.fw_version

    # --- 0. tools, keys, sanity of the arguments -------------------------------
    say('== cold-snap packaging: ELF -> signed Mk4 artifact (nothing is flashed) ==')
    say('[0] tools and keys')
    need(OBJCOPY, 'llvm-objcopy (set $OBJCOPY)')
    need(READELF, 'llvm-readelf (set $READELF)')
    cli = need(os.path.join(COLDCARD, 'cli'), 'coldcard-firmware/cli (set $COLDCARD_TREE)')
    stm32 = need(os.path.join(COLDCARD, 'stm32'), 'coldcard-firmware/stm32')
    need(os.path.join(cli, 'signit.py'), 'signit.py')
    key = need(os.path.join(stm32, 'keys', '%02d.pem' % args.pubkey_num),
               'signing key %02d.pem' % args.pubkey_num)
    need(os.path.join(stm32, 'keys', '%02d.pubkey.pem' % args.pubkey_num),
         'verification key %02d.pubkey.pem' % args.pubkey_num)
    dfu_py = None if args.no_dfu else need(
        os.path.join(COLDCARD, 'external', 'micropython', 'tools', 'dfu.py'), 'dfu.py')
    if len(ver) >= 8:
        raise Abort('version %r is %d chars; signit.py:263 caps it at 7' % (ver, len(ver)))
    if ver[1:2] == '.' and ver[0] < '3':
        raise Abort('version %r has major < 3; check_is_downgrade (verify.c:169-177) '
                    'would refuse it at install time' % ver)
    say('    llvm-objcopy   %s', OBJCOPY)
    say('    signit.py      %s (imported in-process)', os.path.join(cli, 'signit.py'))
    say('    signing key    %s (pubkey_num=%d)', key, args.pubkey_num)
    say('    dfu.py         %s', dfu_py or '(skipped: --no-dfu)')
    say('    version_string %r (%d chars, major >= 3)', ver, len(ver))

    sys.path.insert(0, cli)
    import signit                      # noqa: E402  -- needs sys.path above
    os.chdir(stm32)                    # signit resolves keys/ relative to CWD

    # --- 1. the ELF, and the header slot --------------------------------------
    say('[1] input ELF')
    need(elf, 'ELF')
    blob = open(elf, 'rb').read(SLOT_START - FLASH_ORIGIN + 4)
    if blob[SLOT_START - FLASH_ORIGIN:] == b'\x34\x12\x00\xcc' or blob[:5] == b'DfuSe':
        raise Abort('%s is ALREADY a signed artifact (magic 0xCC001234 at its header '
                    'slot). Refusing rather than double-signing. Pass the ELF.' % elf)
    if blob[:4] != b'\x7fELF':
        raise Abort('%s is not an ELF (starts %r)' % (elf, blob[:4]))
    elf_size, mtime = os.path.getsize(elf), os.path.getmtime(elf)
    when = utc(args.epoch if args.epoch else mtime)
    say('    %s', elf)
    say('    %s B, mtime %sZ', f'{elf_size:,}', utc(mtime).isoformat())

    # Signing a stale ELF is the "harness certified a stale binary" bug with a
    # bench visit attached. firmware/examples is deliberately NOT in this set
    # (examples do not link into the bin) and neither is Cargo.lock -- cargo
    # touches it on any build in any lane, content unchanged, so it only ever
    # produces false aborts.
    newest, src = 0, None
    for root in ('firmware/src', 'hal/src', 'firmware/link.x'):
        p = os.path.join(REPO, root)
        for base, _, files in ([(os.path.dirname(p), None, [os.path.basename(p)])]
                               if os.path.isfile(p) else os.walk(p)):
            for f in files:
                m = os.path.getmtime(os.path.join(base, f))
                if m > newest:
                    newest, src = m, os.path.join(base, f)
    if newest > mtime:
        raise Abort('%s is NEWER than the ELF (%sZ vs %sZ): this ELF is stale. Run '
                    '`cargo build --release` first.'
                    % (src, utc(newest).isoformat(), utc(mtime).isoformat()))
    say('    newer than every input under firmware/src, hal/src and link.x '
        '(newest %sZ)  [OK]', utc(newest).isoformat())

    elf_bytes = open(elf, 'rb').read()
    secs = sections(elf)
    loadable = [s for s in secs
                if s.type == 'PROGBITS' and 'SHF_ALLOC' in s.flags and s.size]
    say('    flash-resident sections (ALLOC PROGBITS, size > 0):')
    say('      %-14s %-10s %-10s %-9s %10s %5s', 'name', 'LMA', 'VMA', 'ELF off',
        'size', 'align')
    for s in loadable:
        say('      %-14s 0x%08x 0x%08x 0x%07x %10s B %4d%s', s.name, s.lma, s.vma,
            s.off, f'{s.size:,}', s.align, '   <- RAM VMA, flash LMA'
            if s.lma != s.vma else '')
    say('      %-14s %10s %10s %9s %10s B sum (NOT the emitted span, see [2])',
        '', '', '', '', f'{sum(s.size for s in loadable):,}')
    unexpected = [s.name for s in loadable
                  if s.name not in VECTOR_SECTIONS + BODY_SECTIONS]
    if unexpected:
        raise Abort('unexpected flash-resident section(s) %s -- objcopy below would '
                    'silently drop them from the artifact. Add them to BODY_SECTIONS '
                    '(and check where link.x put them) before signing.' % unexpected)

    # Requirement: never write a header field without first checking the slot is
    # unpatched. Nothing emits a header, so "unpatched" == no section covers it.
    covering = header_slot_occupants(loadable)
    if covering:
        raise Abort('section(s) %s cover the header slot 0x%08x..0x%08x. Either a '
                    'header IS now emitted (then signit -b will refuse: its vectors '
                    'blob would be 16,384 > 16,256, signit.py:292) or link.x moved. '
                    'Refusing to guess which.' % (covering, SLOT_START, SLOT_END))
    say('    header slot 0x%08x..0x%08x: no section LMA covers it -> unpatched; '
        'signit fills all 10 fields  [OK]', SLOT_START, SLOT_END)

    # --- 2. ELF -> two flat binaries -----------------------------------------
    say('[2] flat binaries (two objcopy runs; one whole-ELF dump would zero-fill '
        'the 16 KiB gap where signit pads 0xff)')
    os.makedirs(outdir, exist_ok=True)
    fw0, fw1 = os.path.join(outdir, 'firmware0.bin'), os.path.join(outdir, 'firmware1.bin')
    jflag = lambda names: [a for n in names for a in ('-j', n)]  # noqa: E731
    # --gap-fill 0 states the fill instead of inheriting llvm-objcopy's default,
    # so the attribution below checks a promise rather than today's behaviour.
    cut = [OBJCOPY, '-O', 'binary', '--gap-fill', '%d' % GAP_FILL]
    run(cut + jflag(VECTOR_SECTIONS) + [elf, fw0])
    run(cut + jflag(BODY_SECTIONS) + [elf, fw1])
    # signit concatenates vectors, header and body at FIXED offsets
    # (signit.py:368), so each group's base address is part of the contract.
    geo = []
    for path, names, want_base in ((fw0, VECTOR_SECTIONS, FLASH_ORIGIN),
                                   (fw1, BODY_SECTIONS, SLOT_END)):
        short = os.path.basename(path)
        grp, base, span, gaps = geometry(loadable, names, short)
        if base != want_base:
            raise Abort('%s would load at 0x%08x, not 0x%08x: signit lays the vectors, '
                        'header and body down at fixed offsets, so a moved base shifts '
                        'the whole image silently. link.x moved -- fix it there.'
                        % (short, base, want_base))
        got = os.path.getsize(path)
        say('    %-14s %-38s %10s B', short, ' '.join(jflag(names)), f'{got:,}')
        say('      0x%08x..0x%08x span %s B = %s B of sections + %s B in %d '
            'alignment gap(s)', base, base + span, f'{span:,}',
            f'{sum(s.size for s in grp):,}',
            f'{sum(hi - lo for lo, hi, _ in gaps):,}', len(gaps))
        for lo, hi, al in gaps:
            prev = [s.name for s in grp if s.lma + s.size == lo][0]
            say('      gap 0x%08x..0x%08x %5d B of 0x%02x: %s ends unaligned, the next '
                'section needs align %d', lo, hi, hi - lo, GAP_FILL, prev, al)
        if got != span:
            raise Abort('%s is %d B but its validated flash-load geometry spans %d B '
                        '(%+d): objcopy emitted bytes the section layout does not '
                        'explain.' % (path, got, span, got - span))
        attribute(open(path, 'rb').read(), base, grp, elf_bytes, gaps, short)
        say('      every byte re-read from the ELF at its own file offset and the gap '
            'fill checked  [OK]')
        geo.append((grp, base, span, gaps))

    # --- 3. padding arithmetic (signit does the padding; we restate + check) --
    say('[3] padding -- fill value 0xff, matching erased flash (sigheader.py:11-12)')
    body = os.path.getsize(fw1)
    vec = os.path.getsize(fw0)
    floor = signit.FW_MIN_LENGTH
    if body >= floor:
        say('    body %s B >= FW_MIN_LENGTH %s B ALREADY EXCEEDED by %s B '
            '-> padding for alignment only', f'{body:,}', f'{floor:,}', f'{body - floor:,}')
    else:
        say('    body %s B < FW_MIN_LENGTH %s B -> signit.py:293 will REFUSE '
            '(it pads for alignment, never up to the floor)', f'{body:,}', f'{floor:,}')
        raise Abort('body too small: %d < %d' % (body, floor))
    a512 = (body + 511) & ~511
    a4k = (a512 + 4095) & ~4095
    say('    align_to(%s, 512)  = %s  (+%d)', f'{body:,}', f'{a512:,}', a512 - body)
    say('    align_to(%s, 4096) = %s  (+%d)   [Mk4 4 K erase unit, signit.py:302-306, '
        'verify.c:106]', f'{a512:,}', f'{a4k:,}', a4k - a512)
    say('    body %s B + %d B of 0xff = %s B; vectors %d B + %s B of 0xff = %s B',
        f'{body:,}', a4k - body, f'{a4k:,}', vec,
        f'{signit.FW_HEADER_OFFSET - vec:,}', f'{signit.FW_HEADER_OFFSET:,}')
    fw_len = signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE + a4k
    say('    firmware_length = %s + %d + %s = %s (0x%x) = %d x 4096',
        f'{signit.FW_HEADER_OFFSET:,}', signit.FW_HEADER_SIZE, f'{a4k:,}',
        f'{fw_len:,}', fw_len, fw_len // 4096)
    # The body group's base is only the body's base because signit puts the
    # 16,256 B vector region and the 128 B header in front of it. If the
    # reference tree ever changes either size, the two stop lining up and every
    # artifact offset computed from an LMA below is off. Check, do not assume.
    if signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE != SLOT_END - FLASH_ORIGIN:
        raise Abort('signit puts the body at offset %d but link.x puts .text at '
                    '0x%08x = offset %d: the two layouts no longer agree'
                    % (signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE, SLOT_END,
                       SLOT_END - FLASH_ORIGIN))
    end = image_bounds(FLASH_ORIGIN, fw_len)
    say('    image 0x%08x..0x%08x, %s B clear of FLASH_FS 0x%08x  [OK]',
        FLASH_ORIGIN, end, f'{FLASH_FS_BASE - end:,}', FLASH_FS_BASE)

    # --- 4. header fields we are asking signit to write ----------------------
    ts = bcd_timestamp(when)
    say('[4] header fields to be written into the slot (signit.py:315-325)')
    say('      +0  magic_value     0x%08X', signit.FW_HEADER_MAGIC)
    say('      +4  timestamp       %s  (BCD, = %sZ, frozen to %s)', ts.hex(),
        when.isoformat(), 'ELF mtime' if not args.epoch else '--epoch')
    say('      +12 version_string  %r zero-padded to 8', ver)
    say('      +20 pubkey_num      %d', args.pubkey_num)
    say('      +24 firmware_length %d (0x%x) -- TOTAL from 0x%08x, header and '
        'vectors included', fw_len, fw_len, FLASH_ORIGIN)
    say('      +28 install_flags   0 (never FWHIF_HIGH_WATER: OTP ratchet)')
    say('      +32 hw_compat       0x%02x (Mk4|Mk5, -m mk)', signit.MK_4_OK | signit.MK_5_OK)
    say('      +36 best_ts         zeros      +44 future zeros')
    say('      +64 signature       64 B secp256k1 r||s over sha256^2 of the signed range')

    # Reproducibility, both sources of per-run entropy pinned. In-process only.
    signit.timestamp = lambda backdate=0: ts
    _sign = signit.SigningKey.sign_digest

    def deterministic_sign(self, digest, sigencode=None, **kw):
        # sign_digest_deterministic() re-enters sign_digest with the RFC6979 k,
        # so pass that inner call straight through or this recurses forever.
        if 'k' in kw:
            return _sign(self, digest, sigencode=sigencode, **kw)
        return self.sign_digest_deterministic(digest, hashfunc=hashlib.sha256,
                                             sigencode=sigencode)

    signit.SigningKey.sign_digest = deterministic_sign
    say('    clock frozen and ECDSA forced to RFC6979 (deterministic k) so a rerun '
        'of this ELF is byte-identical')

    # --- 5. sign -------------------------------------------------------------
    signed = os.path.join(outdir, 'firmware-signed.bin')
    prev = open(signed, 'rb').read() if os.path.exists(signed) else None
    argv = ['sign', ver, '-k', str(args.pubkey_num), '-m', 'mk', '-b', outdir,
            '-o', signed, '-v', '--keydir', os.path.join(stm32, 'keys')]
    say('[5] sign')
    say('    $ cd %s && signit %s', stm32, ' '.join(argv[:1] + [ver] + argv[2:]))
    quoted(signit, argv)
    got = open(signed, 'rb').read()
    say('    wrote %s  %s B', signed, f'{len(got):,}')
    if len(got) != fw_len:
        raise Abort('signed file is %d B, header says %d B. sdcard.c:233 installs the '
                    'file length while verify.c hashes firmware_length: they must match.'
                    % (len(got), fw_len))

    # --- 6. verify the artifact, independently of the code that made it ------
    say('[6] verify')
    hdr = got[signit.FW_HEADER_OFFSET:signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE]
    f = dict(zip(signit.FWH_PY_VALUES.split(), struct.unpack(signit.FWH_PY_FORMAT, hdr)))
    want = {'magic_value': signit.FW_HEADER_MAGIC, 'timestamp': ts,
            'version_string': ver.encode().ljust(8, b'\0'),
            'pubkey_num': args.pubkey_num, 'firmware_length': fw_len,
            'install_flags': 0, 'hw_compat': signit.MK_4_OK | signit.MK_5_OK,
            'best_ts': bytes(8), 'future': bytes(20)}
    bad = {k: (v, f[k]) for k, v in want.items() if f[k] != v}
    if bad:
        raise Abort('header readback disagrees with what we asked for: %r' % bad)
    if f['signature'] == b'\xff' * 64 or f['signature'] == bytes(64):
        raise Abort('signature field is blank -- signit did not sign')
    say('    all 9 non-signature fields read back exactly as requested  [OK]')
    say('    signature       %s...%s', f['signature'][:8].hex(), f['signature'][-8:].hex())
    # Every byte of the signed container, attributed. Sections come back from the
    # ELF (so signit is checked against the ELF, not against our own flat files),
    # the two fills are checked against their owners' fill values, and the whole
    # list has to tile [0, firmware_length) with no hole and no double claim --
    # that, not a sentence in a document, is what "accounted for" means here.
    regions = [(signit.FW_HEADER_OFFSET, signit.FW_HEADER_SIZE, 'signit header', None),
               (vec, signit.FW_HEADER_OFFSET - vec, '0xff vector pad', PAD_FILL),
               (signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE + body, a4k - body,
                '0xff body pad', PAD_FILL)]
    for grp, base, span, gaps in geo:
        attribute(got, FLASH_ORIGIN, grp, elf_bytes, gaps, 'firmware-signed.bin')
        regions += [(s.lma - FLASH_ORIGIN, s.size, s.name, None) for s in grp]
        regions += [(lo - FLASH_ORIGIN, hi - lo, 'align-%d gap' % al, GAP_FILL)
                    for lo, hi, al in gaps]
    at = 0
    for off, size, what, fill in sorted(regions, key=lambda r: r[0]):
        if off != at:
            raise Abort('byte accounting is %d B %s at offset 0x%05x (before %s): the '
                        'artifact is not exactly its parts'
                        % (abs(off - at), 'short' if off > at else 'double-claimed',
                           at, what))
        if fill is not None and size and set(got[off:off + size]) != {fill}:
            raise Abort('%s [0x%05x,0x%05x) is not all 0x%02x'
                        % (what, off, off + size, fill))
        say('    [0x%05x,0x%05x) %10s B  %s%s', off, off + size, f'{size:,}', what,
            '' if fill is None else ' (0x%02x)' % fill)
        at = off + size
    if at != fw_len:
        raise Abort('byte accounting covers %d B but firmware_length is %d B'
                    % (at, fw_len))
    say('    those %d regions tile [0,%s) exactly: every emitted byte is a section '
        'read back from the ELF, the 128 B header, or padding with a stated fill  [OK]',
        len(regions), f'{fw_len:,}')
    # Our own double-SHA256 over the two spans verify.c:80,83-84 hashes.
    a = hashlib.sha256(got[:signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE - 64])
    a.update(got[signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE:fw_len])
    fw_check = hashlib.sha256(a.digest()).hexdigest()
    say('    sha256^2 over [0,0x3fc0) + [0x4000,%d) = %s', fw_len, fw_check)
    say('    (%s B hashed = firmware_length - 64, verify.c:92)', f'{fw_len - 64:,}')

    check = quoted(signit, ['check', signed])
    if 'CORRECT' not in check:
        raise Abort('signit check did NOT say CORRECT:\n%s' % check)
    if fw_check not in check:
        raise Abort('signit check computed a different sha256^2 than our own read of '
                    'verify.c:80,83-84 (%s):\n%s' % (fw_check, check))
    stamp = '20%s-%s-%s %s:%s:%s UTC' % tuple(ts.hex()[i:i + 2] for i in range(0, 12, 2))
    if stamp not in check:
        raise Abort('signit decodes the timestamp as something other than %s' % stamp)
    say('    signature CORRECT, digest and timestamp agree with our own decode  [OK]')

    # --- 7. DFU wrapper ------------------------------------------------------
    artifacts = [signed]
    if dfu_py:
        dfu = os.path.join(outdir, 'coldsnap-%s.dfu' % ver)
        say('[7] DFU wrapper (element base 0x%08x; sdcard.c:194 and ckcc upgrade both '
            'require exactly that)', FLASH_ORIGIN)
        run([sys.executable, dfu_py, '-b', '0x%08x:%s' % (FLASH_ORIGIN, signed), dfu])
        blob = open(dfu, 'rb').read()
        if blob[:5] != b'DfuSe':
            raise Abort('%s does not start with DfuSe' % dfu)
        if got not in blob:
            raise Abort('%s does not contain the signed image verbatim' % dfu)
        say('    %s  %s B', dfu, f'{len(blob):,}')
        artifacts.append(dfu)

    # --- 8. what to do with it ----------------------------------------------
    say('[8] artifacts (NOT flashed, NOT copied anywhere)')
    for p in artifacts:
        say('    %s  %s B', p, f'{os.path.getsize(p):,}')
    if prev is not None:
        say('    rerun: %s the previous firmware-signed.bin',
            'byte-identical to' if prev == got else 'DIFFERS FROM (!)')
        if prev != got:
            raise Abort('output changed for the same ELF: reproducibility broken')
    say('    deliver with:  ckcc upgrade %s   (stock firmware, after PIN login)',
        artifacts[-1])
    say('    the SD-card path CANNOT install this: sdcard.c:248 CheckMacs the world '
        'digest against SE1 first and prints "wrong world" for anything new')
    return 0


if __name__ == '__main__':
    try:
        import click, ecdsa                      # noqa: F401 -- signit's deps
    except ImportError as e:
        venv = os.path.dirname(os.path.dirname(VENV_PY))
        # sys.prefix, not sys.executable: a venv's python3 is a symlink to the
        # system one, so realpath() can't tell them apart.
        if os.path.exists(VENV_PY) and sys.prefix != venv:
            os.execv(VENV_PY, [VENV_PY, os.path.abspath(__file__)] + sys.argv[1:])
        sys.exit('ABORT: %s -- signit.py needs ecdsa and click. Run:\n'
                 '  python3 -m venv %s\n  %s/bin/pip install ecdsa click'
                 % (e, os.path.dirname(os.path.dirname(VENV_PY)),
                    os.path.dirname(os.path.dirname(VENV_PY))))
    try:
        sys.exit(main())
    except Exception as e:                       # noqa: BLE001 -- one loud exit
        sys.exit('\nABORT (%s): %s' % (type(e).__name__, e))
# EOF
