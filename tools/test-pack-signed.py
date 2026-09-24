#!/usr/bin/env python3
"""Regression checks for tools/pack-signed.py. Plain asserts, no framework.

    python3 tools/test-pack-signed.py

Part A is pure: it drives geometry()/header_slot_occupants()/image_bounds()/
attribute() over synthetic section lists, including the real 4-byte .text ->
.rodata alignment gap, and over the malformed layouts the packer must refuse.
Nothing is read or written.

Part B is end to end and nonzero-exit by construction: it mints a bad-layout ELF
and a corrupted-signature artifact under target/software-only/fixtures/ and shows
the packer and checkfw REFUSING them, for the intended reason, not just failing.
It needs the release ELF and a packed artifact, and it FAILS (never skips) if
they are missing -- a check that cannot run is a missing check, not a pass.

No device, no serial port, no network. The real firmware and the reference tree
are read only; every byte this writes is under target/.
"""
import importlib.util
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIXTURES = os.path.join(REPO, 'target', 'software-only', 'fixtures')
PACKAGE = os.path.join(REPO, 'target', 'software-only', 'package')
ELF = os.path.join(REPO, 'target', 'thumbv7em-none-eabihf', 'release', 'coldsnap_firmware')

sys.dont_write_bytecode = True                  # no tools/__pycache__ outside target/
spec = importlib.util.spec_from_file_location('packsigned',
                                             os.path.join(HERE, 'pack-signed.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)                      # import-safe: main() is under __main__

CASES = 0


def sec(name, lma, size, align=4, off=None, vma=None):
    return P.Sec(name, 'PROGBITS', vma if vma is not None else lma, lma,
                 lma - 0x0802_0000 if off is None else off, size, align,
                 frozenset({'SHF_ALLOC'}))


def refuses(fragment, fn, *a):
    """fn(*a) must raise Abort, and the message must say why."""
    global CASES
    CASES += 1
    try:
        fn(*a)
    except P.Abort as e:
        assert fragment in str(e), 'wrong reason: wanted %r, got %r' % (fragment, str(e))
        return str(e)
    raise AssertionError('%s accepted a layout it must refuse (%s)' % (fn.__name__, fragment))


def accepts(fn, *a):
    global CASES
    CASES += 1
    return fn(*a)


def part_a():
    global CASES
    body = ['.text', '.rodata', '.data']

    # 1. The real layout: a 4 B gap between .text and .rodata that .rodata's
    #    align 8 fully explains. The span is the sum PLUS that gap -- this is the
    #    case the old "file size == sum of section sizes" assertion got wrong.
    real = [sec('.text', 0x0802_4000, 0x4_e8a4),
            sec('.rodata', 0x0807_28a8, 0xe31c, align=8),
            sec('.data', 0x0808_0bc4, 0x24, vma=0x2000_8010, off=0x78010)]
    grp, base, span, gaps = accepts(P.geometry, real, body, 'real')
    assert base == 0x0802_4000, hex(base)
    assert span == 379_880, span
    assert sum(s.size for s in grp) == 379_876, 'the sum is NOT the span'
    assert gaps == [(0x0807_28a4, 0x0807_28a8, 8)], gaps
    assert [s.name for s in grp] == body, 'sorted by LMA, so .data lands last'

    # 2. Contiguous: no gap, and then the span does equal the sum.
    _, _, span, gaps = accepts(P.geometry, [sec('.text', 0x0802_4000, 0x100),
                                            sec('.rodata', 0x0802_4100, 0x40)],
                               body, 'tight')
    assert (span, gaps) == (0x140, []), (span, gaps)

    # 3. Overlap: two sections claiming one flash byte.
    refuses('OVERLAPS', P.geometry, [sec('.text', 0x0802_4000, 0x100),
                                     sec('.rodata', 0x0802_40ff, 0x40)], body, 'overlap')

    # 4. A hole too big for the next section's alignment to explain. Alignment
    #    padding is attributable; this is not, so it must not be emitted.
    refuses('NOT alignment padding',
            P.geometry, [sec('.text', 0x0802_4000, 0x101),
                         sec('.rodata', 0x0802_4200, 0x40, align=8)], body, 'hole')

    # 5. Arithmetic overflow of the address space.
    refuses('overruns 32-bit', P.geometry,
            [sec('.text', 0xffff_ff00, 0x200)], ['.text'], 'wrap')

    # 6. An empty group: the -j list naming something the ELF no longer has.
    refuses('no flash-resident section', P.geometry, real, ['.gone'], 'empty')

    # 7. The header slot, by LMA. The second case is the one a VMA test misses:
    #    a RAM VMA whose flash LMA lands inside the reserved 128 B slot.
    assert P.header_slot_occupants(real) == [], 'the real image leaves the slot alone'
    CASES += 1
    for s in (sec('.text', 0x0802_3f00, 0x200),
              sec('.data', 0x0802_3f80, 0x80, vma=0x2000_8010)):
        assert P.header_slot_occupants([s]) == [s.name], \
            '%s at LMA 0x%08x covers the slot' % (s.name, s.lma)
        CASES += 1

    # 8. Image bounds: FLASH_FS is littlefs's, and 32 bits is all there is.
    assert accepts(P.image_bounds, 0x0802_0000, 397_312) == 0x0808_1000
    accepts(P.image_bounds, 0x0802_0000, P.FLASH_FS_BASE - 0x0802_0000)   # exactly flush
    refuses('reaches into FLASH_FS', P.image_bounds,
            0x0802_0000, P.FLASH_FS_BASE - 0x0802_0000 + 1)
    refuses('overruns 32-bit', P.image_bounds, 0xffff_0000, 0x2_0000)

    # 9. attribute(): a section whose artifact bytes drifted from the ELF, and a
    #    gap filled with something other than 0x00, are both caught.
    elf = bytes(0x2000)
    one = [sec('.text', 0x0802_4000, 0x10, off=0x100)]
    accepts(P.attribute, bytes(0x10), 0x0802_4000, one, elf, [], 'clean')
    refuses('does not match the ELF bytes', P.attribute,
            b'\x01' * 0x10, 0x0802_4000, one, elf, [], 'drift')
    refuses('is not all 0x00', P.attribute, bytes(0x10) + b'\xff' * 0x10,
            0x0802_4000, one, elf, [(0x0802_4010, 0x0802_4020, 8)], 'badfill')

    print('part A: %d pure geometry cases, all as required' % CASES)


def shell(argv, want, what):
    global CASES
    CASES += 1
    p = subprocess.run(argv, capture_output=True, text=True, cwd=REPO)
    out = p.stdout + p.stderr
    print('    $ %s\n      -> exit %d' % (' '.join(argv), p.returncode))
    assert p.returncode == want, 'wanted exit %d, got %d:\n%s' % (want, p.returncode, out)
    assert what in out, 'exit %d but not for the intended reason (wanted %r):\n%s' \
                        % (p.returncode, what, out)
    return out


def part_b():
    signed = os.path.join(PACKAGE, 'firmware-signed.bin')
    for p in (ELF, signed):
        if not os.path.exists(p):
            sys.exit('FAIL: %s is missing. These are end-to-end negatives against the\n'
                     'real artifacts, and skipping them would report a check that never\n'
                     'ran. Build and pack first:\n'
                     '  cargo build --release\n'
                     '  python3 tools/pack-signed.py --pubkey-num 0 --out %s' % (p, PACKAGE))
    os.makedirs(FIXTURES, exist_ok=True)

    # A deliberately bad layout, minted from a COPY of the real ELF: every LMA
    # shifted up by 1.375 MiB. Nothing in the firmware tree is touched.
    bad = os.path.join(FIXTURES, 'bad-layout.elf')
    subprocess.run([P.OBJCOPY, '--change-section-lma', '*+0x160000', ELF, bad], check=True)
    os.utime(bad, None)                 # fresh, so the stale-ELF guard is not the reason
    shell([sys.executable, os.path.join(HERE, 'pack-signed.py'), '--elf', bad,
           '--out', os.path.join(FIXTURES, 'bad-layout-out'), '--no-dfu'],
          1, 'would load at 0x08180000, not 0x08020000')

    # A corrupted signature: one bit of the 64 B signature field at +64 of the
    # header. checkfw R12 is the independent verifier, so it is the one that has
    # to notice -- not the tool that made the file.
    blob = bytearray(open(signed, 'rb').read())
    at = 0x3f80 + 64
    blob[at] ^= 0x01
    bent = os.path.join(FIXTURES, 'bad-signature.bin')
    open(bent, 'wb').write(blob)
    shell(['cargo', 'run', '--quiet', '--target', 'aarch64-apple-darwin',
           '-p', 'coldsnap_firmware', '--example', 'checkfw', '--', bent],
          1, 'REFUSE')

    # The rerun check compares only against an artifact made from the same inputs:
    # a new ELF/timestamp replaces the old artifact (it used to abort after already
    # overwriting it), while a changed output for identical inputs still aborts.
    rerun = os.path.join(FIXTURES, 'rerun-out')
    shutil.rmtree(rerun, ignore_errors=True)
    t = int(os.path.getmtime(ELF))
    pack = [sys.executable, os.path.join(HERE, 'pack-signed.py'), '--pubkey-num', '0',
            '--out', rerun, '--no-dfu', '--epoch']
    shell(pack + [str(t)], 0, 'no previous artifact from these inputs')
    shell(pack + [str(t)], 0, 'byte-identical to the previous')
    shell(pack + [str(t + 1)], 0, 'no previous artifact from these inputs')
    art = os.path.join(rerun, 'firmware-signed.bin')
    blob = bytearray(open(art, 'rb').read())
    blob[-1] ^= 0x01
    open(art, 'wb').write(blob)
    shell(pack + [str(t + 1)], 1, 'reproducibility broken')

    print('part B: 2 end-to-end refusals plus 4 rerun cases, each for the intended reason')


if __name__ == '__main__':
    part_a()
    part_b()
    print('OK: %d cases' % CASES)
