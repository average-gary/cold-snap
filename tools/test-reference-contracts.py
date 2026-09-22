#!/usr/bin/env python3
"""Negative fixtures for tools/check-reference-contracts.py.

Work item 7: prove representative checks actually fail, by altering TEMPORARY
fixtures -- never the live reference checkout and never the live firmware. Three
cases, one per class the prompt names:

    abi-offset      a reference ABI field offset moves      (edited pins.h)
    memory-bound    a reference memory bound moves          (edited Makefile)
    elf-vector      an ELF vector/address assumption breaks (patched ELF copy)

Each case must exit NONZERO *and* the failure must be named: a nonzero exit for
some other reason is not evidence the check works, so the expected check id has
to appear in the checker's FAIL line. A case that fails for the wrong reason is
reported as a failure of this test.

The reference tree is mirrored as a SYMLINK FARM under `target/`, with only the
one overridden file materialised as a real (edited) copy. `~/repos/coldcard-firmware`
is read, never written.
"""

import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.environ.get('COLDCARD_TREE',
                     os.path.join(os.path.dirname(REPO), 'coldcard-firmware'))
FIX = os.path.join(REPO, 'target', 'software-only', 'fixtures', 'refcheck')
CHECKER = os.path.join(REPO, 'tools', 'check-reference-contracts.py')
ELF = os.path.join(REPO, 'target', 'thumbv7em-none-eabihf', 'release', 'coldsnap_firmware')
OBJCOPY = os.environ.get('OBJCOPY', '/opt/homebrew/opt/llvm/bin/llvm-objcopy')


def mirror(src, dst):
    """dst/<name> -> src/<name> for every entry, symlinks only."""
    os.makedirs(dst, exist_ok=True)
    for name in os.listdir(src):
        link = os.path.join(dst, name)
        if not os.path.lexists(link):
            os.symlink(os.path.join(src, name), link)


def fixture_tree(root, overrides=(), remove=()):
    """A read-only mirror of the reference, with a few files edited or absent."""
    shutil.rmtree(root, ignore_errors=True)
    mirror(REF, root)

    def deepen(rel):
        parts = rel.split('/')
        for i in range(1, len(parts)):                  # materialise each dir component
            d = os.path.join(root, *parts[:i])
            if os.path.islink(d):
                real = os.path.realpath(d)
                os.unlink(d)
                mirror(real, d)
        return os.path.join(root, rel)

    for rel, edit in dict(overrides).items():
        tgt = deepen(rel)
        text = edit(open(os.path.realpath(tgt)).read())
        os.unlink(tgt)
        with open(tgt, 'w') as f:
            f.write(text)
    for rel in remove:
        os.unlink(deepen(rel))
    return root


def sub1(pat, repl):
    """One substitution, and it is an error if the pattern was not there."""
    def edit(src):
        out, n = re.subn(pat, repl, src, count=1, flags=re.M)
        if n != 1:
            raise SystemExit('FIXTURE BROKEN: %r matched %d times in the reference '
                             '-- the fixture would not be a negative case' % (pat, n))
        return out
    return edit


def patched_elf(dst, offset, data):
    shutil.copyfile(ELF, dst)
    with open(dst, 'r+b') as f:
        f.seek(offset)
        f.write(data)
    return dst


def vector_table_file_offset(elf):
    """Where .vector_table's bytes live in the file -- via the existing parser."""
    import importlib.util
    sys.dont_write_bytecode = True                       # no tools/__pycache__
    spec = importlib.util.spec_from_file_location(
        'pack_signed', os.path.join(REPO, 'tools', 'pack-signed.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [s.off for s in mod.sections(elf) if s.name == '.vector_table'][0]


def case(name, expect, argv):
    print('\n--- %s: expect nonzero naming %s' % (name, expect))
    print('    $ python3 tools/check-reference-contracts.py %s' % ' '.join(
        a.replace(REPO + '/', '') for a in argv))
    p = subprocess.run([sys.executable, CHECKER, *argv],
                       capture_output=True, text=True, cwd=REPO)
    tail = [l for l in p.stdout.splitlines() if l.startswith('FAIL:')]
    named = [l for l in p.stdout.splitlines()
             if l.strip().startswith('FAILED') and expect in l]
    print('    exit %d' % p.returncode)
    for l in named:
        print('    %s' % l.strip())
    for l in tail:
        print('    %s' % l)
    if p.returncode == 0:
        print('    *** NOT A NEGATIVE CASE: the checker passed. ***')
        return False
    if not named:
        print('    *** WRONG REASON: nonzero, but %s did not fail. Full output:' % expect)
        print(p.stdout[-3000:], p.stderr[-2000:])
        return False
    print('    OK: nonzero for the named reason')
    return True


def main():
    if not os.path.exists(ELF):
        sys.exit('ABORT: %s missing -- run `cargo build --release` first' % ELF)
    os.makedirs(FIX, exist_ok=True)
    ok = []

    # 1. ABI offset: inject a word after is_secondary, which moves `pin` from 8
    #    to 12 and every offset after it, and grows sizeof past
    #    PIN_ATTEMPT_SIZE_V2. This is the drift the Rust-literal-only test at
    #    callgate.rs:1546-1590 cannot see, because it compares Rust to Rust.
    abi = fixture_tree(os.path.join(FIX, 'abi-offset'), {
        'stm32/mk4-bootloader/pins.h': sub1(
            r'^(\s*int\s+is_secondary;.*)$',
            r'\1\n    uint32_t    injected_by_fixture;   // NOT in the real reference')})
    ok.append(case('abi-offset', 'abi/offset-pin',
                   ['--ref', abi, '--skip-pixel', '--allow-unavailable']))

    # 2. Memory bound: move the bootloader's reserved SRAM base down 56 K. Our
    #    link.x RAM then ends *inside* the 8 K the callgate wipes on every SE
    #    operation, so anything we put there does not survive a login.
    mem = fixture_tree(os.path.join(FIX, 'memory-bound'), {
        'stm32/mk4-bootloader/Makefile': sub1(
            r'^BL_SRAM_BASE = 0x2009e000', 'BL_SRAM_BASE = 0x20090000')})
    ok.append(case('memory-bound', 'memory/linkx-ram-end',
                   ['--ref', mem, '--skip-pixel', '--allow-unavailable']))

    # 3a. ELF vector assumption: word 0 of the vector table is the SP the
    #     bootloader loads (startup.S:106). Push it above BL_SRAM_BASE and the
    #     first push lands in memory the callgate wipes.
    vt = vector_table_file_offset(ELF)
    bad_sp = patched_elf(os.path.join(FIX, 'bad-sp.elf'), vt,
                         (0x2009_F000).to_bytes(4, 'little'))
    ok.append(case('elf-vector (SP word)', 'elf/sp-word-is-estack-top',
                   ['--elf', bad_sp, '--skip-pixel', '--allow-unavailable']))

    # 3b. ELF address assumption: clear the Thumb bit on the reset vector. The
    #     bootloader's `bx lr` would switch to ARM state and fault on the first
    #     instruction -- a dead unit, and nothing in the linker refuses it.
    pc = int.from_bytes(open(ELF, 'rb').read()[vt + 4:vt + 8], 'little')
    bad_thumb = patched_elf(os.path.join(FIX, 'bad-thumb-bit.elf'), vt + 4,
                            (pc & ~1).to_bytes(4, 'little'))
    ok.append(case('elf-vector (Thumb bit)', 'elf/reset-vector-thumb-bit',
                   ['--elf', bad_thumb, '--skip-pixel', '--allow-unavailable']))

    # 3c. Invalid image placement: move the whole load image up so it reaches
    #     into FLASH_FS, where the identity record and the share live. Same
    #     technique as target/software-only/fixtures/bad-layout.elf.
    shifted = os.path.join(FIX, 'shifted-lma.elf')
    subprocess.run([OBJCOPY, '--change-section-lma', '*+0x160000', ELF, shifted],
                   check=True)
    ok.append(case('elf-placement (LMA into FLASH_FS)', 'elf/vector-table-at-flash-isr',
                   ['--elf', shifted, '--skip-pixel', '--allow-unavailable']))

    # 4. The SKIP-is-not-a-pass path. A reference tree with unix/simulator.py
    #    absent takes pixel-check.py:239-240 -> skip() -> print SKIP, exit 0.
    #    The wrapper must record UNAVAILABLE and the run must not be green.
    #    pixel-check.py's other skip path (:80, their decoder moved) calls the
    #    same skip(), so one case exercises the classifier for both.
    print('\n--- pixel SKIP path: expect UNAVAILABLE, not COVERED')
    nosim = fixture_tree(os.path.join(FIX, 'no-simulator'),
                         remove=['unix/simulator.py'])
    env = dict(os.environ, COLDCARD_REPO=nosim)
    p = subprocess.run([sys.executable, os.path.join(REPO, 'tools', 'pixel-check.py')],
                       capture_output=True, text=True, cwd=REPO, env=env)
    print('    pixel-check.py alone: exit %d, %r' % (p.returncode,
                                                     p.stdout.strip()[:140]))
    q = subprocess.run([sys.executable, CHECKER, '--ref', nosim],
                       capture_output=True, text=True, cwd=REPO)
    row = [l.strip() for l in q.stdout.splitlines() if 'pixel/their-decoder' in l]
    print('    through the checker: exit %d' % q.returncode)
    for l in row:
        print('    %s' % l)
    good = (p.returncode == 0 and 'SKIP' in p.stdout
            and q.returncode != 0 and any(r.startswith('UNAVAILABLE') for r in row))
    print('    %s' % ('OK: exit-0 SKIP became a nonzero UNAVAILABLE'
                      if good else '*** the SKIP path was swallowed ***'))
    ok.append(good)

    print('\n== %d/%d negative cases behaved ==' % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


if __name__ == '__main__':
    sys.exit(main())
# EOF
