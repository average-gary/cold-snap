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
  * Reproducible: the header format demands a BCD timestamp, so we freeze it to
    the ELF's mtime (override with --epoch / SOURCE_DATE_EPOCH), and we force
    RFC6979 deterministic ECDSA so two runs of the same ELF give the same bytes.
"""
import argparse
import contextlib
import datetime
import io
import hashlib
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
# The only sections that may carry flash-resident content. An unexpected one is
# an abort, not a warning: it would be silently dropped from the artifact.
BODY_SECTIONS = ['.text', '.rodata', '.data']
VECTOR_SECTIONS = ['.vector_table']

SECTION_TYPES = {'NULL', 'PROGBITS', 'NOBITS', 'SYMTAB', 'STRTAB', 'RELA', 'REL',
                 'DYNAMIC', 'NOTE', 'HASH', 'ARM_ATTRIBUTES', 'ARM_EXIDX',
                 'LLVM_ADDRSIG', 'GROUP', 'UNKNOWN'}


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
    """[(name, type, addr, size, flags)] from llvm-readelf, positionally parsed."""
    out, rv = run([READELF, '--sections', '--wide', elf]), []
    for line in out.splitlines():
        idx, _, rest = line.lstrip().partition(']')
        if not idx.startswith('[') or not idx[1:].strip().isdigit():
            continue                    # not a section row (header, flag legend)
        t = rest.split()
        name = '' if t[0] in SECTION_TYPES else t.pop(0)
        # Type Address Off Size ES [Flg] Lk Inf Al -- Flg is absent when empty.
        flags = t[5] if len(t) == 9 else ''
        rv.append((name, t[0], int(t[1], 16), int(t[3], 16), flags))
    if not rv:
        raise Abort('parsed no sections out of %s -- readelf output format changed?' % elf)
    return rv


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

    secs = sections(elf)
    loadable = [s for s in secs if s[1] == 'PROGBITS' and 'A' in s[4] and s[3]]
    say('    flash-resident sections (ALLOC PROGBITS, size > 0):')
    for name, _, addr, size, _ in loadable:
        say('      %-14s 0x%08x %10s B', name, addr, f'{size:,}')
    resident = sum(s[3] for s in loadable)
    say('      %-14s %10s %10s B total', '', '', f'{resident:,}')
    unexpected = [s[0] for s in loadable if s[0] not in VECTOR_SECTIONS + BODY_SECTIONS]
    if unexpected:
        raise Abort('unexpected flash-resident section(s) %s -- objcopy below would '
                    'silently drop them from the artifact. Add them to BODY_SECTIONS '
                    '(and check where link.x put them) before signing.' % unexpected)

    # Requirement: never write a header field without first checking the slot is
    # unpatched. Nothing emits a header, so "unpatched" == no section covers it.
    covering = [s[0] for s in loadable if s[2] < SLOT_END and s[2] + s[3] > SLOT_START]
    if covering:
        raise Abort('section(s) %s cover the header slot 0x%08x..0x%08x. Either a '
                    'header IS now emitted (then signit -b will refuse: its vectors '
                    'blob would be 16,384 > 16,256, signit.py:292) or link.x moved. '
                    'Refusing to guess which.' % (covering, SLOT_START, SLOT_END))
    say('    header slot 0x%08x..0x%08x: no section covers it -> unpatched; signit '
        'fills all 10 fields  [OK]', SLOT_START, SLOT_END)

    # --- 2. ELF -> two flat binaries -----------------------------------------
    say('[2] flat binaries (two objcopy runs; one whole-ELF dump would zero-fill '
        'the 16 KiB gap where signit pads 0xff)')
    os.makedirs(outdir, exist_ok=True)
    fw0, fw1 = os.path.join(outdir, 'firmware0.bin'), os.path.join(outdir, 'firmware1.bin')
    jflag = lambda names: [a for n in names for a in ('-j', n)]  # noqa: E731
    run([OBJCOPY, '-O', 'binary'] + jflag(VECTOR_SECTIONS) + [elf, fw0])
    run([OBJCOPY, '-O', 'binary'] + jflag(BODY_SECTIONS) + [elf, fw1])
    for path, names in ((fw0, VECTOR_SECTIONS), (fw1, BODY_SECTIONS)):
        got = os.path.getsize(path)
        want = sum(s[3] for s in loadable if s[0] in names)
        say('    %-14s %-38s %10s B (sum of section sizes %s)',
            os.path.basename(path), ' '.join(jflag(names)), f'{got:,}', f'{want:,}')
        if got != want:
            raise Abort('%s is %d B but its sections sum to %d B: objcopy gap-filled '
                        '%+d B. Split the -j list so no gap is spanned.'
                        % (path, got, want, got - want))
    say('    no gap fill: both flat files equal the sum of their sections')

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
    # 0xff padding, both regions (verify.c hashes it; erased flash matches it).
    for lo, hi, what in ((vec, signit.FW_HEADER_OFFSET, 'vector'),
                         (signit.FW_HEADER_OFFSET + signit.FW_HEADER_SIZE + body, fw_len,
                          'body')):
        blob = got[lo:hi]
        if blob and set(blob) != {0xFF}:
            raise Abort('%s padding [0x%x,0x%x) is not all 0xff' % (what, lo, hi))
        say('    %s padding [0x%05x,0x%05x) = %s B, all 0xff  [OK]', what, lo, hi,
            f'{hi - lo:,}')
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
