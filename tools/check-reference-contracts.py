#!/usr/bin/env python3
"""Cross-check cold-snap's reference contracts against the real Coldcard sources.

One command, three buckets, and the buckets are the point:

    COVERED      the check ran against a real reference input and agreed
    FAILED       the check ran and DISAGREED -- named, nonzero exit
    UNAVAILABLE  the check could not run (missing reference, moved decoder,
                 absent tool). NOT a pass. Nonzero exit too, unless
                 --allow-unavailable says the caller knows and accepts it.

Nothing here touches a device, a serial port, or the reference checkout: the
reference tree is opened read-only and every artifact goes under `target/`.

What makes this more than self-consistency
------------------------------------------
The C side is obtained by COMPILING the reference's own headers for
`thumbv7em-none-eabihf` -- `pins.h`, `sigheader.h`, `main.h`, `psram.h`,
`verify.h` and the CMSIS/HAL headers the bootloader's own Makefile names -- and
reading the resulting constants out of the object file's `.probe` section. The
declarations are never copied. `sizeof(int)`, `sizeof(void *)` and struct
padding are exactly what a host compile would get wrong, so the probe is built
for ARM32 and its ELF class/machine are asserted before its numbers are used.

The Rust side is PARSED OUT OF THE RUST SOURCE (`pub const NAME: T = EXPR;`),
not re-typed here. A third transcription of 0x0802_4000 in this file would make
the whole exercise circular; a rename or a changed literal in the HAL shows up
as a failed check instead.

The linker side comes from `firmware/link.x` and the reference
`stm32/COLDCARD_MK4/layout.ld` / `stm32/mk4-bootloader/Makefile`, parsed.

What this does NOT establish
----------------------------
Nothing about silicon. Peripheral timing, wait states, FPU/clock behaviour,
actual ATECC608/SE2 responses, real callgate transits, and board-specific
bootloader state (option bytes, RDP level, PCROP, the pairing secret) are all
unverified by every check here and stay bench-only questions. `qemu-boot.sh`
substitutes a stack and memory map and is deliberately NOT invoked: it is a
diagnostic, never a gate.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REF = os.environ.get('COLDCARD_TREE',
                             os.path.join(os.path.dirname(REPO), 'coldcard-firmware'))
DEFAULT_ELF = os.path.join(REPO, 'target', 'thumbv7em-none-eabihf', 'release',
                           'coldsnap_firmware')
OUT = os.path.join(REPO, 'target', 'software-only', 'refcheck')
CLANG = os.environ.get('CLANG', '/opt/homebrew/opt/llvm/bin/clang')
OBJCOPY = os.environ.get('OBJCOPY', '/opt/homebrew/opt/llvm/bin/llvm-objcopy')
READELF = os.environ.get('READELF', '/opt/homebrew/opt/llvm/bin/llvm-readelf')
OBJDUMP = os.environ.get('OBJDUMP', '/opt/homebrew/opt/llvm/bin/llvm-objdump')

# `.cargo/config.toml:32` CFLAGS_thumbv7em_none_eabihf, verbatim: the flags this
# repo already cross-compiles C with. -Os/-ffreestanding do not affect constant
# values but keeping the list identical means one place to change.
ARM_CFLAGS = ['--target=thumbv7em-none-eabihf', '-mcpu=cortex-m4',
              '-mfpu=fpv4-sp-d16', '-mfloat-abi=hard', '-ffreestanding', '-Os']

# `stm32/mk4-bootloader/Makefile:65-75` -- the bootloader's own defines. Read
# from the Makefile at run time (see `makefile_defs`), not hardcoded; this list
# only names WHICH ones a probe needs.
BL_DEFINE_NAMES = ['BL_FLASH_BASE', 'BL_FLASH_SIZE', 'BL_NVROM_BASE',
                   'BL_NVROM_SIZE', 'BL_SRAM_BASE', 'BL_SRAM_SIZE']
# `Makefile:78-80` INC_PATHS, relative to the reference root.
INC_PATHS = ['external/micropython/lib/stm32lib/CMSIS/STM32L4xx/Include',
             'external/micropython/lib/stm32lib/STM32L4xx_HAL_Driver/Inc',
             'external/micropython/lib/cmsis/inc']

RUST_FILES = ['hal/src/lib.rs', 'hal/src/callgate.rs', 'hal/src/psram.rs',
              'hal/src/flash.rs', 'hal/src/display.rs', 'hal/src/keypad.rs',
              'hal/src/rng.rs', 'hal/src/panic.rs', 'hal/src/usb.rs',
              'hal/src/image.rs',
              'firmware/src/entry.rs', 'firmware/link.x']


class Abort(Exception):
    """Something the checker itself cannot proceed past. Loud, nonzero, named."""


def say(fmt, *a):
    print(fmt % a if a else fmt, flush=True)


def run(cmd, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if p.returncode != 0:
        raise Abort('%s exited %d\n%s\n%s' % (cmd[0], p.returncode, p.stdout, p.stderr))
    return p.stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# result buckets
# ---------------------------------------------------------------------------

class Log:
    def __init__(self):
        self.rows = []          # (bucket, group, ident, detail)
        self.notes = []         # recorded discrepancies that are not our failures

    def _add(self, bucket, group, ident, detail):
        self.rows.append((bucket, group, ident, detail))
        say('  %-11s %s/%s%s', bucket, group, ident, '  -- ' + detail if detail else '')

    def ok(self, group, ident, detail=''):
        self._add('COVERED', group, ident, detail)

    def fail(self, group, ident, detail):
        self._add('FAILED', group, ident, detail)

    def unavail(self, group, ident, detail):
        self._add('UNAVAILABLE', group, ident, detail)

    def eq(self, group, ident, got, want, what):
        """The workhorse: C/linker-derived `want` vs Rust-derived `got`."""
        if got is None:
            return self.fail(group, ident, '%s: could not read the cold-snap side '
                                           '(renamed or removed?)' % what)
        if want is None:
            return self.unavail(group, ident, '%s: reference side unavailable' % what)
        big = isinstance(want, int) and not isinstance(want, bool) and want > 0xffff
        fmt = (lambda v: '0x%08x' % v if isinstance(v, int) else repr(v)) if big else repr
        if got != want:
            return self.fail(group, ident, '%s: cold-snap has %s, reference says %s'
                                           % (what, fmt(got), fmt(want)))
        return self.ok(group, ident, '%s == %s' % (what, fmt(want)))

    def need(self, group, ident, rs, *names):
        """The named cold-snap ints, or None after FAILING `ident` with the missing
        names. For arithmetic/bound checks, where a defaulted 0 would pass silently."""
        bad = [n for n in names if not isinstance(rs.get(n), int)]
        if bad:
            self.fail(group, ident, 'could not read the cold-snap side of %s (renamed, '
                      'removed or ambiguous?): %s'
                      % ('/'.join(names), ', '.join('%s=%r' % (n, rs.get(n)) for n in bad)))
            return None
        return [rs[n] for n in names]

    def note(self, text):
        self.notes.append(text)

    def count(self, bucket):
        return sum(1 for r in self.rows if r[0] == bucket)


# ---------------------------------------------------------------------------
# the cold-snap side: parsed out of the real Rust source
# ---------------------------------------------------------------------------

CONST_RE = re.compile(r'^\s*(?:pub(?:\([\w:]+\))? )?const (\w+)\s*:\s*[^=]+?=\s*(.+?);\s*$',
                      re.M | re.S)


def _py(expr):
    """Rust const expression -> Python expression. Nothing clever on purpose."""
    e = expr
    e = re.sub(r'\bcrate::', '', e)
    e = re.sub(r'\b(memmap|core|mem)::', '', e)
    e = re.sub(r'\s+as\s+\*(?:mut|const)\s+\w+', '', e)
    e = re.sub(r'\s+as\s+(u8|u16|u32|u64|usize|i32|isize)\b', '', e)
    e = re.sub(r'\*b"([^"]*)"', r'b"\1"', e)
    e = re.sub(r'(\w+)\.saturating_sub\(([^()]*)\)', r'max(0, \1 - (\2))', e)
    # Rust `/` on integers truncates; Python's `/` would hand back a float and
    # then 0x%x on it throws. No const here is floating point.
    e = re.sub(r'(?<![/])/(?![/])', '//', e)
    # 0x0001_c000 / 1_024 -> strip the readability underscores, identifiers intact
    e = re.sub(r'\b(0[xXbBoO][0-9A-Fa-f_]+|\d[\d_]*)\b',
               lambda m: m.group(0).replace('_', ''), e)
    return e.strip()


def rust_consts(paths):
    """{name: value} for every `const` across `paths` whose value evaluates.

    Fixed-point, because a const may reference one declared later in the file
    (`FW_HEADER_OFFSET = FLASH_ISR_LEN - FW_HEADER_SIZE`) or in another file
    (`BURN_BASE = memmap::FLASH_ISR_BASE`). Anything that never evaluates -- a
    type, a struct literal, a fn pointer -- is dropped; a *requested* name that
    is missing becomes a FAILED check at the call site, which is the drift
    signal we want.

    A name declared twice with DIFFERENT values (local `const LEN` in two
    modules, say) is replaced by a marker string rather than an arbitrary pick,
    so any check that queries it FAILS naming the ambiguity instead of silently
    comparing against whichever declaration was parsed last.
    """
    decls = []
    for p in paths:
        decls += [(p, n, e) for n, e in CONST_RE.findall(open(p).read())]
    vals, env, ambig = {}, {'max': max, '__builtins__': {}}, {}
    for _ in range(len(decls) + 1):
        before = len(vals)
        for p, name, expr in decls:
            if name in ambig:
                continue
            try:
                v = eval(_py(expr), env, vals)               # noqa: S307
            except Exception:                                # noqa: BLE001
                continue
            if name in vals and vals[name] != v:
                ambig[name] = ('<AMBIGUOUS: %s declared with conflicting values '
                               '%r and %r>' % (name, vals[name], v))
                continue
            vals[name] = v
        if len(vals) == before:
            break
    vals.update(ambig)
    return vals


def repr_align(path, type_name):
    """The `align(N)` from `#[repr(C, align(N))]` above `struct <type_name>`."""
    src = open(path).read()
    m = re.search(r'#\[repr\(C,\s*align\((\d+)\)\)\]\s*\npub struct %s\b' % type_name, src)
    return int(m.group(1)) if m else None


def ld_memory(path):
    """{REGION: (origin, length)} out of a linker script's MEMORY block."""
    src = open(path).read()
    out = {}
    for name, o, l in re.findall(
            r'^\s*(\w+)\s*\([rwx]+\)\s*:\s*ORIGIN\s*=\s*([^,]+?)\s*,\s*LENGTH\s*=\s*(\S+)',
            src, re.M):
        out[name] = (_ldnum(o), _ldnum(l))
    return out


def _ldnum(tok):
    tok = tok.strip().rstrip(';')
    mult = {'K': 1024, 'M': 1024 * 1024}.get(tok[-1:].upper(), 1)
    if mult != 1:
        tok = tok[:-1]
    return int(tok, 0) * mult


def makefile_defs(path):
    """{NAME: int} for the `NAME = 0x...` assignments in the bootloader Makefile."""
    src = open(path).read()
    return {n: int(v, 16) for n, v in
            re.findall(r'^(\w+)\s*=\s*(0x[0-9a-fA-F]+)', src, re.M)}


# ---------------------------------------------------------------------------
# the reference side: compile its headers, read the object's .probe section
# ---------------------------------------------------------------------------

def probe(name, source, ref, defs, extra_inc=()):
    """Compile `source` for Cortex-M4 against the real reference headers.

    Returns the `.probe` words. The object is never executed -- its constants
    are read straight out of the section, which is the only honest way to get
    ARM32 `sizeof`/`offsetof` on an aarch64 host.
    """
    os.makedirs(OUT, exist_ok=True)
    c, o, b = (os.path.join(OUT, name + ext) for ext in ('.c', '.o', '.bin'))
    with open(c, 'w') as f:
        f.write(source)
    cmd = [CLANG, *ARM_CFLAGS, '-c', c, '-o', o,
           '-DMCU_SERIES_L4', '-DSTM32L4S5xx']
    cmd += ['-D%s=%#x' % (k, defs[k]) for k in BL_DEFINE_NAMES if k in defs]
    cmd += ['-I' + os.path.join(ref, p) for p in INC_PATHS]
    cmd += ['-I' + p for p in extra_inc]
    say('    $ %s', ' '.join(cmd))
    run(cmd)
    hdr = json.loads(run([READELF, '--elf-output-style=JSON', '--pretty-print',
                          '--file-header', o]))[0]['FileSummary']
    got = (hdr.get('Arch'), hdr.get('AddressSize'))
    if got != ('arm', '32bit'):
        raise Abort('%s compiled to %s, not arm/32bit -- a host-width probe would '
                    'give the wrong offsets, so refusing to use it' % (o, got))
    run([OBJCOPY, '-O', 'binary', '--only-section=.probe', o, b])
    raw = open(b, 'rb').read()
    if not raw or len(raw) % 4:
        raise Abort('%s .probe section is %d bytes -- expected a whole number of '
                    'u32 words' % (o, len(raw)))
    say('    %s: %s (ELF32/ARM), %d words from .probe', name, o, len(raw) // 4)
    return list(struct.unpack('<%dI' % (len(raw) // 4), raw))


ABI_FIELDS = ['magic_value', 'pin', 'pin_len', 'num_fails', 'attempts_left',
              'state_flags', 'hmac', 'change_flags', 'secret', 'cached_main_pin']
# The install-workflow codes `firmware::install` classifies, and the one flag it
# writes. Probed as `unsigned int`, so the negatives arrive modulo 2**32.
EPIN_KEYS = ['EPIN_HMAC_FAIL', 'EPIN_HMAC_REQUIRED', 'EPIN_BAD_MAGIC', 'EPIN_RANGE_ERR', 'EPIN_BAD_REQUEST', 'EPIN_I_AM_BRICK', 'EPIN_AE_FAIL', 'EPIN_MUST_WAIT', 'EPIN_PIN_REQUIRED', 'EPIN_WRONG_SUCCESS', 'EPIN_OLD_ATTEMPT', 'EPIN_AUTH_FAIL', 'EPIN_PRIMARY_ONLY', 'EPIN_SE2_FAIL']
ABI_KEYS = (['sizeof_pinAttempt', 'alignof_pinAttempt']
            + ['off_' + f for f in ABI_FIELDS]
            + ['MAX_PIN_LEN', 'PA_MAGIC_V2', 'PIN_ATTEMPT_SIZE_V1',
               'PIN_ATTEMPT_SIZE_V2', 'AE_SECRET_LEN', 'PA_SUCCESSFUL',
               'PA_IS_BLANK', 'PA_ZERO_SECRET',
               'sizeof_fwheader', 'FW_HEADER_SIZE', 'FW_HEADER_OFFSET',
               'FW_HEADER_MAGIC', 'FW_MIN_LENGTH', 'FW_MAX_LENGTH_MK4',
               'FWH_PK_NUM_OFFSET', 'FWH_NUM_FUTURE', 'FLASH_HEADER_BASE_MK4',
               'off_firmware_length', 'off_pubkey_num', 'sizeof_future',
               'off_hw_compat',
               'sizeof_dfu_flag', 'dfu_flag_addr', 'FIRMWARE_START',
               'PSRAM_BASE', 'PSRAM_SIZE', 'MK_4_OK',
               'sizeof_ptr', 'sizeof_int', 'sizeof_long',
               'CHANGE_FIRMWARE'] + EPIN_KEYS)

ABI_C = '''/* generated by tools/check-reference-contracts.py -- do not edit.
 * Consumes the REFERENCE declarations. Copying them here instead would reduce
 * the whole comparison to self-consistency, which is the one thing it must not
 * be. */
#include <stddef.h>
#include <stdint.h>
#include "pins.h"
#include "sigheader.h"
#include "main.h"
#include "psram.h"
#include "verify.h"
__attribute__((used, section(".probe"))) const unsigned int probe[] = {
    sizeof(pinAttempt_t), _Alignof(pinAttempt_t),
%s
    MAX_PIN_LEN, PA_MAGIC_V2, PIN_ATTEMPT_SIZE_V1, PIN_ATTEMPT_SIZE_V2,
    AE_SECRET_LEN, PA_SUCCESSFUL, PA_IS_BLANK, PA_ZERO_SECRET,
    sizeof(coldcardFirmwareHeader_t), FW_HEADER_SIZE, FW_HEADER_OFFSET,
    FW_HEADER_MAGIC, FW_MIN_LENGTH, FW_MAX_LENGTH_MK4,
    FWH_PK_NUM_OFFSET, FWH_NUM_FUTURE, FLASH_HEADER_BASE_MK4,
    offsetof(coldcardFirmwareHeader_t, firmware_length),
    offsetof(coldcardFirmwareHeader_t, pubkey_num),
    sizeof(((coldcardFirmwareHeader_t *)0)->future),
    offsetof(coldcardFirmwareHeader_t, hw_compat),
    sizeof(dfu_flag_t), (unsigned int)(uintptr_t)dfu_flag, FIRMWARE_START,
    PSRAM_BASE, PSRAM_SIZE, MK_4_OK,
    sizeof(void *), sizeof(int), sizeof(long),
    CHANGE_FIRMWARE,
%s};
''' % (''.join('    offsetof(pinAttempt_t, %s),\n' % f for f in ABI_FIELDS),
       ''.join('    (unsigned int)(%s),\n' % k for k in EPIN_KEYS))

REG_KEYS = ['FLASH_R_BASE', 'SPI1_BASE', 'GPIOA_BASE', 'GPIOB_BASE', 'GPIOD_BASE',
            'RNG_BASE', 'RTC_BASE', 'USB_OTG_FS_PERIPH_BASE', 'RCC_BASE',
            'SRAM1_BASE', 'SRAM2_BASE', 'SRAM3_BASE', 'SRAM3_SIZE',
            'FLASH_SR_BSY', 'FLASH_CR_PNB', 'FLASH_CR_BKER', 'FLASH_OPTR_DBANK',
            'FLASH_KEY1', 'FLASH_KEY2', 'FLASH_PAGE_SIZE', 'FLASH_PAGE_SIZE_128_BITS',
            'SPI_CR2_DS', 'SPI_CR2_DS_Pos', 'SPI_SR_FTLVL', 'SPI_DATASIZE_8BIT',
            'PWR_CR1_DBP', 'RCC_AHB2ENR_GPIOAEN', 'RCC_AHB2ENR_GPIOBEN',
            'RCC_AHB2ENR_GPIODEN', 'RCC_AHB2ENR_RNGEN', 'RCC_APB2ENR_SPI1EN',
            'RCC_APB1ENR1_RTCAPBEN', 'RCC_APB1ENR1_PWREN',
            'off_AHB2ENR', 'off_APB2ENR', 'off_APB1ENR1',
            'SCB_BASE', 'off_VTOR', 'off_CPACR',
            'GPIO_PIN_4', 'GPIO_PIN_6', 'GPIO_PIN_8']

REG_C = '''/* generated by tools/check-reference-contracts.py -- do not edit.
 * The CMSIS values are macro EXPRESSIONS (`AHB2PERIPH_BASE + 0x08060800UL`,
 * `FLASH_CR_PNB_Msk`), so only the preprocessor can resolve them. A grep over
 * these headers cannot. */
#include <stddef.h>
#include "stm32l4s5xx.h"
#include "stm32l4xx_hal_flash.h"
#include "stm32l4xx_hal_dma.h"
#include "stm32l4xx_hal_spi.h"
#include "stm32l4xx_hal_gpio.h"
__attribute__((used, section(".probe"))) const unsigned int probe[] = {
    FLASH_R_BASE, SPI1_BASE, GPIOA_BASE, GPIOB_BASE, GPIOD_BASE,
    RNG_BASE, RTC_BASE, USB_OTG_FS_PERIPH_BASE, RCC_BASE,
    SRAM1_BASE, SRAM2_BASE, SRAM3_BASE, SRAM3_SIZE,
    FLASH_SR_BSY, FLASH_CR_PNB, FLASH_CR_BKER, FLASH_OPTR_DBANK,
    FLASH_KEY1, FLASH_KEY2, FLASH_PAGE_SIZE, FLASH_PAGE_SIZE_128_BITS,
    SPI_CR2_DS, SPI_CR2_DS_Pos, SPI_SR_FTLVL, SPI_DATASIZE_8BIT,
    PWR_CR1_DBP, RCC_AHB2ENR_GPIOAEN, RCC_AHB2ENR_GPIOBEN,
    RCC_AHB2ENR_GPIODEN, RCC_AHB2ENR_RNGEN, RCC_APB2ENR_SPI1EN,
    RCC_APB1ENR1_RTCAPBEN, RCC_APB1ENR1_PWREN,
    offsetof(RCC_TypeDef, AHB2ENR), offsetof(RCC_TypeDef, APB2ENR),
    offsetof(RCC_TypeDef, APB1ENR1),
    SCB_BASE, offsetof(SCB_Type, VTOR), offsetof(SCB_Type, CPACR),
    GPIO_PIN_4, GPIO_PIN_6, GPIO_PIN_8,
};
'''


# ---------------------------------------------------------------------------
# identity: commit + submodule SHAs + per-file content hashes
# ---------------------------------------------------------------------------

def git(ref, *args):
    """git in `ref`, but only if `ref` IS the worktree root.

    Without the toplevel test a fixture tree under `target/` would report
    cold-snap's own HEAD as the reference commit -- a wrong identity is worse
    than none, because it looks reproducible.
    """
    top = subprocess.run(['git', '-C', ref, 'rev-parse', '--show-toplevel'],
                         capture_output=True, text=True)
    if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != os.path.realpath(ref):
        return None
    p = subprocess.run(['git', '-C', ref, *args], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else None


def identity(ref, elf, consumed):
    """Everything needed to reproduce a source-sensitive result.

    A parent commit is NOT enough. The reference tree is routinely dirty and its
    submodules can be modified in place, so the commit is recorded alongside
    `git submodule status` AND a sha256 of every individual file consumed. The
    hashes are the only part that survives a dirty tree.
    """
    ident = {
        'reference_root': ref,
        'reference_head': git(ref, 'rev-parse', 'HEAD'),
        'reference_dirty': (git(ref, 'status', '--porcelain') or '').splitlines(),
        'reference_submodules': (git(ref, 'submodule', 'status') or '').splitlines(),
        'coldsnap_head': git(REPO, 'rev-parse', 'HEAD'),
        'coldsnap_dirty': (git(REPO, 'status', '--porcelain') or '').splitlines(),
        'elf': {'path': elf, 'sha256': sha256(elf) if os.path.exists(elf) else None},
        'toolchain': {},
        'files': {},
    }
    for tool, ver in (('clang', [CLANG, '--version']), ('rustc', ['rustc', '-vV']),
                      ('llvm-readelf', [READELF, '--version'])):
        try:
            ident['toolchain'][tool] = run(ver).splitlines()[0].strip()
        except (Abort, FileNotFoundError, IndexError):
            ident['toolchain'][tool] = None
    for p in consumed:
        rel = os.path.relpath(p, ref) if p.startswith(ref) else os.path.relpath(p, REPO)
        root = 'reference' if p.startswith(ref) else 'cold-snap'
        ident['files']['%s:%s' % (root, rel)] = sha256(p) if os.path.exists(p) else None
    if ident['reference_head'] is None:
        say('    reference is NOT a git checkout (fixture tree?) -- the per-file '
            'sha256 list below is the whole identity')
    elif ident['reference_dirty']:
        say('    reference %s is DIRTY (%d entries) -- the commit alone does not '
            'identify what was read; per-file sha256 does',
            ident['reference_head'][:12], len(ident['reference_dirty']))
    # `git submodule status` reports a `+` only when the checked-out COMMIT
    # differs; a submodule whose worktree is edited in place shows a bare space
    # here and ` M <path>` in the parent. Every CMSIS header a probe consumes
    # lives inside one of these, so record each submodule's own dirt too.
    ident['reference_submodule_dirty'] = {}
    for m in ident['reference_submodules']:
        if m.startswith(('+', '-', 'U')):
            say('    submodule NOT at the recorded commit: %s', m.strip())
        parts = m.strip().split()
        if len(parts) < 2:
            continue
        sub = os.path.join(ref, parts[1])
        dirt = (git(sub, 'status', '--porcelain') or '').splitlines()
        ident['reference_submodule_dirty'][parts[1]] = len(dirt)
        if dirt:
            say('    submodule %s is at %s but its worktree has %d modified/untracked '
                'entries -- the SHA does not identify what was read; the per-file '
                'sha256 list does', parts[1], parts[0].lstrip('+-U')[:12], len(dirt))
    return ident


# ---------------------------------------------------------------------------
# ELF inspection (reuses tools/pack-signed.py's geometry engine)
# ---------------------------------------------------------------------------

def load_packer():
    """tools/pack-signed.py as a module: its geometry engine, not a second one.

    `sections()`, `geometry()`, `align_up()`, `header_slot_occupants()` and
    `image_bounds()` already encode the PT_LOAD LMA resolution, the overlap
    refusal and the "a gap is legal only if it is exactly the alignment padding"
    rule. Re-implementing any of that here would give those rules a second home.
    """
    old, sys.dont_write_bytecode = sys.dont_write_bytecode, True   # no tools/__pycache__
    try:
        spec = importlib.util.spec_from_file_location(
            'pack_signed', os.path.join(REPO, 'tools', 'pack-signed.py'))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.dont_write_bytecode = old


def elf_symbols(elf):
    doc = json.loads(run([READELF, '--elf-output-style=JSON', '--pretty-print',
                          '--symbols', elf]))[0]
    return {s['Symbol']['Name']['Name']: s['Symbol']['Value'] for s in doc['Symbols']}


def check_elf(log, elf, mm, lx, pk):
    """Item 4. Every bound compared against a parsed constant, never a literal."""
    g = 'elf'
    secs = {s.name: s for s in pk.sections(elf)}
    sym = elf_symbols(elf)
    raw = open(elf, 'rb').read()
    vt = secs.get('.vector_table')
    if vt is None:
        return log.fail(g, 'vector_table-present',
                        '%s has no .vector_table section' % elf)

    # --- reset entry: SP word and Thumb PC word, read out of the image itself
    sp, pc = struct.unpack_from('<II', raw, vt.off)
    log.eq(g, 'sp-word-is-estack-top', sp, mm.get('ESTACK_TOP'),
           'vector word 0 (SP the bootloader loads, startup.S:106)')
    if pc & 1:
        log.ok(g, 'reset-vector-thumb-bit', 'word 1 = 0x%08x, LSB set' % pc)
    else:
        log.fail(g, 'reset-vector-thumb-bit',
                 'word 1 = 0x%08x has LSB clear; the bootloader\'s `bx lr` would '
                 'switch to ARM state and fault immediately' % pc)
    text = secs.get('.text')
    if text and text.vma <= (pc & ~1) < text.vma + text.size:
        log.ok(g, 'reset-vector-in-text', 'PC 0x%08x inside .text [0x%08x,0x%08x)'
               % (pc & ~1, text.vma, text.vma + text.size))
    else:
        log.fail(g, 'reset-vector-in-text',
                 'PC 0x%08x is not inside .text' % (pc & ~1))
    if sym.get('entry_point') is not None:
        log.eq(g, 'reset-vector-is-entry-point', pc, sym['entry_point'],
               'vector word 1 vs the ENTRY() symbol')

    # --- placement
    log.eq(g, 'vector-table-at-flash-isr', vt.lma, mm.get('FLASH_ISR_BASE'),
           '.vector_table LMA')
    log.eq(g, 'vector-table-vma-equals-lma', vt.vma, vt.lma,
           '.vector_table VMA (flash-resident, no copy)')
    occ = pk.header_slot_occupants(list(secs.values()))
    if occ:
        log.fail(g, 'header-slot-reserved',
                 'sections %s have LMA bytes inside the 128-byte signature slot '
                 '[0x%08x,0x%08x); signit.py would overwrite them'
                 % (occ, pk.SLOT_START, pk.SLOT_END))
    else:
        log.ok(g, 'header-slot-reserved', 'nothing occupies [0x%08x,0x%08x) by LMA'
               % (pk.SLOT_START, pk.SLOT_END))

    # --- geometry: gaps attributed, not collapsed (pack-signed.py:167-206)
    try:
        grp, base, span, gaps = pk.geometry(list(secs.values()), pk.BODY_SECTIONS, 'body')
        end = pk.image_bounds(vt.lma, (base + span) - vt.lma)
        log.ok(g, 'body-geometry', 'body 0x%08x + %d B, %d attributed alignment gap(s)%s'
               % (base, span, len(gaps),
                  ''.join('; %d B align-%d at 0x%08x' % (hi - lo, al, lo)
                          for lo, hi, al in gaps)))
        log.ok(g, 'image-within-flash-fs',
               'image ends 0x%08x, below FLASH_FS 0x%08x' % (end, pk.FLASH_FS_BASE))
    except pk.Abort as e:
        log.fail(g, 'body-geometry', str(e))

    # --- .data copy source and RAM ranges
    data = secs.get('.data')
    if data is None:
        log.unavail(g, 'data-copy-source', 'no .data section in this image')
    else:
        log.eq(g, 'data-copy-source', data.lma, sym.get('_sidata'),
               '.data LMA vs _sidata (the address step 4 copies FROM)')
        log.eq(g, 'data-vma-start', data.vma, sym.get('_sdata'), '.data VMA vs _sdata')
        log.eq(g, 'data-vma-end', data.vma + data.size, sym.get('_edata'),
               '.data end vs _edata')
    ram_o, ram_l = lx.get('RAM', (None, None))
    for name, lo, hi in (('bss', sym.get('_sbss'), sym.get('_ebss')),):
        if lo is None or hi is None:
            log.fail(g, '%s-range' % name, '_s%s/_e%s missing from the ELF' % (name, name))
        elif ram_o is None:
            log.unavail(g, '%s-range' % name, 'link.x RAM region unreadable')
        elif lo < ram_o or hi > ram_o + ram_l:
            log.fail(g, '%s-range' % name,
                     '[0x%08x,0x%08x) escapes link.x RAM [0x%08x,0x%08x)'
                     % (lo, hi, ram_o, ram_o + ram_l))
        else:
            log.ok(g, '%s-range' % name, '[0x%08x,0x%08x), %d B, inside link.x RAM'
                   % (lo, hi, hi - lo))
    if data is not None and sym.get('_sbss') is not None:
        if max(data.vma, sym['_sbss']) < min(data.vma + data.size, sym['_ebss']):
            log.fail(g, 'bss-disjoint-from-data',
                     '.bss [0x%08x,0x%08x) overlaps .data [0x%08x,0x%08x): the '
                     'zeroing loop would erase copied initialisers'
                     % (sym['_sbss'], sym['_ebss'], data.vma, data.vma + data.size))
        else:
            log.ok(g, 'bss-disjoint-from-data', '.bss starts at .data end (0x%08x)'
                   % sym['_sbss'])
        if sym['_sbss'] == sym['_ebss']:
            log.fail(g, 'bss-nonempty',
                     '_sbss == _ebss == 0x%08x: the zeroing loop on the most '
                     'dangerous path has no user on target' % sym['_sbss'])
        else:
            log.ok(g, 'bss-nonempty', '%d B of .bss to zero' % (sym['_ebss'] - sym['_sbss']))

    # --- static RAM top vs the stack the bootloader will load
    end_sym = sym.get('_end')
    if end_sym is None:
        log.fail(g, 'static-ram-below-stack', '_end missing from the ELF')
    else:
        bl = log.need(g, 'end-below-bl-sram', mm, 'BL_SRAM_BASE')
        if bl is not None:
            log.eq(g, 'end-below-bl-sram', end_sym < bl[0], True,
                   '_end (0x%08x) below BL_SRAM_BASE (the 8 K the callgate wipes)' % end_sym)
        head = sp - end_sym
        if head <= 0:
            log.fail(g, 'static-ram-below-stack',
                     '_end 0x%08x is at or above the initial SP 0x%08x: the first '
                     'push corrupts static RAM' % (end_sym, sp))
        else:
            log.ok(g, 'static-ram-below-stack',
                   'SP 0x%08x - _end 0x%08x = %s B of stack headroom'
                   % (sp, end_sym, f'{head:,}'))

    # --- recorded disassembly review, NOT an automated assertion
    asm = os.path.join(OUT, 'reset-entry.asm')
    try:
        with open(asm, 'w') as f:
            f.write(run([OBJDUMP, '-d', '--disassemble-symbols=entry_point', elf]))
        log.ok(g, 'reset-entry-disassembly-recorded',
               'entry_point disassembly written to %s -- a RECORDED REVIEW '
               'artifact, not an assertion: no check here proves the VTOR store '
               'precedes the first faulting instruction' % asm)
    except (Abort, FileNotFoundError) as e:
        log.unavail(g, 'reset-entry-disassembly-recorded', 'objdump unavailable: %s' % e)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--ref', default=DEFAULT_REF,
                    help='Coldcard reference tree, read-only (default $COLDCARD_TREE '
                         'or ~/repos/coldcard-firmware)')
    ap.add_argument('--elf', default=DEFAULT_ELF, help='release ELF to inspect')
    ap.add_argument('--linker-script', default=os.path.join(REPO, 'firmware', 'link.x'))
    ap.add_argument('--skip-pixel', action='store_true',
                    help='do not run tools/pixel-check.py; it is then recorded '
                         'UNAVAILABLE, never as a pass')
    ap.add_argument('--allow-unavailable', action='store_true',
                    help='exit 0 with unavailable checks present (they are still '
                         'listed, and still not passes)')
    ap.add_argument('--json', help='write the full result record here')
    args = ap.parse_args(argv)

    log = Log()
    ref = os.path.abspath(args.ref)
    mk4 = os.path.join(ref, 'stm32', 'mk4-bootloader')
    layout = os.path.join(ref, 'stm32', 'COLDCARD_MK4', 'layout.ld')
    makefile = os.path.join(mk4, 'Makefile')
    psram_c = os.path.join(mk4, 'psram.c')
    clocks_c = os.path.join(mk4, 'clocks.c')

    say('== cold-snap reference-contract check (no device, no flashing) ==')
    say('[0] inputs')
    for p, what in ((ref, 'reference tree'), (makefile, 'bootloader Makefile'),
                    (layout, 'layout.ld'), (args.elf, 'release ELF'),
                    (args.linker_script, 'link.x')):
        if not os.path.exists(p):
            raise Abort('%s not found at %s' % (what, p))
    for tool in (CLANG, OBJCOPY, READELF):
        if not (os.path.exists(tool) or shutil.which(tool)):
            raise Abort('%s not found (set $CLANG/$OBJCOPY/$READELF)' % tool)

    defs = makefile_defs(makefile)
    missing = [k for k in BL_DEFINE_NAMES if k not in defs]
    if missing:
        raise Abort('%s no longer defines %s -- the probe defines come from there, '
                    'not from this script' % (makefile, missing))
    say('    reference %s', ref)
    say('    -D from Makefile: %s', ' '.join('%s=%#x' % (k, defs[k])
                                             for k in BL_DEFINE_NAMES))

    # --- cold-snap side, parsed
    rs = rust_consts([os.path.join(REPO, f) for f in RUST_FILES if f.endswith('.rs')])
    lx = ld_memory(args.linker_script)
    ref_ld = ld_memory(layout)
    say('    cold-snap: %d consts parsed from %d files; link.x MEMORY %s',
        len(rs), len([f for f in RUST_FILES if f.endswith('.rs')]), sorted(lx))

    consumed = [makefile, layout, psram_c, clocks_c,
                os.path.join(mk4, 'pins.h'), os.path.join(mk4, 'sigheader.h'),
                os.path.join(mk4, 'main.h'), os.path.join(mk4, 'psram.h'),
                os.path.join(mk4, 'verify.h'), os.path.join(mk4, 'basics.h'),
                os.path.join(mk4, 'config.h'), os.path.join(mk4, 'ae.h'),
                os.path.join(mk4, 'console.h'),
                os.path.join(ref, 'stm32', 'COLDCARD_MK4', 'pins.csv'),
                os.path.join(ref, 'shared', 'mempad.py'),
                os.path.join(ref, 'unix', 'simulator.py'),
                os.path.join(ref, 'cli', 'signit.py')]
    consumed += [os.path.join(ref, p, h) for p, h in (
        (INC_PATHS[0], 'stm32l4s5xx.h'),
        (INC_PATHS[1], 'stm32l4xx_hal_flash.h'),
        (INC_PATHS[1], 'stm32l4xx_hal_spi.h'),
        (INC_PATHS[1], 'stm32l4xx_hal_gpio.h'),
        (INC_PATHS[2], 'core_cm4.h'))]
    consumed += [os.path.join(REPO, f) for f in RUST_FILES]

    say('\n[1] reference identity (commit + submodules + per-file sha256)')
    ident = identity(ref, args.elf, consumed)

    say('\n[2] ABI probes, compiled from the reference headers for Cortex-M4')
    abi = dict(zip(ABI_KEYS, probe('abi-probe', ABI_C, ref, defs, extra_inc=[mk4])))
    if len(abi) != len(ABI_KEYS):
        raise Abort('abi probe returned %d words, expected %d' % (len(abi), len(ABI_KEYS)))
    log.eq('abi', 'probe-is-arm32',
           (abi['sizeof_ptr'], abi['sizeof_int'], abi['sizeof_long']), (4, 4, 4),
           'probe (sizeof void*, int, long); this host is %d/%d/%d'
           % (struct.calcsize('P'), struct.calcsize('i'), struct.calcsize('l')))

    a = 'abi'
    log.eq(a, 'pinAttempt-size', rs.get('PIN_ATTEMPT_SIZE'), abi['sizeof_pinAttempt'],
           'sizeof(pinAttempt_t)')
    log.eq(a, 'pinAttempt-size-v2-identity', abi['sizeof_pinAttempt'],
           abi['PIN_ATTEMPT_SIZE_V2'], 'reference sizeof vs its own PIN_ATTEMPT_SIZE_V2')
    log.eq(a, 'pinAttempt-align', repr_align(os.path.join(REPO, 'hal/src/callgate.rs'),
                                             'PinAttempt'),
           abi['alignof_pinAttempt'], '#[repr(C, align(N))] vs _Alignof(pinAttempt_t)')
    OFFS = {'magic_value': 'OFF_MAGIC', 'pin': 'OFF_PIN', 'pin_len': 'OFF_PIN_LEN',
            'num_fails': 'OFF_NUM_FAILS', 'attempts_left': 'OFF_ATTEMPTS_LEFT',
            'state_flags': 'OFF_STATE_FLAGS', 'hmac': 'OFF_HMAC',
            'change_flags': 'OFF_CHANGE_FLAGS',
            'secret': 'OFF_SECRET', 'cached_main_pin': 'OFF_CACHED_MAIN_PIN'}
    cg = open(os.path.join(REPO, 'hal/src/callgate.rs')).read()
    for field, const in OFFS.items():
        m = re.search(r'pub const %s: usize = (\d+);' % const, cg)
        log.eq(a, 'offset-' + field, int(m.group(1)) if m else None,
               abi['off_' + field], 'PinAttempt::%s vs offsetof(pinAttempt_t, %s)'
               % (const, field))
    log.eq(a, 'max-pin-len', rs.get('MAX_PIN_LEN'), abi['MAX_PIN_LEN'], 'MAX_PIN_LEN')
    log.eq(a, 'pa-magic-v2', rs.get('PA_MAGIC_V2'), abi['PA_MAGIC_V2'], 'PA_MAGIC_V2')
    log.eq(a, 'change-firmware', rs.get('CHANGE_FIRMWARE'), abi['CHANGE_FIRMWARE'],
           'callgate::CHANGE_FIRMWARE vs pins.h CHANGE_FIRMWARE')
    for k in EPIN_KEYS:
        v = rs.get(k)
        log.eq(a, k.lower().replace('_', '-'), None if v is None else v % 2**32, abi[k],
               'callgate::%s vs pins.h (mod 2**32)' % k)
    for bit in ('PA_SUCCESSFUL', 'PA_IS_BLANK', 'PA_ZERO_SECRET'):
        log.eq(a, bit.lower().replace('_', '-'), rs.get(bit), abi[bit], bit)
    log.eq(a, 'fw-header-size', rs.get('FW_HEADER_SIZE'), abi['sizeof_fwheader'],
           'memmap::FW_HEADER_SIZE vs sizeof(coldcardFirmwareHeader_t)')
    log.eq(a, 'fw-header-size-macro', abi['sizeof_fwheader'], abi['FW_HEADER_SIZE'],
           'reference sizeof vs its own FW_HEADER_SIZE (verify.c:314 STATIC_ASSERT)')
    log.eq(a, 'fw-header-offset', rs.get('FW_HEADER_OFFSET'), abi['FW_HEADER_OFFSET'],
           'memmap::FW_HEADER_OFFSET')
    log.eq(a, 'fw-length-field-offset', rs.get('FW_LENGTH_FIELD_OFFSET'),
           abi['off_firmware_length'],
           'psram::FW_LENGTH_FIELD_OFFSET vs offsetof(.., firmware_length)')
    log.eq(a, 'fw-min-body-len', rs.get('FW_MIN_BODY_LEN'), abi['FW_MIN_LENGTH'],
           'memmap::FW_MIN_BODY_LEN vs FW_MIN_LENGTH')
    log.eq(a, 'fw-header-magic', rs.get('FW_HEADER_MAGIC'), abi['FW_HEADER_MAGIC'],
           'image::FW_HEADER_MAGIC vs sigheader.h FW_HEADER_MAGIC (verify.c:212)')
    log.eq(a, 'hw-compat-field-offset', rs.get('HW_COMPAT_FIELD_OFFSET'),
           abi['off_hw_compat'],
           'image::HW_COMPAT_FIELD_OFFSET vs offsetof(.., hw_compat)')
    log.eq(a, 'mk-4-ok', rs.get('MK_4_OK'), abi['MK_4_OK'],
           'image::MK_4_OK vs sigheader.h:71 MK_4_OK (enforced in the reference by '
           'shared/utils.py:401-417 only, never by verify.c)')
    log.eq(a, 'burn-len-min', rs.get('BURN_LEN_MIN'), abi['FW_MIN_LENGTH'],
           'psram::BURN_LEN_MIN vs the bootloader\'s own floor (psram.c:264)')
    v = log.need(a, 'burn-len-max-within-fw-max', rs, 'BURN_LEN_MAX')
    if v:
        log.eq(a, 'burn-len-max-within-fw-max', v[0] <= abi['FW_MAX_LENGTH_MK4'], True,
               'psram::BURN_LEN_MAX (%s) <= FW_MAX_LENGTH_MK4 (%s)'
               % (f"{v[0]:,}", f"{abi['FW_MAX_LENGTH_MK4']:,}"))
    log.eq(a, 'dfu-flag-len', rs.get('DFU_FLAG_LEN'), abi['sizeof_dfu_flag'],
           'memmap::DFU_FLAG_LEN vs sizeof(dfu_flag_t) on ARM32')
    log.eq(a, 'dfu-flag-addr', rs.get('DFU_FLAG_ADDR'), abi['dfu_flag_addr'],
           'memmap::DFU_FLAG_ADDR vs main.h:14 dfu_flag')
    log.eq(a, 'psram-base', rs.get('PSRAM_BASE'), abi['PSRAM_BASE'], 'PSRAM_BASE')
    log.eq(a, 'psram-len', rs.get('PSRAM_LEN'), abi['PSRAM_SIZE'], 'PSRAM_LEN vs PSRAM_SIZE')
    log.eq(a, 'flash-erase-floor', rs.get('FLASH_ERASE_FLOOR'), abi['FIRMWARE_START'],
           'memmap::FLASH_ERASE_FLOOR vs verify.h:9 FIRMWARE_START')
    v = log.need(a, 'flash-header-base-mk4', rs, 'FLASH_ISR_BASE', 'FW_HEADER_OFFSET')
    if v:
        log.eq(a, 'flash-header-base-mk4', sum(v), abi['FLASH_HEADER_BASE_MK4'],
               'FLASH_ISR_BASE + FW_HEADER_OFFSET vs sigheader.h:82')
    # the reference's own struct-format contract, which cold-snap's packer relies on
    fwh = re.search(r'#define\s+FWH_PY_FORMAT\s+"([^"]+)"',
                    open(os.path.join(mk4, 'sigheader.h')).read())
    log.eq(a, 'fwh-py-format-size', struct.calcsize('=' + fwh.group(1)[1:]) if fwh else None,
           abi['sizeof_fwheader'], 'struct.calcsize(FWH_PY_FORMAT)')
    log.eq(a, 'fwh-pk-num-offset', abi['off_pubkey_num'], abi['FWH_PK_NUM_OFFSET'],
           'offsetof(.., pubkey_num) vs FWH_PK_NUM_OFFSET')
    if abi['sizeof_future'] != abi['FWH_NUM_FUTURE'] * 4:
        log.note('reference internal inconsistency (NOT a cold-snap failure): '
                 'sigheader.h future[] is %d B = %d words, but FWH_NUM_FUTURE says '
                 '%d. FWH_PY_FORMAT\'s "20s" and sizeof() agree on %d words, so the '
                 'struct is right and FWH_NUM_FUTURE is stale. Nothing in cold-snap '
                 'reads FWH_NUM_FUTURE.'
                 % (abi['sizeof_future'], abi['sizeof_future'] // 4,
                    abi['FWH_NUM_FUTURE'], abi['sizeof_future'] // 4))

    say('\n[3] memory contract (reference layout.ld + Makefile vs memmap + link.x)')
    m = 'memory'
    for region, (rs_base, rs_len) in (('FLASH_ISR', ('FLASH_ISR_BASE', 'FLASH_ISR_LEN')),
                                      ('FLASH_TEXT', ('FLASH_TEXT_BASE', 'FLASH_TEXT_LEN')),
                                      ('FLASH_FS', ('FLASH_FS_BASE', 'FLASH_FS_LEN'))):
        o, l = ref_ld.get(region, (None, None))
        log.eq(m, region.lower() + '-origin', rs.get(rs_base), o,
               'memmap::%s vs layout.ld %s ORIGIN' % (rs_base, region))
        log.eq(m, region.lower() + '-length', rs.get(rs_len), l,
               'memmap::%s vs layout.ld %s LENGTH' % (rs_len, region))
    ro, rl = ref_ld.get('RAM', (None, None))
    log.eq(m, 'sram-base', rs.get('SRAM_BASE'), ro, 'memmap::SRAM_BASE vs layout.ld RAM ORIGIN')
    log.eq(m, 'bl-sram-base-from-layout', rs.get('BL_SRAM_BASE'),
           ro + rl if ro is not None else None,
           'memmap::BL_SRAM_BASE vs layout.ld RAM end')
    for k in ('BL_FLASH_BASE', 'BL_FLASH_SIZE', 'BL_NVROM_SIZE', 'BL_SRAM_BASE'):
        log.eq(m, k.lower().replace('_', '-'), rs.get(k), defs.get(k),
               'memmap::%s vs Makefile %s' % (k, k))
    log.eq(m, 'flash-isr-base-is-mpy-base', rs.get('FLASH_ISR_BASE'),
           defs.get('MPY_FLASH_BASE'),
           'memmap::FLASH_ISR_BASE vs Makefile MPY_FLASH_BASE (where the '
           'bootloader jumps)')
    # our own link.x against the same reference numbers
    lo, ll = lx.get('FLASH_ISR', (None, None))
    log.eq(m, 'linkx-flash-isr-origin', lo, rs.get('FLASH_ISR_BASE'),
           'link.x FLASH_ISR ORIGIN')
    v = log.need(m, 'linkx-flash-isr-fits-header', rs, 'FLASH_ISR_BASE', 'FW_HEADER_OFFSET')
    if v:
        log.eq(m, 'linkx-flash-isr-fits-header', lo + ll if lo is not None else None, sum(v),
               'link.x FLASH_ISR end vs the reserved signature slot')
    lto, ltl = lx.get('FLASH_TEXT', (None, None))
    log.eq(m, 'linkx-flash-text', (lto, ltl),
           (rs.get('FLASH_TEXT_BASE'), rs.get('FLASH_TEXT_LEN')),
           'link.x FLASH_TEXT ORIGIN/LENGTH vs memmap')
    lro, lrl = lx.get('RAM', (None, None))
    log.eq(m, 'linkx-ram-end', lro + lrl if lro is not None else None,
           defs.get('BL_SRAM_BASE'),
           'link.x RAM end vs Makefile BL_SRAM_BASE (the 8 K the callgate wipes)')
    # item 2's RAM exclusion around the bootloader's reboot flag
    df, dl = rs.get('DFU_FLAG_ADDR'), rs.get('DFU_FLAG_LEN')
    if None in (df, dl, lro):
        log.unavail(m, 'dfu-flag-excluded-from-ram', 'missing DFU_FLAG_* or link.x RAM')
    elif df + dl <= lro:
        log.ok(m, 'dfu-flag-excluded-from-ram',
               'dfu_flag [0x%08x,0x%08x) is below link.x RAM ORIGIN 0x%08x, so no '
               'allocation of ours can reach the word main.c:115 reads pre-wipe'
               % (df, df + dl, lro))
    else:
        log.fail(m, 'dfu-flag-excluded-from-ram',
                 'dfu_flag [0x%08x,0x%08x) lies INSIDE link.x RAM starting 0x%08x: '
                 'attacker-influenced bytes there are a remote brick path '
                 '(main.c:115 -> enter_dfu -> LOCKUP_FOREVER at RDP=2)'
                 % (df, df + dl, lro))
    # PSRAM staging vs the bootloader's recovery header and recovery gate
    src = open(psram_c).read()
    mm_r = re.search(r'#define\s+RECHDR_POS\s+.*PSRAM_SIZE\s*-\s*(\d+)', src)
    if not mm_r:
        log.unavail(m, 'psram-stage-below-recovery-header',
                    'psram.c no longer spells RECHDR_POS as PSRAM_SIZE - N')
    else:
        rec_off = abi['PSRAM_SIZE'] - int(mm_r.group(1))
        v = log.need(m, 'psram-stage-below-recovery-header', rs,
                     'PSRAM_STAGE_OFFSET', 'PSRAM_STAGE_LEN')
        stage_end = sum(v) if v else None
        if v and stage_end <= rec_off:
            log.ok(m, 'psram-stage-below-recovery-header',
                   'staging ends at +0x%06x, recovery header at +0x%06x (psram.c '
                   'RECHDR_POS = PSRAM_BASE + PSRAM_SIZE - %s)'
                   % (stage_end, rec_off, mm_r.group(1)))
        elif v:
            log.fail(m, 'psram-stage-below-recovery-header',
                     'staging ends at +0x%06x, past the bootloader recovery header '
                     'at +0x%06x' % (stage_end, rec_off))
    log.eq(m, 'psram-stage-is-lower-half', rs.get('PSRAM_STAGE_LEN'),
           abi['PSRAM_SIZE'] // 2,
           'psram::PSRAM_STAGE_LEN vs the recovery gate\'s PSRAM_SIZE/2 bound '
           '(psram.c:261-266)')
    log.eq(m, 'burn-base-is-firmware-start', rs.get('BURN_BASE'), abi['FIRMWARE_START'],
           'psram::BURN_BASE vs verify.h FIRMWARE_START (psram.c:326 dest)')
    v = log.need(m, 'burn-len-max-reaches-flash-fs', rs, 'BURN_BASE', 'BURN_LEN_MAX', 'FLASH_FS_BASE')
    if v:
        log.eq(m, 'burn-len-max-reaches-flash-fs', v[0] + v[1], v[2],
               'BURN_BASE + BURN_LEN_MAX vs FLASH_FS_BASE (a burn cannot reach the share)')

    # The two packer alignments, read out of `cli/signit.py` rather than retyped.
    # `align_to(len(body), 512)` is every product's rule and is `FW_BODY_ALIGN`;
    # `align_to(body_len, 4096)` is the PSRAM-product branch (Mk4/Q1/Mk5) and is
    # `FW_INSTALL_ALIGN`. The bootloader enforces NEITHER (`verify.c:212-217` has no
    # alignment test), so signit is the only source these can be checked against --
    # which is exactly why they need checking rather than asserting.
    sig_py = os.path.join(ref, 'cli', 'signit.py')
    sig_src = open(sig_py).read() if os.path.exists(sig_py) else ''
    for key, const, pat in (
            ('signit-body-align', 'FW_BODY_ALIGN',
             r'align_to\(len\(body\),\s*(\d+)\)'),
            ('signit-install-align', 'FW_INSTALL_ALIGN',
             r'align_to\(body_len,\s*(\d+)\)')):
        hit = re.search(pat, sig_src)
        if not hit:
            log.unavail(m, key, 'cli/signit.py no longer spells `%s`' % pat)
        else:
            log.eq(m, key, rs.get(const), int(hit.group(1)),
                   'memmap::%s vs cli/signit.py `%s`' % (const, hit.group(0)))
    # And the reason the whole-image length may be judged by the body's rule:
    # `signit.py:315` puts exactly FW_HEADER_OFFSET + FW_HEADER_SIZE bytes ahead of
    # the body, and that prefix is itself a whole number of 4,096-byte units.
    v = log.need(m, 'install-align-divides-header-prefix', rs,
                 'FW_HEADER_OFFSET', 'FW_HEADER_SIZE', 'FW_INSTALL_ALIGN')
    if v and v[2] <= 0:
        log.fail(m, 'install-align-divides-header-prefix', 'FW_INSTALL_ALIGN is %d' % v[2])
    elif v:
        log.eq(m, 'install-align-divides-header-prefix', (v[0] + v[1]) % v[2], 0,
               'FW_HEADER_OFFSET + FW_HEADER_SIZE is a multiple of FW_INSTALL_ALIGN '
               '(so firmware_length is 4 K-aligned exactly when the body is)')

    say('\n[4] registers: compiler-resolved CMSIS/HAL vs the HAL\'s literals')
    reg = dict(zip(REG_KEYS, probe('reg-probe', REG_C, ref, defs)))
    if len(reg) != len(REG_KEYS):
        raise Abort('reg probe returned %d words, expected %d' % (len(reg), len(REG_KEYS)))
    r = 'registers'
    PAIRS = [
        ('flash-r-base', 'FLASH_R_BASE', reg['FLASH_R_BASE']),
        ('flash-key1', 'FLASH_KEY1', reg['FLASH_KEY1']),
        ('flash-key2', 'FLASH_KEY2', reg['FLASH_KEY2']),
        ('flash-cr-pnb', 'FLASH_CR_PNB', reg['FLASH_CR_PNB']),
        ('flash-cr-bker', 'FLASH_CR_BKER', reg['FLASH_CR_BKER']),
        ('flash-sr-bsy', 'FLASH_SR_BSY', reg['FLASH_SR_BSY']),
        ('flash-optr-dbank', 'FLASH_OPTR_DBANK', reg['FLASH_OPTR_DBANK']),
        ('erase-size', 'ERASE_SIZE', reg['FLASH_PAGE_SIZE']),
        ('spi1-base', 'SPI1_BASE', reg['SPI1_BASE']),
        ('spi-cr2-ds-mask', 'SPI_CR2_DS_MASK', reg['SPI_CR2_DS']),
        ('spi-cr2-ds-8bit', 'SPI_CR2_DS_8BIT', reg['SPI_DATASIZE_8BIT']),
        ('spi-sr-ftlvl', 'SPI_SR_FTLVL', reg['SPI_SR_FTLVL']),
        ('gpioa-base', 'GPIOA_BASE', reg['GPIOA_BASE']),
        ('gpiob-base', 'GPIOB_BASE', reg['GPIOB_BASE']),
        ('gpiod-base', 'GPIOD_BASE', reg['GPIOD_BASE']),
        ('cs-pin', 'CS_PIN', reg['GPIO_PIN_4']),
        ('reset-pin', 'RESET_PIN', reg['GPIO_PIN_6']),
        ('dc-pin', 'DC_PIN', reg['GPIO_PIN_8']),
        ('rng-base', 'RNG_BASE', reg['RNG_BASE']),
        ('rcc-ahb2enr-rngen', 'RCC_AHB2ENR_RNGEN', reg['RCC_AHB2ENR_RNGEN']),
        ('rcc-ahb2enr-gpioaen', 'RCC_AHB2ENR_GPIOAEN', reg['RCC_AHB2ENR_GPIOAEN']),
        ('rcc-ahb2enr-gpioben', 'RCC_AHB2ENR_GPIOBEN', reg['RCC_AHB2ENR_GPIOBEN']),
        ('rcc-apb2enr-spi1en', 'RCC_APB2ENR_SPI1EN', reg['RCC_APB2ENR_SPI1EN']),
        ('rtc-base', 'RTC_BASE', reg['RTC_BASE']),
        ('pwr-cr1-dbp', 'PWR_CR1_DBP', reg['PWR_CR1_DBP']),
        ('rcc-apb1enr1-rtcapben', 'RCC_APB1ENR1_RTCAPBEN', reg['RCC_APB1ENR1_RTCAPBEN']),
        ('rcc-apb1enr1-pwren', 'RCC_APB1ENR1_PWREN', reg['RCC_APB1ENR1_PWREN']),
        ('otg-fs-base', 'OTG_FS_BASE', reg['USB_OTG_FS_PERIPH_BASE']),
        ('sram2-alias-base', 'SRAM2_ALIAS_BASE', reg['SRAM2_BASE']),
        ('sram-base-cmsis', 'SRAM_BASE', reg['SRAM1_BASE']),
    ]
    for ident_, rust_name, want in PAIRS:
        log.eq(r, ident_, rs.get(rust_name), want,
               '%s vs the compiler-resolved reference value' % rust_name)
    # the RCC register ADDRESSES the HAL hardcodes, rebuilt from CMSIS
    for ident_, rust_name, off in (('rcc-ahb2enr-addr', 'RCC_AHB2ENR', 'off_AHB2ENR'),
                                   ('rcc-apb2enr-addr', 'RCC_APB2ENR', 'off_APB2ENR'),
                                   ('rcc-apb1enr1-addr', 'RCC_APB1ENR1', 'off_APB1ENR1')):
        log.eq(r, ident_, rs.get(rust_name), reg['RCC_BASE'] + reg[off],
               '%s vs RCC_BASE + offsetof(RCC_TypeDef, ..)' % rust_name)
    log.eq(r, 'scb-base', rs.get('SCB_BASE'), reg['SCB_BASE'],
           'entry.rs SCB_BASE vs CMSIS core_cm4.h')
    log.eq(r, 'scb-vtor', rs.get('SCB_VTOR'), reg['SCB_BASE'] + reg['off_VTOR'],
           'entry.rs SCB_VTOR vs SCB_BASE + offsetof(SCB_Type, VTOR)')
    log.eq(r, 'scb-cpacr', rs.get('SCB_CPACR'), reg['SCB_BASE'] + reg['off_CPACR'],
           'entry.rs SCB_CPACR vs SCB_BASE + offsetof(SCB_Type, CPACR)')
    # clocks.c spells the CPACR mask as an expression in C code, not a macro, so
    # this one is TEXT-matched against the reference and explicitly not
    # compiler-resolved.
    ctext = re.sub(r'\s+', '', open(clocks_c).read())
    if '((3UL<<20U)|(3UL<<22U))' in ctext:
        log.eq(r, 'cpacr-cp10-cp11-full', rs.get('CPACR_CP10_CP11_FULL'),
               (3 << 20) | (3 << 22),
               'entry.rs CPACR_CP10_CP11_FULL vs clocks.c:87-89 (TEXT-matched '
               'expression, not compiler-resolved: it is code, not a macro)')
    else:
        log.unavail(r, 'cpacr-cp10-cp11-full',
                    'clocks.c no longer contains ((3UL<<20U)|(3UL<<22U)); the '
                    'bootloader\'s FPU enable may have moved')
    # board wiring: not registers, but the same "transcribed from reference" risk
    pins_csv = os.path.join(ref, 'stm32', 'COLDCARD_MK4', 'pins.csv')
    csv = open(pins_csv).read()
    for ident_, rust_name, prefix, port in (('keypad-col-pins', 'COL_PINS', 'M2_COL', 'B'),
                                            ('keypad-row-pins', 'ROW_PINS', 'M2_ROW', 'D')):
        want = [int(p) for _, p in sorted(
            re.findall(r'^%s(\d+),P%s(\d+)' % (prefix, port), csv, re.M))]
        log.eq(r, ident_, rs.get(rust_name), want,
               'keypad::%s vs pins.csv %sn on GPIO%s' % (rust_name, prefix, port))
    mempad = open(os.path.join(ref, 'shared', 'mempad.py')).read()
    dm = re.search(r"^DECODER\s*=\s*'([^']+)'", mempad, re.M)
    log.eq(r, 'keypad-decoder', rs.get('DECODER'),
           dm.group(1).encode() if dm else None,
           'keypad::DECODER vs shared/mempad.py DECODER (the matrix map, NOT the '
           'printed layout)')
    say('    COVERAGE: the %d constants above are the whole bounded set. Every '
        'other register address, mask and bit position in hal/src/{flash,display,'
        'keypad,rng,panic,usb}.rs is NOT cross-checked here and is not claimed '
        'validated.', len(PAIRS) + 8)

    say('\n[5] linked release ELF')
    pk = load_packer()
    check_elf(log, args.elf, rs, lx, pk)

    say('\n[6] Coldcard-decoder pixel comparison (tools/pixel-check.py)')
    if args.skip_pixel:
        log.unavail('pixel', 'their-decoder-agrees',
                    'not run (--skip-pixel). Recorded UNAVAILABLE, never a pass.')
    else:
        env = dict(os.environ, COLDCARD_REPO=ref)
        p = subprocess.run([sys.executable,
                            os.path.join(REPO, 'tools', 'pixel-check.py')],
                           capture_output=True, text=True, cwd=REPO, env=env)
        tail = (p.stdout or '').strip().splitlines()[-1:] or ['(no output)']
        # The hazard this exists to close: pixel-check.py prints SKIP and exits 0
        # when the checkout or their decoder is missing. Exit zero is not enough.
        if p.returncode == 0 and 'SKIP:' in p.stdout:
            log.unavail('pixel', 'their-decoder-agrees',
                        'pixel-check.py exited 0 but printed %r -- a missing '
                        'reference checkout or moved decoder is a MISSING CHECK, '
                        'not a pass' % tail[-1])
        elif p.returncode == 0 and 'PASS:' in p.stdout:
            log.ok('pixel', 'their-decoder-agrees', tail[-1])
        else:
            log.fail('pixel', 'their-decoder-agrees',
                     'pixel-check.py exited %d: %s' % (p.returncode, tail[-1]))

    # ---- report
    say('\n== result ==')
    for bucket in ('COVERED', 'FAILED', 'UNAVAILABLE'):
        say('  %-11s %d', bucket, log.count(bucket))
    if log.notes:
        say('\n  recorded discrepancies (reference-internal, not cold-snap failures):')
        for n in log.notes:
            say('    - %s', n)
    say('\n  NOT ESTABLISHED by anything above: peripheral timing, wait states, any '
        'silicon behaviour, real ATECC608/SE2 responses, real callgate transits, and '
        'board-specific bootloader state (option bytes, RDP level, PCROP, pairing '
        'secret). tools/qemu-boot.sh substitutes a stack and memory map and is '
        'deliberately NOT run here: diagnostic, never a gate.')
    say('  Scope of the claim: software/pre-bench checks passed.')

    if args.json:
        os.makedirs(os.path.dirname(args.json), exist_ok=True)
        with open(args.json, 'w') as f:
            json.dump({'identity': ident, 'abi_probe': abi, 'reg_probe': reg,
                       'rows': log.rows, 'notes': log.notes}, f, indent=1, sort_keys=True)
        say('  full record: %s', args.json)

    failed = [r for r in log.rows if r[0] == 'FAILED']
    if failed:
        say('\nFAIL: %d check(s) disagree with the reference: %s',
            len(failed), ', '.join('%s/%s' % (r[1], r[2]) for r in failed))
        return 1
    unavail = [r for r in log.rows if r[0] == 'UNAVAILABLE']
    if unavail and not args.allow_unavailable:
        say('\nINCOMPLETE: %d check(s) could not run: %s. A missing check is not a '
            'pass; pass --allow-unavailable to accept this knowingly.',
            len(unavail), ', '.join('%s/%s' % (r[1], r[2]) for r in unavail))
        return 2
    say('\nPASS: %d checks agree with the reference%s.', log.count('COVERED'),
        ' (%d unavailable, accepted)' % len(unavail) if unavail else '')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:                        # noqa: BLE001 -- one loud exit
        sys.exit('\nABORT (%s): %s' % (type(e).__name__, e))
# EOF
