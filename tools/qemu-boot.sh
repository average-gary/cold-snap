#!/usr/bin/env bash
#
# Boot the UNMODIFIED release image under QEMU and print what it touched.
#
# WHAT THIS IS: a diagnostic, NOT a gate. It answers one question — how far does
# `init_hardware` get on a real 32-bit Cortex-M4F before it hits a register QEMU
# does not model — and it answers it by loading the same ELF the signing tools
# consume. No new source file, no second linker script, no new dependency: the
# `.cargo/config.toml` firmware link is untouched, so the image stays
# byte-identical to the one measured in PLAN.md.
#
# WHAT IT VERIFIES: 32-bit pointer width, arithmetic, and the pure logic
# reachable from the reset vector -- and as of 2026-09-09, on the only machine
# that models our flash, that reach is MUCH shorter than this comment used to
# imply. See the SHIM block below for what each mode actually got to. NOTHING
# ELSE. Every register result is UNVERIFIED-ON-SILICON. QEMU models neither the
# PCROP bootloader, nor SE1/SE2, nor the SSD1306, nor the keypad, nor OTG_FS
# device mode, nor the flash programming controller, nor RDP. Do not quote a run
# of this as evidence about any of them.
#
# Do NOT use `netduinoplus2` unless you understand this: QEMU models an
# `stm32f2xx_spi` at exactly our SPI1 base (0x4001_3000), where CR2.DS and
# SR.FTLVL do not exist. Writes are accepted, FTLVL reads 0, and `drain()`
# returns Ok having verified nothing. Confidently wrong is worse than absent,
# which is why the default is the STM32L4 machine.
#
# ---------------------------------------------------------------------------
# SHIM=1 -- boot a padded flat image instead of the ELF
# ---------------------------------------------------------------------------
# Bare `-kernel` on the ELF cannot boot, and that is a correct result, not a
# bug: a Cortex-M reads SP and PC from the flash base 0x0800_0000 at reset, our
# vector table is at 0x0802_0000, and the 128 KiB below it is the PCROP
# bootloader QEMU does not have. So the core loads SP=0, PC=0 and locks up
# (exit 6, R13=ffffffe0, R15=00000000) having executed nothing.
#
# SHIM=1 builds, from the same ELF, a flat image whose first 8 bytes are our
# SP/PC and whose body sits at the vector table's flash offset, so the reset
# fetch finds OUR table. The gap is filled with 0xff -- erased flash, and NOT
# 0x00, because 0x0000 decodes as `movs r0, r0`: a stray branch into zeroed
# padding would quietly wander instead of faulting.
#
# WHAT SHIM=1 ACTUALLY PROVES, measured 2026-09-09 on qemu 11.1.1: exactly one
# thing -- the vector table is well formed and its reset entry is a valid Thumb
# address in our image. R13 comes back as 0x2009dfe0, our 0x2009e000 minus a
# 32-byte exception frame, which is only possible if QEMU read our table. And
# then it locks up with ZERO instructions retired, because 0x2009_dff8 (the
# reset handler's first `push`) is not backed by RAM on this machine:
#
#   b-l475e-iot01a is an STM32L475 with 96 KiB of SRAM1, 0x2000_0000 ..
#   0x2001_8000 (probed: SP=0x2001_8000 runs, 0x2002_0000 and every value above
#   it locks up after 4 translated instructions). Our stack top is 0x2009_e000
#   and our .bss ends at 0x2001_8058. Both are outside the model. No QEMU
#   machine has both flash at 0x0802_0000 and RAM at 0x2009_e000, so the
#   unmodified image's bring-up cannot run under any of them.
#
# `init_hardware` therefore does NOT execute under SHIM=1, and the callgate is
# never reached -- so there is no point parking a `bx lr` stub at 0x0800_0040
# to get past it. Confirmed by `-d in_asm`: 4 translated instructions, none
# retired, zero `unimp`/`guest error` lines.
#
# SP=<addr> -- A DELIBERATE LIE, and the only setting under which any of our
# instructions retire. It overwrites the shim's stack-top word so the stack
# lands inside the RAM this machine models. SP=0x20018000 executes the VTOR
# write, the CPACR write and ~64 KiB of the .bss zero loop at real 32-bit width
# with hard-float, then faults at 0x2001_8000 -- past the model's SRAM, still
# 0x58 short of our .bss top -- and that fault dispatches through the VTOR we
# just programmed into `fault_trampoline`, which panics and resets forever
# (exit 124). That end state is the evidence: VTOR dispatch and the panic path
# ran. It is NOT our memory map, it cannot produce a pass, and nothing it
# touches is evidence about silicon.
#
# Usage:  tools/qemu-boot.sh [path-to-elf]
# Env:    MACHINE (default b-l475e-iot01a), WALL (seconds, default 60),
#         SHIM (non-empty: pad and boot a flat image), SP (with SHIM, see above),
#         OBJDUMP, OBJCOPY, QEMU
#
# Exit codes — 0 means "QEMU ran and produced an observable trace", and a human
# still has to read that trace. Anything else is a hard stop:
#   2  QEMU not installed
#   3  image missing, its .text is empty, or (SHIM=1) the shim could not be
#      built from it: no .vector_table, a .vector_table VMA that is not a
#      plausible flash offset, a reset vector with bit 0 clear, or a body that
#      did not land at the pad offset
#   4  installed QEMU has no such machine
#   5  QEMU produced NO observable output (one silent-pass case: treat as failure)
#   6  QEMU itself exited non-zero -- the guest may never have executed one
#      instruction (`could not load kernel`, `Trying to execute code outside RAM
#      or ROM`). Its stderr lands in the same log as the guest trace, so a
#      non-empty log is NOT evidence the guest ran. This is the OTHER silent-pass
#      case, and it is what BOTH real modes return today -- bare because nothing
#      sets SP, shim because the SP that gets set is outside modelled RAM.
#      Without this check every run of this script so far would have said OK.
#   124 wall clock exceeded
set -u

ELF="${1:-target/thumbv7em-none-eabihf/release/coldsnap_firmware}"
MACHINE="${MACHINE:-b-l475e-iot01a}"
WALL="${WALL:-60}"
QEMU="${QEMU:-qemu-system-arm}"
OBJDUMP="${OBJDUMP:-}"
if [ -z "$OBJDUMP" ]; then
    if command -v llvm-objdump >/dev/null 2>&1; then OBJDUMP=llvm-objdump
    else OBJDUMP=/opt/homebrew/opt/llvm/bin/llvm-objdump; fi
fi
OBJCOPY="${OBJCOPY:-}"
if [ -z "$OBJCOPY" ]; then
    if command -v llvm-objcopy >/dev/null 2>&1; then OBJCOPY=llvm-objcopy
    else OBJCOPY=/opt/homebrew/opt/llvm/bin/llvm-objcopy; fi
fi

# One trap instead of an `rm` on each of the five exits below. The shim is half
# a megabyte; leaking one per run in $TMPDIR is the kind of thing nobody
# notices for a year.
LOG=""; IMG=""; FLAT=""
trap 'rm -f "$LOG" "$IMG" "$FLAT"' EXIT

command -v "$QEMU" >/dev/null 2>&1 || {
    echo "FAIL: $QEMU not installed. Install it with:"
    echo "    brew install qemu"
    echo "(~1.5 GB, several minutes. Verified against qemu 11.1.1.)"
    exit 2
}

[ -f "$ELF" ] || { echo "FAIL: no image at $ELF (cargo build --release)"; exit 3; }

# An empty .text links "successfully": --gc-sections will collect an un-KEEPed
# vector table and everything reachable from it, and cargo still says Finished.
# Assert on the bytes, never on the build exit code.
TEXT=$("$OBJDUMP" -h "$ELF" 2>/dev/null | awk '$2==".text"{print $3}')
case "$TEXT" in
    ""|00000000) echo "FAIL: $ELF has no .text ($OBJDUMP -h said '${TEXT:-nothing}')"; exit 3 ;;
esac
echo "image: $ELF  .text=0x$TEXT bytes"

# ---------------------------------------------------------------------------
# SHIM=1: build the padded flat image. Read-only on the ELF -- objcopy, not a
# relink -- so the signed image stays byte-identical. See the header for what
# the resulting boot does and does not prove.
# ---------------------------------------------------------------------------
KERNEL="$ELF"
DFLAGS="guest_errors,unimp"
if [ -n "${SHIM:-}" ]; then
    # Derive the pad from the ELF; do not hardcode 0x20000. The flat image
    # begins at the lowest LMA, which is the vector table, so it has to land
    # back at exactly that offset from the flash base or every absolute address
    # baked into .text points somewhere else.
    VT=$("$OBJDUMP" -h "$ELF" 2>/dev/null | awk '$2==".vector_table"{print $4}')
    [ -n "$VT" ] || { echo "FAIL: $ELF has no .vector_table section; cannot place a shim"; exit 3; }
    PAD=$(( 0x$VT - 0x08000000 ))
    if [ "$PAD" -lt 8 ] || [ "$PAD" -gt 1048576 ]; then
        echo "FAIL: .vector_table at 0x$VT gives a pad of $PAD bytes, which is not a"
        echo "      plausible offset into a 1 MiB flash. Refusing to build a shim."
        exit 3
    fi

    FLAT=$(mktemp -t qemuflat); IMG=$(mktemp -t qemushim)
    "$OBJCOPY" -O binary "$ELF" "$FLAT" || { echo "FAIL: $OBJCOPY could not flatten $ELF"; exit 3; }

    # The reset vector must have bit 0 set. A Cortex-M that loads an even PC
    # takes an INVSTATE UsageFault before the first instruction, and the trace
    # then looks identical to the interesting failures.
    PCW=$(od -A n -t x4 -j 4 -N 4 "$FLAT" | tr -d ' ')
    case "$PCW" in
        *[13579bdf]) : ;;
        *) echo "FAIL: reset vector 0x${PCW:-?} has bit 0 clear -- not a Thumb entry."
           echo "      A shim built from it cannot execute one instruction."
           exit 3 ;;
    esac

    # LC_ALL=C is load-bearing: BSD tr is locale-aware and without it '\377'
    # comes out as the two UTF-8 bytes c3 bf, silently doubling the pad and
    # shifting the whole body off its link address. Measured, not theorised.
    head -c 8 "$FLAT" > "$IMG"
    dd if=/dev/zero bs=$((PAD - 8)) count=1 2>/dev/null | LC_ALL=C tr '\0' '\377' >> "$IMG"
    cat "$FLAT" >> "$IMG"

    # The word at offset PAD is the vector table's SP again, since the body
    # starts there. If it does not match offset 0 the pad is the wrong size,
    # which is the one mistake that produces a plausible-looking dead trace.
    if [ "$(od -A n -t x4 -j 0 -N 4 "$IMG")" != "$(od -A n -t x4 -j "$PAD" -N 4 "$IMG")" ]; then
        echo "FAIL: shim body did not land at offset $PAD -- pad is the wrong size."
        exit 3
    fi

    if [ -n "${SP:-}" ]; then
        python3 -c 'import sys,struct;sys.stdout.buffer.write(struct.pack("<I",int(sys.argv[1],0)))' \
            "$SP" | dd of="$IMG" bs=1 count=4 conv=notrunc 2>/dev/null
        echo "SP OVERRIDE $SP -- THIS IS NOT OUR MEMORY MAP. The stack is being moved"
        echo "    to fit the machine's SRAM so that bring-up retires instructions at"
        echo "    all. Nothing below is evidence about our real stack, and it cannot"
        echo "    pass: it ends in a fault dispatched through VTOR. See header."
    fi
    KERNEL="$IMG"
    # in_asm is the payload in shim mode: TCG caches translations, so this is
    # bounded by code reached, not by run time, and it is the only way to see
    # how far the guest got.
    DFLAGS="in_asm,$DFLAGS"
    echo "shim: pad=$PAD bytes of 0xff below .vector_table (0x$VT), SP/PC at offset 0"
fi

# Tolerant of leading whitespace: a false "no such machine" on a working QEMU
# would be the most annoying possible way for this to be wrong.
timeout 15 "$QEMU" -machine help 2>/dev/null | grep -qE "(^|[[:space:]])$MACHINE([[:space:]]|\$)" || {
    echo "FAIL: installed QEMU has no machine '$MACHINE'. Available Cortex-M:"
    timeout 15 "$QEMU" -machine help 2>/dev/null | grep -iE 'stm32|b-l475|netduino|mps2|lm3s|microbit'
    exit 4
}
[ "$MACHINE" = netduinoplus2 ] && echo "WARNING: netduinoplus2 fakes SPI1 at our base address. See header."

LOG=$(mktemp -t qemuboot)
# -d guest_errors,unimp is the whole point: it names every unmodelled register
# access as it happens, which is the fidelity audit for free.
# Every register poll in this codebase is bounded by a named spin limit, so the
# guest terminates on a Timeout rather than hanging -- but FLASH_SPIN_LIMIT is
# 50,000,000 volatile reads, which under TCG is tens of seconds. Keep WALL well
# above that or a working run reads as a hang.
timeout "$WALL" "$QEMU" -machine "$MACHINE" -nographic \
    -semihosting-config enable=on,target=native \
    -d "$DFLAGS" -kernel "$KERNEL" >"$LOG" 2>&1
RC=$?

echo "--- qemu trace (rc=$RC) ---"
cat "$LOG"
echo "--- end trace ---"

if [ "$RC" = 124 ]; then
    echo "FAIL: exceeded ${WALL}s wall clock. Killed, so nothing below is a result."
    # Still a hard failure and still exit 124: SHIM+SP is a diagnostic whose end
    # state happens to be a reset loop, and a runner that started calling 124 a
    # pass would stop being able to report a real hang.
    [ -n "${SP:-}" ] && echo "      (With SP set this is the EXPECTED end: panic -> NVIC_SystemReset -> repeat.
       The result is the trace above, not this exit code.)"
    exit 124
fi
if [ ! -s "$LOG" ]; then
    echo "FAIL: QEMU exited $RC having printed NOTHING. Nothing was observed, so"
    echo "      nothing is verified -- do not read this as a pass."
    exit 5
fi
# A non-empty log is not evidence the GUEST ran: qemu's own stderr is in there
# too. `qemu-system-arm: could not load kernel` prints a line and exits 1 having
# executed nothing. This image never calls semihosting exit, so a real run ends
# at the wall clock (124) -- any other non-zero rc is qemu failing, not a result.
if [ "$RC" != 0 ]; then
    echo "FAIL: QEMU itself exited $RC. The line(s) above are probably ITS error,"
    echo "      not a guest trace -- the guest may never have executed."
    [ -n "${SHIM:-}" ] && echo "      In shim mode, R13=2009dfe0 with rc=134 is the KNOWN outcome: our vector
      table was read, and then nothing retired because the stack is outside
      this machine's 96 KiB of SRAM. See the header. Not a new finding."
    exit 6
fi
echo "OK: QEMU ran and produced a trace. READ IT -- this script does not judge it."
echo "    32-bit logic and pointer width exercised; registers UNVERIFIED-ON-SILICON."
exit 0
