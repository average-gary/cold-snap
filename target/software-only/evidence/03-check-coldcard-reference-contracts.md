# 03 — Automate reference-contract and linked-ELF validation

## Status: DEGRADED

All six acceptance criteria are met and every check passes for the right reason, but
**one CONFIRMED finding is open** and close-out may not edit source:

> **F7 — two of the 114 checks read the cold-snap side with a silent `0` default, so a
> missing constant reports COVERED instead of the drift signal.**
> `tools/check-reference-contracts.py:726` (`rs.get('BURN_LEN_MAX', 0) <=
> abi['FW_MAX_LENGTH_MK4']`) and `:817` (`stage_end = rs.get('PSRAM_STAGE_OFFSET', 0) +
> rs.get('PSRAM_STAGE_LEN', 0)`). This contradicts the checker's own documented
> contract at `:186-188` ("a *requested* name that is missing becomes a FAILED check at
> the call site, which is the drift signal we want") and the prompt Objective "Make
> source drift fail visibly". The fix is one character per site: drop the `, 0`.
> Breaks no acceptance criterion. Full detail and the reproduction below.

Everything else claimed in this file was independently re-run and reproduced exactly.
The scoped claim that *is* available is **software/pre-bench checks passed** — not
"hardware verified", not "safe for funds".

Repair round, 2026-09-22. cold-snap HEAD at run start
`985f2f121f30ba56331e681dbb72f1ea36204ed7` on branch `software-only/run-2026-09-21`.
Reference `~/repos/coldcard-firmware` at `0431fd2b00095a9ac0e5df4a023acd6eaf6a15a6`,
**read only** — its working tree is byte-for-byte the 00-preflight tamper baseline
(3 modified, 7 untracked docs; `git -C ~/repos/coldcard-firmware status --porcelain | wc -l`
= 10 before and after this work). No device was touched, no port opened, nothing
flashed or provisioned, no callgate invoked. Nothing is committed.

This task had **no implementation at all** when the repair round started: five of the
six CONFIRMED findings were "unmet by absence". All six of those are now fixed. A
seventh CONFIRMED finding (F7, above) was raised by the re-runner *after* the repair
round and is open. Two new files, no existing file modified.

The only claim available from this work is **software/pre-bench checks passed** for
cold-snap's ABI, memory-map, register and linked-ELF assumptions against the real
Coldcard reference sources. Not "hardware verified". Not "safe for funds".

---

## What was added

| File | What it is |
|---|---|
| `tools/check-reference-contracts.py` | The one documented command. 114 checks in five groups, reported in three buckets: COVERED / FAILED / UNAVAILABLE. |
| `tools/test-reference-contracts.py` | The negative-fixture suite: six deliberate-failure cases, each of which must exit nonzero **for the named reason**. |

Generated artifacts, all under ignored `target/`:

- `target/software-only/refcheck/{abi,reg}-probe.{c,o,bin}` — the compiled Cortex-M4
  probes and the raw `.probe` section bytes.
- `target/software-only/refcheck/reset-entry.asm` — recorded disassembly review.
- `target/software-only/refcheck/result.json` — full identity + probe + row record.
- `target/software-only/fixtures/refcheck/` — the negative fixtures (symlink mirrors
  of the reference with one file edited, plus three patched ELF copies).

### Files changed

Committed by this task (the two evidence paths are under ignored `target/` and are staged
with `git add -f`, by explicit path):

| Path | Change |
|---|---|
| `tools/check-reference-contracts.py` | **new**, 992 L — the one documented command |
| `tools/test-reference-contracts.py` | **new**, 211 L — the six negative fixtures |
| `target/software-only/evidence/03-check-coldcard-reference-contracts.md` | **new** — this file |
| `target/software-only/evidence/run.json` | **modified** — `03` entry appended; also carries a one-line backfill of task 01's `"commit"` field from `null` to `985f2f121f30ba56331e681dbb72f1ea36204ed7` at `run.json:8`, left by task 01's close-out (985f2f1 could not contain its own SHA). The value is correct — `git show --stat 985f2f1` is the task-01 commit — and it is committed here rather than reverted, but it is not task 03's work and is named so the diff is not larger than the claim. |

No other tracked file in cold-snap was touched. frostsnap was not touched at all. The
pre-existing user work stays unstaged and unmodified: cold-snap `?? prompts/`; frostsnap
` M frostsnapp/.gitignore`, ` M frostsnapp/macos/Podfile.lock`, ` M justfile`,
`?? frostsnap_coordinator/tests/coldcard_msg_len.rs` (all four verified present and
unchanged at close-out).

Nothing in `hal/`, `firmware/`, `link.x` or any existing tool was changed. No
assertion was deleted, relaxed or weakened; no test was altered; no constant was
hardcoded to make a check pass. `tools/pixel-check.py` was **not** edited — its
`SKIP`-with-exit-zero path is closed by classification in the wrapper, which is
what the prompt asks for ("account for that explicitly") and leaves the script
usable standalone.

---

## The one documented command

From `~/repos/cold-snap`:

```sh
python3 tools/check-reference-contracts.py --json target/software-only/refcheck/result.json
```

Exit codes are the contract:

- **0** — every check COVERED.
- **1** — at least one check FAILED. The last line names every failed check id.
- **2** — nothing failed but at least one check was UNAVAILABLE. **A missing check is
  not a pass.** `--allow-unavailable` turns 2 into 0 for a caller who knows and
  accepts it; the rows still say UNAVAILABLE.

Flags: `--ref DIR` (reference tree, default `$COLDCARD_TREE` then
`~/repos/coldcard-firmware`), `--elf FILE`, `--linker-script FILE`, `--skip-pixel`
(records the pixel check UNAVAILABLE, never as a pass), `--allow-unavailable`,
`--json FILE`.

Negative fixtures:

```sh
python3 tools/test-reference-contracts.py
```

---

## Why this is not self-consistency

Three independent sides are compared, and **none of the three is transcribed into
the checker**:

1. **C side** — the reference's own headers are *compiled*. `pins.h`, `sigheader.h`,
   `main.h`, `psram.h`, `verify.h` and the CMSIS/HAL headers, with the include paths
   and `-D BL_*` defines read out of `stm32/mk4-bootloader/Makefile` at run time
   (`Makefile:47-62` for the values, `:78-80` for the include paths). The constants
   are emitted into a `.probe` section and read back with `llvm-objcopy -O binary
   --only-section=.probe`; **the ARM object is never executed**. Every CMSIS value
   cold-snap depends on is a macro *expression*
   (`RNG_BASE = AHB2PERIPH_BASE + 0x08060800UL`, `FLASH_CR_PNB_Msk`), so only the
   preprocessor can resolve it — a grep cannot, which is exactly why work item 3
   says "compiler-resolved".
2. **Rust side** — parsed out of the real source with a `const NAME: T = EXPR;`
   regex and a fixed-point evaluator over `hal/src/{lib,callgate,psram,flash,display,keypad,rng,panic,usb}.rs`
   and `firmware/src/entry.rs` (327 consts). A third copy of `0x0802_4000` inside the
   checker would have made the whole exercise circular. A renamed or changed Rust
   constant surfaces as a FAILED check, not as a silent pass — demonstrated by the
   abi-offset fixture below.
3. **Linker side** — `firmware/link.x` and the reference
   `stm32/COLDCARD_MK4/layout.ld` MEMORY blocks, parsed (`1984K`/`0x9e000` forms
   both handled).

**32-bit ARM widths, not host widths.** The probe object's ELF summary is asserted
to be `arm`/`32bit` *before any of its numbers are used* — a host probe is refused
rather than trusted. The probe also reports `sizeof(void *)`, `sizeof(int)`,
`sizeof(long)` = **4/4/4** against this host's **8/4/8**, which is recorded as a
check of its own (`abi/probe-is-arm32`). That difference is what would silently
corrupt `offsetof(pinAttempt_t, secret)` and `sizeof(dfu_flag_t)` on a host build.

The existing engines are reused, not rewritten: `tools/pack-signed.py`'s `sections()`
(PT_LOAD LMA resolution), `geometry()` (overlap refusal + "a gap is legal only when
it is exactly the next section's alignment padding"), `align_up()`,
`header_slot_occupants()` and `image_bounds()` are imported as a module.

---

## Coverage by contract

| Group | Checks | What is compared |
|---|---|---|
| `abi` | 33 | `sizeof`/`_Alignof`/9 field offsets of `pinAttempt_t`; `MAX_PIN_LEN`, `PA_MAGIC_V2`, the three `PA_*` state bits, `PIN_ATTEMPT_SIZE_V2`; `sizeof(coldcardFirmwareHeader_t)`, `FW_HEADER_SIZE`/`OFFSET`, `offsetof(firmware_length)` vs `psram::FW_LENGTH_FIELD_OFFSET`, `FWH_PY_FORMAT` size, `FWH_PK_NUM_OFFSET`; `FW_MIN_LENGTH` vs `BURN_LEN_MIN`, `BURN_LEN_MAX <= FW_MAX_LENGTH_MK4`; `sizeof(dfu_flag_t)` and the `dfu_flag` address; `PSRAM_BASE`/`SIZE`; `FIRMWARE_START` vs `FLASH_ERASE_FLOOR`; `FLASH_HEADER_BASE_MK4` |
| `memory` | 22 | `layout.ld` FLASH_ISR / FLASH_TEXT / FLASH_FS origin+length and RAM origin+end vs `memmap`; `Makefile` `BL_FLASH_BASE/SIZE`, `BL_NVROM_SIZE`, `BL_SRAM_BASE`, `MPY_FLASH_BASE`; `link.x` FLASH_ISR / FLASH_TEXT / RAM against both; the `dfu_flag` RAM exclusion; PSRAM staging vs the bootloader's `RECHDR_POS` recovery header and the `psram.c:261-266` `PSRAM_SIZE/2` gate; `BURN_BASE`/`BURN_LEN_MAX` reaching exactly `FLASH_FS_BASE` |
| `registers` | 40 | flash bank geometry (`FLASH_R_BASE`, `KEY1/2`, `CR_PNB`, `CR_BKER`, `SR_BSY`, `OPTR_DBANK`, `ERASE_SIZE` vs `FLASH_PAGE_SIZE`); SPI1 + `CR2_DS` mask/8-bit + `SR_FTLVL`; GPIOA/B/D bases and the three OLED pins vs `GPIO_PIN_4/6/8`; RNG; RTC + `PWR_CR1_DBP`; the three RCC enable registers **rebuilt as `RCC_BASE + offsetof(RCC_TypeDef, …)`** plus five enable bits; OTG-FS base; SRAM1/SRAM2-alias bases; `SCB_BASE` + `offsetof(SCB_Type, VTOR/CPACR)`; board wiring `COL_PINS`/`ROW_PINS` vs `pins.csv` and `DECODER` vs `shared/mempad.py` |
| `elf` | 18 | SP word 0 vs `ESTACK_TOP`; reset word 1 Thumb bit, inside `.text`, equal to the `ENTRY()` symbol; `.vector_table` LMA and VMA at `FLASH_ISR_BASE`; the 128-byte header slot unoccupied *by LMA*; body geometry with its one 4-byte align-8 gap attributed; image end below `FLASH_FS`; `.data` LMA vs `_sidata`, VMA vs `_sdata`/`_edata`; `.bss` inside `link.x` RAM, disjoint from `.data`, non-empty; `_end` below `BL_SRAM_BASE` and below SP |
| `pixel` | 1 | Their `OLEDSimulator.new_contents` decoder vs `ui::Frame::pixel`, via `tools/pixel-check.py`, with both of its SKIP paths classified UNAVAILABLE |

**Explicit non-claim for group 3, as work item 3 requires:** those 40 values are the
whole bounded set. Every *other* register address, mask and bit position in
`hal/src/{flash,display,keypad,rng,panic,usb}.rs` — the register *offsets* within each
peripheral, the USB FIFO partition, every polling limit, `RTC_WPR` keys, the `AIRCR`
vectkey, the panic magics — is **not** cross-checked and is **not** claimed validated.

**Startup ordering** (item 4, "where practical") is a **recorded disassembly review**,
not an automated assertion, and the checker says so in the row itself:
`target/software-only/refcheck/reset-entry.asm` holds `llvm-objdump -d
--disassemble-symbols=entry_point`. `entry_point` tail-calls
`entry::init_hardware`, so the VTOR/CPACR store order lives one frame down and no
check here proves the VTOR store precedes the first faulting instruction. That stays
a read, not a gate.

**QEMU is not a gate.** `tools/qemu-boot.sh` substitutes a stack and memory map; the
checker never invokes it and prints that fact in its closing scope statement.

---

## Reference identity

`result.json`'s `identity` block, all of which the checker prints or records:

- reference commit `0431fd2b00095a9ac0e5df4a023acd6eaf6a15a6`, and the fact that its
  worktree is **DIRTY (10 entries)**;
- all six submodule SHAs from `git submodule status`, plus **each submodule's own
  worktree dirt count**. This matters and is not hypothetical: `git submodule status`
  shows every submodule at its recorded commit (no `+` prefix), yet
  `external/libngu` and `external/micropython` each have 2 modified/untracked
  entries of their own — and every CMSIS/HAL header the register probe consumes lives
  under `external/micropython`. Neither the parent commit nor the submodule SHA
  identifies what was actually read;
- **sha256 of all 32 individual files consumed** — 16 reference files (the 9 headers,
  `Makefile`, `layout.ld`, `psram.c`, `clocks.c`, `pins.csv`, `mempad.py`,
  `simulator.py`), the 5 CMSIS/HAL headers, and the 11 cold-snap files parsed;
- sha256 of the ELF inspected
  (`2678fafc54b534b224c85400dcb376bb86726b7a9b2ea3dafb7552d64b01bb30`);
- clang 21.1.3, llvm-readelf 21.1.3, rustc 1.88.0.

A fixture tree is correctly recorded as *not* a git checkout: `git()` refuses to
answer unless the directory it is handed **is** the worktree root, so a mirror under
`target/` cannot report cold-snap's own HEAD as the reference commit. A wrong
identity is worse than none, because it looks reproducible.

---

## Commands, with cwd, exit code and elapsed time

Every command below ran with **`cwd=/Users/garykrause/repos/cold-snap`**, no exception.
Three independent executions are recorded and labelled:

- **(I)** the implementer's repair-round run;
- **(R)** the re-runner's independent re-run — a different agent, same twelve commands,
  every exit code, count and named failure reason reproduced;
- **(C)** close-out's own run, 2026-09-22, which is where the elapsed times come from
  (the earlier two rounds recorded exit codes but not wall time, so no elapsed figure is
  attributed to them rather than invented).

| # | Command (verbatim) | cwd | Exit (I) | Exit (R) | Exit (C) | Elapsed (C) |
|---|---|---|---|---|---|---|
| 1 | `cargo build --release` | `/Users/garykrause/repos/cold-snap` | 0 | 0 | **0** | 2.11 s |
| 2 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | `/Users/garykrause/repos/cold-snap` | 0 | 0 | **0** | 0.41 s |
| 3 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | `/Users/garykrause/repos/cold-snap` | 0 | 0 | **0** | 0.48 s |
| 4 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal --features fake-flash,test-seam` | `/Users/garykrause/repos/cold-snap` | 0 | 0 | **0** | 5.78 s |
| 5 | `python3 tools/check-reference-contracts.py --json target/software-only/refcheck/result.json` | `/Users/garykrause/repos/cold-snap` | 0 | 0 | **0** | 10.15 s |
| 6 | `python3 tools/test-reference-contracts.py` | `/Users/garykrause/repos/cold-snap` | 0 | 0 | **0** | 26.63 s |
| 7 | `python3 tools/check-reference-contracts.py --ref target/software-only/fixtures/refcheck/abi-offset --skip-pixel --allow-unavailable` | `/Users/garykrause/repos/cold-snap` | 1 | 1 | **1** | 0.42 s |
| 8 | `python3 tools/check-reference-contracts.py --ref target/software-only/fixtures/refcheck/memory-bound --skip-pixel --allow-unavailable` | `/Users/garykrause/repos/cold-snap` | 1 | 1 | **1** | 0.41 s |
| 9 | `python3 tools/check-reference-contracts.py --elf target/software-only/fixtures/refcheck/bad-sp.elf --skip-pixel --allow-unavailable` | `/Users/garykrause/repos/cold-snap` | 1 | 1 | **1** | 8.42 s |
| 10 | `python3 tools/check-reference-contracts.py --elf target/software-only/fixtures/refcheck/bad-thumb-bit.elf --skip-pixel --allow-unavailable` | `/Users/garykrause/repos/cold-snap` | 1 | 1 | **1** | 8.35 s |
| 11 | `python3 tools/check-reference-contracts.py --elf target/software-only/fixtures/refcheck/shifted-lma.elf --skip-pixel --allow-unavailable` | `/Users/garykrause/repos/cold-snap` | 1 | 1 | **1** | 8.32 s |
| 12 | `python3 tools/check-reference-contracts.py --ref target/software-only/fixtures/refcheck/no-simulator` | `/Users/garykrause/repos/cold-snap` | 2 | 2 | **2** | 0.48 s |

Rows 1-4 are the prompt's Checks block. Rows 5-6 are "the reference/ELF checker and its
negative fixtures". Rows 7-12 are the individual negative cases, invoked one at a time so
each nonzero exit and each named check id is visible on its own rather than only as
row 6's aggregate. Close-out's raw record: `target/software-only/refcheck/closeout-rerun.json`.

The re-runner additionally forced a genuine recompile for row 1 (deleting the
`coldsnap_firmware`/`coldsnap_hal` fingerprints and the ELF, both under ignored
`target/`) so that a fully cached "Finished in 0.64 s" could not stand in for a build:
it relinked in 7.36 s to the same 652,992-byte ELF. It also confirmed with `-v` that
`clippy-driver` really lints `coldsnap_hal` and `coldsnap_firmware` lib+bin for
thumbv7em (three `clippy-driver` invocations), because cargo prints no
"Checking coldsnap_firmware" line and a reader could otherwise assume rows 2-3 linted
nothing of ours. `.cargo/config.toml:2` sets `build.target = "thumbv7em-none-eabihf"`,
so row 1 does produce the ELF row 5 inspects — the run is self-contained.

The exit codes above are each process's own status, captured directly — no pipeline
status, no warning count standing in for a compiler invocation. Both clippy
invocations emit 18 pre-existing warning lines and still exit 0; no Rust file was
touched by this work, so none of those warnings is new.

`cargo test` result lines, in full:

```
test result: ok. 292 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.82s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Checker summary line, verbatim:

```
== result ==
  COVERED     114
  FAILED      0
  UNAVAILABLE 0
...
PASS: 114 checks agree with the reference.
```

The pixel check ran for real (not skipped) in that run:

```
[6] Coldcard-decoder pixel comparison (tools/pixel-check.py)
  COVERED     pixel/their-decoder-agrees  -- PASS: their decoder and Frame::pixel agree; all 7 caught
```

---

## Negative-check results

`python3 tools/test-reference-contracts.py` → exit **0**, `== 6/6 negative cases
behaved ==`. Each case must exit nonzero **and** the expected check id must appear in
the checker's FAIL line; a nonzero exit for a different reason is reported as a
failure of the suite. Nothing in `~/repos/coldcard-firmware` and no live firmware was
mutated for any of them: the reference is mirrored as a symlink farm under
`target/software-only/fixtures/refcheck/` with one file materialised as an edited
copy, and the ELF cases are patched *copies*.

**1. ABI offset** — `stm32/mk4-bootloader/pins.h` copy with one `uint32_t` injected
after `is_secondary`, so `pin` moves 8 → 12:

```
$ python3 tools/check-reference-contracts.py --ref target/software-only/fixtures/refcheck/abi-offset --skip-pixel --allow-unavailable
    exit 1
    FAILED      abi/offset-pin  -- PinAttempt::OFF_PIN vs offsetof(pinAttempt_t, pin): cold-snap has 8, reference says 12
    FAILED      abi/offset-pin_len  -- PinAttempt::OFF_PIN_LEN vs offsetof(pinAttempt_t, pin_len): cold-snap has 40, reference says 44
    FAIL: 10 check(s) disagree with the reference: abi/pinAttempt-size, abi/pinAttempt-size-v2-identity, abi/offset-pin, abi/offset-pin_len, abi/offset-num_fails, abi/offset-attempts_left, abi/offset-state_flags, abi/offset-hmac, abi/offset-secret, abi/offset-cached_main_pin
```

This is precisely the drift `hal/src/callgate.rs:1546-1590` cannot see, because that
test compares Rust literals to Rust literals. It is left in place and untouched; the
C-derived comparison is additive.

**2. Memory bound** — `Makefile` copy with `BL_SRAM_BASE = 0x2009e000` → `0x20090000`,
i.e. `link.x`'s RAM now ends *inside* the 8 K the callgate wipes on every SE
operation:

```
$ python3 tools/check-reference-contracts.py --ref target/software-only/fixtures/refcheck/memory-bound --skip-pixel --allow-unavailable
    exit 1
    FAILED      memory/linkx-ram-end  -- link.x RAM end vs Makefile BL_SRAM_BASE (the 8 K the callgate wipes): cold-snap has 0x2009e000, reference says 0x20090000
    FAIL: 2 check(s) disagree with the reference: memory/bl-sram-base, memory/linkx-ram-end
```

**3a. ELF vector assumption — SP word.** Vector word 0 patched to `0x2009F000`, above
`BL_SRAM_BASE`:

```
$ python3 tools/check-reference-contracts.py --elf target/software-only/fixtures/refcheck/bad-sp.elf --skip-pixel --allow-unavailable
    exit 1
    FAILED      elf/sp-word-is-estack-top  -- vector word 0 (SP the bootloader loads, startup.S:106): cold-snap has 0x2009f000, reference says 0x2009e000
    FAIL: 1 check(s) disagree with the reference: elf/sp-word-is-estack-top
```

**3b. ELF address assumption — Thumb bit.** Reset vector LSB cleared, which would make
the bootloader's `bx lr` switch to ARM state and fault on the first instruction:

```
$ python3 tools/check-reference-contracts.py --elf target/software-only/fixtures/refcheck/bad-thumb-bit.elf --skip-pixel --allow-unavailable
    exit 1
    FAILED      elf/reset-vector-thumb-bit  -- word 1 = 0x0803936e has LSB clear; the bootloader's `bx lr` would switch to ARM state and fault immediately
    FAIL: 2 check(s) disagree with the reference: elf/reset-vector-thumb-bit, elf/reset-vector-is-entry-point
```

**3c. Invalid image placement.** `llvm-objcopy --change-section-lma '*+0x160000'` on a
copy — the same technique as task 01's `bad-layout.elf` — puts the image into
`FLASH_FS`, where the identity record and the share live:

```
$ python3 tools/check-reference-contracts.py --elf target/software-only/fixtures/refcheck/shifted-lma.elf --skip-pixel --allow-unavailable
    exit 1
    FAILED      elf/vector-table-at-flash-isr  -- .vector_table LMA: cold-snap has 0x08180000, reference says 0x08020000
    FAIL: 4 check(s) disagree with the reference: elf/vector-table-at-flash-isr, elf/vector-table-vma-equals-lma, elf/body-geometry, elf/data-copy-source
```

**4. The `SKIP`-with-exit-zero path.** A reference mirror with `unix/simulator.py`
absent takes `tools/pixel-check.py:239-240` → `skip()` → print `SKIP`, **exit 0**.
`pixel-check.py`'s other skip path (`:80`, their decoder moved) calls the same
`skip()`, so one case exercises the classifier for both:

```
    pixel-check.py alone: exit 0, 'SKIP: no Coldcard checkout at .../no-simulator (set COLDCARD_REPO); the'
    through the checker: exit 2
    UNAVAILABLE pixel/their-decoder-agrees  -- pixel-check.py exited 0 but printed 'SKIP: no Coldcard checkout at ... (set COLDCARD_REPO); their decoder is the reference' -- a missing reference checkout or moved decoder is a MISSING CHECK, not a pass
    INCOMPLETE: 1 check(s) could not run: pixel/their-decoder-agrees. A missing check is not a pass; pass --allow-unavailable to accept this knowingly.
```

An exit-0 `SKIP` becomes a nonzero UNAVAILABLE. On a machine with no
`~/repos/coldcard-firmware` this reference check can no longer disappear into a green
result.

---

## Discrepancies found

**D1 — reference-internal, reported not fixed (not ours to fix).**
`stm32/mk4-bootloader/sigheader.h:34` declares `uint32_t future[5]` (20 B, confirmed
by `sizeof` on the ARM probe) but `:58` says `FWH_NUM_FUTURE 7`. `FWH_PY_FORMAT`'s
`"20s"` and `struct.calcsize` both agree with the struct, so the struct is right and
`FWH_NUM_FUTURE` is stale. Nothing in cold-snap reads `FWH_NUM_FUTURE`. The checker
records this as a note, deliberately **not** as a failure — it is the reference's own
inconsistency, and turning it into a cold-snap failure would make our exit code
hostage to their comment. `~/repos/coldcard-firmware` is read-only.

**D2 — stale doc anchors in cold-snap, found and NOT fixed (out of scope for this
round).** `hal/src/callgate.rs:882,893,905-923` and `:1559` cite `pins.h:96-116` for
the `pinAttempt_t` fields; today's struct is at `pins.h:47-68`. `:709`/`:1501` cite
`pins.h:37` for `PA_MAGIC_V2` (actual `:38`; `:37` is V1). `:699,920,1491,1546` cite
`pins.h:71` for `PIN_ATTEMPT_SIZE_V2` (actual `:72`; `:71` is V1). `:942` cites
`pins.h:85` for `EPIN_PIN_REQUIRED` (actual `:84`). Root `Cargo.toml`'s
`profile.release` comment cites `dispatch.c:417-418` for `enter_dfu()` returning
`EPERM`; the `EPERM` is at `dispatch.c:161-165` and `:417-418` is
`flash_lockdown_hard(OB_RDP_LEVEL_2)`. **Every numeric value at those sites is
correct** — the 114 checks above prove all of them against the real header — only the
line citations rotted. Not fixed because this repair round is scoped to the six
CONFIRMED findings and none of them is a doc anchor; a comment sweep across five
files would be exactly the scope expansion the round forbids. Worth a separate pass.

**No discrepancy was found between cold-snap's constants and the reference's.** All
114 comparisons agree. That is the result, not an assumption: the abi-offset and
memory-bound fixtures prove the same code reports disagreement when there is any.

---

## Findings, one by one

| # | Finding | Fixed? |
|---|---|---|
| 1 | The reference/ELF contract checker the Checks block names does not exist | **Fixed.** `tools/check-reference-contracts.py`, 114 checks, covered/failed/unavailable buckets, distinct exit codes. |
| 2 | None of the three demanded negative fixtures exist | **Fixed.** `tools/test-reference-contracts.py`: ABI offset, memory bound, ELF vector/address (three variants), plus the SKIP path. 6/6 nonzero for the named reason. |
| 3 | `pixel-check.py` still exits 0 on SKIP and nothing accounts for it | **Fixed** by classification, not by editing the script: the wrapper detects `exit 0` + `SKIP:` and records UNAVAILABLE, which makes the run exit 2. Proved by case 4 above. |
| 4 | No evidence record for task 03 | **Fixed.** This file, plus a `03` entry in `target/software-only/evidence/run.json`, plus the machine record in `target/software-only/refcheck/result.json`. |
| 5 | Task 03 has no implementation at all — every criterion unmet by absence | **Fixed.** All six acceptance criteria met; see the table below. |
| 6 | Required evidence file was never written | **Fixed.** This file. |
| 7 | Two of the 114 checks report COVERED when the cold-snap constant they claim to validate is absent (`tools/check-reference-contracts.py:726`, `:817`) | **NOT fixed — OPEN. This is why the task is DEGRADED.** Found by the re-runner *after* the repair round, so no repair pass has addressed it, and close-out is forbidden from editing source. |

### F7 in full — the open finding

Both sites read the cold-snap side with a silent default instead of letting a missing
name surface:

```python
# tools/check-reference-contracts.py:726
rs.get('BURN_LEN_MAX', 0) <= abi['FW_MAX_LENGTH_MK4']
# tools/check-reference-contracts.py:817
stage_end = rs.get('PSRAM_STAGE_OFFSET', 0) + rs.get('PSRAM_STAGE_LEN', 0)
```

A defaulted `0` satisfies both bounds unconditionally, so a renamed or deleted constant
produces a green COVERED row instead of a FAILED drift signal. Reproduced at close-out by
importing the module and replaying both call sites verbatim with `rs = {}` (every
cold-snap constant absent) against this run's real probe values
(`FW_MAX_LENGTH_MK4` = 1,966,080; `PSRAM_SIZE` = 8,388,608):

```
  COVERED     abi/burn-len-max-within-fw-max  -- psram::BURN_LEN_MAX (0) <= FW_MAX_LENGTH_MK4 (1,966,080) == True
  COVERED     memory/psram-stage-below-recovery-header  -- staging ends at +0x000000, recovery header at +0x7fffe0
```

Blast radius is partly contained by sibling checks that use undefaulted lookups:
`memory/burn-len-max-reaches-flash-fs` (`:834`, compares `BURN_BASE + BURN_LEN_MAX`
against an undefaulted `FLASH_FS_BASE`) catches a missing `BURN_LEN_MAX`, and
`memory/psram-stage-is-lower-half` (`:827`) catches a missing `PSRAM_STAGE_LEN`.
`PSRAM_STAGE_OFFSET` (`hal/src/psram.rs:194`, value `0`) is consumed by the checker only
at `:817`, so its rename or removal is caught nowhere and the run still exits 0 at
114/114. The run's *current* result is unaffected — all three constants exist and every
value agrees — so this is a weak guard, not a wrong result.

A second re-runner observation was **PLAUSIBLE, not CONFIRMED**: `run.json:8`'s
`"commit"` backfill sitting outside the range the implementer enumerated. Attributed and
disclosed under *Files changed* above; the value is correct.

### Acceptance criteria

| # | Criterion (prompt's wording, abridged) | Verdict | Basis |
|---|---|---|---|
| 1 | One documented command compares the current Rust/ELF contract with real reference inputs and reports covered, failed, and unavailable checks separately | **met** | `python3 tools/check-reference-contracts.py` — 114 COVERED / 0 FAILED / 0 UNAVAILABLE, three buckets, three distinct exit codes (0 / 1 / 2). Rows 5, 7-12 above. |
| 2 | Changed reference ABI or invalid image placement causes a named nonzero failure | **met** | Six negative cases, 6/6 nonzero **and** the expected check id present in the FAIL line; nonzero-for-the-wrong-reason is itself a suite failure. Rows 6-12. |
| 3 | Cross-target checks use 32-bit ARM layouts rather than assuming host widths | **met** | Probe object's `arm`/`32bit` summary asserted *before* its numbers are used, a non-ARM object refused rather than trusted; `sizeof(void*, int, long)` = 4/4/4 vs host 8/4/8 recorded as its own check `abi/probe-is-arm32`. |
| 4 | Every source-sensitive result carries enough identity to reproduce it | **met** | Reference commit + 6 submodule SHAs + **per-submodule worktree dirt** + sha256 of all 32 consumed files + ELF sha256 + clang/llvm-readelf/rustc versions. A fixture mirror is recorded as *not* a git checkout rather than borrowing cold-snap's HEAD. |
| 5 | Passing checks explicitly leave peripheral timing, silicon behavior, actual secure-element calls, and board-specific bootloader state unverified | **met** | The non-claim is printed by the checker on **every** run (verbatim in close-out's row output: "NOT ESTABLISHED by anything above: peripheral timing, wait states, any silicon behaviour, real ATECC608/SE2 responses, real callgate transits, and board-specific bootloader state"), and enumerated as B1-B7 below. |
| 6 | QEMU with a substituted stack/memory map remains a diagnostic, not a pass gate | **met** | `tools/qemu-boot.sh` is never invoked by either tool and is untouched on this branch; the checker states this in its closing scope statement. |

6 of 6 met. **No criterion is "not met", and none required the
unverifiable-without-hardware verdict** — every criterion here is about the checker's own
behaviour, which is fully decidable on the host. What hardware *would* be needed for is
the separate question of whether the verified contracts hold on silicon, which is not an
acceptance criterion and is recorded as B1-B7 instead. The task is DEGRADED on the open
finding F7, not on a criterion.

---

## Forbidden-shortcut audit

Each item checked by name. **Global list** (the run's shared rules):

| Shortcut | Result |
|---|---|
| Claiming a command ran that did not run; not pasting real exit codes | **Not taken.** All 12 commands were executed three times by three agents; close-out's own exit codes and elapsed times come from `target/software-only/refcheck/closeout-rerun.json`. |
| Treating exit 0 with `SKIP` as a pass (`tools/pixel-check.py` does exactly this) | **Not taken — this is the finding the task closed.** Row 12 proves `pixel-check.py` alone exits 0 printing `SKIP:` while the checker turns that into `UNAVAILABLE pixel/their-decoder-agrees` and exit **2**. |
| Capturing a filtering pipeline's status instead of the process's; equating a warning count with a successful compiler invocation | **Not taken.** Every exit code is the process's own (`subprocess.run` return code, no shell pipeline). Rows 2-3 emit 18 pre-existing `warning:` lines and the recorded status is cargo's, not a grep's. |
| Hardcoding historical figures (379,876 vs 379,880 body-sum gap; 508 tests; 60,512 of 65,536; the 12-device keygen ceiling) as current evidence | **Not taken.** None of those numbers appears in either new tool; grep-verified by the re-runner. Every figure here is measured this run: 114 checks, 292+5+19 tests, 652,992-byte ELF. |
| Deleting or relaxing a failing assertion to make a build pass | **Not taken.** No existing assertion, test or constant was edited; two new files only. `hal/src/callgate.rs:1546-1590`'s Rust-literal test is left in place and the C-derived comparison is additive. |
| Claiming "hardware verified" or "safe for funds" | **Not taken.** The only claim made, in the checker's output and in this file, is "software/pre-bench checks passed", scoped. |
| Reporting unit tests as an integration run, or a mocked effect as a real one | **Not taken.** Row 4 is labelled a host unit/integration-test run on `aarch64-apple-darwin` with `fake-flash`; no callgate, device, port, flash, provisioning, OTP write or network was involved, and the ARM probe object is read, never executed. |
| Physical device / serial / USB / flashing / provisioning / OTP / real callgate / public network | **None occurred.** |
| Writing to `~/repos/coldcard-firmware`, or mutating it to stage a negative test | **Not done.** Its dirt is 10 entries before and after (`git -C ~/repos/coldcard-firmware status --porcelain \| wc -l` = 10, re-confirmed at close-out). Fixtures are symlink mirrors under `target/` with one materialised edited copy; ELF cases patch copies. |
| New signing authority / manifest / allowlist / factory cert / share-proof gate | **None added.** No key material of any kind is touched by this task. |
| Generated output outside ignored `target/`; clobbering unrelated user work | **Not done.** All artifacts under `target/software-only/{refcheck,fixtures}/`; the five pre-existing user-work entries across both repos are untouched. |
| Pushing or opening a PR | **Not done.** One local commit only. |

**Task-03 list** (this prompt's own prohibitions):

| Shortcut | Result |
|---|---|
| "Do not replace the C types with copied declarations that would make the comparison self-consistency only" | **Not taken.** The probes `#include` the reference's real `pins.h`/`sigheader.h`/`main.h`/`psram.h`/`verify.h` and the CMSIS/HAL headers under `-I<ref>/...`; the Rust side is parsed from real `hal/`/`firmware/` source (327 consts), not transcribed. Three independent sides, none copied into the checker. |
| "inspect their object constants without attempting to execute ARM code on the host" | **Honoured.** Constants are read out of the `.probe` section with `llvm-objcopy -O binary`; nothing ARM is executed. |
| "Report the exact coverage; do not claim every register access was validated" | **Honoured.** 40 named register constants, with the explicit non-claim that every other offset/mask/bit in `hal/src/{flash,display,keypad,rng,panic,usb}.rs` is **not** validated. |
| "Attribute alignment gaps without collapsing them" | **Honoured.** `elf/body-geometry` attributes the single 4-byte align-8 gap rather than folding it into a sum. |
| "distinguish automated assertions from a recorded disassembly review" | **Honoured.** Startup ordering is labelled a recorded review (`target/software-only/refcheck/reset-entry.asm`), explicitly not an assertion, in the row itself. |
| "A missing reference checkout or moved decoder is a missing check, not a pass" | **Honoured.** UNAVAILABLE → exit 2; see row 12. |
| "A parent commit alone does not identify dirty files or changed submodules" | **Honoured.** Per-submodule dirt is recorded and is not hypothetical: `external/libngu` and `external/micropython` each carry 2 entries of their own while `git submodule status` shows no `+`. |
| "Never mutate the live reference checkout or live firmware to conduct these negative checks" | **Honoured**, as above. |
| "Preserve exit statuses; do not equate a warning-count pipeline with a successful compiler invocation" | **Honoured**, as above. |
| "never invoke a callgate or access a physical device" | **Honoured.** |
| QEMU as a gate | **Not done.** Never invoked. |

The one weakness found by this audit's own standard is F7: two rows are structurally
capable of passing vacuously. It is reported open, not written down as clean.

---

## What stays unverified — residual bench-only questions

In the prompt's own terms, a passing run of these checks "explicitly leave[s] **peripheral
timing, silicon behavior, actual secure-element calls, and board-specific bootloader
state** unverified" (acceptance criterion 5); startup ordering is checked "in emitted code
where practical" and is here a "**recorded disassembly review**" distinguished from an
automated assertion (work item 4); the register set is "a **bounded, documented set**" and
this run does "**not claim every register access was validated**" (work item 3); and "QEMU
with a substituted stack/memory map **remains a diagnostic, not a pass gate**"
(criterion 6), so nothing it would show is claimed here either.

Mapped onto those terms: B1 is *peripheral timing*; B2 is *silicon behavior*; B3 is
*actual secure-element calls*; B4 is *board-specific bootloader state*; B5 is the
*recorded disassembly review* boundary; B6 is the reference's own recovery path, compared
as bounds only; B7 is the *bounded* register set.

Everything below is untouched by all 114 checks. A green run says nothing about any
of it.

- **B1 Peripheral timing and wait states.** Flash program/erase timing,
  `FLASH_SPIN_LIMIT`, SPI FIFO drain, RNG seed-error recovery. Only silicon answers.
- **B2 Silicon behaviour generally.** The `DBANK` option-byte value on a real unit
  (4 K vs 8 K erase granularity), FPU/clock behaviour after `CPACR`, whether
  `SRAM3` reads back as the bootloader left it.
- **B3 Real secure-element calls.** No callgate transit was performed. Whether
  sub-call 0 is counter-free, whether `attempts_left` behaves as read, whether
  `PIN_ATTEMPT_SIZE_V2` is what *this* bootrom expects at run time — all bench.
- **B4 Board-specific bootloader state.** RDP level, option bytes, PCROP, the
  pairing secret, the OTP min-version floor, and whether an install path exists at
  all on the unit in hand.
- **B5 Startup instruction order on target.** The `reset-entry.asm` review is a read
  of the emitted code, one frame above the VTOR/CPACR stores. No automated check
  proves the VTOR store precedes the first faulting instruction.
- **B6 The bootloader's PSRAM recovery path.** `RECHDR_POS` and the `psram.c:261-266`
  gate are compared as *bounds* only; nothing here exercises
  `psram_recover_firmware()`, and no `arg2 = 7` burn is bound in cold-snap.
- **B7 The 40-constant register set is bounded.** Every other register offset, mask
  and bit in the HAL is transcription that this run does not check.
