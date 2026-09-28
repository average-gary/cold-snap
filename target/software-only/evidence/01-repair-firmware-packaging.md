# 01 — Repair firmware packaging and verify the artifact

## Status: DEGRADED

All 6 acceptance criteria are met and every check passes for the right reason, but one
CONFIRMED finding is still open, so this is not a PASS:

> **Open CONFIRMED finding — `tools/test-pack-signed.py:174-176`.** The corrupted-signature
> end-to-end case asserts only that `checkfw`'s output contains `REFUSE`, the generic
> verdict line that every rejection prints, not that rule **R12** (the signature check) is
> the rule that failed. The run today does fail on R12 — verified by reading the output,
> quoted below — so the check passes for the right reason *now*; the guard, not the result,
> is weak. If `checkfw` later stopped verifying signatures but failed some other rule on
> this fixture, the test would still pass. The fix is one word, `'REFUSE'` → `'R12'`, at
> that line. It breaks no acceptance criterion and no forbidden-shortcut rule; the
> close-out agent may not edit source, so it is carried forward rather than silently
> dropped. The sibling bad-layout case *does* assert its specific reason
> (`tools/test-pack-signed.py:164`).

No other finding is open. Nothing is blocked: every tool the task needs was present and
every command in the prompt's Checks block ran to completion.

Repair round plus close-out, 2026-09-21. cold-snap HEAD at run start:
`ecc8ebcc25872167d6cd360134bf224efafedbc8`. The implementer and both review rounds left
everything uncommitted; this close-out makes the task's single commit on branch
`software-only/run-2026-09-21`, staging only `README.md`, `tools/pack-signed.py`,
`tools/test-pack-signed.py` and the two evidence files by explicit path. Scope claim
available from this work: **software/pre-bench checks
passed** for the artifact's format, digest and signature. No device was touched, no
port opened, nothing flashed or provisioned. `~/repos/coldcard-firmware` was read
only and its working tree is byte-for-byte the 00-preflight tamper baseline
(3 modified, 7 untracked docs — re-checked after the last run).

## The cause

The packer asserted that a flat `objcopy -O binary -j ...` file equals the **sum of
its section sizes**. Against the linked image that is simply false. `.rodata`'s
*section* alignment is 8 and `.text` ends at `0x080728a4`, so the linker leaves four
bytes there, `llvm-objcopy` emits them, and the body comes out 379,880 B against a
379,876 B sum:

```
.vector_table  LMA 0x08020000  VMA 0x08020000  ELF off 0x0010000       64 B  align 4
.text          LMA 0x08024000  VMA 0x08024000  ELF off 0x0014000  321,700 B  align 4
.rodata        LMA 0x080728a8  VMA 0x080728a8  ELF off 0x00628a8   58,140 B  align 8
.data          LMA 0x08080bc4  VMA 0x20008010  ELF off 0x0078010       36 B  align 4
```

The four bytes were never the bug; the assertion was. Its own advice ("Split the
`-j` list so no gap is spanned") cannot be taken: the gap is *inside* the body, and
the only way to close it is to move `.rodata` — i.e. to change the linked image to
suit the checker, which the task forbids and which would be the wrong fix anyway.
Two related facts the old code never used: an ELF section header has no LMA field,
so `.data`'s flash address was invisible (the code carried its RAM VMA
`0x20008010`), and `.data`'s ELF **file** offset `0x078010` is *not* contiguous with
`.rodata`'s file end `0x070bc4` even though their LMAs are.

## Files changed

```
M  /Users/garykrause/repos/cold-snap/tools/pack-signed.py        (+/- the geometry fix; see below)
A  /Users/garykrause/repos/cold-snap/tools/test-pack-signed.py   (new, 184 lines, 18 cases)
M  /Users/garykrause/repos/cold-snap/README.md                   (packaging docs + dated retractions)
A  /Users/garykrause/repos/cold-snap/target/software-only/evidence/01-repair-firmware-packaging.md  (this file)
A  /Users/garykrause/repos/cold-snap/target/software-only/evidence/run.json                         (run roll-up)
```

`git diff --stat` for the two modified tracked source files: `README.md | 69 ++`,
`tools/pack-signed.py | 286 ++`, 301 insertions, 54 deletions. No other tracked file in any
repository was modified. `firmware/link.x` was deliberately not touched — moving a section
to satisfy the checker is the forbidden fix.

## What changed

**`/Users/garykrause/repos/cold-snap/tools/pack-signed.py`** (modified)

| anchor | change |
|---|---|
| `:24-33` | docstring: the sum is not the geometry; placement is by LMA |
| `:66` | new `FLASH_FS_BASE = 0x0818_0000` (`hal/src/lib.rs:181`, `link.x:47`) |
| `:76` | new `GAP_FILL, PAD_FILL = 0x00, 0xFF` — two fills, two owners, stated not inherited |
| `:83` | new `Sec` namedtuple: `name type vma lma off size align flags` |
| `:119-161` | `sections()` rewritten on `llvm-readelf --elf-output-style=JSON --sections --program-headers`. LMA comes from the containing `PT_LOAD`: `p_paddr + (sh_offset − p_offset)`. Aborts if a flash-resident section's file range is not in exactly one `PT_LOAD`. Replaces the positional column parse and its `len(t) == 9` flags heuristic. |
| `:167-207` | **new `geometry(secs, names, what)`** — this is the fix. Returns `(group in LMA order, base, span, gaps)`; `span = max(lma+size) − min(lma)`. Refuses a 32-bit wrap, an overlap, and any gap that is not exactly `align_up(prev_end, next.align) − prev_end`. |
| `:209-216` | **new `header_slot_occupants()`** — the slot test, now by LMA. The old inline test used `s[2]` (VMA) and so could not see a section whose flash bytes land in `0x08023F80..0x08024000` while its VMA sits in RAM. |
| `:218-229` | **new `image_bounds()`** — refuses a 32-bit wrap and any image reaching `FLASH_FS`. |
| `:231-249` | **new `attribute()`** — per-section byte-for-byte compare against the ELF at that section's own file offset, plus a fill check on every gap. |
| `:343` | read the ELF once for the byte-for-byte compares |
| `:349-360` | `[1]` prints LMA, VMA, ELF offset, size and alignment per section, and labels the sum as *not* the emitted span |
| `:382` | `--gap-fill 0` passed explicitly, so `attribute()` checks a promise rather than today's `llvm-objcopy` default |
| `:386-406` | `[2]` per group: `geometry()`, base-address contract (`firmware0.bin` must load at `0x08020000`, `firmware1.bin` at `0x08024000` — signit concatenates at fixed offsets), size against `span` not sum, every gap printed with address/size/fill/reason, then `attribute()` |
| `:441-451` | `[3]` asserts signit's `FW_HEADER_OFFSET + FW_HEADER_SIZE` still equals `SLOT_END − FLASH_ORIGIN`, then `image_bounds()` on `firmware_length` |
| `:516-547` | `[6]` replaces the two-region `0xff` check with a full region table over the signed container: every section (re-read from the ELF, so signit is checked against the ELF and not against our own flat files), every alignment gap, the 128 B header and both `0xff` pads must **tile `[0, firmware_length)`** with no hole and no double claim |

Kept unchanged on purpose: the unexpected-section abort, the stale-ELF guard, the
frozen BCD timestamp and RFC6979 shim, the 9-field header readback, the own
double-SHA256 cross-check against `signit check`, the DFU wrap, the rerun-identity
check, `firmware/link.x` (no section moved), `firmware/examples/checkfw.rs`,
`coldsnap_firmware::firmware_digest`, `hal/src/lib.rs`.

**`/Users/garykrause/repos/cold-snap/tools/test-pack-signed.py`** (new, 184 lines)
Plain asserts, no framework. Part A drives the pure functions over synthetic
section lists — the real 4 B gap (`span == 379_880` while `sum == 379_876`), a
contiguous group, an overlap, a hole alignment does not explain, a 32-bit wrap, an
empty `-j` group, the header slot by LMA including the RAM-VMA/flash-LMA case,
`FLASH_FS` flush and one byte over, and `attribute()` on drifted section bytes and
a wrong gap fill: **16 cases**. Part B is end to end and refuses to skip: it mints
a bad-layout ELF (`llvm-objcopy --change-section-lma '*+0x160000'` from a copy) and
a corrupted-signature artifact under `target/software-only/fixtures/`, and requires
both to exit nonzero for the named reason. If the ELF or the packed artifact is
missing it **fails** rather than skipping.

**`/Users/garykrause/repos/cold-snap/README.md`** (modified) — `:1102-1106` ELF size
650,532 → 652,992 and the re-run date, with the dated retraction; `:1120-1128`
body 379,584 → 379,880 and the removal of the stale "compares each flat file
against the sum of its section sizes" sentence; `:1130-1149` a new paragraph
documenting the reproduced defect, the exact abort text, why the abort's advice was
untakeable, and the geometry that replaced it; `:1151-1161` a new paragraph on
LMA-vs-VMA and the non-contiguous file offsets; `:1163-1165` `≥ FW_MIN_LENGTH by`
117,440 → 117,736 and `align_to(379880, 512) = 379,904 (+24)`; `:1172-1174`
1,344 → 1,048 B of `0xff` with its dated retraction; `:810-813` notes that the
flash-budget row's 379,940 B is a section **sum** and that 379,944 B are emitted;
`:1096`/`:1323-1328` the new regression script listed. Every existing dated
measurement and retraction was preserved; new figures follow the same
`**this read X until YYYY-MM-DD**` form. `AUDIT-2026-09-10.md` untouched.

## Commands — pass 1, the implementer's own run

cwd `/Users/garykrause/repos/cold-snap` for every command. Real exit codes, captured from
each process directly, never from a pipeline. Elapsed time was recorded only for step 1
(`Finished release profile in 0.41s`, printed by cargo); the implementer did not time the
other five, and no figure is invented for them here — pass 3 below times all of them.

```
1 cargo build --release                                              EXIT=0
2 python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/package
                                                             (run A) EXIT=0
3 python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/package
                                                             (run B) EXIT=0
4 cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw
    -- target/software-only/package/firmware-signed.bin              EXIT=0
5 cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw
    -- target/software-only/package/coldsnap-6.0.0cs.dfu             EXIT=0
6 python3 tools/test-pack-signed.py                                  EXIT=0
```

Step 1 was a no-op link (`Finished release profile in 0.41s`), so the signed
artifacts are from the 2026-09-18 00:43 ELF, 652,992 B — the same ELF the defect
was reproduced against. Steps 4 and 5 both print
`RESULT: ACCEPT — 12/12 locally checkable rules pass.` followed by the four
`NOT CHECKED` device-state rules. Step 6 prints
`part A: 16 pure geometry cases, all as required` / `part B: 2 end-to-end refusals,
both nonzero for the intended reason` / `OK: 18 cases`.

## Commands — pass 2, the re-runner's independent re-run

A separate agent re-ran the whole Checks block itself, from cwd
`/Users/garykrause/repos/cold-snap`, in zsh, redirecting each command to a file and reading
`$?` — so every code below is the process's own status, not a pipeline's. It deleted
`target/software-only/{package,fixtures}` first, so nothing it measured was a stale
artifact. Its logs are on disk at `/Users/garykrause/repos/cold-snap/target/software-only/verify/*.log`.
It did not record elapsed times.

| # | command | exit |
|---|---|---|
| 1 | `cargo build --release` | 0 |
| 2 | `python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/package` (run A, after `rm -rf target/software-only/{package,fixtures}`) | 0 |
| 3 | same command, run B — printed `rerun: byte-identical to the previous firmware-signed.bin` | 0 |
| 3a | `cmp target/software-only/verify/runA/firmware-signed.bin target/software-only/package/firmware-signed.bin` | 0 |
| 3b | `cmp target/software-only/verify/runA/coldsnap-6.0.0cs.dfu target/software-only/package/coldsnap-6.0.0cs.dfu` | 0 |
| 3c | `cmp target/software-only/verify/runA/firmware1.bin target/software-only/package/firmware1.bin` | 0 |
| 4 | `cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/package/firmware-signed.bin` → `RESULT: ACCEPT — 12/12` | 0 |
| 5 | same for `target/software-only/package/coldsnap-6.0.0cs.dfu` → `RESULT: ACCEPT — 12/12` | 0 |
| 6 | `python3 tools/test-pack-signed.py` → `OK: 18 cases` | 0 |
| 7 | `python3 tools/pack-signed.py --elf target/software-only/fixtures/bad-layout.elf --out target/software-only/fixtures/bad-layout-out --no-dfu` — negative, `ABORT (Abort): firmware0.bin would load at 0x08180000, not 0x08020000` | 1 (intended) |
| 8 | `cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/fixtures/bad-signature.bin` — negative, `[FAIL] R12 ... signature failed verification` / `RESULT: REFUSE` | 1 (intended) |
| 9 | pre-fix reproduction from `git show HEAD:tools/pack-signed.py` into `target/software-only/verify/prefix-pack-signed.py`, same ELF — `firmware1.bin is 379880 B but its sections sum to 379876 B: objcopy gap-filled +4 B` | 1 (intended) |
| 10 | mutation check: `geometry()` reverted to `sum(x.size for x in grp)` in a copy under `target/software-only/verify/mutant/` → `AssertionError: 379876` | 1 (intended) |
| 11 | `grep -rn "SKIP" target/software-only/verify/*.log` — no match anywhere | 1 (no match) |
| 12 | `git status --porcelain` → ` M README.md`, ` M tools/pack-signed.py`, `?? prompts/`, `?? tools/test-pack-signed.py` | 0 |
| 13 | `git -C /Users/garykrause/repos/coldcard-firmware status --porcelain` → 10 entries, HEAD `0431fd2b00095a9ac0e5df4a023acd6eaf6a15a6` | 0 |

It independently computed sha256 `94b89e20b5c68a0cb9c12e4201874ef6a3c0b1a643fddd618ba5ec7f0faef2bc`
for `firmware-signed.bin` and `e057a37831fcbfa8892b3248747b41e5e32b1a3ace93f841ea13f1ec288c65e1`
for the DFU — the same values as pass 1 — re-derived README's arithmetic
(379,880 − 262,144 = 117,736; `align_to(379880,512)` = 379,904, +24; 380,928 − 379,880 =
1,048 B of `0xff`; 64 + 379,880 = 379,944 emitted against a 379,940 B section sum), and
confirmed every cited `file:line` anchor lands where the write-up claims.

## Commands — pass 3, the close-out agent's own timed re-run

Third independent execution, same run (2026-09-21), cwd `/Users/garykrause/repos/cold-snap`. Each
command was run under `/usr/bin/time -p`, which passes the child's exit status through, and
its own status read from `$?` — no pipeline anywhere. Logs:
`/Users/garykrause/repos/cold-snap/target/software-only/closeout/c*.log`.

| # | command (verbatim) | exit | elapsed (real) |
|---|---|---|---|
| 1 | `cargo build --release` | 0 | 1.76 s |
| 2 | `python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/package` | 0 | 0.98 s |
| 3 | `python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/package` | 0 | 0.20 s |
| 4 | `cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/package/firmware-signed.bin` | 0 | 1.58 s |
| 5 | `cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/package/coldsnap-6.0.0cs.dfu` | 0 | 0.76 s |
| 6 | `python3 tools/test-pack-signed.py` | 0 | 0.91 s |
| 7 | `python3 tools/pack-signed.py --elf target/software-only/fixtures/bad-layout.elf --out target/software-only/fixtures/bad-layout-out --no-dfu` | 1 (intended) | 0.18 s |
| 8 | `cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/fixtures/bad-signature.bin` | 1 (intended) | 1.24 s |

Both packaging runs are full runs, not a short-circuit: each prints the whole `[1]`..`[8]`
transcript including the region-tiling table and `signature CORRECT`, and each prints
`rerun: byte-identical to the previous firmware-signed.bin`. Steps 4 and 5 both print
`RESULT: ACCEPT — 12/12 locally checkable rules pass.` and the four `NOT CHECKED`
device-state lines. Step 6 prints `OK: 18 cases`. Step 7's abort names the moved base;
step 8's failure names R12 verbatim:
`[FAIL] R12 signature over double-SHA256(signed range): expected valid under approved_pubkeys[0], actual signature failed verification; fw_check 5d899ca0...`.
`grep -rn 'SKIP' target/software-only/closeout/` matches nothing (exit 1). After this third
pass the artifact hashes are unchanged from passes 1 and 2 — a third reproducibility
confirmation, from a third agent, after the re-runner had deleted and regenerated the
whole output directory in between.

### Before the fix (the reproduction, same ELF, same command)

```
EXIT=1
ABORT (Abort): .../target/software-only/package/firmware1.bin is 379880 B but its
sections sum to 379876 B: objcopy gap-filled +4 B. Split the -j list so no gap is
spanned.
```

### After the fix — what `[2]` now prints

```
firmware0.bin  -j .vector_table                               64 B
  0x08020000..0x08020040 span 64 B = 64 B of sections + 0 B in 0 alignment gap(s)
  every byte re-read from the ELF at its own file offset and the gap fill checked  [OK]
firmware1.bin  -j .text -j .rodata -j .data              379,880 B
  0x08024000..0x08080be8 span 379,880 B = 379,876 B of sections + 4 B in 1 alignment gap(s)
  gap 0x080728a4..0x080728a8     4 B of 0x00: .text ends unaligned, the next section needs align 8
  every byte re-read from the ELF at its own file offset and the gap fill checked  [OK]
```

### Every emitted byte, attributed — what `[6]` now prints

```
[0x00000,0x00040)         64 B  .vector_table
[0x00040,0x03f80)     16,192 B  0xff vector pad (0xff)
[0x03f80,0x04000)        128 B  signit header
[0x04000,0x528a4)    321,700 B  .text
[0x528a4,0x528a8)          4 B  align-8 gap (0x00)
[0x528a8,0x60bc4)     58,140 B  .rodata
[0x60bc4,0x60be8)         36 B  .data
[0x60be8,0x61000)      1,048 B  0xff body pad (0xff)
those 8 regions tile [0,397,312) exactly: every emitted byte is a section read back
from the ELF, the 128 B header, or padding with a stated fill  [OK]
image 0x08020000..0x08081000, 1,044,480 B clear of FLASH_FS 0x08180000  [OK]
```

## Deliberate-failure cases, with their real exit codes

**Invalid layout** — every LMA of a *copy* of the release ELF shifted up 1.375 MiB
(`llvm-objcopy --change-section-lma '*+0x160000'`, into
`target/software-only/fixtures/bad-layout.elf`; the real ELF and the reference tree
were not touched):

```
$ python3 tools/pack-signed.py --elf target/software-only/fixtures/bad-layout.elf \
    --out target/software-only/fixtures/bad-layout-out --no-dfu
EXIT=1
ABORT (Abort): firmware0.bin would load at 0x08180000, not 0x08020000: signit lays
the vectors, header and body down at fixed offsets, so a moved base shifts the whole
image silently. link.x moved -- fix it there.
```

**Corrupted signature** — one bit flipped at `0x3f80 + 64` of a copy of
`firmware-signed.bin`, judged by the independent checker rather than by the tool
that made the file:

```
$ cargo run --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw \
    -- target/software-only/fixtures/bad-signature.bin
EXIT=1
[FAIL] R12 signature over double-SHA256(signed range): expected valid under
       approved_pubkeys[0], actual signature failed verification; fw_check
       5d899ca0...  [verify.c:226+232]
RESULT: REFUSE — 1 of 12 rules failed.
```

Both are re-run by `tools/test-pack-signed.py`, which asserts the exit code and a
substring of the message. The two guards are **not equally strong**, and the earlier
write-up of this file overstated the second one:

| case | asserted exit | asserted text | is that the *reason*? |
|---|---|---|---|
| bad layout (`:164`) | 1 | `would load at 0x08180000, not 0x08020000` | yes — the specific abort |
| bad signature (`:174-176`) | 1 | `REFUSE` | **no** — the generic verdict line, printed by any of the 12 rules failing |

The bad-signature run really does fail on R12 (output quoted above, read directly, not
inferred), so it passes for the right reason today. The weak guard is the open CONFIRMED
finding recorded under **Status** at the top of this file.

**The regression checks are not vacuous.** Mutation test: a copy of the packer
under `target/software-only/fixtures/mutant/` with `geometry()`'s return changed
back to `sum(x.size for x in grp)` makes part A fail immediately —
`AssertionError: 379876` at `assert span == 379_880`. Exit 1. The mutant copy was
deleted afterwards.

## Reproducibility

Byte-identical. Three consecutive packaging runs from the same ELF and frozen
timestamp; the packer's own comparison printed
`rerun: byte-identical to the previous firmware-signed.bin` on runs B and C, exit 0
each. The DFU container was compared separately (`cmp` of run B's copy against run
C's output, exit 0), since the packer's own check covers only the raw image.

```
firmware-signed.bin   397,312 B  sha256 94b89e20b5c68a0cb9c12e4201874ef6a3c0b1a643fddd618ba5ec7f0faef2bc
coldsnap-6.0.0cs.dfu  397,621 B  sha256 e057a37831fcbfa8892b3248747b41e5e32b1a3ace93f841ea13f1ec288c65e1
sha256^2 of the signed range     5d899ca040912f873e285704bf6110ca8fea4c8f4916e38fd8a8e8dfb75f21d3
```

`firmware_length = 16,256 + 128 + 380,928 = 397,312 (0x61000) = 97 × 4096`, hashed
span 397,248 B (`firmware_length − 64`).

## Artifacts

```
/Users/garykrause/repos/cold-snap/target/software-only/package/firmware0.bin           64 B
/Users/garykrause/repos/cold-snap/target/software-only/package/firmware1.bin      379,880 B
/Users/garykrause/repos/cold-snap/target/software-only/package/firmware-signed.bin 397,312 B
/Users/garykrause/repos/cold-snap/target/software-only/package/coldsnap-6.0.0cs.dfu 397,621 B
/Users/garykrause/repos/cold-snap/target/software-only/fixtures/bad-layout.elf     (negative case)
/Users/garykrause/repos/cold-snap/target/software-only/fixtures/bad-signature.bin  (negative case)
```

All under ignored `target/`. Nothing was signed with anything but dev key 0
(`pubkey_num=0`); that signature satisfies the bootloader's image format and
establishes no release provenance.

## Acceptance criteria — the prompt's six bullets, verbatim

Criteria are quoted exactly as `prompts/software-only/01-repair-firmware-packaging.md`
writes them. **6 met, 0 not met, 0 unverifiable-without-hardware.**

| # | criterion (prompt's wording) | verdict | what settles it |
|---|---|---|---|
| 1 | "The current ARM ELF packages successfully without changing section placement" | **met** | pass-3 step 2 exit 0 against the same 652,992 B ELF the defect reproduced on; `firmware/link.x` untouched and no `--change-section-*` on the real ELF; `[2]` prints the group bases still at `0x08020000` / `0x08024000` |
| 2 | "Every emitted byte is attributed to a section, header, or documented padding" | **met** | `[6]` tiles `[0, 397312)` with 8 regions, no hole and no double claim; each section re-read from the ELF at its *own* file offset; both fills stated (`GAP_FILL 0x00`, `PAD_FILL 0xFF`) and `--gap-fill 0` passed explicitly rather than inherited from `llvm-objcopy`'s default |
| 3 | "Raw and DFU artifacts pass the locally checkable `checkfw` rules" | **met** | pass-3 steps 4 and 5, exit 0 each, `RESULT: ACCEPT — 12/12 locally checkable rules pass.`; the 4 device-state rules print `NOT CHECKED` and are *not* counted as passes |
| 4 | "A corrupted signature and an invalid layout fail explicitly" | **met** | pass-3 steps 7 and 8, exit 1 each, for the named reason: moved base `0x08180000`, and `[FAIL] R12 ... signature failed verification`. Both are re-run inside `tools/test-pack-signed.py`. The open finding is about the *strength of one assertion's substring*, not about whether the case fails explicitly — it does |
| 5 | "Repeated packaging of identical inputs is byte-identical" | **met** | 3 agents, 7 packaging runs total (3 + 2 + 2), one deletion of the whole output directory in between; `rerun: byte-identical to the previous firmware-signed.bin` from the packer, plus independent `cmp` (exit 0) on `firmware1.bin`, `firmware-signed.bin` and the DFU, plus identical sha256 across passes 1-3 |
| 6 | "Results distinguish artifact validity from unmeasured bootloader/device state" | **met** | `checkfw` reports 12 locally checkable rules separately from U1-U4 `NOT CHECKED — device state, absent from this file`; the section below carries them forward as bench-only; the only claim made anywhere in this file is "software/pre-bench checks passed", scoped |

Work items 1-7 of the prompt all have a corresponding artifact: 1 → the section table under
**The cause**; 2 → `geometry()` at `tools/pack-signed.py:167-207` with LMA-derived placement;
3 → the unexpected-section abort kept plus overlap / wrap / header-slot / `FLASH_FS` refusals;
4 → `attribute()` at `:231-249` and the `[6]` tiling of the signed container; 5 →
`tools/test-pack-signed.py` and the two nonzero negatives; 6 → the reproducibility section
and both checkers (`signit check` inside `[5]`, `checkfw` externally); 7 → the README anchors
listed above.

## Forbidden-shortcut audit

Each rule checked by name, against the tree and the logs rather than against the write-up.

**Global list (orchestrated-run shared rules)**

| rule | result |
|---|---|
| "Never claim a command ran that did not run. Paste real exit codes." | **clean.** Every code in this file came from `$?` of the named process. Pass 3 re-ran all 8 commands first-hand; pass 2 re-ran them independently with its logs left on disk at `target/software-only/verify/`. The first review round caught exactly this failure mode (an empty implementation) and it was repaired, not narrated over. |
| "Exit 0 with `SKIP` output is not a pass." | **clean.** `grep -rn 'SKIP'` over `target/software-only/closeout/` and `target/software-only/verify/*.log` matches nothing (exit 1 both times). `tools/test-pack-signed.py` part B is written to **fail**, not skip, if the ELF or the packed artifact is missing. `tools/pixel-check.py` was not used by this task. |
| "Capture the process's status, never a filtering pipeline's." | **clean.** Pass 3 used `/usr/bin/time -p cmd > log 2>&1; rc=$?`, which forwards the child's status; grepping happened afterwards against the saved file. Pass 2 used the same redirect-then-`$?` shape in zsh. No `cmd | grep` was ever the thing measured. |
| "Historical figures are reproduction clues, never current evidence and never hardcoded constants." | **clean.** 379,876 / 379,880 appear in `tools/pack-signed.py` and `tools/test-pack-signed.py` in exactly two roles: as the *pre-fix* abort text quoted in the docstring/README prose, and as the expected value of a synthetic part-A case whose inputs are stated in the test itself. The packer computes `span` and the per-section sum from the ELF every run; no size is compared to a literal. The 508-test, 60,512/65,536-byte arena and 12-device figures belong to other tasks and appear nowhere in this change. |
| "Never delete or relax a failing assertion to make a build pass." | **clean and independently checked.** The old assertion at `tools/pack-signed.py:243-249` was *replaced by a stricter one*: the new `geometry()` refuses overlaps, 32-bit wrap, unexplained holes, moved group bases and `FLASH_FS` crossing — all of which the old sum test could not see. Mutation-checked in both directions: reverting `geometry()` to `sum(x.size for x in grp)` makes part A fail with `AssertionError: 379876` (exit 1), so the new check is not vacuous. |
| "No label of 'hardware verified' or 'safe for funds'." | **clean.** Neither phrase occurs. The only claim is "software/pre-bench checks passed", scoped to format, digest and signature, with an explicit sentence that nothing here shows the image boots or is safe for funds. |
| "Unit tests are never reported as an integration run. A mocked effect is never reported as a real one." | **clean.** Part A (16 cases) is labelled *pure geometry over synthetic section lists* and part B (2 cases) is labelled *end to end*; the printed summary keeps them separate and the totals are never merged into a claim about the device. The RFC6979 shim is a determinism fix inside signing, not a mock of the signature: the signature is verified twice by two independent verifiers (`signit check` and `checkfw` R12). |
| Absolute prohibition — no device, serial port, USB, flashing, provisioning, OTP write, callgate, network broadcast | **clean.** No such command exists in any of the three passes' logs. The packer's closing line *prints* a `ckcc upgrade` suggestion; it was never run. |
| Absolute prohibition — `/Users/garykrause/repos/coldcard-firmware` is read-only | **clean.** HEAD still `0431fd2b00095a9ac0e5df4a023acd6eaf6a15a6` and 10 porcelain entries, byte-for-byte the 00-preflight baseline, re-checked after pass 3. The bad-layout fixture was minted from a **copy** of cold-snap's own ELF into `target/software-only/fixtures/`. |
| Absolute prohibition — dev key 0 only; no new signing authority, manifest, allowlist, certificate or gate | **clean.** `--pubkey-num 0` and `stm32/keys/00.pem` only. Nothing was added that turns a digest into trust. |
| Absolute prohibition — generated output under ignored `target/`; preserve unrelated user work | **clean.** Every artifact and fixture is under `target/software-only/`. `?? prompts/` is untouched and unstaged. frostsnap's four pre-existing entries are byte-for-byte unchanged and untouched. |
| Absolute prohibition — never push, never open a PR | **clean.** One local commit on `software-only/run-2026-09-21`, no `git push`, no `gh pr`. |

**Task list (`01-repair-firmware-packaging.md`'s own prohibitions)**

| rule (prompt's wording) | result |
|---|---|
| "Do not simply remove the failed assertion or move aligned sections to satisfy it" (Work 3) | **clean** — see the global row above; replaced with a stricter check, `link.x` untouched. This is the shortcut the task exists to forbid, and the abort's own advice ("Split the `-j` list so no gap is spanned") was the untakeable one. |
| "Use `.data`'s LMA for artifact placement" / "Preserve every section at its linked offset" (Work 2) | **clean** — `.data` is placed at LMA `0x08080bc4`, not VMA `0x20008010`, and every section is re-read at its own ELF file offset (`.data`'s `0x078010` is not contiguous with `.rodata`'s file end `0x070bc4`, so a contiguous read would silently be wrong). |
| "Continue rejecting unexpected loadable sections, overlaps, arithmetic overflow, header-slot occupation, and images crossing into `FLASH_FS`" (Work 3) | **clean** — all five kept, and the header-slot test was *upgraded* from VMA to LMA, which the old code could not do. Each has a part-A case. |
| "Add no manifest or release key"; the signature "does not establish trusted release provenance" | **clean** — stated in this file and in the packer's output. |
| "Run no device, flashing, provisioning, or physical serial-port commands" | **clean.** |
| "Do not run an installer" (Checks) | **clean** — `ckcc upgrade` printed, never invoked. |
| "Do not commit or push unless requested" | **respected as scoped.** The implementer left everything uncommitted. The orchestrated run's close-out step is the request; one commit, no push. |
| "Preserve dated measurements/retractions in existing project documents" (Work 7) | **clean, independently re-checked.** Every existing dated retraction survives in its original `**this read X until YYYY-MM-DD**` form; the six new figures use the same form. `AUDIT-2026-09-10.md` untouched. |
| "Those figures are a reproduction clue, not values to hardcode" (Work 1) | **clean** — see the global row. |
| "Inspect repository instructions and `git status` before editing; preserve user changes" | **clean** — `?? prompts/` preserved. One real incident, disclosed: `tools/__pycache__` was deleted mid-task and two `.pyc` files in it turned out to be **tracked**; they were restored with `git checkout -- tools/__pycache__`, `git status --porcelain tools/__pycache__` is now empty, and `tools/test-pack-signed.py` sets `sys.dont_write_bytecode` so the import cannot re-create a third. |
| "prefer source over stale prose" (Read first) | **clean** — every README figure the change touches was re-measured from the ELF and the artifacts, and the stale "sum of its section sizes" sentence was removed rather than reworded. |

## CONFIRMED findings and their disposition

Three review agents ran: a verifier, a read-only cheat-hunter, and an independent re-runner.
Ten CONFIRMED findings in total. **Nine fixed, one open.**

| # | CONFIRMED finding | raised by | fixed by the repair? |
|---|---|---|---|
| 1 | "Task 01 is entirely unimplemented: the packaging command still aborts on the exact defect it was asked to repair" (`tools/pack-signed.py:246-249`, exit 1) | verifier | **yes** — `geometry()` replaced the sum assumption; step 2 exits 0 in all three passes |
| 2 | "Both `checkfw` checks in the Checks block exit 2 because the artifacts were never produced" | verifier | **yes** — both artifacts exist; both checks exit 0 with `ACCEPT — 12/12` |
| 3 | "The mandatory deliberate-failure cases do not exist, so neither the corrupted-signature nor the invalid-layout negative case can be re-run" | verifier | **yes** — `tools/test-pack-signed.py`, 18 cases, both negatives nonzero for the named reason |
| 4 | "Reproducibility criterion is unevaluable: the repeat packaging run aborts at the same point with no bytes to compare" | verifier | **yes** — byte-identical across 6 runs and 3 agents, verified by the packer's own comparison *and* by independent `cmp` and sha256 |
| 5 | "Task 01 produced no work at all — empty diff, clean tree, unchanged HEAD" | cheat-hunter | **yes** — 2 modified + 1 new source file, 301 insertions |
| 6 | "The section-sum assertion is intact and the 4-byte gap is still present; nothing consumes `.data`'s flash LMA" (`tools/pack-signed.py:243-249`) | cheat-hunter | **yes** — `sections()` derives LMA as `p_paddr + (sh_offset − p_offset)` from the containing `PT_LOAD`; `.data` placed at `0x08080bc4` |
| 7 | "No regression coverage for an alignment gap, malformed layout, or corrupted signature was added anywhere" | cheat-hunter | **yes** — same as 3; the real 4 B gap is a part-A case (`span == 379_880` while `sum == 379_876`) |
| 8 | "The required evidence file does not exist, so any downstream Return summary for task 01 would be fabricated" | cheat-hunter | **yes** — this file |
| 9 | "No prohibition was violated, because nothing was written — reference repo and user work are untouched" (recorded as a negative result, not a defect) | cheat-hunter | **still true after the repair** — re-verified above; coldcard-firmware and all user work unchanged |
| 10 | "Claim overstates one assertion's specificity: the `checkfw` negative asserts only `REFUSE`, not the R12 signature failure it quotes" (`tools/test-pack-signed.py:174-176`) | re-runner | **NO — OPEN.** This is why the status is DEGRADED. The inaccurate sentence in *this file* has been corrected (see the table under the two negatives); the weak assertion in the test is unchanged, because the close-out agent may not edit source. One-word fix: `'REFUSE'` → `'R12'`. Breaks no acceptance criterion. |

## Residual bench-only questions — the prompt's own terms

The prompt asks for "the device-state checks still requiring a bench" and for results that
"distinguish artifact validity from unmeasured bootloader/device state". Those are these four,
and `checkfw` prints them on every run, including the two passing ones above:

- **U1** world checksum / SE1 `CHECKMAC` of `KEYNUM_firmware` (`verify.c:305,326,336`).
  Covers flash *outside* the image, so no file can satisfy it. A never-blessed image
  takes the red-light branch (`verify.c:344-347`): ~25 s delay, then boots.
- **U2** OTP min-version floor (`verify.c:143,181`), install path only, and it
  ratchets with every install already done on that unit.
- **U3** RDP level (`verify.c:340`): decides "Factory boot" vs red light, and
  whether a failed verify can still reach `enter_dfu`.
- **U4** that an install path exists at all — only `pins.c:1276-1340` from a
  logged-in MicroPython installs new firmware; `sdcard_recovery` cannot
  (`sdcard.c:248` needs SE1 to already hold this image's world hash).

Nothing above is evidence that this image boots on hardware or is safe for funds.

## Git state

`git status --porcelain` in `/Users/garykrause/repos/cold-snap` immediately before the
close-out commit:

```
 M README.md
 M tools/pack-signed.py
?? prompts/
?? tools/test-pack-signed.py
```

Staged for the commit, by explicit path only — never `git add -A`, never `git add .`:
`README.md`, `tools/pack-signed.py`, `tools/test-pack-signed.py`, and, with `git add -f`
because they live under ignored `target/`,
`target/software-only/evidence/01-repair-firmware-packaging.md` and
`target/software-only/evidence/run.json`.

Deliberately **not** staged: `?? prompts/` (pre-existing user work, left exactly as it is),
everything else under `target/` (the artifacts, the fixtures and the three passes' logs stay
ignored and uncommitted), and all four of frostsnap's pre-existing entries. frostsnap was
not touched at all, so it gets no commit. `/Users/garykrause/repos/coldcard-firmware` gets
no commit and was never written.

`tools/__pycache__/` holds two tracked `.pyc` files; they are unmodified, are not staged,
and `tools/test-pack-signed.py` sets `sys.dont_write_bytecode` so importing the packer
cannot add a third.

One honest limitation of the roll-up: a commit cannot contain its own SHA, so
`target/software-only/evidence/run.json` is committed with `"commit": null` and the real SHA
is written into it immediately afterwards, leaving that one file modified in the working
tree for the next task's close-out to carry. The SHA is reported in this task's return
value. No amend, no rewrite — the history stays one commit for this task.

## Follow-up 2026-09-24 — fix 3

- **Closed:** finding 10 (the checkfw corrupted-signature negative in `tools/test-pack-signed.py` asserted only `REFUSE`). It now asserts `[FAIL] R12 signature over double-SHA256(signed range)`; a bare `R12` would still match checkfw's `[PASS] R12` line. Mutation A (append 4 KiB, so checkfw refuses on R9 with `[PASS] R12`): new assertion exit 1, old exit 0.
- Detail, commands and mutation logs: `10-followup.md`, sections `## Fix 3 …`. Scope: software/pre-bench checks passed, for these checks only.

## Follow-up 2026-09-28 — fix 7

- **Closed:** the readiness runner's `checkfw-negative-signature` stage (the runner's copy of this task's corrupted-signature negative) matched any `[FAIL] R12 `, including R12's "range unusable" length refusal. It now requires `[FAIL] R12 signature over double-SHA256(signed range): `, copied from a real checkfw run on `fixtures/bad-signature.bin`. A self-test proves the range-unusable line comes out failed; the old pattern (M1) and a looser one (M2) both fail that test. checkfw and the R12 codes are unchanged.
- **Still open:** PLAUSIBLE only. That same line is also printed for pubkey_num != 0 and signature-parse failures.
- Detail: `10-followup.md` § Fix 7.
