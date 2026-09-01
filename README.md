# cold-snap

A Frostsnap signing device on COLDCARD Mk4 hardware.

**Status: phases 0 and 1 complete; phases 2, 3 and 4 written and host-verified,
all still unproven on silicon. Architecture decided 2026-08-12.** Frostsnap's
hardware-independent crates are vendored and verified to cross-compile for the
Mk4's exact target, Frostsnap's own crypto path no longer routes through C
libsecp256k1, and `hal/` supplies the STM32L4S5 substrate: `NorFlash` over
`FLASH_FS`, a fail-closed **2-source** `RngCore`, the bootloader callgate, a
panic handler that resets rather than halts, and — new — USB CDC over OTG_FS
carrying the `frostsnap_comms` framing. **No hardware has been touched** — the
on-silicon assumptions are listed in PLAN.md §9 and DECISIONS.md. No UI.

**The transport is written; it has never enumerated.** `hal/src/usb.rs` is a
hand-rolled OTG_FS device-mode + CDC-ACM driver and `hal/src/comms.rs` is the
frostsnap framing over it, with the two split so that everything a coordinator
controls lands in the module that has no registers in it and is therefore fully
host-testable. The frame ceiling is enforced **structurally** — the reassembly
buffer *is* `[u8; FRAME_LIMIT]`, so the bound cannot be forgotten, only deleted.
`usb.rs` was mutation-tested before being called done: 23 deliberate defects, 23
caught, 0 survivors (PLAN.md §8.2).

**A real coordinator has completed a keygen and a signature against this code, on
the host.** `hostcheck/` drives an **unmodified** sibling `frostsnap_coordinator`
against `firmware/examples/stub.rs` over a pty, in two processes: a 9-of-9 keygen,
nonce replenishment, and a signature that **verifies**, at two chunk sizes, plus a
`HeldShares2` round-trip in which all nine devices report their stored access
structure and the coordinator compares it to its own. The device side is the
SHIPPING dispatch (`coldsnap_firmware::Session`) over a `FakeFlash` at the shipped
geometry, with the keypair from `identity::load_or_create` and the nonce slots on
flash -- and mid-run it drops every signer and rebuilds them from those flash bytes,
so the coordinator finishes the keygen and the signature with devices whose
`DeviceId` was read back out of flash. What this does **not** cover
is *consent*: the stub auto-acks `SignatureRequest`, so the approval policy — the
only thing between a coordinator and a signature — has never been exercised on the
gate path.

The session hash **is** compared, and this paragraph claimed otherwise until
2026-08-27: `hostcheck/src/main.rs:1188-1217` checks every device's computed hash
against the coordinator's across two OS processes and two *different builds* of
`frostsnap_core`, and bails on a mismatch by name. What is still open is one level up
and easy to conflate with it — the comparison is **core-to-core, not
screen-to-coordinator**. Nothing asserts that the four bytes `ui::keygen_check`
actually draws are the coordinator's, and those four bytes are what a human compares.
See PLAN.md §8 phase 4 and §9 item 12.

**This firmware requires a global allocator, and does not register one.** A library
must not — registering one would silently override the future `main`'s choice. The
requirement was proven by a `staticlib` link, which is the only build shape that
surfaces it (PLAN.md §9 item 7). Both `frostsnap_comms` decode legs are now bounded:
**8,192 B outer** and **20,480 B inner**, against the vendored 32 KiB that governed
both before — and the vendored constant itself has since come down to the same
20,480, so one number bounds both.

**That ceiling was 2,060 and is now 4,096 — a documented reversal, DECISIONS.md 7.**
Enforcing 2,060 refused FOUR real messages. Re-measured against the actual
`ReceiveSerial` framing rather than the message body (which is what earlier drafts
of PLAN.md §7 measured, understating everything by the envelope, 36 B upstream /
34 B downstream): a `SignatureShare` carrying a full 30-nonce replenish is
**2,105 B** for even one share; an inbound `RequestSign` crosses 2,060 at **11
owned inputs (2,238 B)**; keygen `CertifyPlease` at **9-of-9 is 2,179 B** — it is
`195·n + 33·t + 127`, so the largest configuration that fitted was 8-of-8 — and
`HeldShares2` at **14 stored shares (2,215 B)**, which the *device itself* emits, so
that one was not even coordinator-provoked. 2,060's provenance is Coldcard's **HID**
reassembly buffer, not a CDC or `frostsnap_comms` constraint, and a bound borrowed
from another transport's framing that refuses the protocol's own traffic is not a
security property.

**4,096 rather than 3,072** because 3,072 fails `RequestSign` at 20 owned inputs /
3 outputs (**3,944 B**), which is inside the declared envelope. (Earlier drafts
cited a two-segment `NonceResponse` at 4,038 B "which the coordinator can force";
that rested on a claim that the coordinator never splits nonce streams, which is
**false** — corrected 2026-08-19, PLAN.md §7 cap 1.) The declared envelope is **n ≤ 12
devices at any t ≤ n** (12-of-12 = 2,863 B, 1,233 spare); n ≥ 13, >20 owned inputs
and ≥3 nonce segments are out of scope and are refused. Both pinning tests were
updated to the new number rather than deleted — one of them now asserts the
opposite of what its old name said, so it was renamed — and the four newly-admitted
sizes are pinned by a test, so the reversal's justification is executable rather
than prose. **4,096 is necessary but not sufficient:** three device-side
construction caps (one nonce segment per frame, a `HeldShares2` cap, `Debug`
truncation) are **REQUIRED and UNIMPLEMENTED**, because they live in
message-construction code that does not exist yet — without them the device can
still build a frame over any bound. PLAN.md §7.

**Phase 2 is not signed off.** An adversarial review of the substrate found 9
defects, including two that a passing test suite could not have caught: a
`FLASH_SR` ordering bug where one transient fault wedged all later flash writes
permanently, and a `DBANK` geometry check that had **zero callers** and so never
ran — which at `DBANK == 0` would have destroyed both copies of an A/B nonce slot
while reporting success. `flash.rs` had no tests at all; six deliberate mutations
to it left the whole suite green.

Re-verifying the earlier panic-site work then found **3 more**, in the vendored
tree rather than the HAL — so the register is a record of what has been looked at,
not a bound on what is there. The one that matters most is not a panic at all:
`TransactionTemplate::fee()` summed wire-supplied values with `sum::<u64>()`, and
since `overflow-checks = false` in the shipped profile made the wrap silent while
`cargo test` left it on, the same coordinator message *panicked* in tests and
*wrapped* in firmware — where the wrap let an invalid transaction past the
device's only arithmetic validation of it, pre-consent. A second would have made
phase 5's sign-approval screen reset-loop on an ordinary OP_RETURN output.

All 12 are now addressed, and as of 2026-08-17 the whole tree **compiles and its
268 host tests pass** — the flash fixes and the vendored ones were written in
sessions with no working shell, so until then they were verified by reading only.
The full register is **PLAN.md §8.1**, with phase 3's mutation register at §8.2.
What still blocks the gate is now hardware, not the toolchain: nothing here has run
on silicon.

See **[DECISIONS.md](DECISIONS.md)** for the seven settled architectural choices —
including the fact that C libsecp256k1 **remains** in the graph because
rust-bitcoin is retained, and that "panic → DFU" is impossible on production
hardware and is now "panic → system reset".

Note that the "3 independent entropy sources" this project was originally scoped
around **does not exist**: SE1's RNG is fed 20 bytes of our own STM32 TRNG
(`ae.c:1332`) so it is not independent, and SE2's `se2_read_rng` returns a *static*
page (`se2.c:1341-1343`) so it is not entropy at all. The count is 2, with SE2
reclassified as fixed personalisation. PLAN.md §5.1.

See **[PLAN.md](PLAN.md)** for the architecture, the three walls (display, root
of trust, brick risk), and phasing.

## Build

```sh
cargo build --release
```

The target defaults to `thumbv7em-none-eabihf` via `.cargo/config.toml`.
Requires the Rust 1.88.0 toolchain (pinned in `rust-toolchain.toml`) plus clang
for `secp256k1-sys`, which `cc-rs` builds from C.

```sh
rustup target add thumbv7em-none-eabihf --toolchain 1.88.0
```

`.cargo/config.toml` points `CC_thumbv7em_none_eabihf` at Homebrew's clang. On
a system without it, either install `arm-none-eabi-gcc` or adjust the path.

A C compiler **is required and will stay required**: `bitcoin` 0.32.8 declares
its `secp256k1` dependency non-optionally, so `secp256k1-sys` and `cc-rs` are in
the graph for as long as rust-bitcoin is retained (decision 4). Dropping
`libsecp_compat_0_29` did *not* remove them — verified by pointing `CC` at a
nonexistent path afterwards, which still fails inside cc-rs.

## Test

Host tests need an explicit `--target` to override `build.target`, and explicit
features because the vendored manifests set `default = []`. **`cargo test
--workspace` does not compile** — one test target
(`frost_backup/tests/descriptor_match.rs`) wants `frostsnap_coordinator` and
`miniscript`, neither vendored.

Measured 2026-08-19 after bounding both decode legs and pinning the vendored
budget, all passing, **268 total**:

```sh
T=aarch64-apple-darwin
cargo test --target $T -p frostsnap_macros                              #   7
cargo test --target $T -p frostsnap_embedded --features std             #  17  (15 without std)
cargo test --target $T -p frostsnap_comms    --features coordinator     #  10
cargo test --target $T -p frostsnap_core     --features coordinator     #  63
cargo test --target $T -p coldsnap_hal --features fake-flash,test-seam   # 219
cargo test --target $T -p coldsnap_firmware                              #  36  (22 lib + 14 bin)
cargo test --target $T -p frost_backup --lib --test proptest \
  --test specification_tests --test recovery_tests --test error_handling \
  --test checksum_statistics                                            #  19
```

Note that a bare `for cmd in ...` loop over those argument strings does **not**
work in fish — it does not word-split variables, so each string arrives as one
argument and five of the six crates report a silent zero. Run them literally.

`frostsnap_core` went 51 → 63 and `coldsnap_hal` 60 → 88 over the phase-2 review,
then 88 → 137 in phase 3 (+18 `comms.rs`, +31 `usb.rs`), then → 143 with the
`Link::poll` property tests and the vendored-wire round trip, then → **145** with
the two `comms` tests decision 7's `FRAME_LIMIT` reversal added, then → **148**
with the three that pin `DECODE_ALLOC_LIMIT` (PLAN.md §9 item 7(c)), then → **151**
with the three inner-leg `decode_body` tests, then → **152** with the pin on the
vendored `MAX_MESSAGE_ALLOC_SIZE` (§9 item 7(d)), then → **171** with `identity.rs`
(18 lib + 1 integration: the flash-backed device secret);
`frostsnap_embedded`'s no-std count went 7 → 15, which is the more interesting
number because those are the A/B-write and nonce-slot tests and they are the ones
that run in the configuration the firmware actually uses.

Beyond the unit tests, `hostcheck/` (its own workspace) runs a real
`frostsnap_coordinator` against real `comms.rs` framing over a pty in two
processes — the coordinator holds the pty SLAVE, `firmware/examples/stub.rs` the
MASTER as its fd 0/fd 1. Build the stub binary first; `cargo run` exits 0 only if
the coordinator itself verified the signature and every device's held share:

```sh
cargo build --target $T -p coldsnap_firmware --example stub
(cd hostcheck && cargo run)   # prints "M1+M2+M3+M5 PASS: ..."; failures name the state
```

One more gate, and it is the last one before a bench: `firmware/examples/checkfw.rs`
asks whether the Mk4 bootloader's `verify_firmware()` would ACCEPT a packaged
artifact. Run it on whatever the packaging step emitted (raw `signit.py` output or
a `.dfu` — it walks DfuSe to the element at `0x0802_0000` the way
`mk4-bootloader/sdcard.c:156-205` does), every time that artifact changes:

```sh
cargo run --target $T -p coldsnap_firmware --example checkfw -- <artifact>
# exit 0 accept · 1 refuse · 2 usage · 3 self-test failed
```

It checks 12 rules, each printing `expected -> actual [verify.c:NNN]`, and it
prints the four rules it CANNOT check (SE1 world checksum, OTP min-version, RDP
level, whether an install path exists at all) on every run including a passing
one — an "ACCEPT" here is not a boot guarantee. The signature check is the
valuable one: it reuses `coldsnap_firmware::firmware_digest` for the signed range
and adds only the outer SHA-256, so there is exactly one implementation of that
range in the tree. Before it reports anything it re-verifies a known-good vector
taken from Coldcard's own released Mk4 6.3.5X image (also `pubkey_num=0`) and
aborts with exit 3 if that fails; it was validated by running it against that
whole image, not just against our own output.

`cargo clippy --all-targets` and `cargo doc` are clean on both `coldsnap_hal` and
`frostsnap_core`. Note `cargo doc -p coldsnap_hal` needs `--features fake-flash,test-seam`
or intra-doc links into the test double and the entropy seam dangle, and `cargo doc -p
frostsnap_core --features coordinator` needs `--target $T` for the same
`build.target` reason the tests do.

Note `coldsnap_hal` needs `--features fake-flash,test-seam` for its `tests/`
directory; both are off by default so a test double or an entropy bypass can never
be linked into firmware.

`frostsnap_core` no longer needs a per-target allowlist: the two research files
that broke it wholesale were moved to `tools/research-scratch/` (see
`vendor/README.md`). `frost_backup` still does, for `descriptor_match.rs`.

`coldsnap_hal`'s 214 are 197 lib + 5 in `tests/host_smoke.rs` (target shape and
link-time invariants) + 12 in `tests/integration_frostsnap_over_hal.rs` — the only
tests in the tree that wire the **real** `frostsnap_embedded::AbSlot` /
`frostsnap_core::device_nonces` stack to the HAL's flash geometry and `Entropy`.
That file is what catches a `WRITE_SIZE`/`SECTOR_SIZE`/`RngCore`-bound mismatch,
none of which is visible to a single-module test.

**What the old count concealed, and it is the reason PLAN.md §8.1 exists.** None of
the original 44 lib tests touched `flash.rs`. Its coverage was zero, and coverage of the
register-level driver still is — six deliberate mutations to it (deleting the
containment bound, `checked_add` → `wrapping_add`, deleting the alignment check,
deleting the erase-floor guard, inverting the bank-select bit, and making
`dbank_ok` return unconditional `true`) left the entire suite green, because the
tests exercised the `FakeFlash` double rather than the driver. `flash.rs` now has
its own test module covering everything pure in it, plus a `SimPort` that models
the `FLASH_SR` error *latch* — enough to reproduce the wedge described in §8.1.
The program/erase sequence itself remains bench-only, deliberately: a host model of
`CR`/`KEYR`/`ACR` would be built from the same datasheet reading as the driver, so
agreement would prove only self-consistency.

**Phase 3 was therefore mutated before it was called written.** 23 deliberate
defects in `usb.rs`, each aimed at a specific named test, **23 caught, 0
survivors** — among them three of the four ST HAL bugs the driver deliberately does
not copy (`USB_ReadPacket`'s 3-byte overrun past the caller's buffer, the 2-bit
`USB_REQ_RECIPIENT_MASK` on a 5-bit field, and `PCD_WriteEmptyTxFifo` trusting one
`DTXFSTS` read for a whole packet). The fourth — `USB_SetDevSpeed` not clearing
`DSPD` before setting it — is in the ARM-only bring-up path and so has no host test
to fail; it is read-verified only. The mutation that stands out is "write to the TX
FIFO without checking for space": it
is caught by the *test double* asserting, which is the one thing a test double
must do — be no more permissive than the hardware it stands in for. One honest
gap: deleting `fifo_write`'s spin countdown outright **hangs** rather than fails,
because on a wedged FIFO the countdown is the only proof of termination — the same
position `flash::FLASH_SPIN_LIMIT` is in. Full list in PLAN.md §8.2.

Omitting `--features std` on `frostsnap_embedded` silently drops all
`NorFlashLog` coverage — the log used for nonce durability. See PLAN.md §7.

## Flash budget

```sh
CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target-dir /tmp/cs-flash
python3 tools/measure-flash.py '/tmp/cs-flash/thumbv7em-none-eabihf/release/deps/*.rlib'
```

LTO must be off or code is still bitcode and measures as ~0. Use a **clean,
dedicated** target dir — the live `./target` accumulates stale duplicate rlibs
that the tool's glob double-counts.

Current state against Mk4's 1,425,408-byte `FLASH_TEXT`
(`stm32/COLDCARD_MK4/layout.ld:17`):

| | Bytes | % |
|---|---|---|
| C `secp256k1-sys` (`secp-lowmemory` tables) | 96,947 | 6.8% |
| `rust-bitcoin` + encodings | 327,408 | 23.0% |
| Frostsnap + pure-Rust crypto + `coldsnap_hal` | 436,543 | 30.6% |
| **All, as built** | **860,898** | **60.4% — fits** |
| (without C `secp256k1-sys`) | 763,951 | 53.6% |

**Those are rlib sums with LTO off, i.e. upper bounds, and the gap to a real
linked image is now measured and it is large.** `firmware/` links, and
`target/thumbv7em-none-eabihf/release/coldsnap_firmware` is **298,148 B = 20.92%**
flash-resident (`.vector_table` 64 + `.text` 257,272 + `.rodata` 24,712 + `.data`
32, from `llvm-objdump -h`), measured 2026-08-25 with a real `FrostSigner` linked.
That is **3.1× smaller** than the
rlib estimate, because LTO plus `--gc-sections` drops everything unreferenced.

It is a **floor, not the budget**, and the reason is specific: nothing in `boot()`
constructs a `FrostSigner`, so keygen and signing are not referenced and the EC
math is only partly pulled in (`llvm-nm` finds 37 frostsnap/secp/schnorr symbols
and exactly **1** `rust-bitcoin` symbol against `rust-bitcoin`'s 23.0% rlib row).
The trajectory so far: 11,604 B with `boot()` polling USB but never touching
`comms` — at which point `--gc-sections` had dropped the entire workload and the
figure was bring-up overhead only — then 94,304 B once `comms::Link::poll` and
`decode_body` were wired in, then 99,684 B with `identity`, then **101,416 B** once
the identity-hold screen gave `ui`/`display` a caller (`+1,732 B`, of which
`.rodata` `+924 B` is the measured font-table cost). Seven of the eight screens are
still dropped because nothing calls them yet, then **282,080 B** once `boot()`
constructed a real `FrostSigner` and dispatched to it — a 2.78× jump, with
`rust-bitcoin` going **1 → 14** symbols and the frostsnap/secp/schnorr/bitcoin total
reaching **205**. Deleting the single `session.recv` call drops `.text` by 142,916 B
and `bitcoin` back to 1, which is how we know `boot()` is what pulls the workload in
rather than `--gc-sections` keeping it by accident. Still a floor, but a much
smaller-margin one: what remains unlinked is only the UI screens no dispatch arm
reaches yet.

That is **+16,669 (+1.2 pt) over the 844,229 phase-0 baseline**: +5,101 for the
first round of panic-site work in the vendored crates, +15,873 for the
`coldsnap_hal` rlib, and **+253 for the three `Option`-returning fixes** in
`bitcoin_transaction.rs` plus one `saturating_sub` in `flash.rs` — less −4,482 of
generic instantiations that moved out of the frostsnap rlibs into `coldsnap_hal`'s.
Every number is measured with LTO **off**, so they are upper bounds — `lto =
"fat"` collapses the duplicated monomorphisations. See `vendor/README.md` for the
per-change split.

**The whole phase-3 transport cost +3,461 bytes** (857,125 → 860,586, +0.3 pt),
which is the entire delta: `libcoldsnap_hal.rlib` went 12,098 → **15,559**
(14,606 `.text` + 953 `.rodata`) and nothing else moved. That buys `comms.rs` +
`usb.rs`, descriptors and all. The 4,096-byte reassembly buffer is not part of it:
it is SRAM, held inline in a `Link` the caller places, and nothing in this tree
places one yet. Note the real cost is **2 × `FRAME_LIMIT`**, not one: `encode_frame`
takes a `&mut [u8; FRAME_LIMIT]` as well, so the raise from 2,060 paid twice —
4,120 → **8,192 B, 1.25% of 640 KiB** (DECISIONS.md 7).

**+253 bytes is what closing three wire-reachable defects cost**, which is worth
recording because "it will bloat the image" is the usual argument for leaving an
`expect()` in embedded code. At this budget it buys 0.02 pt.

**The "+32,513 bytes" was real, and then it was reclaimed. Both figures are correct
for the tree that produced them, and the reason is worth more than either number.**

`comms::decode_body` made `coldsnap_hal` the first ARM caller of the
`CoordinatorSendBody` decode tree, which took `libcoldsnap_hal.rlib` from 15,565 to
**48,062 B** and the image to **893,099 B (62.7%)**. Lowering the vendored
`MAX_MESSAGE_ALLOC_SIZE` from `1 << 15` to **20,480** — the same value as
`comms::ENCAPS_DECODE_LIMIT` — then took the rlib back to **15,873 B** and the image
to **860,898 B (60.4%)**. Net cost of bounding both decode legs: **+312 bytes.**

The mechanism, confirmed by experiment rather than inferred: `bincode`'s `Limit<L>` is
a **const generic**, so a config's limit is part of its *type*. While the vendored
constant was 32,768 and ours was 20,480, `BINCODE_CONFIG` and `ENCAPS_CONFIG` were
two different types, and the entire `CoordinatorSendBody` decode tree was
monomorphised **twice** — once per limit, ~32 KB each. Making the two constants equal
collapses them into one instantiation.

Reproduce it in one step: set `MAX_MESSAGE_ALLOC_SIZE` back to `32_768`, rebuild into
a clean target dir, and the image returns to 893,099 with the hal rlib at 48,062;
restore 20,480 and it returns to 860,898 / 15,873.

Two consequences worth carrying. **Aligning that constant is worth 32,201 bytes of
flash**, which is a second and previously unstated argument for the change beyond the
tighter bound. And **a differing const-generic limit silently duplicates every
monomorphisation downstream of it** — so introducing a third distinct limit would cost
another ~32 KB, which is the reason `ENCAPS_ALLOC_CEILING` tracks
`ENCAPS_DECODE_LIMIT` by reference instead of restating a number.

An intermediate note here claimed this growth "does not reproduce" and blamed a dirty
target dir. That was wrong: both measurements were taken in clean dedicated dirs and
both reproduce exactly: the *tree* changed between them, not the measurement. The
retraction has itself been retracted.

What survives the retraction is the *generalisation*, which was sound and is worth
keeping on its own evidence (the allocator discovery, PLAN.md §9 item 7): **an
rlib-only build hides a cost until something concrete calls it.** What does not
survive is this instance of it. Headroom is **564,510 B**.

**It fits.** `bitcoin`'s `secp-lowmemory` feature sets `ECMULT_WINDOW_SIZE=4`
and `ECMULT_GEN_PREC_BITS=2`, shrinking the C library 92% (1,177,733 → 96,947)
with no source changes. Without it the build is 135% of `FLASH_TEXT` and does
not link. The tradeoff is slower EC math; **signing latency is unmeasured** — see
PLAN.md §9, "Genuinely open". It is the highest-value remaining unknown: a bad
answer partly reopens decision 4, and it cannot be settled on the host.

Dropping `schnorr_fun`'s `libsecp_compat_0_29` (decision 3) is **done**, and it
was worth far less than earlier drafts of this file claimed: **−1,185 bytes**
(845,414 → 844,229), **not −97 KB**, and it removed neither `cc-rs` nor the C
toolchain requirement. What it did remove is `secp256kfun` as a consumer of C
libsecp256k1 — `cargo tree -i secp256k1@0.29.1` now shows `bitcoin` as the sole
parent. See `vendor/README.md` and DECISIONS.md decision 3.

## Packaging: ELF → signed artifact

```sh
python3 -m venv target/pack-venv && target/pack-venv/bin/pip install ecdsa click  # once
python3 tools/pack-signed.py                     # re-execs into that venv itself
```

One command, every byte printed. Writes `target/pack/firmware-signed.bin`
(299,008 B, raw image at `0x08020000`) and `target/pack/coldsnap-6.0.0cs.dfu`
(299,317 B). **It flashes nothing** and writes only under `--out`.
Numbers below are from a real run against the release ELF (551,260 B).

**Two `llvm-objcopy` runs, never one.** `-j .vector_table` → 64 B;
`-j .text -j .rodata -j .data` → 282,016 B. A single whole-ELF dump zero-fills the
16 KiB hole between `.vector_table` and `.text`, where signit's own padding is
`0xff`. The tool proves no fill happened by comparing each flat file against the
sum of its section sizes — widening the `-j` list to span the gap aborts with
`objcopy gap-filled +16320 B`. It also aborts if the ELF ever grows a
flash-resident section it does not know about, since objcopy would drop it
silently.

**The 256 KiB floor is already cleared, so padding is alignment-only.** Body
282,016 B ≥ `FW_MIN_LENGTH` 262,144 B by 19,872 B. `align_to(282016, 512)` =
282,112 (+96), then `align_to(282112, 4096)` = 282,624 (+512) — Mk4/Mk5 take the
4 K branch (`cli/signit.py:302-306`, `verify.c:106`), *not* the 512 that
`memmap::FW_BODY_ALIGN` records. 608 B of `0xff` in total, plus 16,192 B of `0xff`
after the vectors. `firmware_length = 16,256 + 128 + 282,624 = 299,008 (0x49000)`
= 73 × 4096 — a **total** measured from `0x08020000`, header and vector region
included, not a body length.

**The header is not emitted by our build, and must not be.** `link.x` shrinks
`FLASH_ISR` to `0x3F80` so nothing can grow into the slot, and
`cli/signit.py:315-325` builds all ten fields at pack time — two of them (the
wall-clock BCD `timestamp`, and the `signature` over the other 63 header bytes)
are unknowable at link time. So the pre-flight assertion is that **no section
covers `0x08023F80..0x08024000`**; if one ever does, the tool aborts rather than
guess whether the slot is unpatched or already filled (a faked overlap aborts with
`section(s) ['.text'] cover the header slot`). Fields written: magic `0xCC001234`,
timestamp, `6.0.0cs`, `pubkey_num=0`, length, `install_flags=0` (never
`FWHIF_HIGH_WATER`, which is an OTP ratchet), `hw_compat=0x28` (Mk4|Mk5), zeros —
then the signature. All nine non-signature fields are read back out of the
finished artifact and compared against what was requested.

**Reproducible and idempotent.** The header format demands a timestamp, so it is
frozen to the ELF's mtime (override with `--epoch` or `SOURCE_DATE_EPOCH`) and
ECDSA is forced to RFC6979, which makes two runs byte-identical; a rerun compares
against the previous output and aborts if it differs. Handed an already-signed
`.bin` or a `.dfu` it refuses ("ALREADY a signed artifact") instead of
double-signing.

**It verifies before it claims anything.** Independent double-SHA-256 over
`[0,0x3fc0) + [0x4000,firmware_length)` (`verify.c:80,83-84`), both `0xff` padding
regions byte-checked, then `signit check` run in-process — and it aborts unless
that prints `ECDSA Signature: CORRECT`, agrees with the independently computed
digest, and decodes back the exact timestamp requested. Exit 0 means all of that
held; any failure exits 1 with `ABORT (…)` naming what and where.

**It refuses a stale ELF.** If anything under `firmware/src`, `hal/src` or
`firmware/link.x` is newer than the ELF it aborts and tells you to
`cargo build --release` — same class of bug as the harness that once certified a
stale stub. `firmware/examples` is excluded (examples do not link into the bin) and
so is `Cargo.lock`, which cargo touches on every build in every lane.

Version `6.0.0cs` is not cosmetic: `check_is_downgrade` (`verify.c:169-177`)
refuses `major < 3` at install time, so a `--fw-version` like `1.2.3` is rejected
up front.

Delivery is `ckcc upgrade target/pack/coldsnap-6.0.0cs.dfu` through **stock**
firmware after PIN login. The SD-card path is not a delivery route: `sdcard.c:248`
CheckMacs the world digest against SE1 and prints "wrong world" for any image not
already blessed there. Key 0 is the published dev key (`stm32/keys/00.pem`,
byte-identical to `approved_pubkeys[0]`), which costs a warning screen — ~25 s on a
release bootloader — and then boots. Every claim here about on-device behaviour is
source-reading only, **unverified on silicon**; and before touching a unit,
establish whether it is at RDP=2, because at RDP < 2 a failed verify still reaches
`enter_dfu()` and is recoverable.

## Layout

```
DECISIONS.md          the seven settled architectural choices (2026-08-12; 7 is
                      the FRAME_LIMIT reversal, 2026-08-18)
PLAN.md               architecture and phasing
hal/src/              coldsnap_hal — the entire hardware surface:
  callgate.rs           the blx into the PCROP bootloader
  comms.rs              frostsnap framing, bounded and gated (no registers)
  flash.rs              NorFlash over FLASH_FS
  display.rs            SSD1306 128x64 over SPI1 — unverified-on-silicon in full
  ui.rs                 the 1,024 B MONO_VLSB framebuffer and the eight screens of
                        PLAN.md §4.2. No registers, so every screen is host-testable
                        AND host-renderable: see examples/ui_render.rs
  identity.rs           the durable device secret in FLASH_FS: generated once from
                        `Entropy`, never regenerated; corrupt or ambiguous REFUSES
                        rather than re-identifying (a new DeviceId orphans shares)
  heap.rs               the measured heap budget: consts only, no allocator
                        registered and no placement yet (PLAN.md §9 item 7)
  panic.rs              panic -> NVIC_SystemReset, RTC-backed reset counter
  rng.rs                fail-closed 2-source RngCore
  singleton.rs          the take-once guard flash/rng/usb share
  usb.rs                OTG_FS device mode + CDC-ACM (no protocol knowledge)
  examples/heap_profile.rs  the heap measurement behind heap.rs; host-only
  examples/ui_render.rs     every screen and page as ASCII + BMP, for layout review
                            with no hardware: cargo run -p coldsnap_hal --example ui_render
firmware/             coldsnap_firmware — the bin crate that LINKS. Owns the vector
                      table, the entry point, `link.x` (11 live ASSERTs) and the
                      only registered `#[global_allocator]`. ARM-only; `boot()` is
                      `cfg(target_arch = "arm")`, so its 14 tests cover the host-
                      testable half only.
hostcheck/            the harness's COORDINATOR side. Its OWN workspace, and it
                      Its module header is the harness's measurement + mutation record.
                      must stay that way: one cargo graph cannot hold both
                      coldsnap_hal and upstream frostsnap_coordinator (lockfile
                      package collision on frost_backup). Needs a sibling
                      ../frostsnap checkout. 133 std crates that the ARM build
                      never sees.
vendor/frostsnap/     upstream crates @ 0bbc18be (MIT), see vendor/README.md
tools/measure-flash.py
tools/pack-signed.py  ELF -> signed, bootloader-acceptable artifact, one command.
                      Prints every step and byte count, verifies what it produced,
                      flashes nothing. See "Packaging" above.
tools/research-scratch/  wire-size and decode-allocation measurements; not part of
                      any build. Each file carries its own copy-in/run/delete
                      commands and provenance caveats -- read those before quoting.
```

There is no bin target, no entry point and no linker script yet: the workspace
builds rlibs only. The `usb.rs` ⇄ `comms.rs` composition is three lines and lives
in a test rather than in an event loop for that reason.

## Licensing

Vendored Frostsnap code is MIT (`vendor/frostsnap/LICENSE`). Coldcard firmware
is MIT, but `hardware/` in that repo is proprietary and not licensed for
commercial use — relevant if this ever targets custom boards.

Installing custom firmware on a Coldcard requires signing with the published
key zero and carries a permanent warning screen and forced boot delay. A crash
before the login path completes **bricks the device**; see PLAN.md §6.

Note that DFU is **not** a recovery path on a production unit: `enter_dfu` is
gated on flash readout protection, not on the PIN, and returns `EPERM` at RDP=2
(`stm32/mk4-bootloader/dispatch.c:150-165`), where the bootloader's own
`enter_dfu()` locks up rather than trying (`main.c:256-258`). PLAN.md §6.1.
