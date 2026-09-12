# cold-snap

A Frostsnap signing device on COLDCARD Mk4 hardware.

**Status: phases 0 and 1 complete; phases 2, 3, 4 and the mono UI written and
host-verified, all still unproven on silicon. Architecture decided 2026-08-12.**
Frostsnap's hardware-independent crates are vendored and verified to cross-compile
for the Mk4's exact target, Frostsnap's own crypto path no longer routes through C
libsecp256k1, and `hal/` supplies the STM32L4S5 substrate: `NorFlash` over
`FLASH_FS`, a fail-closed **2-source** `RngCore`, the bootloader callgate, a
panic handler that resets rather than halts, USB CDC over OTG_FS carrying the
`frostsnap_comms` framing, the 4×3 membrane keypad, and all eight PLAN.md §4.2
screens over a 1,024-byte `MONO_VLSB` framebuffer. `firmware/` is the bin target
that links them: a vector table, a reset entry that sets `VTOR`, a registered
`#[global_allocator]`, and an event loop. **No hardware has been touched** — the
on-silicon assumptions are listed in PLAN.md §9 and DECISIONS.md.

**This paragraph ended "No UI." until 2026-09-10.** That was wrong, and had been
for weeks: `hal/src/ui.rs` is 5,541 lines rendering every §4.2 screen, and PLAN.md
§9 item 16 recorded the UI as fully linked — all eight screens with real callers —
on 2026-09-10. The status line also said "phases 2, 3 and 4", omitting the UI,
the keypad and the bin target entirely.

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
`DeviceId` was read back out of flash.

**Consent is exercised on the gate path, and this paragraph denied it until
2026-09-10.** It read "the stub auto-acks `SignatureRequest`, so the approval
policy — the only thing between a coordinator and a signature — has never been
exercised". Both halves are false. `firmware/examples/stub.rs:499` gates
`SignatureRequest` on `digit.accepts(key)`, where the digit is a fresh randomised
`ui::ConfirmDigit` drawn on the very frame the consent answered (`stub.rs:466-489`)
and the key comes back from `advertised_key()` reading it out of the rendered
pixels (`stub.rs:405-417`) — so a script cannot answer without having read the
screen correctly, which is what makes the check structural rather than bolted on.
And `hostcheck` runs a **third pass** on every invocation in which every device
presses `x` at the signing screen (`hostcheck/src/main.rs:776`), failing the run if
a declined prompt ever yields a signature share (`:1520`, `A DECLINED PROMPT
PRODUCED A SIGNATURE`). Measured this session: `all 9/9 device(s) pressed \`x\` at
the signing screen and NOT ONE signature share reached the coordinator`.

Since 2026-09-11 **every** consent screen asks for the randomised digit, including
the keygen check. It used to print `1=match` and accept a fixed `key == b'1'`, on the
reasoning that the strong gesture belonged to the screens that move money — which had
it backwards, because the measure that picks a confirm key is how much a script can
fake, and by that measure the anti-MITM screen was the weakest one on the device.
`ui::keygen_check` now takes a `ConfirmDigit`; `KEYGEN_MATCH_KEY` is gone. Shown with
no source change: `COLDSNAP_GLASS_KEYS=1yy` now exits 1 with 8 of 9 devices declining
(the ninth happened to draw `1` — the 1-in-5, made visible), and `=9yy` with 9/9. The
one half no host test can supply is still a *person* reading the screen.

The session hash **is** compared, and this paragraph claimed otherwise until
2026-08-27: `hostcheck/src/main.rs:1414-1444` checks every device's computed hash
against the coordinator's across two OS processes and two *different builds* of
`frostsnap_core`, and bails `SESSION HASH MISMATCH` by name. **The
screen-to-coordinator half is closed too, since 2026-08-31, and this paragraph
denied that until 2026-09-10** — it claimed "nothing asserts that the four bytes
`ui::keygen_check` actually draws are the coordinator's". `stub.rs::glass_code()`
reads those four bytes back off the same `ui::Frame` the consent answered, using the
shipped `ui::Frame::cell_2x` rather than a second copy of the mapping, and reports
them on the existing wire as a `Debug` line; `hostcheck/src/main.rs:1465-1481`
requires all nine devices to have reported and bails `GLASS CODE MISMATCH: <id>
RENDERED <x> on the screen a human reads aloud, but this coordinator's session hash
starts <y>`. See PLAN.md §8 phase 4 and §9 item 12.

Also asserted, and previously undocumented here: `hostcheck` forges a
`CoordinatorSendBody::DataErase` at every device mid-run and fails unless all nine
**refuse** it and can still sign (`hostcheck/src/main.rs:1239-1265,1484-1490`).

**This firmware requires a global allocator and registers exactly one, in the bin
crate.** `firmware/src/alloc.rs:238` is `#[cfg_attr(target_os = "none",
global_allocator)]` over `linked_list_allocator` 0.10.6 on a 64 KiB static arena,
brought up by `alloc::init()` at boot step 5 (`firmware/src/main.rs:1269`), after
`.bss` and `.data`. It is target-gated so the host test build keeps the harness's
own allocator. The arena is measured into `.bss`, not `.uninit`: `llvm-nm` puts
`ALLOCATOR` at `0x2000_8038`, 65,564 B, which is all but 8 bytes of the 65,572-byte
`.bss` — so it costs zero flash and its ready-sentinel is zeroed by the entry's
`.bss` loop for free. `hal/src/heap.rs` stays constants-only; a *library* must not
register one, because that would override the binary's choice.

**This paragraph read "and does not register one" until 2026-09-10**, as did
README's own Layout block entry for `heap.rs`, while the Layout block eleven lines
further down already credited `firmware/` with "the only registered
`#[global_allocator]`" — the same file asserting both. Verified by mutation:
deleting the attribute fails `cargo build --release` at exit 101, `error: no global
memory allocator found but one is required`. The original requirement was proven by
a `staticlib` link, which is the only build shape that surfaces it for a library
(PLAN.md §9 item 7). Both `frostsnap_comms` decode legs are now bounded:
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
than prose.

**All three device-side construction caps are implemented, and this paragraph
called them "REQUIRED and UNIMPLEMENTED" until 2026-09-10.** They live in
`Outbox::push` (`firmware/src/lib.rs:422`), which is the message-construction code
the old text said "does not exist yet" — it does, along with the event loop and the
bin target it claimed were absent. Cap (a): a multi-segment `NonceResponse` is split
one frame per segment, so the four streams the flutter coordinator asks for come
back as four frames instead of one ~8 KB frame the encoder would refuse. Cap (b): an
over-large `HeldShares2` is refused **whole** as `CommsError::FrameTooLong`, never
truncated — dropping shares from a restoration reply would tell the coordinator a
share does not exist, which is a data-loss-shaped lie. Cap (c): `Debug` is cut to
`DEBUG_MESSAGE_LIMIT` = 256 B on a UTF-8 boundary, because `String::truncate` off a
boundary panics and a panic here is a brick. All three are mutation-tested — see
PLAN.md §7.

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

All 12 are now addressed, and the whole tree **compiles and its 565 host tests
pass** (re-measured 2026-09-10; **this read 268 until then**, which was the
2026-08-19 figure and never counted `coldsnap_firmware` at all) — the flash fixes
and the vendored ones were written in
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

Re-measured 2026-09-10, all passing, **565 total** = `coldsnap_hal` 284 +
`coldsnap_firmware` 165 + vendored 116. **This headline read "268 total" until
2026-09-10** while the per-crate lines beneath it had been updated in place and
already summed to 565 — a stale headline over a current breakdown, in one paragraph,
which is the exact shape README's "Flash budget" section carried a `372,688 B`
headline in:

```sh
T=aarch64-apple-darwin
cargo test --target $T -p frostsnap_macros                              #   7
cargo test --target $T -p frostsnap_embedded --features std             #  17  (15 without std)
cargo test --target $T -p frostsnap_comms    --features coordinator     #  10
cargo test --target $T -p frostsnap_core     --features coordinator     #  63
cargo test --target $T -p coldsnap_hal --features fake-flash,test-seam   # 284  (267 lib + 5 + 12)
cargo test --target $T -p coldsnap_firmware                              # 165  (114 lib + 51 bin)
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
the coordinator itself verified the signature and every device's held share.

Since 2026-09-11 it also drives the **restoration flows** from upstream's own
`UiProtocol` drivers — the backup reveal, the check quiz, the physical-backup ingest
and the consolidation — with the assertions taken off the device's FRAMEBUFFER rather
than off its say-so: the 25 words its reveal draws are read back with the shipped
`ui::Frame::cell` and re-encoded through upstream's `ShareBackup::from_words` to be
compared against the coordinator's own expected share image, and the quiz is answered
only from what that reveal showed.

The same day it also closed **naming** — a coordinator-previewed name, 14 chars and 56
bytes at once so it sits on the wire bound and the flash bound simultaneously, reaches
flash on all nine devices and comes back byte-exact as `SetName` — and **`erase_device`**,
where upstream's own driver is now proven never to complete against a device that
refuses `DataErase` outright.

**This said "every flow the device implements is now driven by a real coordinator" until
a review falsified it**, and the exception is worth naming rather than rounding off:
`Session::recv` also admits `CoordinatorSendBody::Cancel`, which is not a stub — it
clears `clear_tmp_data`, the previewed name, and the reveal, recorded-question, entry and
quiz grants, six security-relevant pieces of state whose whole point is that a cancelled
ceremony acks nothing. No harness sends it, so none of that is exercised. The legacy
`SavePhysicalBackup` (v1) is admitted and undriven too; only `SavePhysicalBackup2` is.
See PLAN.md §9 item 12 for what each driven flow does and does not prove.

```sh
cargo build --target $T -p coldsnap_firmware --example stub
(cd hostcheck && cargo run)   # prints "M1+M2+M3+M5+M7 PASS: ..."; failures name the state
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

Both of those run for the HOST, so neither ever sees the 181
`cfg(target_arch = "arm")` blocks (re-measured 2026-09-10 — usb 88, flash 22,
`firmware/src/main.rs` 15, panic 13, callgate 11, keypad 8, display 8, rng 6,
`firmware/src/lib.rs` 4, `firmware/src/entry.rs` 4, `hal/src/lib.rs` 1, `ui.rs` 1;
**this read 169** on the 2026-09-08 count. The count moves, the gate
does not care — it is a whole-target compile). These two do (PLAN.md §9 item 22). They are the
cheapest gates in the project — measured 2026-09-08: **8.2 s** from a genuinely empty
`CARGO_TARGET_DIR`, **2.5 s** after touching `hal/` or `firmware/`, **0.21 s** warm —
because clippy only emits metadata, so it never pays codegen or LTO:

```sh
cargo clippy --release --target thumbv7em-none-eabihf \
  -p coldsnap_hal -p coldsnap_firmware 2>&1 | grep -cE "hal/src|firmware/src"   # 0
cargo doc --release --target thumbv7em-none-eabihf -p coldsnap_hal \
  --features fake-flash,test-seam --no-deps 2>&1 | grep -cE "^warning"          # 0
```

A **third** device line, added 2026-09-09. Note the missing `--release` — that is
the entire point, and it is not a typo:

```sh
cargo clippy --target thumbv7em-none-eabihf \
  -p coldsnap_hal -p coldsnap_firmware 2>&1 | grep -cE "hal/src|firmware/src"   # 0
```

Cost **4.4 s** warm, measured 2026-09-09, and it passes clean today. It is the only
gate here in which const-eval runs with `overflow-checks` **on**, so it is the only
one that can see a `usize` overflow that exists only at 32 bits. The release profile
sets `overflow-checks = false`, and in const-eval that does not merely skip a check —
**it wraps**, silently, whenever the arithmetic is inside a `const fn` body. Measured
three ways: a `pub const fn scale(n: usize) -> usize { n * 4 }` called as
`scale(0x4000_0000)` returns **0** under `--release`, so `assert!(scale(..) > 0)`
fails on its own logic rather than on the overflow, and `const _: [(); 0] = [(); V]`
type-checks and **exits 0**. The same expression under the dev profile is
`error[E0080]: attempt to compute 1073741824_usize * 4_usize, which would overflow`,
naming the operation. At 64 bits it is 4294967296 and no host gate can ever see it.

**Proven by a planted probe, not by a passing count.** A
`pub const fn planted_probe(n: usize) -> usize { n * 100 }` plus
`const _: () = assert!(planted_probe(FLASH_SPIN_LIMIT as usize) > 0)`, inside the
existing `#[cfg(target_arch = "arm")]` block in `hal/src/flash.rs`, run on a
throwaway `git archive HEAD` copy so the live tree was never touched:

| gate | exit | `hal/src\|firmware/src` hits |
| --- | --- | --- |
| `clippy --release --target thumbv7em` (the two existing lines) | **0** | **0** |
| `clippy --target thumbv7em` (the new line) | **101** | **2** |

50,000,000 × 100 wraps to 705,032,704, which is `> 0`, so the existing gate is
clean — the probe must be `pub` and documented for this to be an honest comparison,
because a private one trips `dead_code` and the existing gate catches that instead,
for the wrong reason. With the probe removed, both gates go back to 0/0.

Three things about the two `--release` lines, each of which cost a run to learn:

- **No `--all-targets`.** Dev-dependencies (proptest → getrandom) have no
  `thumbv7em` support: 298 errors, mostly `can't find crate for std`. The library
  and binary targets are what matter here anyway.
- The `doc` line **needs** `--features fake-flash,test-seam`, for the same dangling
  intra-doc links as the host line above. Without them you get 6 spurious
  `unresolved link to fake::FakeFlash` — a feature artifact, not a device finding.
- No `--lib` is needed and no allocator problem arises. Clippy stops at
  `--emit=metadata`, so `main.rs`'s `#![no_main]`, the vector table,
  `alloc.rs:238`'s `#[global_allocator]` and `.cargo/config.toml`'s
  `-Tfirmware/link.x` never reach
  a linker. (This bullet said "the **absent** `#[global_allocator]`" until
  2026-09-10; one is registered — the point about `--emit=metadata` is unaffected.)
  Cargo prints one status line per package, so you may see
  `Compiling coldsnap_firmware` (its build script) and no second `Checking` line;
  the bin **is** checked — a planted defect is what proves that, not the log.

`cargo build --release` already catches *rustc*-level lints in `cfg`-arm code (a
planted `[0u8; 4][9]` there fails it on `unconditional_panic`, deny-by-default).
What it does not catch is anything clippy-only, which is the hole these two close.

**What these three lines do and do not execute.** They do not run any code, but they
are not purely textual either: every `const _: ()` block and every `const` initialiser
in `hal/` and `firmware/` is **const-evaluated for `thumbv7em-none-eabihf`, with
`usize` = 32 bits**, inside and outside `cfg`-arm blocks alike, because const-eval is
not optional in rustc. Verified by planting
`const _: () = assert!(size_of::<usize>() == 8)`: `--target thumbv7em` gives
`error[E0080]`, `--target aarch64-apple-darwin` compiles clean. So the **compile-time**
half of the `cfg`-arm assertions already runs at the real pointer width; what has never
run is anything **runtime** — every non-`const` register access, poll and spin limit.
See PLAN.md §9 item 22 for exactly where that line falls.

### `tools/qemu-boot.sh` — a diagnostic that has now been RUN, and still NOT a gate

```sh
brew install qemu                       # done here: qemu 11.1.1, 2026-09-09
tools/qemu-boot.sh                      # bare -kernel on the ELF      -> exit 6
SHIM=1 tools/qemu-boot.sh               # padded flat image            -> exit 6
SHIM=1 SP=0x20018000 tools/qemu-boot.sh # + a FAKE stack (see below)   -> exit 124
# MACHINE / WALL / QEMU / OBJDUMP / OBJCOPY override
```

Boots on `-machine b-l475e-iot01a` (STM32L4x5 — same family as our L4S5, so RCC and
GPIO sit at the addresses our code writes) with `-d guest_errors,unimp`, which names
every unmodelled register access as it happens. Zero new source files, no second linker
script, and `.cargo/config.toml` is untouched. `SHIM=1` reshapes the image with
`llvm-objcopy -O binary` **after** the link, never by relinking, so the ELF the signing
tools consume is unchanged — confirmed by `shasum` before and after, and structurally
guaranteed because nothing outside `tools/` was touched to add the mode.

It is **not** in the gate list and must not be added to one: it depends on a `brew
install`, and its result needs reading rather than asserting. The image emits no
semihosting output, so there is no pass criterion. **Every register result is
UNVERIFIED-ON-SILICON**, at every tier: QEMU models neither the PCROP bootloader, nor
SE1/SE2, nor the SSD1306, nor the keypad, nor OTG_FS device mode, nor the flash
programming controller, nor RDP. Do not use `netduinoplus2`: it models an
`stm32f2xx_spi` at exactly our SPI1 base `0x4001_3000`, where `CR2.DS` and `SR.FTLVL` do
not exist, so writes are accepted, `FTLVL` reads 0 and `drain()` returns `Ok` having
verified nothing.

**What the three modes actually produced, measured 2026-09-09 on qemu 11.1.1.**

*Bare* is exit **6** and that is the correct answer, not a defect: a Cortex-M reads SP
and PC from the flash base `0x0800_0000` at reset, our vector table is at `0x0802_0000`,
and the 128 KiB below it is the PCROP bootloader QEMU does not have. The core loads
`SP=0`, `PC=0` and locks up — `R13=ffffffe0`, `R15=00000000`, zero guest instructions.

*`SHIM=1`* prepends `0x20000` bytes of `0xff` carrying our SP/PC in the first 8, so the
reset fetch finds **our** table, and it proves exactly one thing: that table is well
formed and its reset entry is a valid Thumb address in our image. `R13` comes back
`2009dfe0` — our `0x2009e000` minus a 32-byte exception frame — which is only possible if
QEMU read our vector table. Then it locks up with **zero instructions retired**:

> `b-l475e-iot01a` is an STM32L475 with **96 KiB** of SRAM1, `0x2000_0000` ..
> `0x2001_8000`. Our stack top is `0x2009_e000` and our `.bss` ends at `0x2001_8058`.
> Both are outside the model, so the reset handler's first `push` faults. Probed by
> bisecting the SP word: `0x2001_8000` runs, and `0x2002_0000` and every value above it
> lock up after 4 translated instructions. **No available QEMU machine has both flash at
> `0x0802_0000` and RAM at `0x2009_e000`**, so the unmodified image's bring-up cannot run
> under any of them.

`init_hardware` therefore does **not** execute under `SHIM=1`, and the callgate is never
reached — so there is nothing to gain from parking a `bx lr` stub at `0x0800_0040` to get
past it, and none is provided. `-d in_asm` confirms it: 4 translated instructions, none
retired, and **zero** `unimp`/`guest error` lines, so nothing touched an unmodelled
peripheral first either.

*`SP=<addr>`* is **a deliberate lie**, loudly labelled at runtime, and the only setting
under which any of our instructions retire. It overwrites the shim's stack-top word so
the stack lands in the RAM this machine does model. At `0x20018000` the guest executes
the VTOR write, the CPACR write and ~64 KiB of the `.bss` zero loop at real 32-bit width
with hard-float; the loop then faults at `0x2001_8000`, past the model's SRAM and still
`0x58` short of our `.bss` top, and **that fault dispatches through the VTOR just
programmed** into `fault_trampoline`, which panics and `NVIC_SystemReset`s forever
(exit **124**). The end state is the evidence — VTOR dispatch and the panic path ran on
real widths — and the exit code deliberately stays **124** rather than becoming a pass,
because a runner that started calling 124 success would lose the ability to report a real
hang. It is not our memory map, it cannot produce a pass, and it is evidence about
nothing else.

The script's failure paths are the part that **is** verified, each demonstrated
2026-09-09 with a stub `qemu-system-arm`, because a runner that exits 0 because nothing
ran is the failure mode to rule out first: QEMU absent → **2** (prints the `brew`
line), image missing or `.text` empty → **3**, machine unknown to the installed QEMU →
**4**, QEMU exits 0 having printed **nothing** → **5**, QEMU itself exiting non-zero →
**6**, wall clock exceeded → **124**. All five stub paths were re-run in **both** modes
after `SHIM=1` was added; the two live paths (**6** bare and shim, **124** with `SP`) were
re-run against real QEMU.

`SHIM=1` adds four more ways to earn exit **3**, each proved live by mutation rather than
by inspection: no `.vector_table` section, a `.vector_table` VMA that is not a plausible
offset into a 1 MiB flash, a reset vector with bit 0 clear (an even PC takes an INVSTATE
UsageFault before the first instruction and the trace then looks like the interesting
failures), and a body that did not land at the pad offset. That last one is not
hypothetical: **BSD `tr` is locale-aware**, so `tr '\0' '\377'` without `LC_ALL=C` emits
the two UTF-8 bytes `c3 bf`, silently doubling the pad and shifting the entire body off
its link address. Deleting the `LC_ALL=C` reproduces it, and the assert — the word at
offset `PAD` must equal the word at offset 0, since both are the vector table's SP —
catches it and refuses.

**Exit 6 was added 2026-09-09 by adversarial re-verification, and it closes a real
hole**: the first cut treated *any* non-empty log as "QEMU ran and produced a trace",
but qemu's own stderr shares that log, so a stub answering `-machine help` and then
printing `qemu-system-arm: Kernel image must be loaded` and exiting **1** got
**exit 0 and the word OK** — with the guest never executing one instruction. It has since
been vindicated: exit 6 is what **both** real modes return, and without it every run of
this script to date would have printed OK. This image never calls semihosting exit,
so a run that genuinely executes ends at the wall clock; any other non-zero rc is qemu
failing. Both `-machine help` probes are now `timeout 15`-bounded as well — a stub that
hung there hung the whole script past `WALL`, since `WALL` only ever covered the guest.
The `.text` check is not paranoia: a `no_std` thumbv7em
binary whose vector table is neither `#[used]` nor `KEEP`ed links "successfully" to a
**zero-byte** `.text` under `--gc-sections`, and cargo still prints `Finished`.
`WALL` defaults to 60 s because `FLASH_SPIN_LIMIT` is 50,000,000 volatile reads, which
under TCG is tens of seconds — set it too low and a working run reads as a hang.

Note `coldsnap_hal` needs `--features fake-flash,test-seam` for its `tests/`
directory; both are off by default so a test double or an entropy bypass can never
be linked into firmware.

`frostsnap_core` no longer needs a per-target allowlist: the two research files
that broke it wholesale were moved to `tools/research-scratch/` (see
`vendor/README.md`). `frost_backup` still does, for `descriptor_match.rs`.

`coldsnap_hal`'s 284 are 267 lib + 5 in `tests/host_smoke.rs` (target shape and
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
| Frostsnap + pure-Rust crypto + `coldsnap_hal` + `coldsnap_firmware` | 475,045 | 33.3% |
| **All, as built** | **899,400** | **63.1% — fits** |
| (without C `secp256k1-sys`) | 802,453 | 56.3% |

**Re-measured 2026-09-10 in a clean dedicated target dir. The rows read 436,543 /
860,898 / 60.4% / 763,951 until then** — the 2026-08-19 measurement, taken before the
UI, the keypad, the share store, 25-word entry, the quiz and the bin crate existed.
Only the third row moved: the two C and rust-bitcoin rows are byte-identical, and the
whole +38,502 is `libcoldsnap_hal.rlib` 15,873 → **30,627** (27,636 `.text` + 2,991
`.rodata`) plus `libcoldsnap_firmware.rlib` **21,000** (18,912 + 2,088), a crate that
did not exist at the previous measurement and appears in no earlier row.

**Those are rlib sums with LTO off, i.e. upper bounds, and the gap to a real
linked image is now measured and it is large.** `firmware/` links, and
`target/thumbv7em-none-eabihf/release/coldsnap_firmware` is **377,192 B = 26.46%**
flash-resident (`.vector_table` 64 + `.text` 319,088 + `.rodata` 58,004 + `.data`
36, from `objdump -h`), re-measured 2026-09-11 in a CLEAN target dir with a real
`FrostSigner`, 25-word entry, the `CheckBackup` quiz and the keygen check's randomised
digit all linked. **This row read 376,752 B = 26.43% (`.text` 318,640, `.rodata`
58,012) until then**, which was the 2026-09-10 figure; note `.rodata` went DOWN by 8 B
as a 12-byte literal legend was replaced by a composed one, so the +440 is not a pure
addition. That is **2.4× smaller** than the
rlib estimate, because LTO plus `--gc-sections` drops everything unreferenced.
`.bss` is `0x2000_8034..0x2001_8058`, i.e. 65,572 B, of which 65,564 is the
allocator arena (`ALLOCATOR` at `0x2000_8038`) — so `.bss` is the heap plus eight
bytes, and `.uninit` is empty. (The ratio read **2.3×** against the 860,898 rlib
sum; at the re-measured 899,400 it is 2.39×.)

**Read the components, not just the headline.** Until 2026-09-10 this paragraph
carried a `372,688 B` headline over a breakdown that summed to `282,080` and a
following sentence claiming "nothing in `boot()` constructs a `FrostSigner`" — an
image and a claim several steps stale, because the headline was updated in place
and the prose beneath it was not. Every figure here is now re-measured together.

It remains a **floor, not the budget**, but the margin is much smaller than it was
and the reason has changed: `boot()` now constructs a real `FrostSigner`, so the EC
math *is* linked — `llvm-nm` finds **190** frostsnap/secp/schnorr/bitcoin symbols
(frostsnap 118, bitcoin 34, schnorr 28, secp256k1 22) and **22**
`coldsnap_hal::ui` symbols, re-measured 2026-09-10. **These read 267 and 17 until
then**, and neither reproduced: the pair is quoted identically in PLAN.md §10, so
both were carried forward rather than re-derived. What is still absent is refused,
not unreferenced (see PLAN.md §9). The trajectory, each step a real caller appearing
rather than a code addition: 11,604 B with `boot()` polling USB but never touching
`comms` — at which point `--gc-sections` had dropped the entire workload and the
figure was bring-up overhead only — then 94,304 B once `comms::Link::poll` and
`decode_body` were wired in · 99,684 B with `identity` · **101,416 B** once the
identity-hold screen gave `ui`/`display` a caller (`+1,732 B`, of which `.rodata`
`+924 B` is the measured font-table cost) · **282,080 B** once `boot()` constructed
a real `FrostSigner` and dispatched to it — a 2.78× jump, with `rust-bitcoin` going
**1 → 14** symbols. Deleting the single `session.recv` call drops `.text` by
142,916 B and `bitcoin` back to 1, which is how we know `boot()` is what pulls the
workload in rather than `--gc-sections` keeping it by accident · 297,064 B once the
remaining §4.2 consent screens got honest callers · 331,116 B with the keypad
driver and real consent · 362,288 B once `DisplayBackup`, `mark_sensitive` and the
persistent share store landed · 372,688 B once 25-word entry made restore possible
· 376,752 B once `CheckBackup` became a real 8-question quiz behind its own
consent digit (+4,064 B, of which +2,232 B is `firmware/src/quiz.rs` acquiring its
first caller rather than any new code) · **377,192 B** once the keygen check stopped
printing a fixed `1=match` and started printing the randomised `press_legend(confirm)`
(+440 B net: a `Buf<16>` legend build and a call, less the 12-byte literal it replaced,
which is why `.rodata` fell 8 B while `.text` rose 448).

That is **+55,171 (+3.87 pt) over the 844,229 phase-0 baseline**: +5,101 for the
first round of panic-site work in the vendored crates, +30,627 for the
`coldsnap_hal` rlib, +21,000 for the `coldsnap_firmware` rlib, and **+253 for the
three `Option`-returning fixes** in `bitcoin_transaction.rs` plus one
`saturating_sub` in `flash.rs` — less −4,482 of generic instantiations that moved
out of the frostsnap rlibs into `coldsnap_hal`'s, and −1,328 of other net movement.
**This read "+16,669 (+1.2 pt)" with a "+15,873 `coldsnap_hal` rlib" term and no
`coldsnap_firmware` term at all until 2026-09-10**; that breakdown was the
2026-08-19 one, and its sum has been re-derived rather than adjusted.
Every number is measured with LTO **off**, so they are upper bounds — `lto =
"fat"` collapses the duplicated monomorphisations. See `vendor/README.md` for the
per-change split.

**The whole phase-3 transport cost +3,461 bytes** (857,125 → 860,586, +0.3 pt),
which is the entire delta: `libcoldsnap_hal.rlib` went 12,098 → **15,559**
(14,606 `.text` + 953 `.rodata`) and nothing else moved. That buys `comms.rs` +
`usb.rs`, descriptors and all. (Both rlib figures are the phase-3-era ones and are
kept as the marginal cost of that change; the rlib is **30,627 B** today.) The
4,096-byte reassembly buffer is not part of it: it is SRAM, held inline in a `Link`
the caller places — and **`boot()` places one**, in the event loop's own frame
(`firmware/src/main.rs:1950`), where its `[u8; FRAME_LIMIT]` is the largest single
object on a stack with **548,776 B** of runway (`ESTACK_TOP 0x2009_e000 − _end
0x2001_8058`). **This sentence read "nothing in this tree places one yet" until
2026-09-10**, and DECISIONS.md 7 carried the same denial.
Note the real cost is **2 × `FRAME_LIMIT`**, not one: `encode_frame`
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

Reproduce the *mechanism* in one step: set `MAX_MESSAGE_ALLOC_SIZE` back to `32_768`,
rebuild into a clean target dir, and the duplicate monomorphisation comes back. The
**absolute** figures above (893,099 / 48,062 / 860,898 / 15,873) are the 2026-08-19
tree's and will not reproduce today — the baseline is now 899,400 with the hal rlib at
30,627, so expect ~+32 KB from that baseline rather than a return to 893,099. Read the
delta, not the endpoints.

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
survive is this instance of it. Headroom on the rlib sum is **526,008 B**
(1,425,408 − 899,400); on the linked image it is **1,048,656 B**. **This read
564,510 B until 2026-09-10**, against the stale 860,898 total.

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
(393,216 B, raw image at `0x08020000`) and `target/pack/coldsnap-6.0.0cs.dfu`
(393,525 B). **It flashes nothing** and writes only under `--out`.
Numbers below are from a real run against the release ELF (650,592 B), re-run
2026-09-10, exit 0, `rerun: byte-identical to the previous firmware-signed.bin`.

**Every figure in this section was one image stale until 2026-09-10**: it read
299,008 / 299,317 / 551,260 / 282,016 and derived the whole padding chain from
them. 282,016 is 282,080 − 64, i.e. the 2026-08-25 trajectory step this file's own
"Flash budget" section lists — the block was internally consistent (73 × 4096 =
299,008, 96 + 512 = 608), which is exactly what made it read as freshly measured.

**Two `llvm-objcopy` runs, never one.** `-j .vector_table` → 64 B;
`-j .text -j .rodata -j .data` → 376,688 B. A single whole-ELF dump zero-fills the
16 KiB hole between `.vector_table` and `.text`, where signit's own padding is
`0xff`. The tool proves no fill happened by comparing each flat file against the
sum of its section sizes — widening the `-j` list to span the gap aborts with
`objcopy gap-filled +16320 B`. It also aborts if the ELF ever grows a
flash-resident section it does not know about, since objcopy would drop it
silently.

**The 256 KiB floor is already cleared, so padding is alignment-only.** Body
376,688 B ≥ `FW_MIN_LENGTH` 262,144 B by 114,544 B. `align_to(376688, 512)` =
376,832 (+144), then `align_to(376832, 4096)` = 376,832 (**+0**) — Mk4/Mk5 take the
4 K branch (`cli/signit.py:302-306`, `verify.c:106`), *not* the 512 that
`memmap::FW_BODY_ALIGN` records, and this body happens to land on 92 × 4096 already,
so the two branches agree and the 4 K step costs nothing. That is a coincidence of
the current image, not a property — do not read it as the 4 K branch being
irrelevant. 144 B of `0xff` in total, plus 16,192 B of `0xff`
after the vectors. `firmware_length = 16,256 + 128 + 376,832 = 393,216 (0x60000)`
= 96 × 4096 — a **total** measured from `0x08020000`, header and vector region
included, not a body length. 393,152 B are hashed (`firmware_length − 64`,
`verify.c:92`).

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
  keypad.rs             the Mk4 4x3 membrane matrix (cols PB0-PB2, rows PD8-PD11,
                        pins.csv:74-80). Row scan order is reshuffled per scan from
                        `Entropy` — the Tempest defence — and that call site is
                        pinned by a source-reading test, not just by review
  heap.rs               the measured heap budget and the four forbidden SRAM
                        regions: consts only. The allocator itself is registered in
                        the bin crate (firmware/src/alloc.rs), never here, so no
                        library can dictate it to its consumers (PLAN.md §9 item 7)
  lib.rs                pub mod memmap — every flash and RAM address, mirrored by
                        link.x's ASSERTs so the two cannot drift
  panic.rs              panic -> NVIC_SystemReset, RTC-backed reset counter
  rng.rs                fail-closed 2-source RngCore
  singleton.rs          the take-once guard flash/rng/usb/keypad/display share
  usb.rs                OTG_FS device mode + CDC-ACM (no protocol knowledge)
  examples/heap_profile.rs  the heap measurement behind heap.rs; host-only
  examples/heap_lifo.rs     the LIFO probe that disqualified a bump arena, and the
                            wrapper shape firmware/src/alloc.rs ships
  examples/ui_render.rs     every screen and page as ASCII + BMP, for layout review
                            with no hardware: cargo run -p coldsnap_hal --example ui_render
hal/tests/            host_smoke.rs (target shape and link-time invariants) and
                      integration_frostsnap_over_hal.rs — the only place the real
                      frostsnap_embedded::AbSlot / device_nonces stack runs against
                      the HAL's own geometry and Entropy
firmware/             coldsnap_firmware — the bin crate that LINKS. ARM-only; boot()
                      is cfg(target_arch = "arm"), so its 165 host tests cover the
                      host-testable half only:
  main.rs               the 16-entry vector table, entry_point, boot() and the event
                        loop. Owns the Outbox that applies the three §7 caps
  entry.rs              the reset path: SCB->VTOR first, then CPACR, .bss, .data
  lib.rs                Session — the coordinator dispatch, the consent gate, the
                        page cursor, and Outbox::push's three construction caps
  alloc.rs              the tree's ONLY #[global_allocator]: linked_list_allocator
                        over a 64 KiB static arena in .bss, plus a dealloc bounds
                        check and an init sentinel that is not 0xdeadbeef
  store.rs              the keygen triple persisted as one 512 B record in a
                        vendored AbSlot; commit word last, so a tear reads Damaged
  wordentry.rs          25-word share INGEST — the only path that takes a secret in
  quiz.rs               the CheckBackup quiz: 8 of 25 positions, three candidates,
                        distractors chosen so the triple does not identify its answer
  link.x                the memory map and 10 link-time ASSERTs
  examples/stub.rs      the harness's DEVICE side: the shipping Session over a
                        FakeFlash, with consent read back off the framebuffer
  examples/simulator.rs a live coordinator session on a rendered panel
  examples/checkfw.rs   would the Mk4 bootloader's verify_firmware() ACCEPT this
                        artifact? 12 checkable rules, 4 it names as uncheckable
  examples/heap_session.rs  the firmware-side heap probe behind heap.rs's figures
hostcheck/            the harness's COORDINATOR side. Its module header is the
                      harness's measurement + mutation record. Its OWN workspace,
                      and it must stay that way: one cargo graph cannot hold both
                      coldsnap_hal and upstream frostsnap_coordinator (lockfile
                      package collision on frost_backup). Needs a sibling
                      ../frostsnap checkout. 133 std crates that the ARM build
                      never sees.
vendor/frostsnap/     upstream crates @ 0bbc18be (MIT), see vendor/README.md
tools/measure-flash.py   the rlib sums in "Flash budget"; needs LTO off
tools/pack-signed.py  ELF -> signed, bootloader-acceptable artifact, one command.
                      Prints every step and byte count, verifies what it produced,
                      flashes nothing. See "Packaging" above.
tools/pixel-check.py  an independent decoder for the framebuffer, so ui.rs's own
                      cell()/cell_2x() readback cannot agree with itself and be wrong
tools/qemu-boot.sh    a DIAGNOSTIC, never a gate. See its section above
tools/sim-window.sh   drives examples/simulator.rs
tools/research-scratch/  wire-size and decode-allocation measurements; not part of
                      any build. Each file carries its own copy-in/run/delete
                      commands and provenance caveats -- read those before quoting.
```

**This block ended with "There is no bin target, no entry point and no linker script
yet: the workspace builds rlibs only. The `usb.rs` ⇄ `comms.rs` composition is three
lines and lives in a test rather than in an event loop for that reason." until
2026-09-10.** All three exist, and the same block twenty lines above already called
`firmware/` "the bin crate that LINKS" that "owns the vector table, the entry point,
`link.x`" — the file contradicted itself across one page. `usb.rs` ⇄ `comms.rs` is
composed in `boot()`'s event loop, which places the `Link` at
`firmware/src/main.rs:1950` and drives it at `:1995-2008`. The same pass added
`keypad.rs`, `hal/src/lib.rs`, `hal/examples/heap_lifo.rs`, `hal/tests/`, all seven
`firmware/src/` modules, all four `firmware/examples/`, and three `tools/` entries,
none of which this "layout" had ever listed; corrected `link.x`'s ASSERT count from
11 to the measured **10**; and corrected `firmware/`'s test count from 14 to **165**.

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
