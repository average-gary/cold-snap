//! # Placement: four forbidden regions, two of them newly found
//!
//! Established 2026-08-20 from the Coldcard source at
//! `/Users/garykrause/repos/coldcard-firmware`. Usable SRAM is
//! `[0x2000_0000, 0x2009_e000)` = 647,168 B, so with `HEAP_BYTES` at 64 KiB there is
//! ~500 KiB of slack — placement is not tight, it is just *constrained*, and two of
//! the constraints were not previously written down anywhere.
//!
//! 1. **At or above `BL_SRAM_BASE = 0x2009_e000`** — the callgate wipes that 8 K on
//!    entry *and* exit (`startup.S:124-134,148-156`) and `crate::callgate` enters it
//!    for every SE operation. Already recorded.
//! 2. **Across `DFU_FLAG_ADDR = 0x2000_8000`, 12 bytes — NEW, and it is a remote
//!    brick path, not merely a layout nit.** The bootloader `memcmp`s that address
//!    against `REBOOT_TO_DFU` at `main.c:115`, which is **before** its
//!    `wipe_all_sram()` at `main.c:130`. So bytes that survive a reset are read on the
//!    next boot, and a match reaches `enter_dfu()` → `if(flash_is_security_level2())
//!    { LOCKUP_FOREVER(); }` (`main.c:250-258`) — a permanent hang at RDP=2 with no
//!    DFU and no recovery. Since [`crate::panic`] resets on *every* panic and a
//!    coordinator influences heap contents, a heap or frame buffer laid across that
//!    address turns "attacker causes a panic" into "attacker bricks the device".
//!    Verified by reading both sites, not inferred.
//!    Note this is the opposite hazard from (1): that region cannot hold our data
//!    because it is *wiped*; this one because it is *read*.
//! 3. **The `0x1000_0000` SRAM2 alias** (`stm32l4s5xx.h:1290`) is the same physical
//!    memory as part of the window at `SRAM_BASE`. A containment check written
//!    against one range can be satisfied via the other, so bounds checks must be
//!    written against physical extent, not one alias.
//! 4. **PSRAM at `0x9000_0000`, 8 MiB** — configured by the bootloader
//!    (`psram_setup()`, `main.c:150`) and *not* used by this firmware. Its capacity
//!    was recorded in PLAN.md §9 item 5 as unverified from Coldcard source; it is in
//!    the source, so that item is closed as declined rather than deferred.
//!
//! # The allocator question is settled by measurement, 2026-08-20
//!
//! Two candidates were eliminated by running the real workload, not by argument.
//! `hal/examples/heap_lifo.rs` drives one device's heap through
//! keygen → nonce replenishment → six signing rounds under a candidate allocator.
//!
//! **A LIFO-rollback bump is WRONG. It leaks monotonically.** Measured, reproducible
//! (`LIFO_ROUNDS=6 heap_lifo 3`): the bump head grows **+25,464 B per signing round,
//! exactly linearly** — 99,784 → 125,248 → 150,712 → 176,176 → 201,640 → 227,104 —
//! while live stays pinned at 18,034 B. The LIFO hit rate is **113/449 = 25.2%**, so
//! three frees in four cannot move the pointer. Dropping the entire `FrostSigner`
//! leaves live at 0 and head at 227,104: **nothing is reclaimed, ever.** The first
//! over-limit at 64 KiB arrives during *nonce replenishment*, before the first
//! signature. This is a leak, not a high-water mark, so no arena size fixes it — which
//! is also why raising [`HEAP_BYTES`] was not the answer.
//!
//! The cause is the same one that disqualified a plain bump-reset arena: `FrostSigner`
//! keeps allocations alive across frames *and grows that set after transient ones*
//! (`device.rs:37,48,50,88`), so the free order is not LIFO and cannot be made so.
//!
//! **`buddy_system_allocator` is also wrong, for a different reason.** It rounds every
//! request up to a power of two, so the 20,480 B [`crate::comms::ENCAPS_DECODE_LIMIT`]
//! leg is charged **32,768 B**. The binding relation below becomes
//! `18,036 + 8,192 + 32,768 = 58,996` (17,844 on the re-measured live figure — the
//! conclusion about buddy does not move), leaving 6,540 B — *exactly* the figure this file
//! recorded before the 2026-08-18 encaps fix. Buddy gives back all the headroom that
//! fix bought and hands a hostile coordinator a ~2x amplifier: claim 16,385, be charged
//! 32,768.
//!
//! **`linked_list_allocator` 0.10.6 is the candidate that survives**, after a
//! line-by-line review. First-fit with address-ordered coalescing, no power-of-two
//! rounding, zero dependencies, and RUSTSEC-2022-0063 (memory corruption) is patched in
//! ≥ 0.10.2. Miri clean 26/26 under Stacked Borrows and Tree Borrows with
//! strict-provenance.
//!
//! **Panic sites, corrected 2026-08-21 — an earlier version of this paragraph was
//! wrong.** It claimed there were four, all in `HoleList::new`, on the grounds that
//! `#[cfg(test)]` at `hole.rs:433` made lines 443/501/535/554 test-only. That is not
//! what that attribute does: it applies to the single following function, `first_hole`
//! (`hole.rs:434-441`). `impl Cursor` opens at `:492` with **no** cfg, and the real test
//! module is `pub mod test` at `:683`. Verified by reading all four sites.
//!
//! The accurate count is **9 reachable release-active panic sites**:
//!
//! - **init-time**, in `HoleList::new`: `:330 :331 :336 :344`. Called once from the
//!   entry with constants we choose, so a failure is a deterministic first-boot build
//!   error. Backing the heap with `[MaybeUninit<u32>; _]` (align 4 =
//!   `align_of::<Hole>()` on a 32-bit target) makes all four true by construction.
//! - **deallocate path**: `assert!` at `:501 :535 :554`, `.expect()` at `:667`, and
//!   `.unwrap()` at `:422`. These are corruption tripwires and are **deliberately
//!   kept** — on this board a panic is a counted reset, which is strictly better than
//!   silently corrupting the free list.
//! - **`:443`** is release-active but unreachable, because `extend()` is forbidden.
//! - **The allocate path has none.** Nothing between `:60-220` or `:368-405` panics,
//!   and `alloc` returns null on exhaustion rather than panicking. That is the property
//!   that mattered most and it holds.
//!
//! **One real defect, and it is why our `dealloc` must bounds-check before delegating.**
//! `check_merge_bottom` (`hole.rs:246-252`) tests only an *upper* bound on the freed
//! node, then computes `(node as usize) - (bottom as usize)`. A pointer *below* the heap
//! underflows that subtraction — release has no overflow checks — yielding a huge
//! `offset` and installing a roughly 4 GiB hole in the free list. The `:501` assert does
//! not catch it: it tests `node + size <= hole`, the other end. So a wrapper `dealloc`
//! must reject any `ptr` outside `[heap_lo, heap_lo + HEAP_BYTES)` and panic, converting
//! silent free-list corruption into a counted reset.
//!
//! Also established while reviewing: `LockedHeap` and its `GlobalAlloc` impl are both
//! `#[cfg(feature = "use_spin")]`, and `Heap` is `Send` but **not** `Sync`, so
//! "register `#[global_allocator]`" is not a one-liner — it needs a wrapper holding an
//! `UnsafeCell<Heap>` with `unsafe impl Sync`. Do **not** enable `use_spin`: with
//! `PRIMASK` set there is nothing to contend with, and a spinlock would hang forever if
//! an ISR ever allocated. That wrapper is already written and host-exercised at
//! `hal/examples/heap_lifo.rs:197-256`; reuse its shape rather than writing a second one.
//!
//! Still owed: `extend`, `init_from_slice` and `from_slice` must never be called, and
//! nothing may branch on `free()`/`used()`/`size()` (`lib.rs:204` wraps in release,
//! `:221` is UB pre-init). Pin `=0.10.6`: upstream cannot build its own tests for a
//! 32-bit target (`src/test.rs:168`), so a version bump re-owes the 32-bit Miri run.
//!
//! Still owed before it ships: the line-by-line `unsafe` review PLAN.md §1 requires of
//! whichever allocator wins. Nothing here pays that debt.
//!
//! # A sentinel must never be `0xdeadbeef`
//!
//! The guard that makes an un-`init`ed control block fail closed compares a magic word.
//! That word must not be `0xdeadbeef`, `0x0000_0000` or `0xffff_ffff`: the bootloader
//! fills SRAM1, SRAM2 and SRAM3 with exactly `0xdeadbeef`
//! (`mk4-bootloader/main.c:42,47-49`), so a guard using it as its sentinel reports
//! "initialised" on every cold boot — the one condition it exists to detect.
//!
//! # RE-MEASURED 2026-08-25 AGAINST THE SHIPPED CONSTRUCTION. Read this first.
//!
//! Everything below this section that carries a number was measured with
//! `FrostSigner::new_random` + `MemoryNonceSlot` on a 64-bit host
//! (`hal/examples/heap_profile.rs`, `hal/examples/heap_lifo.rs`). **Neither is on any
//! device path**: `boot()` and `firmware/examples/stub.rs` both go through
//! `Session::open`, which derives the keypair from flash and puts the nonce slots on
//! flash. `firmware/examples/heap_session.rs` now drives THAT construction against a
//! real `FrostCoordinator`, through the real framing and the real `Outbox`, inside a
//! real `linked_list_allocator` 0.10.6 arena of exactly [`HEAP_BYTES`]:
//!
//! | Figure | Bytes | Supersedes |
//! |---|---|---|
//! | [`MEASURED_ARENA_FOOTPRINT_BYTES`] — arena high-water at n = 12, holes included | **60,512** | nothing; the fit number never existed before |
//! | [`MEASURED_PEAK_BYTES`] — true simultaneous requested bytes, n = 12 | **54,496** | 48,166 (a sum of two maxima), and the 35,413 below |
//! | [`MEASURED_LIVE_BYTES`] — held between frames, no clear called | **17,844** | 18,036 |
//! | largest single allocation | 11,520 | 7,200 |
//! | `allocate_first_fit` failures at 64 KiB | **0** | — |
//!
//! **IT FITS, and the margin is 5,024 B (7.7%) at the declared envelope.** Per-round
//! series flat across three signing rounds; largest free block after teardown 65,520
//! of 65,536, so the arena coalesces fully. The same harness refuses allocations at
//! **n = 16**. Nothing here licenses raising [`HEAP_BYTES`] — a bigger arena would
//! hide unbounded growth, and at RDP=2 a hidden brick is permanent.
//!
//! Two claims below are now **retracted by measurement**, not by argument:
//!
//! * "The hostile decode legs do not stack on top of [the live peak] — the device
//!   processes one frame at a time" (next section). The harness holds the outer leg
//!   (`Link::poll`), the inner leg (`comms::decode_body`), `Session::recv`,
//!   `Session::confirm` and the `staged_mutations` drain in one span **with the
//!   `Outbox` undrained**, and that is where the 54,496 B comes from. They do stack.
//! * "every pointer, length and capacity halves … estimated 10–40%" (see
//!   [`MEASURED_PEAK_BYTES`]). The direction is right, the magnitude is not:
//!   `secp256kfun` reaches the curve through `k256`, whose `FieldElement10x26`
//!   (32-bit) and `FieldElement5x52` (64-bit) are both exactly 40 B, so `Point` is
//!   120 B on both widths and the dominant consumers do not shrink at all.
//!
//! # SUPERSEDED (2026-08-20): the true simultaneous peak is 35,413 B, not 48,166
//!
//! [`MEASURED_PEAK_BYTES`] is a high-water figure that includes churn a non-reusing
//! allocator never gives back. With a reusing allocator the largest number of bytes live
//! *at once* is **35,413 B in at most 26 blocks, largest single block 7,200 B** (n=3;
//! 35,676 B at n=9). The hostile decode legs do not stack on top of it — the device
//! processes one frame at a time and that peak already includes the decoded inbound
//! message — so the governing bound remains the relation below.
//!
//! # `buddy_system_allocator` would undo the encaps fix. Do not take it unexamined.
//!
//! Measured 2026-08-20, and it reverses the earlier survey's recommendation: buddy
//! rounds every request **up to the next power of two**, so the 20,480 B
//! [`crate::comms::ENCAPS_DECODE_LIMIT`] leg is charged **32,768 B**. The binding
//! relation below then becomes `18,036 + 8,192 + 32,768 = 58,996`, leaving 6,540 B
//! spare — *numerically the exact figure this file recorded before the 2026-08-18
//! encaps fix*. Buddy gives back the entire headroom that fix bought, and hands a
//! hostile coordinator a free ~2x amplifier: claim 16,385 bytes, be charged 32,768.
//!
//! That does not disqualify it, but it does mean `HEAP_BYTES` and the allocator
//! choice are one decision and not two, and that the survey's `+851 B of flash` was
//! the wrong axis to choose on.
//!
//! How much heap this firmware needs, and why the region it lives in is still
//! deferred.
//!
//! **This module contains no code, deliberately.** It is three constants and the
//! compile-time relations between them. There is no allocator type here, no
//! `#[global_allocator]`, and no dependency on an allocator crate. That is the
//! finding, not an omission — see *What is not here* below.
//!
//! # The requirement, settled by measurement
//!
//! A `#[global_allocator]` is **required**. Forcing the monomorphisation of
//! [`crate::comms::Link::poll`] at the real inbound type and then forcing a link
//! step:
//!
//! ```text
//! cargo rustc --release -p coldsnap_hal --crate-type staticlib
//! error: no global memory allocator found but one is required
//! ```
//!
//! `cargo build --release` does not report this — an rlib defers the allocator
//! check to link time — so every clean device build in this tree was *silent* on
//! the question rather than evidence about it. The requirement enters through
//! `EncapsBody(Vec<u8>)` and `Destination::Particular(BTreeSet<DeviceId>)` in
//! `ReceiveSerial<Upstream>`. Running that probe today still reports the error,
//! and that is the correct outcome: a library must not register the allocator.
//!
//! # The size, measured
//!
//! `hal/examples/heap_profile.rs` (host, release, `--features heap-profile`)
//! drives a real `FrostCoordinator` against real vendored `FrostSigner`s through
//! keygen → nonce replenishment → a signature that is asserted to verify, with a
//! tracking allocator. Per-device figures, not process figures: transient heap is
//! measured in windows around single device calls, and live heap destructively, by
//! dropping one `FrostSigner` out of the map and watching the net-bytes counter
//! fall.
//!
//! SUPERSEDED by the 2026-08-25 table above; kept because it is where the *shape* of
//! the figures (n-independent live, +112 B per nonce slot) was established.
//!
//! | Figure | Bytes | Notes |
//! |---|---|---|
//! | [`MEASURED_LIVE_BYTES`] | 18,036 (now 17,844) | one device, live across frames. **Constant**: identical at group size 1/2/3/5/9, identical after 1/2/4 signing sessions, +112 B per extra nonce slot |
//! | worst transient frame | 30,130 | one device, `recv:KeyGen` at *n* = 9 |
//! | [`MEASURED_PEAK_BYTES`] | 48,166 | the sum of those two. An upper bound *by construction* — they do not co-occur, since the worst window is during keygen when live is lower |
//!
//! Two consequences that shaped the numbers below. Decode is perfectly LIFO
//! (`held == 0` for every inbound frame, including the largest that fits
//! [`crate::comms::FRAME_LIMIT`]) — but device *processing* retains 18,036 B
//! across frames, so **a bump-reset arena is disqualified**: the reset point would
//! free live key material. `FrostSigner` holds two `BTreeMap`s, a `String` and a
//! `BTreeMap` of encrypted shares (`frostsnap_core/src/device.rs:37,48,50,88`),
//! and the long-lived set *grows* after transient allocations, so no high-water
//! scheme rescues it either.
//!
//! And a firmware to-do that is worth 69% of the live figure: 12,456 B of the
//! 18,036 B is keygen scratch (the same amount whether or not signing ran), freed by
//! `FrostSigner::clear_unfinished_keygens()` (`device.rs:249`). The event loop should
//! call **that**, and not the wider `clear_tmp_data()` — they free the same 12,456 B
//! but `clear_tmp_data` also clears the restoration leg, so it can discard a
//! typed-in physical backup. See [`MEASURED_LIVE_BYTES`] for the measurement and the
//! scope; it deliberately records the figure for firmware that calls **neither**, so
//! the budget does not depend on a call nobody has written yet.
//!
//! # The safety factor
//!
//! [`HEAP_BYTES`] is 64 KiB = 1.36 × [`MEASURED_PEAK_BYTES`] — **1.20 × on the
//! 2026-08-25 re-measurement, and 1.083 × on the arena footprint that is the real
//! constraint ([`MEASURED_ARENA_FOOTPRINT_BYTES`])**. The stated factor
//! is only half the argument; the binding constraint is the compile-time relation
//! below, which is what makes 64 KiB a *derived* number rather than a round one:
//!
//! > [`MEASURED_LIVE_BYTES`] + [`crate::comms::DECODE_ALLOC_LIMIT`] +
//! > [`ENCAPS_ALLOC_CEILING`] ≤ [`HEAP_BYTES`]
//!
//! — 18,036 + 8,192 + 20,480 = 46,708, with **18,828 B spare**; with
//! [`OUTBOX_CEILING`] and the re-measured live figure it is
//! 17,844 + 8,192 + 20,480 + 8,160 = 54,676, with **10,860 B spare** (measured, not
//! recomputed: `heap_session` prints it). In words: a device
//! holding a full key share must survive the worst *hostile* frame, on both decode
//! legs at once, without an OOM. That relation is why
//! [`crate::comms::DECODE_ALLOC_LIMIT`] and this constant are asserted against
//! each other rather than chosen separately: widen either leg back toward the
//! vendored `1 << 15` and 64 KiB stops being sufficient — the build fails instead of
//! the device. (This relation read `+ 32,768 = 58,996, 6,540 B spare` until the
//! inner leg was bounded on 2026-08-18. It is [`MEASURED_PEAK_BYTES`] = 48,166 that
//! constrains [`HEAP_BYTES`] now, not the hostile ceiling.)
//!
//! Why an OOM must not be reachable at all, rather than merely survivable: on
//! stable there is no `#[alloc_error_handler]`, so `handle_alloc_error` →
//! `__rdl_oom` → `panic!` → [`crate::panic`]'s handler → `NVIC_SystemReset`
//! (verified by symbol chain in a thumbv7em staticlib). An OOM is a *reset*, on a
//! unit where RDP=2 makes DFU impossible, and it is indistinguishable in the RTC
//! counter from any other panic.
//!
//! **What 64 KiB is not.** It is not validated against any particular allocator's
//! overhead. A buddy allocator rounds to powers of two and can waste up to 2× on
//! internal fragmentation; TLSF wastes less. Whichever is chosen, the first thing
//! to do is re-run the profile against it. This is a reservation derived from the
//! workload, not a figure any allocator has met.
//!
//! # The region: DEFERRED, and this is the crux
//!
//! Nothing here says *where*. Four reasons, none of which a library can settle:
//!
//! 1. **There is no linker script and no entry point.** Placement is a linker
//!    fact, and PLAN.md §9 item 1 records that none is scheduled before phase 5.
//! 2. **SRAM is not zeroed — it is *filled* with `0xdeadbeef`** by the bootloader
//!    (`mk4-bootloader/main.c:42,47,130`). Every candidate allocator's control
//!    block is a Rust `static`, i.e. `.bss`, and nothing in this repo zeroes
//!    `.bss` yet. An allocator that comes up with `head.next == 0xdeadbeef` writes
//!    through it on the first allocation. This is the same defect
//!    [`crate::singleton`] exists to fix for `AtomicBool`, and it is why the
//!    allocator wrapper phase 5 writes should carry a magic word that is *not*
//!    `0xdeadbeef` and refuse (return null → OOM → counted reset) until `init`
//!    has set it. Fail-closed, and loud instead of silent.
//! 3. **The top 8 K at [`crate::memmap::BL_SRAM_BASE`] is not available.** The
//!    callgate wipes it on every entry **and** exit (`startup.S:124-134,148-156`)
//!    and [`crate::callgate`] enters it for every SE operation. This is a hard
//!    refusal, independent of allocator choice.
//! 4. **PSRAM is uncharacterised** (PLAN.md §9 item 5). If it lands, the available
//!    size changes by an order of magnitude and the allocator choice changes with
//!    it.
//!
//! # What is not here, and why
//!
//! **No `#[global_allocator]`.** Measured, both directions: a library that
//! registers one does not fail the host build, it **silently overrides std's**
//! (575 allocations went through it before a test body ran), and with the
//! realistic device shape — a fixed arena not yet `init`ed, whose `alloc` returns
//! null — the test binary `SIGABRT`s before a single test runs, with `cargo build`
//! still clean. It is also one-way: a consumer that registers its own gets
//! `error: the #[global_allocator] in this crate conflicts with global allocator
//! in: coldsnap_hal`. So registering here would decide the heap for
//! `examples/stub.rs`, for `hostcheck`, and for the future `main`.
//!
//! **Not behind a feature either.** Features are additive, and `hal/Cargo.toml`
//! already self-references as a dev-dependency with features, so any `alloc`
//! feature would unify **on** for every dev target — the 575-allocations case
//! arriving through the back door. The `panic-handler` gate is not the precedent:
//! a library `#[panic_handler]` is a hard `E0152` on the host, so that `cfg`
//! converts an *error* into absence, while an allocator `cfg` would convert a
//! *silent override* into absence. Absence is the stronger guarantee, the same way
//! `rx: [u8; FRAME_LIMIT]` is stronger than a length check.
//!
//! **No allocator type or crate yet.** The candidates were measured as thumbv7em
//! staticlibs: the whole flash spread between cheapest and dearest is 1,513 B =
//! 0.11% of `FLASH_TEXT`, so flash is a non-criterion, and the
//! `#[global_allocator]` is a one-line swap in one file, so nothing is locked in
//! by waiting. What *is* still owed before any of them ships is a line-by-line
//! review of its `unsafe` code (PLAN.md §1's rule; download counts are not a
//! substitute), and the choice itself flips on PSRAM. Adding the dependency now
//! would buy a type nothing can register, at the cost of an unreviewed
//! allocator in the manifest.
//!
//! # What phase 5's `main` must write
//!
//! Three things, in this order, after `BootHealth::read()` and before anything
//! decodes a frame:
//!
//! ```text
//! 1. zero .bss and copy .data in the reset entry     // or the control block is 0xdeadbeef
//! 2. static HEAP_MEM: [u8; heap::HEAP_BYTES]         // placed by the linker script, below BL_SRAM_BASE
//! 3. #[global_allocator] + one init call             // in the BINARY, never in this crate
//! ```
//!
//! Item 1 is a correctness precondition for every other `static` in this tree
//! already; the allocator is only where forgetting it is silent.

use crate::comms::DECODE_ALLOC_LIMIT;
use crate::memmap::{BL_SRAM_BASE, SRAM_BASE};

/// Heap to reserve, in bytes. 64 KiB.
///
/// **Validated 2026-08-25 against the shipped construction and the shipped
/// allocator**, by `firmware/examples/heap_session.rs`: the whole workload at the
/// declared envelope (n = 12, t = 12) through a real `linked_list_allocator`
/// 0.10.6 arena of exactly this size needs **60,512 B of arena footprint** and
/// refuses nothing. See [`MEASURED_ARENA_FOOTPRINT_BYTES`] — that figure, not the
/// assert below, is now the binding constraint, and the margin at the envelope is
/// **5,024 B (7.7%)**.
///
/// It was derived as 1.36 × [`MEASURED_PEAK_BYTES`]; on the re-measured peak that
/// factor is **1.20×**. Do not read the difference as room: the same harness
/// refuses allocations at **n = 16** (5 nulls, first in keygen for 4,256 B), so
/// this budget covers the declared envelope and about two devices past it, and
/// nothing more.
pub const HEAP_BYTES: usize = 64 * 1024;

/// Peak heap one device needed in the measured workload, in bytes — a **true
/// simultaneous** peak of requested bytes (`sum(Layout::size())` live at once),
/// not a sum of maxima.
///
/// # Measured 2026-08-25 against the shipped construction
///
/// **54,496 B**, by `firmware/examples/heap_session.rs` at n = 12, t = 12, host
/// 64-bit `aarch64-apple-darwin`, **release**. That harness drives
/// `identity::load_or_create` → `Session::open` → `NonceAbSlot` over `FakeFlash`
/// against a real `FrostCoordinator`, and the measured span holds the outer decode
/// leg (`Link::poll`), the inner leg (`comms::decode_body`), `Session::recv`,
/// `Session::confirm` and the `staged_mutations` drain **with the `Outbox`
/// undrained** — the co-residency the assert below claims. In at most 30
/// simultaneous blocks; largest single allocation 11,520 B. It grows with the group
/// size at roughly +1,170 B per device (35,894 at n = 9, 55,664 at n = 13).
///
/// **SUPERSEDES 48,166 B**, which was `hal/examples/heap_profile.rs`'s figure for
/// `FrostSigner::new_random` + `MemoryNonceSlot` — a construction no device path
/// uses — and was a *sum by construction* (18,036 live + a 30,130 worst transient
/// frame) of two things that file said do not co-occur. The real simultaneous peak
/// is **6,330 B larger** than that sum, which is why the old figure is retracted
/// rather than kept as the conservative one.
///
/// Host, 64-bit; the device is 32-bit thumbv7em and the direction is
/// **conservative** — `linked_list_allocator`'s min block and rounding are
/// `2*size_of::<usize>()` / `align_of::<usize>()`, i.e. 16/8 here against 8/4
/// there, there is no per-allocation header, and 8-byte alignment padding is never
/// smaller than 4-byte. But the **magnitude is low single-digit percent, not the
/// 10–40% this file used to claim**: `secp256kfun` reaches the curve through
/// `k256`, whose `FieldElement10x26` (32-bit) and `FieldElement5x52` (64-bit) are
/// both exactly 40 B, so `Point` is 120 B on both widths (the release figure
/// recorded under [`ENCAPS_ALLOC_CEILING`]) and the dominant consumers — nonce
/// vectors, share images, agg nonces, signature shares — do not shrink at all. Do
/// not spend that correction.
pub const MEASURED_PEAK_BYTES: usize = 54_496;

/// Arena **footprint** high-water, in bytes: the highest offset ever handed out by
/// a real `linked_list_allocator` 0.10.6 in an arena of exactly [`HEAP_BYTES`].
///
/// This is the *fit* number, and since 2026-08-25 it is the binding constraint on
/// [`HEAP_BYTES`] — larger than [`MEASURED_PEAK_BYTES`] because it also contains
/// the holes first-fit left behind. **60,512 B at n = 12**, measured by
/// `firmware/examples/heap_session.rs` (see that constant for the construction and
/// the caveats), with **0** `allocate_first_fit` failures and a post-teardown
/// largest free block of 65,520 B of 65,536 — so the arena coalesces fully and
/// nothing is stranded.
///
/// Where the cliff is, measured on the same harness: n = 12 → 60,512 (5,024 spare),
/// n = 13 → 63,976, n = 14 → 63,968, **n = 16 → 5 nulls** (first in keygen,
/// requesting 4,256 B). One null is `handle_alloc_error` → panic → reset, and at
/// RDP=2 with no PIN UI that reset is permanent, so the correct reading is that the
/// budget covers the declared envelope with 7.7% to spare and fails a few devices
/// past it.
pub const MEASURED_ARENA_FOOTPRINT_BYTES: usize = 60_512;

/// Heap one device holds *across* frames, in bytes, measured destructively by
/// dropping the device's whole state.
///
/// # Re-measured 2026-08-25 against the shipped construction: 17,844 B
///
/// **17,844 B**, by `firmware/examples/heap_session.rs` — `Session::open` +
/// `NonceAbSlot` over `FakeFlash`, real coordinator, host 64-bit, release. Read at
/// quiescence *before* any clear, because the shipped dispatch makes none
/// (`firmware/src/lib.rs` calls `clear_tmp_data` on `Cancel` and nothing else), so
/// this is what the device really holds between frames. Identical at n = 9, 12, 13
/// and 14, so it is still n-independent. `clear_unfinished_keygens()` takes it to
/// **5,388 B**; dropping the `Session` takes it to 0, which is the destructive part.
///
/// **SUPERSEDES 18,036 B** (`hal/examples/heap_profile.rs`, with
/// `FrostSigner::new_random` and `MemoryNonceSlot`). The shipped construction is
/// **192 B smaller**, as predicted
/// from the layouts: `AbSlots<S>` is a `Vec<S>`, and a `NonceAbSlot` element (two
/// `FlashPartition`s + an `Option<AbWriteOutcome>`) is smaller than a
/// `MemoryNonceSlot` element (an inline `Option<Versioned<SecretNonceSlot>>`), so
/// moving the nonce bodies to flash *reduces* the resident set. The old figure also
/// never matched any measurement in the tree, which reported 18,034.
///
/// The paragraphs below are the 2026-08-18 findings for the superseded figure. They
/// still hold in substance — the reclaimable block is 12,456 B there and 12,456 B
/// here (17,844 − 5,388) — and the guidance about *which* clear to call is unchanged.
///
/// Constant in every direction that was swept: group size, number of signing
/// sessions, and workload stage. Only nonce slots move it, at +112 B each. This is
/// what makes a static budget provable — there is no unbounded growth here to
/// defend against. 12,456 B of it is keygen scratch that
/// `FrostSigner::clear_tmp_data()` frees; this figure assumes firmware does not
/// call it.
///
/// # Measured 2026-08-18: the 12,456 B is reclaimable, and cheaply
///
/// Calling the clear at the point firmware would — right after `keygen_finalize`
/// stages the share — leaves the full flow working: keygen, nonce replenishment, a
/// signature that verifies, and a `HeldShares2` round-trip, at both chunk sizes.
/// Exercised by `hal/examples/stub.rs`'s `STUB_CLEAR_TMP` (both settings runnable, so
/// the comparison is the evidence rather than a one-way edit).
///
/// Two things worth knowing before firmware relies on it:
///
/// - **Prefer the narrower `clear_unfinished_keygens()`** (`device.rs:249`). It frees
///   the same 12,456 B and, unlike `clear_tmp_data()`, cannot discard a typed-in
///   physical backup — `clear_tmp_data` also clears the restoration leg.
/// - **The saving is empty-but-allocated `BTreeMap` leaf nodes, not live data.** All
///   three keygen tmp maps are already `remove`d by the keygen legs before this
///   point; only `clear()` releases the nodes. That is why the figure is
///   n-independent (identical at n = 1, 9, 11, 12, 13).
///
/// Scope, stated because a green run does not license a general claim: safe for
/// keygen → nonces → sign → `HeldShares2` with one keygen in flight and no unsaved
/// physical backup. Restoration, backup consolidation, physical-backup entry, naming
/// and screen-verify have never been driven by any harness in this tree.
pub const MEASURED_LIVE_BYTES: usize = 17_844;

/// Largest amount the firmware's dispatch outbox parks on the heap, in bytes.
///
/// `coldsnap_firmware`'s `Outbox` holds *encoded* frames until the caller drains
/// them, so a 4-stream nonce replenishment parks four frames at once. **MEASURED**
/// at 4 × 2,040 B by `nonce_response_is_split_one_segment_per_frame` — 2,040 B is
/// also PLAN.md's single-segment figure, which is why the one-segment-per-frame cap
/// is what bounds this rather than `FRAME_LIMIT`.
///
/// This constant lives here, in the module that owns the budget, but the VALUE is
/// owned by `coldsnap_firmware`: if that cap changes, this changes. It is in the
/// binding assert below because it is the largest single thing the dispatch keeps on
/// the heap, and an assert that omits the largest consumer is not binding — it was
/// omitted until 2026-08-25, when the dispatch first existed.
///
/// It is additive to [`MEASURED_LIVE_BYTES`] rather than inside it: the live figure
/// was measured against `FrostSigner::new_random` + `MemoryNonceSlot`, a construction
/// the device no longer uses, and there was no outbox at all when it was taken.
pub const OUTBOX_CEILING: usize = 4 * 2_040;

/// The ceiling on the **nested** `EncapsBody` decode, which re-enters `bincode`
/// with a fresh budget while the outer `Vec` is still live.
///
/// **Now [`crate::comms::ENCAPS_DECODE_LIMIT`] (20,480 B), where the vendored
/// `MAX_MESSAGE_ALLOC_SIZE` was `1 << 15`.** (That vendored constant has since come
/// down to the same 20,480 — 2026-08-19 — so the two now agree; this one is still
/// the binding one, because a re-vendor can revert that and not this.)
/// Bounded 2026-08-18 by decoding the body in
/// this crate under its own limit rather than calling the vendored
/// `WireCoordinatorSendBody::decode`. Tracks that constant by reference so the two
/// cannot drift.
///
/// Recorded here rather than in [`crate::comms`] because it is a *heap sizing*
/// input, not a refusal this crate owns. [`crate::comms::DECODE_ALLOC_LIMIT`]
/// bounds the outer leg only.
///
/// # Measured 2026-08-18, FIXED 2026-08-18, shared const lowered 2026-08-19
///
/// The inner leg was real and worse per attacker byte than the outer one: a
/// **20-byte** inner blob provoked a **32,640 B single allocation**. The outer fix
/// had closed only the *loop* — the repeat-on-every-poll amplification — not the
/// one-shot claim. Both are now closed, and combined worst per frame is
/// **8,192 + 20,480 = 28,672 B**, down from ~65,516.
///
/// The largest **legitimate** inner allocation measured on this leg is **5,120 B**
/// (release) at the declared envelope edge, which is what left the room to lower it.
/// Two things had to be dealt with first, and both were:
///
/// 1. **The constant is shared with the other decode direction — now measured.**
///    `MAX_MESSAGE_ALLOC_SIZE` is private to `frostsnap_comms` and also governs
///    device→coordinator bodies. That direction's peak is **17,664 B** debug /
///    15,360 B release for the largest frame `FRAME_LIMIT` admits at all (61 nonces
///    in one segment), so 20,480 clears both legs in both profiles and the vendored
///    const came down to it (PLAN.md §9 item 7(d)). The mechanism this crate uses is
///    still the local one — `EncapsBody::as_bytes()` plus
///    [`crate::comms::decode_body`] under [`crate::comms::ENCAPS_DECODE_LIMIT`] —
///    because a refusal in our own code cannot be undone by a re-vendor.
///
/// 2. **The refusal boundary MOVES WITH `debug_assertions`, which is the profile
///    divergence that already bit this project once.** `size_of::<Point>()` is 120 B
///    in release and 144 B in debug, so the wire-to-memory amplification is 3.64x
///    release against 4.36x debug. A 16 KiB limit refuses nothing in release, but
///    4.36 x 4,069 = 17,741 > 16,384, so host tests and the device would disagree
///    about where the boundary is. This is the same class as the
///    `overflow-checks = false` release / `true` dev defect in PLAN.md §8.1, where
///    one coordinator message panicked in tests and wrapped in firmware. **Size the
///    margin off the DEBUG column**, or the tests are measuring a different device.
///
/// Do not lower it further. 16,384 does not clear 17,664, and 8,192 is *actively*
/// unsafe as a shared bound: measured, it refuses the real production 30-nonce
/// `NonceResponse` in debug (8,704) while admitting it in release (7,424) — exactly
/// the divergence in 2 above. Picking a bound while a whole direction is unmeasured
/// is how 2,060 happened (DECISIONS.md 7).
pub const ENCAPS_ALLOC_CEILING: usize = crate::comms::ENCAPS_DECODE_LIMIT;

/// The relations that make [`HEAP_BYTES`] a derived number. Breaking any of them
/// is a build failure rather than a device that resets in the field.
const _: () = {
    // The measured workload fits. 1.20x on the re-measured peak (was a stated 1.36x
    // on the superseded 48,166).
    assert!(HEAP_BYTES >= MEASURED_PEAK_BYTES);
    assert!(MEASURED_PEAK_BYTES > MEASURED_LIVE_BYTES);

    // THE BINDING CONSTRAINT since 2026-08-25: the real allocator's footprint,
    // holes included, in an arena of exactly this size. Everything else here is
    // requested bytes, which no allocator can actually pack that tightly. Shrink
    // `HEAP_BYTES` and this is what fails first.
    assert!(HEAP_BYTES > MEASURED_ARENA_FOOTPRINT_BYTES);
    assert!(MEASURED_ARENA_FOOTPRINT_BYTES > MEASURED_PEAK_BYTES);

    // A device holding a full key share survives the worst hostile frame on both
    // decode legs at once. This is the binding constraint, and it is what ties
    // `comms::DECODE_ALLOC_LIMIT` to this figure: restore the vendored 32 KiB on
    // the outer leg and this assert fails.
    assert!(
        MEASURED_LIVE_BYTES + DECODE_ALLOC_LIMIT + ENCAPS_ALLOC_CEILING + OUTBOX_CEILING
            <= HEAP_BYTES
    );

    // The reservation fits in the SRAM our firmware may use at all. Necessary,
    // nowhere near sufficient: stack, statics and two `FRAME_LIMIT` buffers share
    // this space, and the linker script that would prove it does not exist.
    assert!(HEAP_BYTES < (BL_SRAM_BASE - SRAM_BASE) as usize);
};
