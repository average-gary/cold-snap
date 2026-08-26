//! cold-snap firmware image for the Coldcard Mk4 (STM32L4S5, Cortex-M4F).
//!
//! **This is the most dangerous file in the project.** A crash before the login
//! path completes bricks the unit, and there is no recovery: DFU is RDP-gated
//! (`mk4-bootloader/dispatch.c:150-165` returns `EPERM`) and the bootloader's own
//! `enter_dfu()` calls `LOCKUP_FOREVER()` rather than trying
//! (`mk4-bootloader/main.c:256-258`).
//!
//! # The handoff, as read from the bootloader
//!
//! The bootloader reads **exactly two words** from
//! [`memmap::FLASH_ISR_BASE`](coldsnap_hal::memmap::FLASH_ISR_BASE)
//! (`mk4-bootloader/startup.S:102-112`): word 0 into `SP`, word 1 into `PC` via
//! `bx lr`. Word 1's LSB **must be set** for Thumb — here that comes free from
//! taking a function pointer on a Thumb target, and it is verified in the linked
//! ELF rather than assumed. `r0` arrives as `1` (`reset_mode`, ignorable) and `LR`
//! holds the entry address itself, so **the entry must never return**: hence
//! `-> !`.
//!
//! State on arrival, all read from bootloader source:
//!
//! * PRIMASK = 1, interrupts globally masked (`dispatch.c:98`, never re-enabled).
//! * `SCB->VTOR` **not set** — still 0, aliasing the bootloader's vector table
//!   whose fault handlers are `bkpt; b .` (`startup.S:43-59`). So a HardFault
//!   today is an infinite hang, not a reset. Setting VTOR is the highest-value
//!   instruction in the entry, and it is step 1 of [`entry::init_hardware`].
//! * FPU already enabled (`clocks.c:87-89`), but behind a compile-time `#if`, so
//!   the entry re-asserts CPACR anyway.
//! * SYSCLK 120 MHz. SysTick **running** at 1 kHz with TICKINT clear. The callgate
//!   polls its COUNTFLAG for SE1 timeouts and COUNTFLAG clears on read, so nothing
//!   here may reprogram or disable SysTick, and nothing may `cpsie i`.
//! * All SRAM below [`memmap::BL_SRAM_BASE`](coldsnap_hal::memmap::BL_SRAM_BASE)
//!   arrives filled with `0xdeadbeef`, **not zeroed**
//!   (`mk4-bootloader/main.c:42,47-49`). That is why
//!   [`singleton::TakeOnce`](coldsnap_hal::singleton::TakeOnce) is tagged, and why
//!   `.bss` zeroing is mandatory rather than a nicety.
//!
//! # The boot sequence, in order
//!
//! [`entry_point`] runs PLAN.md's amended step list and nothing else:
//!
//! | Step | What | Where |
//! |---|---|---|
//! | 0 | vector table: SP, reset, 14 fault trampolines | [`VECTOR_TABLE`], `link.x` |
//! | 1-4a | VTOR, CPACR, `.bss`, `.data`, `compiler_fence` | [`entry::init_hardware`] |
//! | 5 | `#[global_allocator]` init | [`alloc::init`] |
//! | 6 | `BootHealth::read()` — **before any clear** | [`boot`] |
//! | 7 | `Entropy::boot(Sources)` — fail-closed | [`boot`] |
//! | 8 | `StmFlashToken::take().open()` — DBANK geometry | [`boot`] |
//! | 8b | `identity::load_or_create` — the durable secret, or a hold | [`boot`] |
//! | 8c | `Session::open` — the flash-backed `FrostSigner` | [`boot`] |
//! | 9 | `UsbToken::take().open()` — OTG_FS + CDC-ACM | [`boot`] |
//! | 10 | bounded event loop, then the panic-counter clear | [`boot`] |
//! | 11 | never returns | `-> !` everywhere |
//!
//! Steps 6-10 are ARM-only because `BootHealth::read`, `bump_counter` and
//! `clear_counter` are all `#[cfg(target_arch = "arm")]` in the HAL — there are no
//! backup registers to read on a host. On a host build [`entry_point`] therefore
//! falls through to a spin loop, which is what keeps `entry.rs`'s host tests
//! buildable.
//!
//! Length rules, both now satisfied: `cli/signit.py:293` requires the *body* —
//! everything at or after `FLASH_TEXT_BASE`, i.e. `.text + .rodata + .data`, and
//! *not* the 16 K vector+header region — to be `>= FW_MIN_BODY_LEN` (256 K), and
//! `signit.py:295,305` pads it to 512 and then, on the Mk4/Mk5 branch, to **4096**
//! (`verify.c:106`: the installer erases 4 K pages). The measured body is
//! 282,016 B, 19,872 B over the floor, and signit pads it by 608 B. Padding is
//! signit's job; never hand it a pre-padded body.
//!
//! Neither rule bounds `firmware_length` in the header, which is the whole image
//! including the 16 K: `verify.c:215` floors *that* at 256 K and `verify.c:212-217`
//! enforces no alignment at all.
//!
//! # What is deliberately NOT brought up
//!
//! * **No clock, PWR or RCC work here.** `usb::bring_up` enables `OTGFSEN`,
//!   `PWREN` and `PWR_CR2.USV` itself (`hal/src/usb.rs:1755-1790`); the 48 MHz
//!   CLK48 source is assumed live from the bootloader's PLLSAI1-Q and is
//!   programmed by nobody in this tree. That is a documented gap in [`usb`], not
//!   one this file papers over.
//! * **No consent input.** There is no keypad or button driver anywhere in this
//!   tree, so `Session::confirm` is unreachable from here: a `CheckKeyGen` or
//!   `SignatureRequest` prompt is *drawn* and then waits forever. Fail-closed —
//!   no coordinator can make this device sign on its own — but it also means
//!   keygen cannot complete on hardware until a button driver lands.
//! * **No durable share or name store.** Nothing drains
//!   `session.signer.staged_mutations()` and `memmap::FS_FREE_OFFSET` is still
//!   unclaimed, so a completed keygen would not survive a reset. The nonce
//!   slots and the identity *do* survive; those are the two that must.
//! * **No UI task.** The panel is drawn on the way into a state and never in a
//!   loop, here as in the identity hold: one `show` per event, so a wedged panel
//!   can never turn the event loop into a hang.

#![no_std]
// `no_main` only when we are NOT the host test harness. `cargo test` generates its
// own `main`, and `#![no_main]` suppresses it — the link then fails with
// `Undefined symbols: "_main"`. MEASURED: that is the only thing that stood between
// `entry.rs` and having host tests at all. `#![no_std]` needs no such gate; rustc's
// test harness pulls `std` in for itself.
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod alloc;
mod entry;

use coldsnap_hal::memmap;

/// The vector table: `SP`, the entry, then 14 fault trampolines.
#[repr(C)]
struct VectorTable {
    /// Word 0 -> `SP`. Our free choice; the bootloader takes whatever is here.
    stack_top: u32,
    /// Word 1 -> `PC`, LSB set by the Thumb function-pointer relocation.
    reset: unsafe extern "C" fn() -> !,
    /// Vectors 2..15 — NMI, HardFault, MemManage, BusFault, UsageFault, the four
    /// reserved slots, SVCall, DebugMon, reserved, PendSV, SysTick.
    ///
    /// All 14, including the reserved slots, not just the five real faults. A
    /// reserved slot cannot be taken by hardware, but "cannot" here rests on
    /// reading the core right, and a wrong non-zero pointer costs one reset while a
    /// wrong zero costs the unit. Filling them is free.
    ///
    /// **These are why step 1 is worth anything.** Without them `VTOR` points at a
    /// two-word table and a fault fetches whatever follows it in `FLASH_ISR` —
    /// zero, since nothing else is emitted there. A zero vector escalates to
    /// HardFault, and a HardFault with a zero vector is lockup: the exact
    /// permanent hang that moving `VTOR` off the bootloader's `bkpt; b .` table
    /// was supposed to remove.
    exceptions: [extern "C" fn() -> !; 14],
}

/// Placed at `0x0802_0000` by `firmware/link.x`.
///
/// `#[used]` plus `KEEP()` in the linker script: without both, LTO or `--gc-sections`
/// drops the only thing the bootloader ever reads and the unit jumps to `0xdeadbeef`.
#[used]
// Section name gated for the same reason as `no_main` above: a bare
// `.vector_table` is not a legal mach-o section specifier ("requires a segment and
// section separated by a comma"), so under a host test build LLVM aborts before any
// test can run. `not(test)` and not `target_os = "none"` so that the ARM build —
// which is what the linker script and every ASSERT act on — is affected by nothing
// at all.
#[cfg_attr(not(test), link_section = ".vector_table")]
static VECTOR_TABLE: VectorTable = VectorTable {
    // Top of usable SRAM. A full-descending stack never writes *at* `SP`, so
    // being equal to `BL_SRAM_BASE` does not touch the bootloader's 8 K — which
    // the callgate wipes on every entry AND exit.
    stack_top: memmap::ESTACK_TOP,
    reset: entry_point,
    exceptions: [fault_trampoline; 14],
};

/// Vectors 2..15: one bare `panic!()`, which `hal::panic` turns into a counted
/// reset (DECISIONS.md decision 6).
///
/// One handler for all fourteen on purpose. `IPSR` already says which exception
/// was taken and the counter already says how often, so per-vector handlers would
/// add flash and a maintenance surface to report something the core reports for
/// free. `-> !` matches the table's field type and is honest: a fault handler here
/// never returns to the faulting instruction, because the faulting state is exactly
/// what must not be resumed.
///
/// Safe `extern "C" fn`, not `unsafe`: it takes no arguments and touches nothing,
/// so there is no contract for a caller to break, and it coerces to the table's
/// pointer type either way. The hardware pushes the exception frame; nothing here
/// reads it.
extern "C" fn fault_trampoline() -> ! {
    // A `&'static str`, no formatting arguments: `core::fmt` machinery on this path
    // would be flash spent on a message nothing can display.
    panic!("fault");
}

/// Reset entry. `LR` holds this address, so returning would jump back here with a
/// dirtied machine state: the signature is `-> !` and that is not negotiable.
///
/// # Safety
///
/// Only ever called by the bootloader's `bx lr` handoff, once, on a machine with
/// masked interrupts, `VTOR` = 0 and `0xdeadbeef`-filled SRAM.
#[no_mangle]
pub unsafe extern "C" fn entry_point() -> ! {
    // Steps 1-4a: VTOR, CPACR, `.bss`, `.data`, `compiler_fence`. Nothing may be
    // moved above this call — every instruction before the VTOR store inside it
    // runs with faults still vectoring into the bootloader's `bkpt; b .`.
    //
    // SAFETY: this is the reset entry, reached once, from the bootloader's `bx lr`.
    // No `static` has been read and nothing has allocated.
    unsafe { entry::init_hardware() };

    // Step 5: the heap. AFTER step 3, not merely after step 4 — the allocator's
    // `READY` sentinel lives in `.bss` (measured: `.bss._ZN..ALLOCATOR..`), so an
    // init before the zeroing loop would be overwritten by it and every later
    // allocation would be refused. Before step 6 because everything from here on
    // is allowed to allocate.
    //
    // SAFETY: `.bss` and `.data` are initialised by the call above, and this is the
    // first and only call.
    unsafe { alloc::init() };

    #[cfg(target_arch = "arm")]
    boot();

    // Host builds only: steps 6-10 need backup registers, an SE and an OTG core.
    // `spin_loop()` rather than a bare `loop {}` so there is an instruction in the
    // body to find in a disassembly.
    #[cfg(not(target_arch = "arm"))]
    loop {
        core::hint::spin_loop();
    }
}

/// Steps 6-11: boot health, entropy, flash, USB, then the event loop.
///
/// Split out of [`entry_point`] only because every counter function it calls is
/// `#[cfg(target_arch = "arm")]` in the HAL. Diverges, so [`entry_point`] can call
/// it as a statement and still be `-> !`.
///
/// # Failure policy
///
/// Bring-up failures `panic!()`, which is a *counted* reset, not a halt
/// (DECISIONS.md decision 6): a transient fault self-heals because the bootloader
/// still holds a verified signed image, and a deterministic one is bounded by
/// [`PANIC_RESET_THRESHOLD`](coldsnap_hal::panic::PANIC_RESET_THRESHOLD) rather than
/// looping forever. There is no DFU fallback to reach: DECISIONS.md decision 6
/// records DFU as hardware-impossible at RDP=2 (dispatch.c:150-165).
///
/// Durable-state failures are the third case and neither of the other two: a
/// damaged identity record, or a stored secret that is not a scalar, is
/// bit-for-bit identical on the next boot, so they *hold* — see `hold`, which
/// draws one frame and then spins, above USB bring-up so the device never
/// enumerates.
///
/// Runtime failures inside the loop **must not** panic, and that asymmetry is
/// deliberate. `Cdc::poll` can fail on a coordinator-supplied oversize packet
/// (`UsbError::OversizePacket`), so panicking there would hand a hostile
/// coordinator a remote reset loop. The FIFO is drained on that error anyway, so the link resynchronises
/// on the next packet; dropping the error is the fail-safe direction here.
#[cfg(target_arch = "arm")]
fn boot() -> ! {
    use coldsnap_hal::panic::{bump_counter, clear_counter, BootHealth, Counter};
    use coldsnap_hal::{comms, display, flash, identity, rng, ui, usb};
    use coldsnap_firmware::{
        firmware_digest, prompt_screen, DebugFlash, Fault, Outbox, Session,
    };
    use core::cell::RefCell;
    use frostsnap_comms::Sha256Digest;
    use frostsnap_core::device::DeviceToUserMessage;

    /// Say why, then hold forever. The two durable-state faults — a damaged
    /// identity record and a stored secret that is not a scalar — share this
    /// because they are the same situation: bytes on flash that will be
    /// bit-for-bit identical on the next boot, so a counted reset cannot help and
    /// would only spend the `Counter::Panic` budget on the way to
    /// `LOCKUP_FOREVER`.
    ///
    /// Drawing happens on the way *in* and never inside the hold: one frame, no
    /// loop, so a wedged panel cannot turn a hold into a hang. Every step is
    /// best-effort — a `?` or an `unwrap` here would turn a display fault into a
    /// reset loop, which is the opposite of the point. The panel is opened here
    /// rather than at step 8 so the happy path pays nothing for it.
    fn hold(reason: &str) -> ! {
        let mut frame = ui::Frame::new();
        ui::identity_fault(&mut frame, reason);
        if let Some(Ok(mut panel)) = display::PanelToken::take().map(display::PanelToken::open) {
            let _ = panel.show(frame.as_bytes());
        }
        loop {
            core::hint::spin_loop();
        }
    }

    /// Draw one prompt, if this device can draw it at all.
    ///
    /// The map itself is
    /// [`prompt_screen`](coldsnap_firmware::prompt_screen), in the pure library
    /// and NOT here, because `boot` is `#[cfg(target_arch = "arm")]`: a map in
    /// this file is invisible to every host test and to the pty harness, and —
    /// the part that matters — `Session::confirm` could not share it. It does
    /// share it, so a request whose screen refused can never be signed. All this
    /// function adds is the panel, which is the only ARM-only thing about
    /// drawing.
    ///
    /// `Ok(false)` is an informational prompt with no screen: leave whatever is
    /// already on the panel rather than blanking it. An `Err` frame holds
    /// [`ui::refusal`](coldsnap_hal::ui::refusal) and is worth showing — the
    /// device saying no is something a user is entitled to see.
    ///
    /// Nothing here can be *confirmed*: there is no button driver, so the prompt
    /// is the end of the road. See the module docs.
    fn draw_prompt(panel: Option<&mut display::Panel>, prompt: &DeviceToUserMessage) {
        let Some(panel) = panel else { return };
        let mut frame = ui::Frame::new();
        if prompt_screen(&mut frame, prompt) == Ok(false) {
            return;
        }
        let _ = panel.show(frame.as_bytes());
    }

    // --- Step 6: read the counters BEFORE anything clears one. --------------
    // Not merely diagnostics-ordering hygiene: `read_counter` is what calls
    // `enable_backup_access`, so this is also where the backup domain becomes
    // writable for the clear at the bottom of the loop.
    let health = BootHealth::read();

    // --- Step 7: entropy, fail-closed. -------------------------------------
    // `take_all()` is the whole `Sources` proof; `Entropy::boot` is the only
    // unconditional constructor, so a stub source cannot reach this line.
    let Some(sources) = rng::Sources::take_all() else {
        // Unreachable by construction — this is the first and only `take_all` in
        // the image — so if it fires, a `TakeOnce` tag decoded wrong and every
        // singleton in the tree is suspect. Reset, do not continue without entropy.
        panic!("entropy singletons already taken");
    };
    let mut entropy = match rng::Entropy::boot(sources) {
        Ok(entropy) => {
            // Rule 4 of `panic::boot_sequencing`: clear `RngFault` only once
            // entropy is *proven*, which is precisely what an `Ok` here is. Its
            // budget is separate from `Panic`'s, so it clears here and not with the
            // other one.
            let _ = clear_counter(Counter::RngFault);
            entropy
        }
        Err(_fault) => {
            // The one counter nothing else bumps: `Counter::RngFault` documents
            // itself as "consecutive `RngFault`s at boot", and this is the only
            // place a boot-time entropy failure is observable. Bump BEFORE the
            // panic — the panic handler only ever touches `Counter::Panic`, so
            // without this the entropy budget would never accumulate.
            //
            // No retry loop. A stuck source stays stuck (`Entropy::boot`'s own
            // docs) and retrying at boot is a brick, so this resets instead.
            let _ = bump_counter(Counter::RngFault);
            panic!("entropy fail-closed");
        }
    };

    // --- Step 8: flash. ----------------------------------------------------
    // `open()` and not a bare `take()`: opening is what reads `FLASH->OPTR` and
    // applies the DBANK check, and it clears the stale `FLASH->SR` error bits the
    // bootloader leaves behind (including `PEMPTY`). Both are once-per-boot work,
    // and doing them here means a wrong page geometry is a reset at boot instead of
    // a surprise on the first nonce write.
    let Some(Ok(flash)) = flash::StmFlashToken::take().map(flash::StmFlashToken::open) else {
        panic!("flash geometry");
    };
    // Into a `RefCell` immediately, because the signer's nonce slots hold a
    // SHARED borrow of the flash for as long as `boot`'s frame lives, while
    // `identity::load_or_create` wants `&mut`. `borrow_mut()` below is a
    // statement-scoped temporary, so the `RefMut` is dead before the slots exist.
    // `DebugFlash` supplies the `core::fmt::Debug` that `FrostSigner::new`'s bound
    // demands and nothing else — delete it the day the HAL grows its own impl.
    //
    // From here on `flash` has the same rule `link` has: nothing may hold a borrow
    // across a call that might take another, because a `RefCell` double-borrow
    // panics and every reachable panic on this unit is a brick.
    let flash = RefCell::new(DebugFlash(flash));

    // --- Step 8b: identity. ------------------------------------------------
    // Generated once, on the first boot that finds no committed record, and read
    // back off flash on every boot after that. `DeviceId` derives from this
    // secret, so a second one is a second device and every share the user holds
    // would be orphaned — which is why `load_or_create` refuses rather than
    // regenerates when a committed record does not verify.
    //
    // NOT a panic on `Err`, unlike steps 7-9 above, and the failure policy at the
    // top of this function says why: a damaged flash record is stable across
    // resets, so panicking on it spends a bounded counter on an unclearable fault
    // and ends in `LOCKUP_FOREVER`. The refusal is a hold, and the hold is DARK —
    // it sits below step 9, so USB never comes up and no coordinator can reach a
    // device that cannot prove its identity. See the `Err` arm.
    //
    // Placed after step 8 deliberately: flash is already proven open here, so
    // "generated a key but could not persist it" is unreachable rather than
    // handled.
    let secret = match identity::load_or_create(&mut *flash.borrow_mut(), &mut entropy) {
        Ok(secret) => secret,
        // HOLD, and deliberately not a `panic!()` like every bring-up step above.
        // The asymmetry is the point: those faults are plausibly transient, so a
        // counted reset can self-heal. An identity fault is a property of bytes
        // sitting in flash, so it is bit-for-bit identical on the next boot —
        // panicking would spend the `Counter::Panic` budget on a fault that cannot
        // clear and end in `LOCKUP_FOREVER`, which is indistinguishable from dead
        // silicon at a bench.
        //
        // Held BEFORE USB, so a device that cannot prove which device it is never
        // enumerates and a coordinator can never talk to it. `Damaged` in
        // particular means this device may ALREADY have announced and be holding
        // the user's shares, so continuing under a fresh identity is the one
        // outcome that destroys a wallet rather than merely failing.
        //
        // The hold stays above USB bring-up: a device that cannot prove which
        // device it is must never enumerate. Do NOT resolve a future diagnostic
        // need by moving USB earlier — that trades the security property for a
        // channel. The panel is the diagnostic, and it needs no host.
        // PLAN.md §9 item 14: the hold used to be DARK, which is correct
        // fail-closed behaviour but indistinguishable from dead silicon at a
        // bench. Say why, then hold — see `hold`, which diverges, so this arm
        // still cannot fall through to a device without an identity.
        Err(fault) => hold(match fault {
            // Wording matters: this is the one that means "this device may
            // already hold the user's shares", i.e. do not re-key it.
            identity::IdentityFault::Damaged => "damaged record",
            identity::IdentityFault::Flash(_) => "flash refused",
            identity::IdentityFault::VerifyFailed => "write unverified",
            identity::IdentityFault::NoScalar => "no valid scalar",
        }),
    };

    // --- Step 8c: the signer. ----------------------------------------------
    // The real `FrostSigner`, keyed by the durable identity secret and backed by
    // the nonce slots in `FLASH_FS` — not `new_random`, not `MemoryNonceSlot`. A
    // signer whose nonces do not survive a power cycle re-issues nonces after a
    // reset, and FROST nonce reuse leaks the share.
    //
    // FAILURE POLICY, and it is the third of three in this function on purpose.
    // `Session::open`'s only failure is `Fault::IdentityScalar`: the stored secret
    // is not a usable scalar. That is a property of bytes in flash, identical on
    // the next boot, so it belongs with the identity hold and NOT with the
    // `panic!()`s of steps 7-9 — a counted reset cannot clear it and would end in
    // `LOCKUP_FOREVER`. Same hold, same screen, and the same reason string
    // `IdentityFault::NoScalar` gets, because to a user at a bench it is the same
    // fault: this device cannot prove which device it is.
    //
    // Unreachable in practice — `load_or_create` only ever returns bytes it has
    // checked are `0 < s < n` — but it is an `Option`, so it is an arm and never an
    // `expect`.
    let mut session = match Session::open(&flash, &secret) {
        Ok(session) => session,
        Err(_fault) => hold("no valid scalar"),
    };

    // The digest a coordinator sees. Computed once, before USB, over the range the
    // bootloader signs; `firmware_digest` bounds the header's length field three
    // ways before using it.
    //
    // An all-zero digest when the header is unreadable, never a panic and never a
    // skipped announce: zeros can match no released firmware, so upgrade
    // eligibility fails closed, and the device still announces and is still
    // usable. On real hardware `None` is unreachable — the bootloader will not
    // start an image whose header it could not verify.
    //
    // Nothing in this tree emits the header and nothing should: `link.x` reserves
    // the 128 bytes by shrinking `FLASH_ISR`, and `cli/signit.py` writes the slot
    // itself at pack time from its own CLI arguments (`signit.py:315-325`),
    // *discarding* whatever the input had there (`signit.py:275-276` splits the
    // `-r` input around the slot and keeps neither end of it). So `Some` is the
    // path taken for any signed artifact, and `None` only for an unsigned flat
    // binary on a bench, where the slot is still erased `0xff`.
    //
    // SAFETY: `FLASH_ISR_BASE .. + FLASH_ISR_LEN + FLASH_TEXT_LEN` is this image's
    // own memory-mapped, read-only flash, const-asserted contiguous and to end at
    // `FLASH_FS_BASE` in `hal/src/lib.rs`. Nothing writes it, so a shared slice
    // over it aliases nothing mutably. Erased cells read as `0xff`; no read past
    // the header's length field happens unless that field passed its bounds.
    let image = unsafe {
        core::slice::from_raw_parts(
            memmap::FLASH_ISR_BASE as *const u8,
            (memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN) as usize,
        )
    };
    let digest = firmware_digest(image).unwrap_or(Sha256Digest([0u8; 32]));

    // The panel, for the rest of the boot. Best-effort and `Option`: a device that
    // cannot draw is still a device that can sign, so a display fault must not be a
    // reset. Taken AFTER both holds above, each of which diverges, so the
    // take-once can never be contended.
    let mut panel = display::PanelToken::take()
        .map(display::PanelToken::open)
        .and_then(Result::ok);

    // One standby frame, before USB, so a bench sees a live device rather than a
    // dark one while it waits for a coordinator. Every field is the truth: this
    // device has no stored name (it sends `NeedName` on every announce) and holds
    // no share (nothing persists `staged_mutations()` yet).
    if let Some(panel) = panel.as_mut() {
        let mut frame = ui::Frame::new();
        ui::standby(&mut frame, "no name", "", None);
        let _ = panel.show(frame.as_bytes());
    }

    // --- Step 9: USB. ------------------------------------------------------
    // `open()` runs `bring_up`, which enables `OTGFSEN`/`PWREN`/`USV` itself. The
    // 48 MHz CLK48 source is NOT programmed by anything in this tree — see the
    // module docs. Nothing here fakes it.
    let Some(Ok(mut cdc)) = usb::UsbToken::take().map(usb::UsbToken::open) else {
        panic!("usb bring-up");
    };

    // --- Step 10: the event loop. ------------------------------------------
    let mut packet = [0u8; usb::MAX_PACKET_SIZE];
    // Latched so the clear is attempted once, not on every iteration of a hot loop
    // that would otherwise write a backup register forever.
    let mut cleared = false;

    // The device end of the wire. `Link::new` is `const`, and this lives in `boot`'s
    // frame rather than in a `static` on purpose: `boot` never returns, so the frame
    // is effectively permanent, and a `static` would put `FRAME_LIMIT` bytes in `.bss`
    // for the entry to zero on every boot for no benefit. The stack descends from
    // `ESTACK_TOP` with 548,268 B of runway (MEASURED: `ESTACK_TOP - _end` in the
    // linked ELF), so a 4 KiB inline buffer is affordable — but it IS the largest
    // single thing on this stack, ahead of `ui::Frame` at 1,024 B and the signer at
    // 272 B, so it is the first place to look if the runway ever gets tight. There
    // is no stack-depth tool in this tree to say when that is, and no guard page
    // either: Armv7E-M has no MSPLIM, so the runway is the only thing between a
    // descending SP and the bootloader's `dfu_flag`.
    let mut link = comms::Link::new();

    // Set inside `poll`'s callback and acted on after it returns. `poll` borrows
    // `link` mutably for the duration of the callback, so nothing that touches
    // `link` — or that could panic into a path that inspects it — may run in there.
    // Deferring the write also keeps the USB write off the callback's stack depth.
    let mut send_magic_reply = false;

    // Replies, already encoded and already capped (one nonce segment per frame, a
    // truncated `Debug`, an over-long `HeldShares2` refused whole). Filled inside
    // `poll`'s callback and drained to `cdc` after it returns, for the same reason
    // `send_magic_reply` is: the callback holds `link` and must not also reach the
    // USB write path.
    let mut outbox = Outbox::new(session.device_id());

    loop {
        // `unwrap_or(0)` and never `?`/`unwrap`: see the failure policy above. A
        // coordinator chooses the packet length.
        let n = cdc.poll(&mut packet).unwrap_or(0);

        // Every byte from here to `decode_body` is coordinator-controlled. The bound
        // is structural — `Link`'s accumulator IS `[u8; FRAME_LIMIT]` — and both
        // decode legs are limited (`DECODE_ALLOC_LIMIT`, `ENCAPS_DECODE_LIMIT`), so
        // this is the first place in the image where those refusals actually run.
        let mut handled_frame = false;
        // Read off the link itself rather than latched across iterations, so the
        // `continue` on a desync cannot leave a stale flag behind: `Link::poll`
        // unlinks on desync, so the next successful handshake is an edge again and
        // re-announces, which is exactly what a restarted coordinator needs.
        let was_linked = link.is_linked();
        let polled = link.poll::<comms::FromCoordinator, _>(&packet[..n], |frame| {
            match frame {
                // The coordinator re-sends its pattern every `MAGIC_BYTES_PERIOD`
                // until it reads our reply, so seeing this once we are already
                // linked is ordinary, not an error.
                comms::ReceiveSerial::MagicBytes(_) => send_magic_reply = true,
                comms::ReceiveSerial::Message(msg) => {
                    // `decode_body`, NOT the vendored `.decode()`: the vendored one
                    // re-enters bincode with a 32 KiB budget where a 20-byte inner
                    // blob provokes a 32,640 B allocation. See `comms::decode_body`.
                    match comms::decode_body(msg.message_body) {
                        Ok(body) => {
                            // Unchanged from before the dispatch landed, and
                            // deliberately: a decoded frame is what proves the
                            // core reset, the FIFOs, enumeration, every control
                            // transfer, the RX path and both decode legs worked.
                            // What the device then chooses to DO with the body —
                            // answer it, refuse it, or find it out of order — is
                            // policy, and a refusal is a healthy image, not an
                            // unhealthy one.
                            handled_frame = true;
                            // The dispatch. NOTHING here may panic: every byte in
                            // `body` is coordinator-controlled, so a panic is a
                            // remote reset loop, and `session` reports with a
                            // `Fault` rather than unwinding.
                            match session.recv(body, &mut entropy, &mut outbox) {
                                // Drawn inside the callback because the panel is
                                // not `link` and is not `flash`: no borrow of
                                // either is held across it. Replies still leave via
                                // the outbox after `poll` returns.
                                Ok(prompts) => {
                                    for prompt in &prompts {
                                        draw_prompt(panel.as_mut(), prompt);
                                    }
                                }
                                // A policy refusal is worth a screen — it is the
                                // device saying no, which a user is entitled to
                                // see. A state error (`Cancel` mid-keygen, a
                                // replayed phase) is the coordinator's bookkeeping
                                // and there is nothing to show; either way this
                                // returns, never resets.
                                Err(Fault::Refused(_)) => {
                                    if let Some(panel) = panel.as_mut() {
                                        let mut frame = ui::Frame::new();
                                        ui::refusal(&mut frame);
                                        let _ = panel.show(frame.as_bytes());
                                    }
                                }
                                Err(_fault) => {}
                            }
                        }
                        // Not a desync: the framing is intact and the link stays up,
                        // so one unreadable body must not drop a working link.
                        Err(_e) => {}
                    }
                }
                // Conch is off on this firmware (`Downstream::VERSION_SIGNAL` is 2 and
                // the conch protocol needs 1), and `Reset` is the coordinator telling
                // us to drop state we do not hold yet.
                _ => {}
            }
        });

        if polled.is_err() {
            // `Link::poll` has already unlinked itself, so recovery is to wait for
            // the coordinator's next magic bytes. Nothing to do but keep polling —
            // and specifically NOT to reset: a desync is a coordinator that mis-spoke,
            // not a fault in this device, and resetting on it would let a hostile
            // coordinator reset-loop us.
            continue;
        }

        if send_magic_reply {
            send_magic_reply = false;
            // A const, not an `encode_frame` call: the ARM send path should not need
            // a `FRAME_LIMIT` staging buffer and a monomorphised encoder to say hello.
            let _ = cdc.write(&comms::MAGIC_REPLY);
        }

        // Announce on the LINK EDGE, after the magic reply, exactly where upstream
        // does it (`device/src/esp32_run.rs:349-367`: the `PowerOn` ->
        // `Established` transition). Not once per boot — a coordinator that
        // restarts re-sends magic and expects a fresh announce — and not on every
        // magic frame, which arrives every `MAGIC_BYTES_PERIOD` for as long as we
        // are linked.
        //
        // `let _`, not `?`: `announce` can only fail by refusing to frame a 32-byte
        // digest and a `NeedName`, which cannot happen, and if it somehow did, an
        // unannounced device that keeps polling is recoverable while a reset loop
        // is not. There is no `SetName` to send instead — this device has nowhere
        // durable to keep a name, so it asks for one every time.
        if !was_linked && link.is_linked() {
            let _ = session.announce(digest, &mut outbox);
        }

        // The only place a reply reaches the wire. `write` chunks to
        // `MAX_PACKET_SIZE` itself and the framing is self-delimiting, so one call
        // per drain is enough however many frames are buffered — and draining
        // every iteration is what keeps the outbox's ~8 KiB worst case (a 4-stream
        // nonce replenishment) from being resident.
        if outbox.frames() > 0 {
            let bytes = outbox.take();
            let _ = cdc.write(&bytes);
        }

        // One received data packet means the core reset, the FIFOs, enumeration,
        // every control transfer and the RX path all worked: "at least one full
        // iteration that did real work", not merely "reached the loop" (rule 2). An
        // empty poll does not count, which is why this is `n > 0` and not
        // `is_configured()`.
        //
        // `!health.in_reset_loop()` is the second condition and it is load-bearing:
        // on a unit already past the threshold, clearing here would reset the
        // budget to 0 on every boot, so a fault that fires just after this point
        // would loop forever instead of the counter reaching
        // `PANIC_RESET_THRESHOLD` and the reset loop terminating. Refusing to clear
        // lets the counter finish climbing. (There is no DFU fallback beyond it —
        // decision 6, RDP=2.) 
        //
        // `let _ =` on the result, per rule 3: a dead backup domain must not be a
        // dead device.
        if handled_frame && !cleared && !health.in_reset_loop() {
            cleared = true;
            let _ = clear_counter(Counter::Panic);
        }
    }
}
