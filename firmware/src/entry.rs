//! Hardware bring-up: **steps 1-4a** of PLAN.md's amended step list.
//!
//! # What is here, and why in this order
//!
//! 1. `SCB->VTOR <- memmap::FLASH_ISR_BASE`, then `dsb()`. **First**, because the
//!    bootloader hands off with VTOR still 0, aliasing its own vector table whose
//!    fault handlers are `bkpt; b .` (`mk4-bootloader/startup.S:43-59`). NMI is
//!    unmaskable and reachable from a flash double-bit ECC error, so every
//!    instruction executed before this write sits in a window where a fault hangs
//!    forever instead of resetting — which is exactly what DECISIONS.md decision 6
//!    exists to prevent. Nothing may be moved above it.
//! 2. `CPACR <- CP10/CP11 full access`, then `dsb(); isb()`. `-eabihf` is a
//!    hard-float ABI: any `f32`/`f64` crossing a call boundary travels in
//!    `s0`/`d0`, which is a NOCP UsageFault with the FPU off, and LTO can pull
//!    `libm` in without anyone noticing. The bootloader already enables the FPU
//!    (`clocks.c:87-89`) but behind a compile-time `#if`, so this is a defensive
//!    re-assert. It is **not** for `memcpy`: measured, zero FP instructions in any
//!    of the 27 `mem*` bodies on thumbv7em. Before steps 3-4 because those loops
//!    are the first code that could plausibly be vectorised into FP registers by a
//!    future compiler.
//! 3. Zero `.bss`, explicit `u32` `write_volatile` loop over `_sbss.._ebss`.
//! 4. Copy `.data`, explicit `u32` loop from `_sidata` into `_sdata.._edata`.
//!    **Both loops are mandatory**: which one a given `static` needs is decided by
//!    whether its initialiser is zero, not by choice. 3 before 4 is not required
//!    for correctness — the spans are disjoint by construction (`link.x` places
//!    `.bss` after `.data`) — but the pair must complete before anything reads a
//!    `static`, because all SRAM below `memmap::BL_SRAM_BASE` arrives filled with
//!    `0xdeadbeef` (`mk4-bootloader/main.c:42,47-49`), not zeroed.
//!
//! Then step 4a: `compiler_fence(SeqCst)`. The barrier there is against the
//! *compiler*, not the bus — there is no D-cache on Cortex-M4 and the ART
//! accelerator caches I-fetch from flash only, so no cache maintenance is owed.
//!
//! Everything from step 5 on — heap init, `BootHealth::read()`, the singleton
//! takes, USB, the event loop — belongs to the wire-up agent and lands after
//! [`init_hardware`] returns. What it needs from here is simply that on return
//! every `static` in the image holds its declared initial value, and that a fault
//! from that point on reaches our own trampolines rather than the bootloader's
//! `b .`.
//!
//! # Deliberately NOT here
//!
//! * **SysTick is untouched.** The callgate polls its COUNTFLAG for SE1 timeouts
//!   and COUNTFLAG *clears on read*, so reprogramming or disabling it silently
//!   breaks every SE operation.
//! * **No `cpsie i`.** PRIMASK arrives set (`dispatch.c:98`) and stays set.
//! * **No clock, PWR or RCC work.** SYSCLK is already 120 MHz; USB's 48 MHz is the
//!   wire-up agent's problem.
//!
//! # The testable/untestable split
//!
//! Same split as `usb.rs` (registers, untestable) vs `comms.rs` (pure, fully
//! tested): [`zero_words`] and [`copy_words`] are pure functions over their
//! bounds and are host-tested below over ordinary arrays. Only the SCB writes and
//! the linker-symbol plumbing — which resolve to nothing on a host — sit in the
//! `#[cfg(target_arch = "arm")]` module, and they are the only lines no test can
//! reach.

/// Zero `[start, end)`, one `u32` at a time.
///
/// `write_volatile` so LLVM cannot elide stores to memory it can prove nothing
/// reads (which is the whole of `.bss` as far as it can see, since the `static`s
/// living there have not been touched yet), and cannot turn the loop into a
/// `memset` call — there is no libc here and `compiler_builtins`' `memset` is not
/// something this path should depend on before `.data` exists.
///
/// The bound is `<`, i.e. `end` is one-past-the-end and is never written. It is
/// `_ebss`, which `link.x` places at the start of `.uninit` — the heap backing
/// store. Writing it would zero someone else's memory.
///
/// # Safety
///
/// `start` and `end` must be 4-aligned, `start <= end`, and `[start, end)` must be
/// a writable span within one allocation. `link.x` ASSERTs the alignment of the
/// real bounds at link time.
// Off ARM only `mod arm` calls these, and `mod arm` does not exist there, so the
// host non-test build (which cannot link anyway -- no `main`) sees them as dead.
// `cfg_attr`, NOT a bare `allow`: on ARM the dead-code check stays live, so
// deleting the step-3 or step-4 call site is still a warning.
#[cfg_attr(not(target_arch = "arm"), allow(dead_code))]
unsafe fn zero_words(start: *mut u32, end: *mut u32) {
    let mut p = start;
    while p < end {
        // SAFETY: `p` is in `[start, end)`, which the caller guarantees is
        // writable and aligned.
        unsafe {
            p.write_volatile(0);
            p = p.add(1);
        }
    }
}

/// Copy words from `src` into `[dst, dst_end)`.
///
/// The destination drives the loop because the destination is what has a known
/// end: `_sdata.._edata` are section bounds, while `_sidata` is only a load
/// address with no symbol marking its end. Copying `dst_end - dst` words is
/// therefore the same count either way, and asking the source for its length
/// would mean trusting a symbol the linker does not define.
///
/// Volatile on both ends: on the write for the same reason as [`zero_words`], and
/// on the read so the pair cannot be fused into a `memcpy` call.
///
/// # Safety
///
/// All three pointers 4-aligned, `dst <= dst_end`, `[dst, dst_end)` writable, and
/// `src` readable for the same number of words. The spans must not overlap.
// Off ARM only `mod arm` calls these, and `mod arm` does not exist there, so the
// host non-test build (which cannot link anyway -- no `main`) sees them as dead.
// `cfg_attr`, NOT a bare `allow`: on ARM the dead-code check stays live, so
// deleting the step-3 or step-4 call site is still a warning.
#[cfg_attr(not(target_arch = "arm"), allow(dead_code))]
unsafe fn copy_words(src: *const u32, dst: *mut u32, dst_end: *mut u32) {
    let mut s = src;
    let mut d = dst;
    while d < dst_end {
        // SAFETY: `d` is in `[dst, dst_end)` and `s` is the matching word of the
        // source span, both guaranteed by the caller.
        unsafe {
            d.write_volatile(s.read_volatile());
            s = s.add(1);
            d = d.add(1);
        }
    }
}

/// Bring the machine up far enough to run Rust: steps 1-4a above.
///
/// Returns with every `static` holding its declared initial value and with faults
/// vectoring into this image. Steps 5-10 follow at the call site.
///
/// # Safety
///
/// Callable exactly once, from the reset entry, before any `static` is read and
/// before any allocation. Calling it twice would re-zero `.bss` and re-copy
/// `.data` underneath live state.
pub unsafe fn init_hardware() {
    // Every line of the body touches either an SCB register or a linker-defined
    // symbol, neither of which exists on a host, so the body is ARM-only and the
    // host build of this function is empty. The loop LOGIC it delegates to is
    // target-independent and tested below.
    #[cfg(target_arch = "arm")]
    // SAFETY: the caller's contract is this function's contract, forwarded.
    unsafe {
        arm::init();
    }
}

/// The untestable half: two SCB registers and five linker symbols.
///
/// Nothing in here can run on a host — `hal::panic::{dsb, isb}` are themselves
/// `#[cfg(target_arch = "arm")]`, and `_sbss` and friends are undefined symbols
/// off-target — so it is quarantined behind one `cfg` and kept as thin as it can
/// be: no logic, only addresses, bounds and call order.
#[cfg(target_arch = "arm")]
mod arm {
    use coldsnap_hal::memmap;
    use coldsnap_hal::panic::{dsb, isb};
    use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

    /// System Control Block base. ARMv7-M ARM (ARM DDI 0403E.e) §B3.2.2, table
    /// B3-4 "System control block registers": SCB occupies `0xE000_ED00`.
    const SCB_BASE: u32 = 0xE000_ED00;

    /// `SCB->VTOR`, SCB offset `0x08` (DDI 0403E.e §B3.2.5, "Vector Table Offset
    /// Register"). Bits `[31:7]` are the table base; `0x0802_0000` satisfies the
    /// alignment rule (base aligned to at least the table size rounded up to 32
    /// words), which `link.x` also states as `ALIGN(512)`.
    const SCB_VTOR: *mut u32 = (SCB_BASE + 0x08) as *mut u32;

    /// `SCB->CPACR`, SCB offset `0x88` (DDI 0403E.e §B3.2.20, "Coprocessor Access
    /// Control Register").
    const SCB_CPACR: *mut u32 = (SCB_BASE + 0x88) as *mut u32;

    /// CP10 and CP11 at full access: CPACR `[21:20]` = `0b11` and `[23:22]` =
    /// `0b11` (DDI 0403E.e §B3.2.20). CP10 and CP11 must always be programmed
    /// identically — they are the two halves of one FPU access control.
    const CPACR_CP10_CP11_FULL: u32 = 0x00F0_0000;

    /// The only `static` in this image that lands in `.bss`, and it exists for
    /// exactly that reason.
    ///
    /// Every `static` in `coldsnap_hal` has a non-zero initialiser and lands in
    /// `.data`, and zero of the 131 device rlibs contain a `.bss` section at all —
    /// so without this word `_sbss == _ebss`, [`zero_words`](super::zero_words) is
    /// called with an empty span, and the loop on the most dangerous path in the
    /// project has no user on target. `AtomicU32` rather than `u32` because a
    /// plain immutable `static u32` goes to `.rodata` in flash; interior
    /// mutability is what forces it into writable SRAM, and a zero initialiser is
    /// what puts it in `.bss` rather than `.data`.
    ///
    /// `#[used]` so `--gc-sections` cannot delete the section and take
    /// `_sbss != _ebss` with it.
    #[used]
    static BSS_CANARY: AtomicU32 = AtomicU32::new(0);

    extern "C" {
        /// `.bss` start, `link.x`. 4-aligned by a link-time ASSERT.
        static mut _sbss: u32;
        /// `.bss` end, one-past. Also the start of `.uninit`, so never written.
        static mut _ebss: u32;
        /// `.data` start in RAM (VMA).
        static mut _sdata: u32;
        /// `.data` end in RAM, one-past.
        static mut _edata: u32;
        /// `.data` image in flash (LMA) — `LOADADDR(.data)`.
        static _sidata: u32;
    }

    /// # Safety
    ///
    /// See [`init_hardware`](super::init_hardware); this is its body.
    pub(super) unsafe fn init() {
        // SAFETY: each write below is to a fixed, documented memory-mapped
        // register; the two loops are given the linker's own section bounds,
        // whose alignment `link.x` ASSERTs and whose containment within RAM the
        // same script enforces.
        unsafe {
            // --- Step 1: faults become ours. Nothing may precede this. --------
            SCB_VTOR.write_volatile(memmap::FLASH_ISR_BASE);
            // `dsb` and not `compiler_fence`: the store must have left the write
            // buffer before the next fault can be taken, and a `compiler_fence`
            // emits zero instructions.
            dsb();

            // --- Step 2: FPU. -----------------------------------------------
            // Read-modify-write, not a bare store: CP0..CP7 are reserved on this
            // core and read as zero, but preserving whatever the bootloader left
            // costs two instructions and cannot be wrong. Safe without a lock —
            // PRIMASK is set and no other master writes CPACR.
            let cpacr = SCB_CPACR.read_volatile();
            SCB_CPACR.write_volatile(cpacr | CPACR_CP10_CP11_FULL);
            // `dsb` then `isb`: drain the store, then flush the pipeline, so the
            // first FP instruction cannot already be in flight from before the
            // coprocessor was enabled. Both are required and neither is a
            // `compiler_fence`.
            dsb();
            isb();

            // --- Step 3: zero `.bss`. ---------------------------------------
            super::zero_words(
                core::ptr::addr_of_mut!(_sbss),
                core::ptr::addr_of_mut!(_ebss),
            );

            // The loop's only on-target check. A non-zero read here means either
            // the loop is wrong or the linker bounds are, and both are silent
            // corruption of every `static` in the image — so trip immediately.
            // `read_volatile` rather than `load()` because LLVM can see that
            // nothing ever stores to this `static` and is entitled to fold an
            // atomic load of it to the constant 0, which would delete the check.
            //
            // Panicking before step 4 is sound: `hal::panic`'s recursion guard
            // `PANIC_DEPTH` is tagged with `DEPTH_MAGIC`, so an untagged
            // `0xdeadbeef` decodes as depth 0 and the handler is correct
            // pre-`.data` (`hal/src/panic.rs`, "SRAM IS NOT ZERO ON THIS BOARD").
            if core::ptr::read_volatile(BSS_CANARY.as_ptr()) != 0 {
                panic!("bss not zeroed");
            }

            // --- Step 4: copy `.data`. --------------------------------------
            // Mandatory, not a nicety: `hal::panic`'s `PANIC_DEPTH` initialiser is
            // `DEPTH_MAGIC = 0xD3E1_0000`, non-zero, so it lives here and not in
            // `.bss`. Without this loop it reads `0xdeadbeef` forever.
            super::copy_words(
                core::ptr::addr_of!(_sidata),
                core::ptr::addr_of_mut!(_sdata),
                core::ptr::addr_of_mut!(_edata),
            );

            // --- Step 4a: publish. ------------------------------------------
            // Enough on this part: no D-cache on Cortex-M4, and the ART
            // accelerator caches instruction fetch from flash only, so the two
            // loops' stores are already coherent with every later load. All that
            // is owed is that the compiler not sink them past the first `static`
            // read.
            //
            // BENCH NOTE: upgrade to `dsb(); isb()` if a `.ramfunc` ever lands
            // here. Copying *code* into SRAM needs the instruction stream flushed,
            // which a `compiler_fence` (zero instructions emitted) does not do.
            compiler_fence(Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_words, zero_words};

    /// Sentinel that is not a plausible correct value for either loop to write,
    /// so a guard word still holding it proves the loop stayed in bounds.
    const GUARD: u32 = 0xA5A5_A5A5;

    #[test]
    fn zero_words_clears_every_word_in_the_span() {
        let mut ram = [1u32, 2, 3, 4, 5, 6];
        let start = ram.as_mut_ptr();
        // SAFETY: `[start, start+6)` is the whole array.
        unsafe { zero_words(start, start.add(6)) };
        assert_eq!(ram, [0; 6]);
    }

    #[test]
    fn zero_words_does_not_write_at_or_past_the_end_bound() {
        // `_ebss` is the first word of `.uninit`, i.e. the heap. Writing it is
        // silent corruption of memory this loop does not own.
        let mut ram = [GUARD; 5];
        let start = ram.as_mut_ptr();
        // SAFETY: the span is the first three words of a five-word array.
        unsafe { zero_words(start, start.add(3)) };
        assert_eq!(ram, [0, 0, 0, GUARD, GUARD]);
    }

    #[test]
    fn zero_words_on_an_empty_span_writes_nothing() {
        // The span the real `_sbss.._ebss` had before `BSS_CANARY` existed, and
        // the span it returns to if that canary is ever deleted.
        let mut ram = [GUARD; 2];
        let start = ram.as_mut_ptr();
        // SAFETY: `start == end`, so the loop body never runs.
        unsafe { zero_words(start, start) };
        assert_eq!(ram, [GUARD; 2]);
    }

    #[test]
    fn copy_words_copies_every_word_including_the_last() {
        let flash = [0xD3E1_0000u32, 0x1111_1111, 0x2222_2222, 0x3333_3333];
        let mut ram = [0xDEAD_BEEFu32; 4];
        let dst = ram.as_mut_ptr();
        // SAFETY: four words of source, four words of destination, disjoint.
        unsafe { copy_words(flash.as_ptr(), dst, dst.add(4)) };
        assert_eq!(ram, flash);
    }

    #[test]
    fn copy_words_leaves_the_source_untouched() {
        // Source and destination swapped is not a visible failure in the
        // destination when the destination happens to start out interesting, so
        // check the flash image explicitly. On target it is in flash and the
        // write would fault or be dropped, not merely be wrong.
        let flash = [0xD3E1_0000u32, 0x1111_1111];
        let mut ram = [0xDEAD_BEEFu32; 2];
        let dst = ram.as_mut_ptr();
        // SAFETY: two words each way, disjoint spans.
        unsafe { copy_words(flash.as_ptr(), dst, dst.add(2)) };
        assert_eq!(flash, [0xD3E1_0000u32, 0x1111_1111]);
        assert_eq!(ram, flash);
    }

    #[test]
    fn copy_words_does_not_write_past_the_destination_end() {
        let flash = [1u32, 2, 3, 4, 5];
        let mut ram = [GUARD; 5];
        let dst = ram.as_mut_ptr();
        // SAFETY: the destination span is the first two words of `ram`; `flash`
        // is longer, which is exactly the case an over-run would expose.
        unsafe { copy_words(flash.as_ptr(), dst, dst.add(2)) };
        assert_eq!(ram, [1, 2, GUARD, GUARD, GUARD]);
    }

    #[test]
    fn copy_words_on_an_empty_span_copies_nothing() {
        let flash = [1u32, 2];
        let mut ram = [GUARD; 2];
        let dst = ram.as_mut_ptr();
        // SAFETY: `dst == dst_end`, so the loop body never runs.
        unsafe { copy_words(flash.as_ptr(), dst, dst) };
        assert_eq!(ram, [GUARD; 2]);
    }
}
