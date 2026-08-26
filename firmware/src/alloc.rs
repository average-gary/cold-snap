//! The image's single `#[global_allocator]`: `linked_list_allocator` 0.10.6 over a
//! 64 KiB static arena, plus the two guards that make its failure modes *counted
//! resets* instead of silent free-list corruption.
//!
//! It lives in the bin crate, never in the HAL — `hal/src/heap.rs` is constants
//! only, because a library that registers a global allocator dictates it to every
//! consumer including host tests.
//!
//! # Why a hand-rolled wrapper
//!
//! `linked_list_allocator::LockedHeap` **and its `GlobalAlloc` impl** are both
//! `#[cfg(feature = "use_spin")]`, and `Heap` is `Send` but not `Sync`. We do not
//! enable `use_spin`: PRIMASK is 1 for the whole life of this image
//! (`mk4-bootloader/dispatch.c:98`, never re-enabled) so there is nothing to
//! contend with, and a spinlock would *hang forever* if an ISR ever allocated —
//! on a unit with no DFU that is worse than any race. So the wrapper is ours:
//! `UnsafeCell<Heap>` + `unsafe impl Sync` + `impl GlobalAlloc`, the shape already
//! host-exercised as `Lll`/`lll_alloc`/`lll_dealloc` at
//! `hal/examples/heap_lifo.rs:197-256`, with the measurement counters stripped.
//!
//! The arena is `[MaybeUninit<u32>; _]` and not `[MaybeUninit<u8>; _]` on purpose:
//! `align_of::<u32>()` = 4 = `align_of::<Hole>()` on a 32-bit target, which makes
//! all four init-time panics in `HoleList::new` (`hole.rs:330,331,336,344`) true by
//! construction rather than by argument.
//!
//! # GUARD 1: the dealloc bounds check. This is the point of this file.
//!
//! `check_merge_bottom` (`hole.rs:246-252`) tests only an **upper** bound on the
//! freed node and then computes `(node as usize) - (bottom as usize)`. A pointer
//! *below* the heap underflows that subtraction — `overflow-checks = false` in
//! release — yielding a huge offset and installing a roughly 4 GiB hole in the free
//! list, after which the allocator hands out arbitrary addresses. The `hole.rs:501`
//! assert does **not** catch it: that one tests `node + size <= hole`, the other
//! end. So `dealloc` rejects any pointer outside `[arena, arena + ARENA_BYTES)`
//! *before* delegating, and a rejection is `panic!()` → [`coldsnap_hal::panic`]'s
//! counted reset. A reset that increments a counter beats a live free list that
//! points into the bootloader's 8 K.
//!
//! The remaining release-active asserts on the deallocate path (`hole.rs:501,535,554`,
//! `.expect()` at `:667`, `.unwrap()` at `:422`) are deliberately KEPT for the same
//! reason: they are corruption tripwires, and a counted reset is the better failure.
//! The **allocate** path has none, and returns null on exhaustion rather than
//! panicking — that is the property that made this crate the choice.
//!
//! # GUARD 2: the init sentinel. It must not be `0xdeadbeef`.
//!
//! All SRAM below `BL_SRAM_BASE` arrives filled with `0xdeadbeef`, not zeroed
//! (`mk4-bootloader/main.c:42,47-49`). So a "have I been initialised?" word whose
//! ready value is `0xdeadbeef` reports *initialised* on every cold boot — the one
//! condition it exists to detect. Same for `0x0000_0000` (what the `.bss` loop
//! leaves) and `0xffff_ffff`. [`READY`] is none of the three, and a mismatch makes
//! `alloc` return null → `handle_alloc_error` → panic → counted reset, rather than
//! handing out a pointer derived from a `Heap` full of `0xdeadbeef`.
//!
//! # Forbidden calls
//!
//! Never `extend`, `init_from_slice` or `from_slice`, and never branch on
//! `free()`/`used()`/`size()` (`lib.rs:204` wraps in release, `:221` is UB
//! pre-init). Forbidding `extend` is also what makes `hole.rs:443` unreachable.
//!
//! # Fit, measured not assumed
//!
//! At [`heap::HEAP_BYTES`] = 64 KiB: n=3 over 24 rounds high-water 38,640 B, n=9
//! over 6 rounds 42,336 B, both zero nulls with a flat per-round series, and 65,520
//! of 65,536 free again after the signer is dropped, so coalescing works.
//!
//! # Running the tests in this file
//!
//! `cargo test -p coldsnap_firmware` cannot work: the crate root is `#![no_std]`
//! `#![no_main]` and its `#[panic_handler]` is gated on `target_os = "none"`, so the
//! bin does not build for the host at all (`error: #[panic_handler] function
//! required` / `Undefined symbols: _main`). The tests are therefore run by
//! compiling *this file* as its own test crate — everything under test is reachable
//! without the rest of the image:
//!
//! ```text
//! # builds the rlibs; the bin link then fails on _main/panic_handler, which is expected
//! cargo build -p coldsnap_firmware --target aarch64-apple-darwin
//! D=target/aarch64-apple-darwin/debug/deps
//! rustc --test --edition 2021 firmware/src/alloc.rs -o /tmp/alloc_test \
//!   -L dependency=$D -L dependency=target/debug/deps \
//!   --extern coldsnap_hal=$(ls -t $D/libcoldsnap_hal-*.rlib | head -1) \
//!   --extern linked_list_allocator=$(ls -t $D/liblinked_list_allocator-*.rlib | head -1)
//! /tmp/alloc_test
//! ```
//!
//! The second `-L` is not optional: `coldsnap_hal` pulls the `bincode_derive`
//! **proc macro**, whose dylib cargo puts in the host `target/debug/deps` and not
//! under the target triple. Without it the failure is a misleading
//! `E0463: can't find crate for coldsnap_hal`.

use coldsnap_hal::heap;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use linked_list_allocator::Heap;

/// Arena length in `u32` words. See the module docs for why the element type is
/// `u32` and not `u8`.
const WORDS: usize = heap::HEAP_BYTES / 4;

/// The arena's true byte length — what [`Heap::init`] is handed and what the
/// [`Arena::contains`] bound is computed from. Derived from the word count rather
/// than from [`heap::HEAP_BYTES`] directly so it can never exceed the array.
const ARENA_BYTES: usize = WORDS * 4;

/// A [`heap::HEAP_BYTES`] that is not a multiple of 4 would silently give a heap
/// smaller than the constant claims. Build failure instead.
const _: () = assert!(ARENA_BYTES == heap::HEAP_BYTES);

/// Written by [`Arena::init_once`] and required by `alloc`. Not `0xdeadbeef` (cold
/// SRAM), not `0` (post-`.bss`-loop), not `0xffff_ffff` (erased flash / bus fault
/// reads) — see GUARD 2 in the module docs. Value is `b"HLL1"` little-endian.
const READY: u32 = 0x484c_4c31;

/// The whole allocator: control block and backing store in one static, so the
/// dealloc bounds come from the same object that was handed to [`Heap::init`] and
/// cannot drift from it, and so the tests can exercise an instance of their own.
struct Arena {
    /// The allocator proper. Garbage (`0xdeadbeef`) until `init_once` overwrites
    /// both of its fields; [`READY`] is what stops anyone reading it before then.
    heap: UnsafeCell<Heap>,
    /// GUARD 2's sentinel.
    ready: UnsafeCell<u32>,
    /// The backing store.
    ///
    /// Placement is **measured, not assumed**: the whole `ALLOCATOR` static is
    /// emitted into `.bss._ZN..ALLOCATOR..`, 65,564 B, which `link.x`'s
    /// `*(.bss .bss.*)` collects — so it costs **zero flash** and the `ready` word
    /// gets zeroed by the entry's step-3 loop for free. (Read from the pre-LTO
    /// object: `cargo rustc --release -p coldsnap_firmware -- --emit=obj=/tmp/fw.o`
    /// then `llvm-readobj --syms`. It cannot be read from the linked image yet
    /// because nothing allocates, so the linker discards it — even under `#[used]`,
    /// which for ELF is an LLVM-level hint and does not stop section GC.)
    ///
    /// If 64 KiB of boot-time zeroing ever shows up in a measurement, `link.x`
    /// already places a `.uninit` (NOLOAD, after `_ebss`, before `_end`) that sits
    /// outside the zeroing range; moving it there is one `#[link_section]`, but it
    /// must then be `cfg_attr(target_os = "none", ..)` because Mach-O section names
    /// need a `segment,section` pair and the host test build would stop compiling.
    store: UnsafeCell<[MaybeUninit<u32>; WORDS]>,
}

// SAFETY: single-threaded by construction. PRIMASK is 1 for the life of the image
// and nothing here re-enables interrupts, so there is exactly one thread of control
// and no ISR can re-enter `alloc`/`dealloc`. This is the same argument that lets us
// skip `use_spin`; if either premise ever changes, this impl is the thing to revisit.
unsafe impl Sync for Arena {}

impl Arena {
    /// `const` so the static needs no runtime constructor. `Heap::empty()` is
    /// itself a `const fn`.
    const fn new() -> Self {
        Self {
            heap: UnsafeCell::new(Heap::empty()),
            ready: UnsafeCell::new(0),
            store: UnsafeCell::new([MaybeUninit::uninit(); WORDS]),
        }
    }

    /// Low bound of the backing store.
    fn lo(&self) -> usize {
        self.store.get() as usize
    }

    /// `true` iff `p` is inside the backing store. `wrapping_sub` rather than
    /// `p >= lo && p < lo + ARENA_BYTES` so the *check itself* cannot be the thing
    /// that overflows.
    fn contains(&self, p: usize) -> bool {
        p.wrapping_sub(self.lo()) < ARENA_BYTES
    }

    /// GUARD 2.
    fn is_ready(&self) -> bool {
        // SAFETY: single-threaded; no reference to `*ready` is held across this read.
        unsafe { *self.ready.get() == READY }
    }

    /// Hand the backing store to the heap. Idempotent: a second call returns
    /// without touching anything, because re-`init`ing a live heap would publish a
    /// single whole-arena hole over blocks that are still allocated.
    ///
    /// # Safety
    ///
    /// Call after `.bss` and `.data` are set up (`ready` lives in `.bss`, so an
    /// earlier call is undone by the zeroing loop — fail-closed, but useless).
    unsafe fn init_once(&self) {
        if self.is_ready() {
            return;
        }
        // SAFETY: single-threaded, and `&mut Heap` does not escape this block.
        // `store` is `'static`, 4-aligned, `ARENA_BYTES` long, and nothing else
        // ever reads or writes it — the only path to it is through this heap.
        unsafe {
            (*self.heap.get()).init(self.store.get().cast::<u8>(), ARENA_BYTES);
            *self.ready.get() = READY;
        }
    }
}

unsafe impl GlobalAlloc for Arena {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_ready() {
            // GUARD 2: fail CLOSED. Null is the documented "allocation failed"
            // answer, so this reaches `handle_alloc_error` -> panic -> counted
            // reset instead of returning a pointer computed from `0xdeadbeef`.
            return ptr::null_mut();
        }
        // SAFETY: single-threaded; `&mut Heap` does not escape. `allocate_first_fit`
        // has no release-active panic site and returns `Err` on exhaustion.
        match unsafe { (*self.heap.get()).allocate_first_fit(layout) } {
            Ok(p) => p.as_ptr(),
            Err(()) => ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // GUARD 1. See the module docs: `hole.rs:246-252` underflows on a pointer
        // below the heap and installs a ~4 GiB hole, and `hole.rs:501` tests the
        // other end so it does not catch it. `is_ready` is checked here too because
        // a free against an uninitialised `Heap` corrupts just as thoroughly.
        if !self.is_ready() || !self.contains(p as usize) {
            panic!("dealloc outside the heap arena");
        }
        // SAFETY: `p` is in the arena and `is_ready`, so it came from `alloc` above
        // with this `layout` (the `GlobalAlloc` contract supplies the rest).
        unsafe { (*self.heap.get()).deallocate(NonNull::new_unchecked(p), layout) };
    }
}

/// The registered allocator.
///
/// `#[global_allocator]` is applied only on the device: on the host this file is
/// compiled as its own test crate (see the module docs) and stealing the test
/// harness's allocator would deadlock it against [`READY`] before the first test
/// ran. Same conditional-by-target shape as `hal/src/panic.rs`'s `#[panic_handler]`.
#[cfg_attr(target_os = "none", global_allocator)]
static ALLOCATOR: Arena = Arena::new();

/// Bring the heap up. **Call exactly once**, from the entry, after `.bss` and
/// `.data` (PLAN.md step 5). Until it runs, every allocation is refused.
///
/// # Safety
///
/// Requires `.bss` and `.data` to be initialised. Extra calls are harmless — the
/// [`READY`] sentinel makes this idempotent — but the first one must not be early.
// The `#[allow(dead_code)]` that used to sit here is gone: `main.rs`'s
// `entry_point` calls this at step 5, so the warning it suppressed can no longer
// fire, and keeping it would hide a real regression if that call were ever removed.
pub unsafe fn init() {
    // SAFETY: forwarded to the caller's obligation above.
    unsafe { ALLOCATOR.init_once() };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test declares its own `static A: Arena` rather than sharing one: 64 KiB
    // is too much for a test thread's stack, and separate instances keep the tests
    // independent of each other's free lists.

    /// GUARD 2's whole reason for existing: cold SRAM is `0xdeadbeef`-filled, the
    /// `.bss` loop leaves `0`, and a bus-faulted or erased read gives `0xffff_ffff`.
    /// A sentinel equal to any of the three reports "initialised" when it is not.
    #[test]
    fn sentinel_is_not_a_cold_boot_pattern() {
        assert_ne!(READY, 0xdead_beef, "cold SRAM fill: main.c:42,47-49");
        assert_ne!(READY, 0x0000_0000, "what the .bss zeroing loop leaves");
        assert_ne!(READY, 0xffff_ffff, "erased flash / faulted read");
    }

    /// GUARD 1's predicate, at all four boundaries. `lo - 4` is the case
    /// `check_merge_bottom` underflows on.
    #[test]
    fn bounds_accept_inside_and_reject_outside() {
        static A: Arena = Arena::new();
        let lo = A.lo();
        assert!(A.contains(lo), "first byte is in range");
        assert!(A.contains(lo + ARENA_BYTES - 1), "last byte is in range");
        assert!(!A.contains(lo - 4), "below the heap: the underflow case");
        assert!(!A.contains(lo + ARENA_BYTES), "one past the end");
        assert!(!A.contains(0), "null");
    }

    /// The end-to-end version of GUARD 1: a real pointer from `alloc` survives
    /// `dealloc`, so the check is not simply rejecting everything.
    #[test]
    fn alloc_then_dealloc_accepts_an_in_range_pointer() {
        static A: Arena = Arena::new();
        unsafe { A.init_once() };
        let l = Layout::from_size_align(64, 4).unwrap();
        let p = unsafe { A.alloc(l) };
        assert!(!p.is_null(), "64 B out of {ARENA_BYTES} must succeed");
        assert!(A.contains(p as usize), "alloc handed out an in-range pointer");
        unsafe { A.dealloc(p, l) };
        // Coalesced back to one hole: the same request must be servable again.
        let q = unsafe { A.alloc(l) };
        assert_eq!(p, q, "the freed block came back");
    }

    /// GUARD 1 on the pointer that matters — below the arena.
    #[test]
    #[should_panic(expected = "dealloc outside the heap arena")]
    fn dealloc_below_the_arena_panics() {
        static A: Arena = Arena::new();
        unsafe { A.init_once() };
        let l = Layout::from_size_align(64, 4).unwrap();
        let p = unsafe { A.alloc(l) };
        assert!(!p.is_null());
        unsafe { A.dealloc((A.lo() - 4) as *mut u8, l) };
    }

    /// GUARD 1 at the other end, which is the one `hole.rs:501` *does* cover — but
    /// only after the free has already been let in.
    #[test]
    #[should_panic(expected = "dealloc outside the heap arena")]
    fn dealloc_above_the_arena_panics() {
        static A: Arena = Arena::new();
        unsafe { A.init_once() };
        unsafe {
            A.dealloc(
                (A.lo() + ARENA_BYTES) as *mut u8,
                Layout::from_size_align(64, 4).unwrap(),
            )
        };
    }

    /// GUARD 2. The heap is initialised *and then* the sentinel is stamped with the
    /// cold-boot fill, which is exactly the state the guard exists to refuse: a
    /// control block that could serve a request but has not been vouched for. The
    /// mutation this catches is deleting the `is_ready` check from `alloc`, which a
    /// plain `Heap::empty()` cannot catch because that returns `Err` anyway.
    #[test]
    fn alloc_refuses_when_the_sentinel_is_stale() {
        static A: Arena = Arena::new();
        unsafe { A.init_once() };
        unsafe { *A.ready.get() = 0xdead_beef };
        let p = unsafe { A.alloc(Layout::from_size_align(64, 4).unwrap()) };
        assert!(p.is_null(), "a stale sentinel must fail closed, got {p:?}");
    }

    /// A second `init` must not republish the arena over live blocks.
    #[test]
    fn init_is_idempotent() {
        static A: Arena = Arena::new();
        let l = Layout::from_size_align(64, 4).unwrap();
        unsafe { A.init_once() };
        let p = unsafe { A.alloc(l) };
        unsafe { A.init_once() };
        let q = unsafe { A.alloc(l) };
        assert!(!p.is_null() && !q.is_null());
        assert_ne!(p, q, "re-init would have handed out the live block again");
        unsafe { A.dealloc(p, l) };
        unsafe { A.dealloc(q, l) };
    }
}
