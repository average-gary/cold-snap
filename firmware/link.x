/* cold-snap firmware link script — STM32L4S5 / Coldcard Mk4.
 *
 * Every number here is READ, not chosen, except where marked "our free choice".
 * The citations are to the Coldcard sources; the same values are mirrored with
 * fuller commentary in `hal/src/lib.rs` `pub mod memmap`, and the ASSERTs at the
 * bottom exist so a drift between the two fails at LINK time rather than at boot
 * on a unit that cannot be recovered.
 *
 * Wired in by `-C link-arg=-Tfirmware/link.x` in the repo root
 * `.cargo/config.toml`, under `[target.thumbv7em-none-eabihf]` only. That path is
 * relative to cargo's invocation directory, i.e. the workspace root.
 */

MEMORY
{
  /* FLASH_ISR: where the bootloader looks for our vector table
   * (`layout.ld:16`; `verify.h:9` FIRMWARE_START; `Makefile:52` MPY_FLASH_BASE).
   *
   * LENGTH is 0x3F80, NOT the region's 0x4000. The last 128 bytes
   * (`0x0802_3F80` = `sigheader.h:82` FLASH_HEADER_BASE_MK4, size
   * `sigheader.h:38`) are the signature header slot, inserted POST-LINK by
   * `cli/signit.py`, which asserts the vector blob is <= that offset
   * (`signit.py:292`). A linker script must RESERVE it, never emit it. Shrinking
   * the region is how that reservation is enforced: overflow is a link error.
   *
   * Emitting it is not merely unnecessary, it is a no-op at best and a packaging
   * failure at worst. signit builds all ten fields itself from its CLI arguments
   * (`signit.py:315-325`) and two of them — the wall-clock `timestamp` and the
   * `signature` over the other 63 header bytes — are unknowable at link time. On
   * the `-r` path it splits its input into `whole[0:0x3F80]` and
   * `whole[0x4000:]` (`signit.py:275-276`), so anything in the slot is DISCARDED;
   * on the `-b` path an emitted header makes `firmware0.bin` 16,384 B and trips
   * `assert len(vectors) <= FW_HEADER_OFFSET` (`signit.py:292`). The address of
   * this slot is pinned by the FLASH_ISR end ASSERT below and by
   * `hal/src/lib.rs:317`'s `FW_HEADER_OFFSET + FW_HEADER_SIZE == FLASH_ISR_LEN`;
   * that pair is the whole contract, and there is nothing left for a twelfth
   * ASSERT to say. */
  FLASH_ISR  (rx)  : ORIGIN = 0x08020000, LENGTH = 0x3F80

  /* FLASH_TEXT: the firmware body (`layout.ld:17`). 1392 K = 1,425,408 B, the
   * budget every flash percentage in PLAN.md is against. Ends exactly at
   * FLASH_FS (`0x0818_0000`, `layout.ld:18`) — which holds frostsnap key and
   * nonce state and must not be touched by the image. */
  FLASH_TEXT (rx)  : ORIGIN = 0x08024000, LENGTH = 0x15C000

  /* RAM: SRAM1+2+3 are contiguous from 0x2000_0000 (`layout.ld:21`), but our
   * usable window is narrower at BOTH ends, and both bounds are safety-critical.
   *
   * ORIGIN 0x2000_8010, not 0x2000_0000. The bootloader's 12-byte `dfu_flag`
   * lives at 0x2000_8000 (`main.h:14`) and is memcmp'd against REBOOT_TO_DFU at
   * `main.c:115` — BEFORE `wipe_all_sram()` at `main.c:130`. So any byte of ours
   * that survives a reset reaches that comparison, and a match reaches
   * `enter_dfu()` -> `LOCKUP_FOREVER()` at RDP=2. Since `hal::panic` resets on
   * every panic and a coordinator can influence heap contents, placing anything
   * across that address is a REMOTE PERMANENT BRICK. Starting above it (12 bytes
   * rounded up to 16 for alignment) removes the path by construction rather than
   * by review. Note this abandons the 32 KiB below the flag; SRAM is not the
   * constraint here, recoverability is.
   *
   * LENGTH 0x9_5FF0 so the region ends EXACTLY at BL_SRAM_BASE = 0x2009_E000
   * (`Makefile:61`). At or above that address is the bootloader's 8 K, which the
   * callgate WIPES on entry and again on exit (`startup.S:124-134,148-156`), and
   * `crate::callgate` enters it for every SE operation — so nothing of ours can
   * survive there. */
  RAM        (rwx) : ORIGIN = 0x20008010, LENGTH = 0x95FF0
}

/* Roots the reset entry for --gc-sections and silences the "cannot find entry
 * symbol" warning. `_start` does not exist here: the PCROP bootloader owns reset
 * (`startup.S:87-95`) and jumps to a fixed address, so there is no libc startup. */
ENTRY(entry_point)

SECTIONS
{
  /* The only thing the bootloader reads: two words at 0x0802_0000
   * (`startup.S:102-112`). ALIGN(512) is the Cortex-M VTOR constraint (the table
   * base must be aligned to at least the table size, rounded up to 32 words);
   * 0x0802_0000 already satisfies it, and stating it keeps a future grown table
   * honest. KEEP() because nothing in the image references it. */
  .vector_table ORIGIN(FLASH_ISR) :
  {
    . = ALIGN(512);
    _svector_table = .;
    KEEP(*(.vector_table));
    _evector_table = .;
  } > FLASH_ISR

  .text : ALIGN(4)
  {
    *(.text .text.*);
    . = ALIGN(4);
  } > FLASH_TEXT

  .rodata : ALIGN(4)
  {
    *(.rodata .rodata.*);
    /* Read-only-after-relocation data from LLVM; there is no dynamic loader
     * here, so it is just more rodata. */
    *(.got .got.plt);
    . = ALIGN(4);
  } > FLASH_TEXT

  /* .data: VMA in RAM, LMA in flash. The entry copies `_sidata` -> `_sdata`
   * with an explicit u32 loop (step 4), which is why every bound is 4-aligned.
   * This is NOT optional for anything with a non-zero initialiser — e.g.
   * `hal::panic`'s PANIC_DEPTH, whose initialiser is DEPTH_MAGIC 0xD3E1_0000. */
  .data : ALIGN(4)
  {
    _sdata = .;
    *(.data .data.*);
    . = ALIGN(4);
    _edata = .;
  } > RAM AT > FLASH_TEXT
  _sidata = LOADADDR(.data);

  /* .bss: zeroed by the entry's explicit u32 write_volatile loop (step 3).
   * MANDATORY on this board, not housekeeping: SRAM arrives filled with
   * 0xdeadbeef (`main.c:42,47-49`), so an unzeroed `static bool` reads true. */
  .bss (NOLOAD) : ALIGN(4)
  {
    _sbss = .;
    *(.bss .bss.*);
    *(COMMON);
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  /* Deliberately NOT zeroed and NOT copied: the heap backing store and anything
   * else that must keep whatever it had. Placed after .bss so the zeroing loop's
   * upper bound cannot reach it. */
  .uninit (NOLOAD) : ALIGN(4)
  {
    *(.uninit .uninit.*);
    . = ALIGN(4);
  } > RAM
  _end = .;

  /* Nothing below is emitted into the image. Unwind tables in particular: the
   * release profile is `panic = "abort"` with no unwinder, so they are dead
   * weight, and leaving them unassigned makes an accidental unwinder LOUD (an
   * orphan-section placement) rather than silent. */
  /DISCARD/ :
  {
    *(.ARM.exidx .ARM.exidx.*);
    *(.ARM.extab .ARM.extab.*);
    *(.comment);
  }
}

/* ---- Containment invariants. Zero flash cost; they fail at LINK time. ------
 *
 * These are the checks that a brick would otherwise have to teach us. */

/* The bootloader jumps to a hardcoded 0x0802_0000 and reads SP/PC from there. If
 * the table moved, the unit executes whatever is at that address instead. */
ASSERT(_svector_table == 0x08020000,
       "link.x: .vector_table must start at FLASH_ISR_BASE 0x08020000 (startup.S:102-112)");

/* The signature header slot stays reserved: nothing we emit may reach
 * 0x0802_3F80 (sigheader.h:82), and the region must not have been widened. */
ASSERT(ORIGIN(FLASH_ISR) + LENGTH(FLASH_ISR) == 0x08023F80,
       "link.x: FLASH_ISR must stop at 0x08023F80 — the 128 B signature header is inserted post-link by signit.py");

/* FLASH_ISR ends where FLASH_TEXT begins, and FLASH_TEXT ends exactly at
 * FLASH_FS 0x0818_0000 (layout.ld:18) — which holds key/nonce state. */
ASSERT(ORIGIN(FLASH_TEXT) == 0x08024000, "link.x: FLASH_TEXT_BASE (layout.ld:17)");
ASSERT(ORIGIN(FLASH_TEXT) + LENGTH(FLASH_TEXT) == 0x08180000,
       "link.x: FLASH_TEXT must stop exactly at FLASH_FS_BASE 0x08180000 (layout.ld:18)");

/* Above the dfu_flag (0x2000_8000 + 12, main.h:14). A byte of ours here that
 * survives a reset can reach enter_dfu() -> LOCKUP_FOREVER() at RDP=2. */
ASSERT(ORIGIN(RAM) >= 0x2000800C,
       "link.x: RAM must start above the bootloader dfu_flag at 0x20008000+12 (main.c:115) — a match there is a permanent brick at RDP=2");

/* Below the bootloader's 8 K, which the callgate wipes on entry AND exit. */
ASSERT(ORIGIN(RAM) + LENGTH(RAM) <= 0x2009E000,
       "link.x: RAM must end at or below BL_SRAM_BASE 0x2009E000 (Makefile:61) — the callgate wipes that 8 K");
ASSERT(_end <= 0x2009E000,
       "link.x: RAM contents crossed BL_SRAM_BASE 0x2009E000");

/* The u32 loops in the entry require 4-aligned, u32-sized spans. If any of these
 * is odd the loops walk past their end. */
ASSERT(_sbss % 4 == 0 && _ebss % 4 == 0, "link.x: .bss bounds must be 4-aligned for the u32 zeroing loop");
ASSERT(_sdata % 4 == 0 && _edata % 4 == 0, "link.x: .data bounds must be 4-aligned for the u32 copy loop");
ASSERT(_sidata % 4 == 0, "link.x: .data LMA must be 4-aligned for the u32 copy loop");
