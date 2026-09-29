# Self-install — MicroSD-first plan after the first bench flash

Written **2026-09-29**, at `69015a5`. Builds on `UPGRADE-PLAN.md` (the PIN decision §1, the verified
facts §3, phases 1-3 §7) and does not repeat it. What changed: the first real Mk4 flash booted
cold-snap to its home screen but **USB never attaches** (host port reports power, no device), so
every install path that starts with USB is blocked on an unexplained hardware fault.

**Status: PLANNED, NOT STARTED.** Nothing below is bound on device. Citations into
`~/repos/coldcard-firmware` are to the read-only reference tree.

---

## 0. The unit already flashed is consumed

No software path can change its image (verified, `mk4-bootloader/main.c:160-182`):

* Its image verifies, so the bootloader boots it and offers no recovery. PSRAM replay, DFU and
  `sdcard_recovery` run only after `verify_firmware()` fails.
* DFU is skipped at RDP2 (`main.c:177`), and `sdcard_recovery` replays only an image whose world
  hash SE1 already holds (`sdcard.c:248`).
* The image has no 18/7 binding and no SD code.

Use it only for non-invasive USB diagnosis: whether it is in a `panic!("usb bring-up")` reset loop
(`firmware/src/main.rs:2078-2080`), other hosts and cables, an OK-held boot, a meter on D+.

**Open:** if the unit shows the red-light "WARN" and ~25 s delay at boot, SE1 may still bless
stock 5.2.0 and not cold-snap. A cold-snap build that deliberately fails its own verify would then
fall into `sdcard_recovery` and restore stock. Unverified and moot for this unit (it cannot install
that build); relevant to how future units are handled.

---

## 1. Callgate sequence (all selector 18, `dispatch.c:341-380`)

1. **21/3 read counter0.** A guard: whether 18/0 ticks it is unverified (`UPGRADE-PLAN.md` §5).
2. **18/0 `pin_setup_attempt`** (`pins.c:531-592`) with an empty PIN. Returns Blank or
   PinSet{attempts_left}. Already `Workflow::setup` in `firmware/src/install.rs`.
3. **21/3 again.** Abort before any counted call if counter0 moved.
4. **Consent screen**: staged digest, header version and timestamp. The human compares the digest
   with the host-side `checkfw` output. Integrity, not trust.
5. **Log in**: collect the PIN (§3), 18/0 again with the PIN and a zero HMAC,
   `login_attempt_permitted` (ATTEMPTS_LEFT_FLOOR = 2), then exactly one **18/2
   `pin_login_attempt`** (`pins.c:695-835`; counted, MAX_TARGET_ATTEMPTS = 13 at `pins.c:28`).
   A wrong PIN keeps the workflow alive and shows attempts_left.
6. **18/7 `pin_firmware_upgrade`** (`pins.c:1277-1346`), reusing the PinAttempt 18/2 returned:
   * `change_flags = CHANGE_FIRMWARE (0x40)` (`pins.c:1288`).
   * `secret[0..8] = (start: u32 = 0, len: u32)` via `PinAttempt::set_firmware_request`
     (`hal/src/callgate.rs:1074`); `start` is an offset from PSRAM_BASE.
   * Bootloader order: PA_SUCCESSFUL (`:1283`); `len >= 32768`, `len <= 2<<20`,
     `start+len <= PSRAM_SIZE` (`:1297-1299`); `verify_firmware_in_ram` (`:1306`), which hashes
     `hdr->firmware_length`, **not `len`** — so `len == firmware_length` is ours to enforce
     (`UPGRADE-PLAN.md` §3.2). A trick PIN triggers `fast_wipe` (`:1312`). Then
     `ae_encrypted_write(KEYNUM_firmware)` (`:1328`), `ae_set_gpio_secure` (`:1332`), and the point
     of no return, `psram_do_upgrade(data, len)` (`:1338`), then reset.
   * No retry on EPIN_AE_FAIL. Stock retries once; we deliberately don't.
7. **Never call 21/2** (the OTP high-water write).

Code:

* `pin_login_attempt` and `pin_firmware_upgrade` wrappers in `hal/src/callgate.rs`, copying
  `pin_setup_attempt` (`:1202`).
* Update the census guard `no_counted_or_destructive_selector_is_reachable_from_this_module`
  (rows and count change; `unsafe { raw(` == 1 still holds).
* `impl install::Bootloader for Gate`, one method per wrapper; replace `Unbound` in
  `install::device_path`.
* Optional: bind 21/0 to read the floor (`dispatch.c:441-445`). Without it, an image below the
  floor still fails safe: 18/7 returns EPIN_AUTH_FAIL before the point of no return.

---

## 2. Image source: MicroSD first

USB has never attached on silicon, so the SD card is the primary path.

* New `hal/src/sdcard.rs`: polling, read-only SDMMC1. Pins PC8-12, CMD on PD2, card detect PC13
  (high = inserted). Coexists with the keypad rows (GPIOD 8-11 via BSRR). Init CMD0/8/ACMD41/2/3/7,
  read with CMD17 single blocks. No filesystem.
* Find the image the bootloader's way (`sdcard.c:221, 282-289`): scan raw blocks for `DfuSe`,
  treat the file as contiguous, take the element at 0x08020000. Reuse the `checkfw.rs:201-245`
  walker for parsing.
* Stream into PSRAM offset 0. The payload starts at byte 293 (unaligned); reuse `Stager::feed`'s
  word carry.
* A local-staging entry on `Stager` in `firmware/src/upgrade.rs`, beside admit/feed: Staged with
  len from the header's firmware_length and digest from `firmware_digest()` (`lib.rs:3185`) over
  the PSRAM read-back.
* Bonus: once `pins.c:1328` runs, SE1 holds the new world hash, so the same contiguous `.dfu` left
  on the card doubles as the bootloader's power-loss recovery.

USB stays secondary: keep `upgrade::run`/`serve`, but make bring-up non-fatal.

**Boot order** (`firmware/src/main.rs`): move the OK-held install branch (6d, `:2100`) ahead of the
6c USB bring-up, or make `panic!("usb bring-up")` (`:2078-2080`) non-fatal. Open the panel inside
the branch, as `hold()` does (`:1606`). The branch never falls through to Session: success resets,
failure holds.

---

## 3. PIN entry, minimum

A pure key-driven state machine in the style of `quiz.rs`, in `hal/src/ui.rs` or a sibling.

* Digits append, up to 6 per part. OK moves prefix → suffix; on a 2-6 digit suffix it submits
  ASCII `prefix-suffix`, the stock format (`login.py:14-15, 126-132`).
* X deletes the last digit, or cancels on an empty field.
* Digits masked; attempts_left shown. Anti-phishing words (selector 16) skipped.
* Still never offers to *create* a PIN (`UPGRADE-PLAN.md` §1.1).
* Host test: key sequences produce the expected bytes and respect the bounds.

---

## 4. Checks before any counted call (all exist)

1. `hal/src/image.rs::check_installable`: magic 0xCC001234; hw_compat 0 or MK_4_OK; header
   firmware_length == staged len; len in [BURN_LEN_MIN, 0x160000]; 4 KiB aligned.
2. `install::request_bounds`: start == 0, end <= PSRAM_STAGE_LEN, len >= 32768, len % 4096 == 0.
3. `CheckedImage::check` again immediately before 18/7 (already in `install.rs`).
4. Signatures stay host-side (`checkfw` R12, U1-U4). On device, `pins.c:1306` is the authority and
   fails before the point of no return.
5. Do **not** require `pubkey_num == 0` on device, so stock images (keys 1-5) can revert. The
   bootloader verifies them; no trust anchor is added.

---

## 5. Revert to stock, and the OTP floor

* `check_is_downgrade` (`verify.c:143-184`) rejects major < 3 or timestamp < the OTP minimum. It
  compares against OTP only, never the installed version.
* **Only 21/2 writes the floor** (`dispatch.c:463-470` → `storage.c:592
  record_highwater_version`), and stock calls it only from the manual "Set High-Water" menu
  (`shared/actions.py:2268-2289`, `flow.py:347`). It does **not** grow per install, so current
  stock passes unless the owner set a higher mark. **This corrects `checkfw`'s U2 note**
  (`firmware/examples/checkfw.rs:499`), which says the floor "grows with every install".
* SD path: copy Coinkite's `.dfu` to the card unchanged.
* USB path: relax `frostsnap_coordinator/src/mk4_firmware.rs:433-435` to accept pubkey_num 1-5 for
  an explicit revert.
* Data loss: stock probably reformats FLASH_FS (0x08180000, `mk4.py make_flash_fs`), destroying the
  cold-snap identity and share. The SE1 seed and PIN survive. The consent screen must say "back up
  share first" for non-key-0 images.

---

## 6. Brick risks

| Risk | Guard |
|---|---|
| `len` ≠ `firmware_length` burns unverified bytes | checked twice (§1.6, §4) |
| Power loss mid-burn (`psram.c:300-363`, ~15 s, unverified) | recoverable only with the exact `.dfu` contiguous on SD; reset mid-burn is covered by PSRAM replay |
| Trick PIN | fast_wipe erases the seed, share survives; a brick trick PIN bricks; `se2_handle_bad_pin` has side effects |
| Attempt exhaustion (13) | stop while 2 remain |
| SE1 failure | EPIN_I_AM_BRICK; `fatal_mitm` locks up |
| 18/0 ticks counter0 | 21/3 guard (§1) |
| Recreating the one-way door | no image ships until vN → stock → vN+1 passes on an expendable unit |
| SDMMC misconfigured | reads fail; fails safe |

Expected, not a fault: key-0 images show the ~25 s devmode warning every boot (`verify.c:320-360`).

---

## 7. Host vs bench

**Host** (`cargo test`, FakeGate, FakePsram, `install-xproc.py`): wrappers and census, Gate impl
(compile), PIN state machine, DfuSe raw-block scanner over a byte slice, local staging with the
unaligned carry, the full install flow including the counter guard.

**Bench only:** SDMMC1 bring-up and clocks; real 18/0, 18/2, 18/7 and whether counter0 moves; burn
time and SD power-loss recovery; the stock revert and what it does to FLASH_FS; the USB root cause.

---

## 8. First milestone

1. Host: 18/2 and 18/7 wrappers plus census, Gate impl, PIN widget, SD scanner plus local staging,
   all green against FakeGate.
2. One bench image: OK held at power-on with a card inserted → panel → SD → PSRAM → consent → 18/0
   with counter guard → PIN → 18/2 → 18/7. All before USB.
3. Proof on an expendable unit with a PIN set: revert to stock from SD, then stock installs the
   next key-0 cold-snap. That closes the one-way door with no USB dependency.
4. Optional: a stock MicroPython unit reads the floor (21/0) and RDP level, and tests SD contiguity.

---

## 9. Unverified assumptions

* 18/0 does not tick counter0 (guarded).
* SDMMC kernel clock and handoff state (`clocks.c:150-185` shows only CLK48 = PLLSAI1).
* Stock reformats a non-LFS FLASH_FS.
* Burn time ~15 s.
* `.dfu` element size equals firmware_length (stock accepts binary_size or binary_size-128).
* Factory OTP floor empty or low; bench units' RDP level.
* PSRAM retention across reset.
* Pin state OTG leaves behind; SE2 trick-PIN side effects.
* The USB attach failure's root cause. Code review found `hal/src/usb.rs` `bring_up` matching ST's
  `stm32l4xx_ll_usb.c` and MicroPython's `usbd_conf.c`; the Mk4 has no USB enable pin (PC6
  `USB_ACTIVE` is an LED) and the bootloader never touches PA11/PA12.

---

## Files

* `hal/src/callgate.rs`, `hal/src/sdcard.rs` (new), `hal/src/ui.rs`
* `firmware/src/install.rs`, `firmware/src/upgrade.rs`, `firmware/src/main.rs`
* `firmware/examples/checkfw.rs` (U2 note)
* `~/repos/frostsnap/frostsnap_coordinator/src/mk4_firmware.rs` (accept stock keys for revert)
