# Self-upgrade path — scoped plan and the PIN decision

Orchestrator-authored, **2026-09-17**, at `2956a39`. Not yet folded into `PLAN.md`/`DECISIONS.md`;
this file is the working record so the next session does not re-derive any of it.

**Status: SCOPED, NOT STARTED.** One lane of PIN-independent foundations is in flight (see §7).
No callgate sub-call is bound, `Upgrade` is still refused, no PIN code exists.

---

## 0. THE PROBLEM, in one paragraph

On an RDP=2 Coldcard there is no DFU and no SWD, and `sdcard_recovery` restores only the image
SE1 already blesses. The **first** flash of cold-snap works, because the factory MicroPython
performs it. The **second** does not, because the upgrade is performed by the firmware that is
running and cold-snap has no upgrade path. So today each iteration costs a device. This feature
fixes that.

---

## 1. THE DECISION

### 1.1 Never offer to create a PIN. Support one only if it is already set.

* **Fresh-from-factory unit (blank PIN): cold-snap NEVER offers to create a PIN.** No PIN-setting
  UI, ever. Two reasons, and the first is the one that matters:
  1. **It buys no security.** The share-encryption key is
     `H("coldsnap/share-encryption/v1" ‖ seed ‖ key_id ‖ access_structure_id ‖ party_index ‖ coord_key)`
     (`firmware/src/lib.rs:365-371`) — **no PIN input, and no MCU-key input**. At rest the share is
     protected by RDP=2 and by the coordinator's contribution, not by a PIN. A PIN would be an
     authorisation factor for operations we choose to gate, nothing more.
  2. **It puts the SE1 login on the critical path of every device.** With no blank-PIN fallback, a
     bug in the login means *no* device can be upgraded — on hardware that cannot be rehearsed
     against (the callgate is PCROP code, testable at no tier) and where 13 malformed attempts
     brick the unit.
* **Unit with a PIN already set from previous Coldcard firmware: SUPPORTED.** cold-snap performs
  the SE1 login (sub-call 18/2) to obtain `PA_SUCCESSFUL`, because the bootloader demands it and
  there is no way to clear a set PIN (§3.3).
* **`pin_change` (18/3) stays unbound and stays classified `Destructive`** (`hal/src/callgate.rs:799`).
  Setting or changing PINs is not this device's job.

### 1.2 The always-required gate is the coordinator's contribution, not the PIN

Every upgrade must carry a `root_shared_key` + `coord_share_decryption_contrib` that **actually
decrypts a share this device holds** — the same check `device/restoration.rs` already applies three
times before a backup reveal. Rationale: **the upgrade door must not be weaker than the share it
protects.** A device holding no share holds no money and upgrades freely.

### 1.3 Why the PIN cannot be the gate on a blank unit — our own source says so

`hal/src/callgate.rs:717-718`, written before this investigation:

> A blank PIN yields none of the security property: the PIN digest is a value anyone can compute,
> so anything gated on it is gated on nothing.

An earlier draft of this plan proposed gating the upgrade on the blank-PIN grant. **That was wrong
and this file exists partly to stop it being re-proposed.** The co-factor: key 0's *private* key is
published (`coldcard-firmware/stm32/keys/README.md`: *"shared on the Internet so anyone can build
experimental code"*), so `verify_signature` is a FORMAT check, not an authorisation check. Blank PIN
+ published key + a consent digit an attacker reads off the glass = 30 seconds of physical
possession becomes persistent code execution. That is the evil-maid hole, and §1.2 is what closes it.

### 1.4 The resulting matrix

| device | PIN | upgrade requires | notes |
|---|---|---|---|
| bench / bring-up | blank | coord-contrib gate + consent | 18/0 grants `PA_SUCCESSFUL` free. Simplest path; debug everything here. |
| fresh, in service | blank | coord-contrib gate + consent | We never offer to add a PIN. |
| migrated Coldcard | already set | 18/2 login **+** coord-contrib gate + consent | Two factors: owner present, group authorises. |

One code path: the coord-contrib gate is unconditional; the PIN login is conditional on
`PA_IS_BLANK` being clear.

### 1.5 The boundary that must hold structurally

**The PIN gates the UPGRADE only — never signing, keygen, or backup.** Upstream Frostsnap has no
PIN on any of those (`rg -c -i '\bpin\b|passphrase|unlock'` over `vendor/frostsnap/frostsnap_core/src`
and `frostsnap_comms/src` returns *nothing*), and adding one would make this a different device.
Once a PIN prompt exists in the tree that boundary is a two-line diff away, so it must be enforced
by the selector guard and by a source pin, not by intent.

---

## 2. WHY "NO PIN" IS DEFENSIBLE AT ALL — the comparison that justifies it

Upstream Frostsnap has no PIN concept by design: *"Frostsnap devices do not handle authentication
of the user directly unlike other devices with on-device pin codes"*
(`frostsnap/docs/key-derivation-design.md:7-8`). Protection is the **threshold** — one device holds
one share, useless below `t`.

| property | upstream prod ESP32-C3 | cold-snap blank-PIN Mk4 @ RDP=2 | winner |
|---|---|---|---|
| PIN / passphrase | none, by design | none | tie |
| share at rest | encrypted, key root = read-protected eFuse | encrypted, key root = **plaintext seed in flash** | upstream |
| plaintext share on flash | **yes, mid-restore** | **no — refused, byte-asserted** | cold-snap |
| flash confidentiality | none (external SPI NOR) | RDP=2, internal flash | cold-snap |
| secure boot | RSA-3072, prod key offline | signature required, **key 0 private key published** | upstream |
| backup-reveal consent | none pre-reveal | randomised digit + `mark_sensitive` | cold-snap |
| wipe / decommission | on-device consent | **none**, `DataErase` refused | upstream |

**Broadly equivalent: stronger on three axes, weaker on three.** "No PIN" matches a shipped design
rather than cutting a corner. The two weaknesses worth carrying as debt — the plaintext identity
secret (`hal/src/identity.rs:68`, its own module doc) and the absent decommission path — are **not
fixed by a PIN.**

*Provenance: the upstream-hardware rows are from a delegated sweep of the `frostsnap` sibling and
are NOT independently verified by the orchestrator. The cold-snap rows are.*

---

## 3. VERIFIED FACTS — do not re-derive these

### 3.1 The upgrade mechanism
* Callgate **selector 18, `arg2 = 7`** → `pin_firmware_upgrade` (`mk4-bootloader/pins.c:1277`).
  Requires `_validate_attempt`, `state_flags & PA_SUCCESSFUL`, `change_flags == CHANGE_FIRMWARE`,
  the image staged in PSRAM with `32768 <= len <= 2<<20`, then `verify_firmware_in_ram`, then a
  `get_is_trick` check.
* On a **blank** PIN, sub-call **18/0** (`pin_setup_attempt`) sets
  `state_flags |= PA_SUCCESSFUL | PA_IS_BLANK`, calls `pin_cache_save(args, zeros)` and
  `set_is_trick(args, NULL)`, then signs the struct (`pins.c:577-590`). So `get_is_trick` is false
  by construction and `fast_wipe()` is unreachable on that path.
* **`change_flags` is OUTSIDE the HMAC window.** `_hmac_attempt` hashes `offsetof(pinAttempt_t, hmac)`
  bytes (`pins.c:356`). Orchestrator's own field arithmetic over `pins.h`: `offsetof(hmac) == 68`,
  `change_flags @ 100`. So a caller sets `CHANGE_FIRMWARE` and the PSRAM `(start,len)` on an
  already-signed struct. **This is the link that makes the feature possible.** `state_flags @ 60`
  and `private_state @ 64` are INSIDE the window, which is why `PA_IS_BLANK` and the trick bit
  cannot be forged.

### 3.2 THE FUND-LOSS DEFECT — the highest-priority guard
`verify_firmware_in_ram` **never reads its `len`**: in `verify.c` `len` appears once, in the
signature; the body hashes `hdr->firmware_length`. But `psram_do_upgrade` **burns `len`**, and the
callgate's only ceiling is `pins.c:1298`'s `if(len > 2<<20)` — **655,360 B past `FLASH_FS_BASE`**.
Signature check and burn length are DECOUPLED, and it happens after the SE1 write and after
`// -- point of no return --`, so **the bootloader is not a backstop.** One wrong integer erases the
identity record, the nonce slots and the share.
⇒ A pure, host-tested ceiling at `FLASH_FS_BASE - FLASH_ISR_BASE` must land **before** any code that
could reach the call. This is lane 1 of §7.

### 3.3 A set PIN cannot be cleared
* `shared/login.py:15` `MIN_PIN_PART_LEN = 2`, enforced at `:126`.
* No USB PIN-change command.
* `shared/actions.py:312`: *"There is ABSOLUTELY NO WAY to 'reset the PIN' or 'factory reset' the
  Coldcard if you forget the PIN."*
* The bootloader *capability* exists — `pin_hash_attempt`'s zero-length case
  (`pins.c:140-145`, *"zero len PIN is the 'blank' value: all zeros, no hashing"*) and
  `pincodes.py:88`'s *"`new_pin_len` … can be zero"* — **with no UI to reach it.**
⇒ "Clear your PIN before migrating" is **not an executable instruction**. An earlier draft of this
plan said it was. Migration of a PIN-set Coldcard means supporting the login (§1.1).

### 3.4 `fast_wipe()` does NOT destroy a cold-snap share
`storage.c:822-832`: `fast_wipe()` is `mcu_key_clear(NULL); NVIC_SystemReset();` — *"dump (part of)
the main seed key and become a new Coldcard"*. It does **not** touch `FLASH_FS`. cold-snap's
identity secret lives in `FLASH_FS` and its share key derives from that seed, never from the MCU key
(`SELECTOR_MCU_KEY_USAGE` is only ever used to read a slot *budget*). So a trick-PIN wipe destroys
the **Coldcard's** seed — retired in any migration — and leaves cold-snap's share intact.
⇒ An earlier draft called the trick-PIN path "fund loss". **That was wrong**, and it was the main
argument against building the login.

### 3.5 Upstream already has the wire protocol, and it is PIN-free
In `vendor/frostsnap/frostsnap_comms/src/lib.rs`: `FIRMWARE_UPGRADE_CHUNK_LEN = 4096` (`:45`),
`FIRMWARE_NEXT_CHUNK_READY_SIGNAL = 0x11` (`:51`), `PrepareUpgrade` (`:314`), `EnterUpgradeMode`
(`:318`), `PrepareUpgrade2` (`:323`, *"digest of deterministic firmware only"*), `AckUpgradeMode`
(`:494`). cold-snap refuses it today at `firmware/src/lib.rs:1039`.
* `FIRMWARE_UPGRADE_CHUNK_LEN` **== our `FRAME_LIMIT` of 4,096**, so DECISIONS.md 7 is untouched.
* **397,312 / 4,096 = 97 exactly** — no partial chunk.
* Our `firmware_digest` already hashes the bootloader's signed range with every length bounded,
  which is the shape `PrepareUpgrade2` wants.
⇒ **Reuse, not invention.** No `vendor/` change is needed.

### 3.6 PSRAM
* Configured and memory-mapped **before firmware runs** — `main.c:150` calls `psram_setup()`
  unconditionally. No OCTOSPI init needed by cold-snap.
* **HARD CONSTRAINT: "All writes must be word aligned. Unaligned read okay."** (`psram.c` header
  comment.) A byte-wise `&mut [u8]` staging write is wrong on hardware, and any host double must
  ENFORCE alignment or a host test passes on an access the silicon refuses — the §8.1 defect-5 class.
* The bootloader's own stash is `recovery_header_t` at `PSRAM_BASE + PSRAM_SIZE - 2048` and requires
  `h->start < PSRAM_BASE + PSRAM_SIZE/2`, so stage in the **lower half**. It gates on
  `verify_world_checksum`, so it cannot bless a new image — it is a torn-burn net, not an install path.
* `psram_wipe()` is reachable from selectors 2 and 3, but **not on cold-snap's panic path**: for
  `arg2 = 0` at RDP=2, `dispatch.c:161-164` takes `rv = EPERM; goto fail;` **before**
  `wipe_all_sram()`/`psram_wipe()`. A staged image survives a panic escalation.

### 3.7 Boot ordering, and the two design contradictions that were resolved
`firmware/src/main.rs` order: entropy singletons → `panic!("entropy singletons already taken")`
(~:1885) → `Entropy::boot` → `panic!("entropy fail-closed")` (~:1906) → `StmFlashToken::open` →
`panic!("flash geometry")` (~:1917) → `identity::load_or_create` → `hold()` (~:1948) → panel →
keypad → USB (~:2086).
* **Contradiction 1 (resolved):** an upgrade listener must precede everything that can panic, but
  USB currently comes after all four. USB's `open()` runs `bring_up` itself and depends on neither
  entropy, flash nor identity, so **it can move ahead of them.**
* **Contradiction 2 (resolved):** a randomised consent digit needs an RNG, and the RNG's failure IS
  `panic!("entropy fail-closed")`. Resolution: the *entry* gate is a **physical boot-time key
  hold**, not a digit. `scan_once<R: RngCore>` is generic and the keypad's own tests drive it with a
  trivial counter, so a hold check needs **no entropy at all** — the row shuffle is an EM defence
  for PIN entry and nothing secret is typed at a hold check. Physical presence is the human proof.
⇒ Consequence: the upgrade path must **not** depend on `Session::open`, so it is reachable on a
device whose SE1, SE2, flash and identity are all broken — which is the failure it exists to survive.

### 3.8 What a stolen device does NOT give up
`DisplayBackup` carries `coord_share_decryption_contrib` **and** `root_shared_key`
(`vendor/frostsnap/frostsnap_core/src/message.rs:59-67`), and the device checks three hashes of the
real polynomial before a prompt reaches the glass. **Physical possession plus button presses does
NOT yield the 25 words** — an earlier draft claimed it did. `RequestHeldShares` *is* admitted with no
consent screen and leaks `key_id`/`threshold`/`share_image`; that leak is upstream's too and declared
acceptable.

### 3.9 Two defects in our own tree, found while scoping
* `hal/src/callgate.rs:800-802` says 18/4 (`pin_fetch_secret`) *"is unreachable without first
  spending a counter tick on case 2"*. **False on a blank-PIN unit**, where 18/0 grants
  `PA_SUCCESSFUL` free. The `Counted` classification stays correct; the stated reason does not.
  Consequence worth documenting for migration: on a blank-PIN Coldcard, **any key-0-signed firmware
  reads the BIP-39 secret for free.** So an old Coldcard seed must be treated as retired.
* **CLOSED 2026-09-18** — decision 2 now carries an `AMENDED` note recording that cold-snap
  ships with no PIN, that the surviving dual-secure-element value is the root of trust rather
  than PIN authorisation, and that the table row describes stock Coldcard firmware and not this
  product. The row itself is left standing because it is true of the platform it names.
  ~~`DECISIONS.md` decision 2 still claims `| PIN | none | mandatory, SE1-enforced |`. False for the
  shipped product.~~

### 3.10 The destructive-selector guard does not currently work
`no_counted_or_destructive_selector_is_reachable_from_this_module` is a REFUSAL, and
`SubCallCost::Destructive`'s doc says destructive sub-calls *"Must not appear in this tree at all"*.
* Its needle `"PIN_SUBCALL_UPGRADE"` is **evaded by naming** — `PIN_SUBCALL_FW_UPGRADE` and
  `PIN_SUBCALL_FIRMWARE_UPGRADE` do not contain it.
* Its needle `"SELECTOR_HIGHWATER"` **cannot fire**: that string exists nowhere but as its own
  needle, while selector 21's one-way OTP burn is already bound as `SELECTOR_OTP` and called.
⇒ Convert to per-selector, per-sub-call **call-site counts**. This is what will keep 18/7 and 18/2
from being bound sloppily, and it is why it is in lane 1.

---

## 4. PHASE PLAN

**Phase 0 — the MicroPython bench unit. PREREQUISITE, not optional.**
Build a `DEBUG_BUILD=1`, key-0-signed sibling MicroPython and keep it resident on one unit. It gives
a REPL on the USART1 RGT pads (115,200 8N1), `ckcc.gate()` for every selector, and `pincodes.py` as
a **working reference** for the exact 18/0 → 18/2 → 18/7 sequence. `check_is_downgrade` compares the
header timestamp only against the OTP list, never against the installed version, so
MicroPython ⇄ cold-snap cycles indefinitely — **the unit stays reflashable forever and costs nothing
permanent.** A good login there also re-arms the 13-attempt budget, turning a one-shot into a
renewable one. This is where the login gets debugged, never on a unit holding a share.

**Phase 1 — the bounds and the guard. Host-only, zero hardware exposure. IN FLIGHT (§7).**
The `FLASH_FS` burn ceiling, the floor, the `len` vs `firmware_length` decoupling refusal, the PSRAM
range/lower-half check; the guard converted to call-site counts; the two stale claims of §3.9.
Nothing has a production caller, so ARM flash must not move.

**Phase 2 — PSRAM primitives. Host-only. IN FLIGHT (§7).**
ARM accessor with word-aligned writes, plus a host double that **refuses an unaligned write and
permits an unaligned read**. Allocation-free — the heap has 5,024 B spare of 65,536 and a staged
image is ~388 KiB.

**Phase 3 — staging over the existing transport. LANDED 2026-09-17 (§7b), hardened §7c, fixed §7d
2026-09-18. Current gate figures are in §7d.**
Admit `EnterUpgradeMode` / `PrepareUpgrade2` / chunks; stream the image into PSRAM's lower half;
verify the digest on-device before spending anything. Early USB per §3.7. No callgate call yet.
Testable end-to-end on the host through `hostcheck` + `examples/stub.rs`.
*Correction to this paragraph's own arithmetic: "97 × 4,096 B" is the size of ONE artifact, not a
constant. The size arrives on the wire and `hostcheck`'s M13 deliberately drives 262,656 B
= 64 × 4,096 + 512, because a 97 × 4,096 exact fit cannot fail the ack arithmetic or the short
tail and would be the vacuous test.*

**Phase 4 — the coord-contrib gate. BLOCKED on one measurement.** The `SharedKey` check of §1.2.
**Needs a wire-size measurement first** — see §5 item 3. The heap half of that item is no longer
outstanding: §7d MEASURED the arena at 60,512 B of 65,536 with 5,024 B spare against the
staging tree, so what is left is how many bytes a `SharedKey`-carrying upgrade message costs on the
wire and in the decode arena.

**Phase 5 — the PIN login (18/2), conditional on `PA_IS_BLANK` being clear.** Only after phase 4.
Debugged on the phase-0 bench unit.

**Phase 6 — the burn (18/7).** The hardware moment. Everything except `psram_do_upgrade` itself has
by then run on the same silicon.

---

## 5. OPEN — must be settled before the phase it gates

1. **Is 18/0 actually free of SE1 counter ticks?** Our own source flags this as read-from-source,
   not measured (`hal/src/callgate.rs:693-695`). **If the counter moves, the whole design is void** —
   it would burn PIN retries on every boot. Measure with `read_counter0` (21/3) before, between and
   after two 18/0 calls, on the phase-0 bench unit. **Gates phase 6.**
2. **Does RDP=2 disable SWD on STM32L4S5?** Not citable from either repo; needs RM0432 §3.5. The
   "RDP=2 is the only thing protecting the plaintext identity secret" claim rests on it.
3. **Does a `SharedKey`-carrying upgrade message fit `FRAME_LIMIT` 4,096 and the heap?**
   **Half settled 2026-09-18 (§7d).** The arena baseline is no longer inherited: with the whole
   staging path in the tree it MEASURES 60,512 B of 65,536, **5,024 B spare**, peak requested 54,496 B,
   0 allocator refusals — run, not argued (`cargo run --release --target aarch64-apple-darwin -p
   coldsnap_firmware --example heap_session --features="coldsnap_hal/test-seam,frostsnap_core/coordinator"`).
   What is STILL OPEN, and it is what actually gates phase 4: the WIRE-SIZE measurement for a
   `SharedKey`-carrying upgrade message, plus the decode-arena cost of admitting one, measured by
   extending `firmware/examples/heap_session.rs` in the §7 style. **Gates phase 4.**
4. **Consent UX for the burn.** Read upstream's own device UX for precedent before inventing one.
   Fallback is the physical key-hold of §3.7.
5. **The `.dfu` must be on a contiguous FAT SD card in the slot before the burn is confirmed.**
   `pins.c` writes the new image's world_check to SE1 *before* `psram_do_upgrade`, so for the ~15 s
   burn the SD net covers the NEW image and only that image. *(Agent-reported; not independently
   verified.)*

---

## 6. EXPLICITLY OUT OF SCOPE

* **Creating or changing a PIN.** 18/3 stays unbound and `Destructive`.
* **Gating signing, keygen or backup on a PIN.** §1.5.
* Folding the PIN into the share-encryption key. It would make the PIN real at-rest protection, but
  losing the PIN would lose the share and every signature would need a prompt. Different product.
* An OTA feature: version negotiation, auto-upgrade, resume, chunk maps, manifests, compression.
  The call takes `(start, len)` and the bootloader re-verifies from scratch.
* On-device signature verification of the staged image — the bootloader does it ~100 ms later inside
  the firewall and only its verdict counts. Keep the cheap digest check.
* Sub-calls 18/3, 18/4, 18/5, 18/6, 18/8 and selectors 3, 19, 21/`arg2=2`, 22, 23, 24.
* Any change under `vendor/frostsnap/`. PUNT EVERYTHING UPSTREAM; §3.5 means nothing is needed.
* A PSRAM pre-wipe — it would break `psram_recover_firmware`, the only torn-burn net.

---

## 7. PHASES 1 AND 2 — LANDED 2026-09-17, verified by the orchestrator

**Read §7d first for the current gate figures.** This section is the 2026-09-17 landing record and
its table is left at the values measured that day; phase 3 (§7b) has since moved the image and the
test counts.

`hal/src/psram.rs` (NEW), `hal/src/lib.rs`, `hal/src/callgate.rs` (tests + one doc), `hal/src/heap.rs`
(docs), `PLAN.md` (one line). Verified independently of the lanes' own reports:

| gate | before | after |
|---|---|---|
| hal | 291 | **315** |
| firmware | 173 | **173** |
| vendored | 116 | **116** |
| sweep total | 580 | **604** |
| ARM image | 379,648 B | **379,648 B — identical section for section** |
| ARM warnings | 0 | **0** |
| clippy, `hal/src`+`firmware/src` | 0 | **0** (the 18 hits in a workspace-wide run are all `uninlined_format_args` inside `vendor/`) |

`psram.rs` had **no production caller on 2026-09-17** — `rg 'psram::' hal/src firmware/src` outside
the module itself returned one doc reference and nothing else — which is why the image did not move
*in this phase*. **Phase 3 (§7b) falsified that**: `firmware/src/main.rs` now constructs
`psram::MappedPsram` and hands it to `upgrade::run`, so the same recipe returns 27 hits today and the
image moved to 379,940 B. Past tense throughout since 2026-09-18; it read as a present-tense claim
with a re-runnable recipe until then, which is the strongest form of pin this tree has and the one
form that cannot be left dated-but-unqualified.

**The finding that matters, and it settles §3.10 by measurement rather than by argument: the OLD
guard survived BOTH required mutations GREEN.** A renamed upgrade constant (`PIN_SUBCALL_FW_UPGRADE`)
and a selector-21 OTP burn call both passed the 2026-09-16 guard untouched. Directly confirmed:
`'PIN_SUBCALL_UPGRADE' in 'PIN_SUBCALL_FW_UPGRADE'` is `False`, and so is the `FIRMWARE` spelling. The
guard is now a frozen 5-row `(selector, arg2)` census read off ARGUMENT POSITION, plus a frozen count
of top-level `u32` constants (so a renamed sub-call reddens on its DECLARATION), plus
`unsafe { raw(` == 1 so every gate entry funnels through `call`'s validation. The four surviving
name needles are documented in the test as *"A TRIPWIRE, NOT THE GUARD"*.

Three further survived-green results worth carrying forward:
* **The lane's own first version of `staged_burn_len_reads_firmware_length_from_the_header` was
  vacuous** — it built its fixture from `FW_LENGTH_FIELD_OFFSET`, the same constant the reader uses,
  so writer and reader moved together and mutating 24 → 28 stayed green. Fixed by spelling the offset
  as the literal `16_280`. Caught by mutation, not review.
* **`FakePsram::span`'s own capacity edge was untested**: `end <= self.cells.len()` → `end <` left all
  291 lib tests green, because no test reached the last byte of a fake. A host double that quietly
  refused its own final word would have looked correct everywhere — the §8.1 defect-5 class in the
  tighter direction. Closed and re-measured to exit 101.
* **Two assertions were literally `assert!(true)`** (`assertions_on_constants`), found by clippy, not
  by the author. **Vacuous-assertion tally 22 → 24.**

Honestly noted: `the_burn_ceiling_is_the_gap_between_flash_isr_and_flash_fs` is **dominated** by the
`const _: ()` block for every mutation of `BURN_LEN_MAX`/`BURN_BASE` — they fail as `E0080` at compile
time, so the named test is not the load-bearing pin for the ceiling. It fires independently only via
`BURN_LEN_MIN`. Kept, but do not read it as the guard.

Remaining baseline to hold: heap **5,024 B** spare, and `PSRAM_STAGE_LEN` is the lower half only, so
the bootloader's recovery header at `PSRAM_BASE + PSRAM_LEN - 2048` is unnameable through
`MappedPsram`.

---

## 7b. PHASE 3 — LANDED 2026-09-17, hardened §7c, fixed §7d 2026-09-18

**Read §7d first for the current gate figures.** This section's table is the 2026-09-17 landing
record and is left at its measured values; §7c re-ran its mutations independently and §7d applied
seven confirmed review findings and re-measured every gate.

`firmware/src/upgrade.rs` (NEW, the `Stager` + `Wire` + `run`), `hal/src/psram.rs` (`Psram::view`,
two impls, one test, two module-doc rewrites), `firmware/src/lib.rs` (`pub mod upgrade`, three
now-false doc comments rewritten, **no behavioural change**), `firmware/src/main.rs` (USB and the
pad moved to steps 6b/6c, new step 6d, `BootRng`/`upgrade_requested`, four new tests, seven comment
rewrites, one false pin fixed), `firmware/examples/stub.rs` (`STUB_UPGRADE` leg + `StdioWire`),
`hostcheck/src/main.rs` (M13, three legs), `firmware/examples/checkfw.rs` (one stale pin).

| gate | before | after |
|---|---|---|
| hal (`--features fake-flash,test-seam`) | 315 | **316** |
| firmware | 173 | **191** (135 lib + 56 bin) |
| vendored | 116 | **116** |
| sweep total | 604 | **623** |
| ARM image | 379,648 B | **380,040 B** (+392 B) |
| ARM warnings | 0 | **0** |
| clippy, `hal/src`+`firmware/src` | 0 | **0** |
| `hostcheck` | `M1+…+M12 PASS` | **`M1+…+M12+M13 PASS`** |

**THE INVOCATION IS PART OF THE IMAGE FIGURE**: `RUSTFLAGS="-C target-cpu=cortex-m4 -C
link-arg=-Tfirmware/link.x" cargo build --release`, in the MAIN checkout, summing
`.vector_table 0x40 + .text 0x4e908 + .rodata 0xe31c + .data 0x24` from `objdump -h`. That is the
same invocation the 379,648 B baseline was taken with. Margin on `FLASH_TEXT` (1,425,408 B) is
**1,045,368 B**; the image is 26.6618% flash-resident. **The image moved for the expected reason**:
`psram.rs` gained its first production caller, so `--gc-sections` no longer drops it, and
`upgrade.rs` is new.

**Heap: unchanged, and that is an argument FROM CONSTRUCTION, not a measurement.** `Stager` is a
fixed-size struct with a `[u8; 4]` carry, chunk bytes are written straight from the wire slice, and
`upgrade.rs` names no `Vec`, `Box`, `collect` or `alloc` above its test cut (pinned by
`nothing_in_this_module_can_answer_a_message_or_allocate`). `run`'s `Link` is 4,096 B of `boot`'s
frame against 548,776 B of measured stack runway. Nothing re-measured
`MEASURED_ARENA_FOOTPRINT_BYTES`: it is pinned only by a `const _: ()` block in `hal/src/heap.rs`
with **no named runtime test**, and the measurement lives in `firmware/examples/heap_session.rs`,
an example that is not in the gate and refuses to run under the debug profile.

### Mutations RUN, not read: 19 device-side + 4 leg-level = 23 CAUGHT, plus 4 survived-green below

**The counts in this heading read "18 device-side + 4 leg-level" and "All 18 restored
byte-identical" until 2026-09-17**, when the hardening pass counted the table: it has **19**
device-side rows and 4 leg-level, i.e. 23 caught, and with the four survived-green results below
that is **27 mutations run**. The implementing agent's own summary said "22 run, 21 caught, 4
survived" — three mutually inconsistent figures in the one section whose purpose is the count. The
authoritative figures are: **27 run, 23 caught, 4 survived-green**, plus the 8 in §7c.

All 23 restored byte-identical (sha256 before == after, checked per run). Each row's "caught by" is
the named test that failed, with the assertion it failed at.

| mutation | caught by |
|---|---|
| `size > BURN_LEN_MAX` → `> PSRAM_STAGE_LEN` | `prepare_refuses_a_size_that_would_burn_past_flash_fs`, exit 101 |
| delete the `TooSmall` arm | `prepare_refuses_an_image_below_the_bootloaders_floor`, `Ok(())`/`Err(TooSmall)` |
| `% FW_BODY_ALIGN` → `% WRITE_ALIGN` | `prepare_refuses_a_size_the_burn_cannot_align` |
| route `PrepareUpgrade` into the `PrepareUpgrade2` arm | `the_legacy_prepare_is_refused_before_a_byte_moves` |
| let `feed` write while `Prepared` | `chunks_are_refused_until_enter_upgrade_mode`, `Ok(1)`/`Err(OutOfOrder)` |
| allow `EnterUpgradeMode` from `Idle` | `enter_upgrade_mode_is_refused_before_a_prepare` |
| drop the `r == size` case from `acks_at` | `every_chunk_is_acked_once_…` at `Ok(64)`/`Ok(65)`, **plus 3 more** |
| return the ack before `verify` | `every_chunk_is_acked_once_…` at `Ok(0)`/`Err(Digest)` |
| `write(OFFSET + written, ..)` → `write(OFFSET, ..)` | 5 tests, incl. `staged_bytes_land_at_the_offset_they_arrived_at` |
| delete the `received + n > size` guard | `a_byte_after_the_announced_size_is_refused_and_stores_nothing` |
| delete the `declared != size` comparison | `the_header_length_must_agree_with_the_announced_size`, `Ok(1)`/`Err(LengthDisagreement)` |
| write `bytes` straight through, no carry | `a_word_split_…_as_one_chunk` at `Err(Psram(NotAligned))` |
| remove `readback_selftest` from `admit` | `staging_on_a_target_with_no_psram_refuses_rather_than_reporting_success` |
| drop `self.written = 0` on re-prepare | `re_preparing_over_a_verified_image_clears_the_verdict_first`, `Err(Psram(OutOfBounds))` |
| `use crate::Session;` above the cut | `nothing_in_this_module_can_answer_a_message_or_allocate`, `1`/`0` |
| move `view`'s `check_read` inside the ARM `cfg` | `the_view_off_arm_shows_nothing_rather_than_something_wrong` (hal), `NotOnThisTarget`/`OutOfBounds` |
| move the USB block back below step 8b | `usb_comes_up_above_entropy_flash_and_identity` |
| `if upgrade_requested(..)` → `if true` | `the_upgrade_listener_is_gated_on_the_physical_hold` |
| `UPGRADE_HOLD_KEY` `b'y'` → `b'q'` | `the_hold_key_is_one_the_pad_can_actually_report` |
| *(leg-level)* drop the `r == size` case | M13 positive leg, `64 ack(s) … expected exactly 65` |
| *(leg-level)* return the ack before `verify` | M13 negative leg, `65 ack(s) … expected exactly 64` |
| *(leg-level)* restore the single-`Option` callback | M13 coalesced leg, `0 ack(s) … expected 65` |
| *(leg-level)* `received == size` → `>= size - 4096` | M13 negative leg, `63 ack(s)` — **dominates** the leg it was written for |

### FOUR SURVIVED-GREEN / WITHDRAWN RESULTS, and they are the point of this section

1. **`self.state = State::Idle` on re-prepare is DEAD.** Deleting it left all 191 firmware tests
   GREEN, exit 0. Every exit from that arm assigns the state anyway — three bounds and the
   self-test all go through `refuse`, and success assigns `Prepared` — so the invariant holds by
   exhaustion over four paths rather than unconditionally. The line is KEPT and labelled (a fifth
   path is one `?` away and a stale `Staged` is what a future phase would burn), and
   `re_preparing_over_a_verified_image_clears_the_verdict_first`'s doc was **corrected** to name
   the `written = 0` mutation it actually catches. Its `Prepared` assertion is the weak leg.
2. **The 100 ms gap after `EnterUpgradeMode` proves nothing on a pty.** M13's first draft asserted
   that deleting it reddens the positive leg, because cold-snap's buffering `Link::poll` would eat
   chunk 0's head. Deleting it left every leg GREEN — a pty delivers separate writes as separate
   reads. The sleep is kept for parity with `usb_serial_manager.rs:681-682` and is labelled
   unproven at its call site. **§3.5's reuse story is intact; the mitigation story was not
   testable here and now says so.**
3. **A fourth M13 leg was DELETED for domination.** It wrote both frames and chunk 0's head
   together and asserted no ack arrived (MEASURED: 0 acks, correct). Every device mutation that
   could make it fire is caught by the NEGATIVE leg first, so it read like coverage. Replaced by
   the coalesced-ADMISSION leg, which is uniquely falsifiable.
4. **A green M13 hid an intermittent bug in its own handshake.** Re-sending magic is correct (the
   device's `scan_magic` consumes the FIRST magic frame without calling `on_frame`, so one send
   never gets a reply) but left a second `MAGIC_REPLY` in the `BufReader` that nothing could
   consume — `read_for_magic_bytes` stops at the first pattern end and `anything_to_read()` asks
   the port, not the buffer. Its first byte is `0x00`, read as chunk 0's ack. Failed ~1 run in 3.
   Fixed with a `raw_read` drain. **Only a leg that switches to raw byte reads can see this.**

### §7c — the HARDENING pass, 2026-09-17: 27 mutations RE-RUN independently, 8 new

Every mutation in the table above was re-applied from scratch by a second agent that read the
source, not the table, and each was reverted with a **sha256 before == after** check inside the same
harness run (a `finally` block, so a failed gate cannot leave a mutated tree). All 23 reproduced
their claimed verdict, and both survived-green source claims reproduced too. Eight mutations the
table did not have:

| new mutation | caught by |
|---|---|
| `Psram::view`'s default body → `Ok(&[])` | `the_view_off_arm_shows_nothing_rather_than_something_wrong` (hal), `Ok([])`/`Err(NotOnThisTarget)` |
| **`FW_LENGTH_FIELD_OFFSET` 24 → 28** | **5 upgrade tests**, at `Err(Unreadable)`/`Ok(65)` — see below. RE-MEASURED 2026-09-18 after §7d's refusal remap: **4** upgrade tests, at `Err(LengthDisagreement)`/`Ok(65)`. The header-length test stopped reddening because it now EXPECTS `LengthDisagreement` on a garbage field, which is the correct verdict either way; the other four still catch it |
| `firmware_digest`'s `header_end - 64` → `- 60` | 6 tests, incl. `every_chunk_is_acked_once_…` at `Err(Digest)` |
| the no-pad arm `return false` → `return true` | `a_pad_that_will_not_open_cannot_arm_the_upgrade_listener`, `assert !upgrade_requested(None)` |
| `BootRng`'s `wrapping_add(0x9e37_79b9)` → `add(0)` | same test, `1`/`1`, "a constant source would fix the scan order" |
| `BootRng::fill_bytes` → a no-op | same test, "fill_bytes wrote nothing" |
| delete `wire.write(&comms::MAGIC_REPLY)` | M13 `stage_session`, "never answered the magic handshake in 5s" |
| delete `check_read` from `FakePsram::view` | **NOTHING — survived green, see below** |

**§7's oldest finding is now CLOSED, and this is the load-bearing result of the pass.** §7 records
`FW_LENGTH_FIELD_OFFSET` 24 → 28 surviving its required mutation GREEN, because the hal fixture was
built from the same constant its reader used. Under the new `upgrade` tests that mutation reddens
**five** tests, because `upgrade.rs`'s fixtures write the length field at the literal `16_280` while
`staged_burn_len` reads it through the constant. Writer and reader no longer move together. The
`- 64` row proves the same thing for the signature punch-out: `announce()` is an independent
implementation of the signed range, so widening the hole in production reddens rather than tracking.

**A FIFTH SURVIVED-GREEN RESULT, and it is unfalsifiable rather than untested.** Deleting
`check_read` from `FakePsram::view` left all 316 hal tests GREEN, exit 0. It cannot do otherwise:
`FakePsram::new` PANICS above `PSRAM_STAGE_LEN`, so `cells.len() <= PSRAM_STAGE_LEN` always, so any
`len` that `check_read` refuses the capacity refuses too — and both answer the same `OutOfBounds`
variant, deliberately, so no leg can ever tell which fired. The test's doc CLAIMED that leg pinned
the ordering ("the DEVICE's window bound runs before the double's own capacity"); that claim was
false and has been rewritten. The line is kept and labelled at its call site, for the one
non-circular reason: `new`'s cap and `new`'s own `#[should_panic]` test are one edit apart — writer
and reader again — and if that cap is relaxed this line becomes the live check. `MappedPsram::view`'s
`check_read`, which is the one that matters, IS covered.

Also swept, with nothing found: **no new `const _: ()` block** was added by phase 3, so no named
runtime test in it is dominated by an `E0080`; **no `#[cfg]`-gated refusal that fails open on the
other target** — `upgrade.rs` has no `cfg` outside its test module, and `MappedPsram::view`'s bound
is outside its `cfg` and proven so by mutation; **zero `assertions_on_constants`**, verified by
planting one `assert!(true)` and confirming clippy fires on it, so the tally stays at 24. The
hardening pass's own edits are comment-only: hal 316 / firmware 191 / sweep 623 unchanged, ARM image
unchanged at 380,040 B with 0 warnings, `cargo doc` 0 warnings, hostcheck `M13 PASS` 3/3.

### Two REAL defects the mutation work found, in production code

* **`upgrade::run` dropped an admission frame.** The callback recorded the admitted message in one
  `Option`, so two `Upgrade` frames in a single 64-byte read left only the second admitted —
  `EnterUpgradeMode` from `Idle`, i.e. `Refuse::OutOfOrder` and an upgrade that could never start.
  Invisible to M13 until the coalesced leg existed, because a pty separated the writes. Fixed by
  admitting inside the callback (`admit` touches neither `link` nor the wire, so it is sound there).
* **`Stager::feed` clobbered a part-filled carry.** Step 3's unconditional
  `self.carry_len = tail.len()` zeroed a carry step 1 had just topped up, so feeding one byte at a
  time dropped three of every four bytes and the transfer ended in `Refuse::Unreadable` (**re-measured
  2026-09-18 after §7d's refusal remap: `Refuse::LengthDisagreement`; the defect is unchanged, only its
  diagnosis moved**). Caught by
  `a_word_split_…`'s `step 1` leg, which is the whole reason that test streams at 1, 2 and 3.

### Honestly noted

* **`Refuse::Psram(_)` has no reachable test.** After admission every write is proven word-aligned
  and inside a span `readback_selftest` already checked. Defence in depth, stated as such.
  (`a_word_split_…` and the extra-bytes test DO observe it, but only under mutation.)
* **`Refuse::Unreadable` WAS NOT unreachable after admission, and this bullet claimed it was until
  2026-09-18.** The reasoning quoted here ("`declared == size` implies all three of
  `firmware_digest`'s bounds") is sound for the `firmware_digest` `None` arm and was never sound for
  the `staged_burn_len` arm above it, which mapped ALL FIVE `StageError`s to `Unreadable` — three of
  them driven by a streamed, coordinator-supplied header field. So the variant fired on ordinary
  hostile input while its own doc said it could not, and `Refuse::LengthDisagreement` — the variant
  §3.2 exists for — was reachable only for a declared length inside `[BURN_LEN_MIN, size]`, which is
  the narrow slice its one test leg happened to use. FIXED in §7d: `TooSmall | TooLarge | Truncated`
  now answer `LengthDisagreement`, `NotInStagingWindow`/`HeaderUnreadable`/no-view keep `Unreadable`,
  and those three ARE unreachable after admission (`size >= FW_MIN_BODY_LEN > 16_384` and
  `size <= BURN_LEN_MAX < PSRAM_STAGE_LEN`). Still an arm and never an `expect`.
* **`impl Wire for usb::Cdc` is read-verified only.** `run`'s loop executes on the host solely
  through `StdioWire`; the three-line `Cdc` impl never runs in any gate.
* **`MappedPsram::view`'s ARM `from_raw_parts` leg is read-verified only**, pinned to the identical
  shipped pattern in `main.rs`'s step 8c flash digest.
* **`upgrade_requested`'s pad READ is read-verified only; its DECISION is not, since §7d.**
  `KeypadToken::open` cannot produce a `Keypad` off ARM, so no host test can call `read_key`. The
  decision was split out as `arms_upgrade(Result<Event, KeypadError>) -> bool` — the shape `answer`
  already had — and `only_the_ok_dome_arms_the_upgrade_listener` drives it over all twelve `DECODER`
  bytes plus `MultiKey`, `Unsettled`, `AllUp` and both `KeypadError`s. **Until then the accept
  condition was pinned by NOTHING**: widening it to `| Ok(Event::MultiKey)` — which is what the
  driver reports for a wet or shorted pad — survived the entire firmware suite green.
* **Two M13 refusals were caught with the wrong diagnosis before `read_ack` learned that a gone
  child is "no ack"**: `Broken pipe` rather than the ack count, because `run` returns on
  `Outcome::Staged` and the stub exits before a missing ack can time out.
* **The consent gate is an ENTRY gate, not a per-message gate.** The human authorises "reflash this
  device this boot", not a digest. Named as a `ponytail:` ceiling on `upgrade_requested`; a
  digest-confirm screen belongs to the phase that burns.
* **There is no timeout on the chunk stream** (upstream has none either; the only one in the
  protocol lives on the host). A torn transfer leaves the device in `Streaming` forever, where it
  does not feed `Link::poll` at all, so recovery is a POWER CYCLE. MEASURED as an M13 leg-ordering
  constraint. Safe only because this phase cannot burn.
* **A unit that dies at `panic!("entropy fail-closed")` or `panic!("flash geometry")` WITHOUT a key
  held has no upgrade path.** Step 6d sits above both, so a held key still reaches the listener.
  Converting those panics into listening holds is decision-sized and is not this phase.

### §7d — the FIX pass, 2026-09-18: seven confirmed review findings applied, 5 mutations RUN

An adversarial review of §7b/§7c produced nine findings that each survived two independent
skeptics. Seven were applied; two are recorded below as deliberate non-fixes. Two of the seven
CHANGED BEHAVIOUR and therefore needed tests, and both tests were mutation-verified in the §7c
harness (one exact-string mutation, gate run, revert inside a `finally` block, `sha256 before ==
after` asserted per run).

| gate | before (§7c) | after (§7d) |
|---|---|---|
| hal (`--features fake-flash,test-seam`) | 316 | **316** (292 + 5 + 19) |
| firmware | 191 | **192** (135 lib + 57 bin) |
| vendored | 116 | **116** (macros 7 + embedded 17 + comms 10 + core 63 + `frost_backup` 19) |
| sweep total | 623 | **624** |
| ARM image | 380,040 B | **379,940 B** (−100 B; +292 B net over the 379,648 B phase-2 baseline) |
| ARM warnings | 0 | **0** |
| clippy, `hal/src`+`firmware/src` | 0 | **0** |
| heap arena high-water | 60,512 B (argued) | **60,512 B of 65,536, 5,024 B spare (MEASURED)** |
| `hostcheck` | `M13 PASS` | **`M1+M2+M3+M5+M7+M8+M9+M12+M13 PASS`, exit 0, 5/5 runs** |

**THE INVOCATION IS PART OF THE IMAGE FIGURE**: `RUSTFLAGS="-C target-cpu=cortex-m4 -C
link-arg=-Tfirmware/link.x" cargo build --release`, in the MAIN checkout, summing
`.vector_table 0x40 + .text 0x4e8a4 + .rodata 0xe31c + .data 0x24` from `/usr/bin/objdump -h`.
Margin on `FLASH_TEXT` (1,425,408 B) is **1,045,468 B**; the image is 26.6548% flash-resident. The
−100 B is `upgrade_requested`'s decision becoming an exhaustive `arms_upgrade` match plus `verify`'s
refusal mapping gaining one arm — i.e. this pass ADDED source and the image got smaller, which is
why it is measured and not predicted.

**HEAP: MEASURED THIS TIME, and that is the one baseline §7b could only argue.** §7b said "unchanged
by construction, not by measurement" because `firmware/examples/heap_session.rs` is not in the gate.
It was RUN: `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example
heap_session --features="coldsnap_hal/test-seam,frostsnap_core/coordinator"`. Arena footprint
high-water **60,512 B of 65,536, 5,024 B spare**, peak requested 54,496 B in ≤ 30 simultaneous
blocks, live-between-frames 17,844 B, 0 allocator refusals, largest free block after dropping the
`Session` 65,520 B of 65,536 (so it still coalesces). `heap.rs`'s binding assert re-evaluates to
17,844 + 8,192 + 20,480 + 8,160 = 54,676 vs 65,536, slack 10,860 B. Unchanged from the 2026-09-17
baseline to the byte — which is what "the staging path allocates nothing" predicted, now on evidence.

#### The two behaviour changes, and their mutations

| mutation | caught by |
|---|---|
| revert `verify`'s `TooSmall \| TooLarge \| Truncated => LengthDisagreement` arm to `Err(_) => Unreadable` (i.e. restore the pre-fix production code) | `the_header_length_must_agree_with_the_announced_size`, exit 101, 134/1, `left: Err(Unreadable)` / `right: Err(LengthDisagreement)` on the `declared = 0` leg |
| widen `arms_upgrade` with `Ok(keypad::Event::MultiKey) => true` | `only_the_ok_dome_arms_the_upgrade_listener`, exit 101, 56/1, "MultiKey is not a decision to reflash" |
| `Ok(keypad::Event::Down(k)) => k == UPGRADE_HOLD_KEY` → `Ok(keypad::Event::Down(_)) => true` | same test, exit 101, 56/1, `'0' must not arm the listener`, `left: true` / `right: false` |

Plus two RE-RUNS of §7b/§7c mutations whose recorded verdict the refusal remap invalidated, so the
table stays true rather than merely plausible:

| re-run mutation | recorded verdict | re-measured 2026-09-18 |
|---|---|---|
| `FW_LENGTH_FIELD_OFFSET` 24 → 28 | 5 upgrade tests at `Err(Unreadable)` | **4** upgrade tests at `Err(LengthDisagreement)`, exit 101, 131/4 — `a_word_split_…`, `every_chunk_is_acked_once_…`, `re_preparing_over_a_verified_image_…`, `staged_bytes_land_…`. §7's oldest finding stays CLOSED: writer and reader still do not move together |
| drop `feed`'s `!rest.is_empty()` carry guard | 1 test at `Err(Unreadable)` | 1 test at `Err(LengthDisagreement)`, exit 101, 134/1, `a_word_split_across_two_packets_lands_the_same_bytes_as_one_chunk`'s `step 1` leg |

**Coverage NOTE, stated rather than buried: the 24 → 28 mutation now reddens 4 tests instead of 5.**
`the_header_length_must_agree_with_the_announced_size` stopped catching it, because reading a garbage
field at the wrong offset now produces the same `LengthDisagreement` that test expects — which is the
CORRECT verdict for a garbage length, so the test is right and its coverage of THAT mutation is
simply redundant with four others. Net coverage is up: the test went from one leg to five.

#### The seven findings applied

1. **`Refuse::Unreadable`'s "Unreachable after admission" was FALSE, and it swallowed most of
   `LengthDisagreement`'s cases.** `verify` mapped all five `StageError`s to `Unreadable`, and three
   of them (`TooSmall`, `TooLarge`, `Truncated`) are driven by a streamed, coordinator-supplied
   header field. So the variant fired on ordinary hostile input — and on any corrupt transfer,
   since an all-zero header field is `TooSmall` — while its own doc, §7b's "Honestly noted" bullet
   and `verify`'s reasoning all said it could not. Remapped: those three answer
   `Refuse::LengthDisagreement`, which is what they mean, and `Unreadable` keeps only the genuinely
   unreachable legs (`view` failure, `NotInStagingWindow`, `HeaderUnreadable`). The remap is not a
   taste call — admission pins `BURN_LEN_MIN <= size <= BURN_LEN_MAX` and `view(size)` makes
   `staged.len() == size`, so each of the three IMPLIES `declared != size`. Fail-closed before and
   after; what changed is the diagnosis and the truth of the pin.
2. **The consent gate's ACCEPT condition was pinned by nothing.** The three source-shape tests
   pinned the call site, the signature, the `None` arm and the constant `UPGRADE_HOLD_KEY == KEY_OK`
   — never that the constant is the thing MATCHED, and never that any other `Event` is refused.
   MEASURED: widening the arm to `| Ok(keypad::Event::MultiKey)` survived all 191 firmware tests
   GREEN with 0 ARM warnings, and `MultiKey` is exactly what the driver reports for a wet or shorted
   pad — so a damp keypad column would have booted every unit into the pre-`Session` listener and
   never into `Session::open`. Fixed the way `answer` already is: the decision is now
   `arms_upgrade(Result<Event, KeypadError>) -> bool`, host-testable, an exhaustive `match` (so a new
   `Event` variant is an `E0004` rather than a silent `false`), driven over all twelve `DECODER`
   bytes plus `MultiKey`/`Unsettled`/`AllUp`/`NotOnThisTarget`/`ColumnsStuckLow`.
3. **Three "No production caller" claims about `psram.rs` were left to rot**, including the exact
   line `psram.rs`'s own rewritten paragraph had cited as the evidence for them. Corrected with the
   dated clause at `hal/src/psram.rs`'s module doc (the "accessor with no production caller"
   sentence), `MappedPsram`'s own doc, `hal/src/lib.rs`'s crate-root module table, and
   `memmap::PSRAM_BASE`'s doc — the last two in a file that was not in phase 3's diff at all.
   `check_burn_len`'s "no caller" claim is now scoped to "none outside this file's own
   `#[cfg(test)]` assertions", which is what it always meant.
4. **The identity-fault "the hold sits above USB bring-up" claim had FOUR homes; phase 3 rewrote
   one.** `hal/src/identity.rs`, `hal/src/ui.rs` and `PLAN.md` §9 item 14 all still asserted the
   ordering as the security property, and `identity.rs` pointed the reader at the `main.rs` site
   that now contradicts it. All three carry `main.rs`'s replacement argument now: the hold is dark
   because it never polls `cdc`, not because of ordering. `PLAN.md`'s archived pre-2026-08-25 text
   also carried "the fix is **not** to bring USB up early"; that prohibition is marked withdrawn,
   with the reason (at RDP=2 a unit with a damaged identity record otherwise has NO reflash path).
5. **`PLAN.md` §10 — the section README, DECISIONS.md and §7b all NAME as the authority for the
   image figure — still said 379,648 B**, so every document that moved to 380,040 B disagreed with
   the source it cited. All five present-tense `PLAN.md` sites corrected (§10's figure and its
   `899,400 / image` ratio, `:172`'s "Current:", `:1044`, `:1231`'s margin), each with the dated
   clause. The historical trail entries — the `secp-lowmemory` both-sides A/B, the trajectory list,
   the `311a41b` recipe-trap paragraph — are deliberately left alone: they are correction records,
   not current-state claims.
6. **`DECISIONS.md` kept 379,648 B in two present-tense sites** while its own Provenance row, edited
   in the same change, said 380,040 B — one of them sixteen lines below a bullet list that change
   edited. Both corrected, plus the Provenance row itself, plus its "`-p coldsnap_firmware` differs
   by 4 B" cross-reference, which §10 had already re-measured at 12 B.
7. **The mutation tally had four values across four documents.** `PLAN.md` §8.2b's heading and
   README's register paragraph printed the exact figures §7b had already retracted, and §8.2b was
   arithmetically impossible on its own face (18 + 4 = 22 run, yet 21 caught + 4 survived = 25).
   The authoritative accounting is a SUM of three dated passes and is now written as one:
   **§7b 27 run / 23 caught / 4 survived-green; §7c 8 run / 7 caught / 1 survived-green; §7d 5 run /
   5 caught / 0 survived = 40 run, 35 caught, 5 survived-green.** README's "three of those four are
   facts about the HARNESS" is now "four of those five".
8. **`hostcheck`'s `stream_chunks` had a dead `owed` parameter.** Both callers passed the literal
   `0`, so its `for i in 0..owed` ack-collection loop executed in no run and `let i = owed + n` was
   always `n` — six lines of ack accounting inside the one function M13 exists to falsify, reading
   as covered because the function around it is. It was scaffolding for the fourth M13 leg §7b
   records as deliberately deleted. Deleted with it. (Nine findings, seven of which are the numbered
   defects above; this is the ninth and the eighth is folded into item 1's doc sweep.)

#### Deliberately NOT fixed, with reasons

* **`self.state = State::Idle` in `Stager::admit` stays**, still dead, still labelled. Unchanged
  judgement from §7b/§7c: one line of fail-closed redundancy against a fifth exit path that is one
  `?` away, on the arm whose job is to stop a stale `Staged` reaching a future burn.
* **`FakePsram::view`'s `check_read` stays**, still unfalsifiable, still labelled at its call site
  with the measurement (§7c). `MappedPsram::view`'s — the one that matters — IS mutation-covered.

#### What phase 4 still needs, unchanged by this pass

Nothing in §5 was settled here, with one exception of scope rather than substance: §5 item 3's
`MEASURED_ARENA_FOOTPRINT_BYTES` half is now a MEASURED 60,512 of 65,536 with 5,024 B spare against
this tree rather than an inherited figure, so the heap side of the phase-4 gate has a current
baseline to extend. The wire-size measurement for a `SharedKey`-carrying upgrade message is still
not done, and it is still what gates phase 4. Also unchanged and still the largest gap: **nothing
has run on silicon.** `MappedPsram`'s ARM `from_raw_parts`, `Cdc`'s `Wire` impl, `upgrade_requested`'s
pad read and `readback_selftest` against real OCTOSPI have never executed.

### Corrections to this file made by phase 3

* **§3.5: "our `firmware_digest` … is the shape `PrepareUpgrade2` wants" is too strong.** Both
  exclude the signature, so they are the same CLASS, but upstream's is a contiguous prefix
  `sha256(bytes[..firmware_size])` while ours is TWO discontiguous ranges — `[0, 16_320)` then
  `[16_384, length)` — because the Mk4 signature sits at byte 16,320 of the image rather than
  appended. Consequence, stated rather than hidden: **a stock coordinator's announced digest will
  not match ours.** That is the fail-closed direction and costs nothing while the driver is a host
  tool.
* **§3.5: "`FIRMWARE_UPGRADE_CHUNK_LEN` == our `FRAME_LIMIT` of 4,096, so DECISIONS.md 7 is
  untouched" is true for the wrong reason.** Decision 7 is untouched because chunks never enter
  `Link`'s accumulator AT ALL. The equality is a coincidence; a chunk could not be a frame anyway,
  since the minimum bincode envelope puts it at ≥ 4,102 B.
* **§3.7: "the keypad's own tests drive `scan_once` with a trivial counter" is false as written.**
  That is true of `shuffle_rows`; `scan_once`'s body is ARM-only and NO host test executes it. The
  conclusion survives — `shuffle_rows` is its only RNG consumer and demonstrably runs off a counter
  — which is why `BootRng` is four lines and takes no entropy.
* **§3.7's `hold()` pin `~:1948` is wrong**; the definition is `fn hold(reason: &str) -> !` and it
  is cited by symbol now. The name is also a trap: `hold` there means "spin forever, dark", while
  §3.7's "key hold" means a finger on a dome. The new one is `upgrade_requested`.
* **§3.7 is silent on the fact that a live comment forbade the reordering it proposes.**
  `main.rs` said "Do NOT resolve a future diagnostic need by moving USB earlier — that trades the
  security property for a channel." That comment is rewritten with what is now true, including the
  exact scope of the regression (one attach event; enumeration still never COMPLETES, because
  `hold` never polls `cdc`) and what re-closes it (step 6d).

## 8. PROVENANCE

Verified by the orchestrator directly: §1.3, §3.1 (including the field arithmetic), §3.2, §3.3,
§3.4, §3.5, §3.6, §3.7, §3.8, §3.9, §3.10.
Agent-reported and **not** independently verified: the §2 upstream-hardware rows, the ~15 s burn
duration, `pins.c:1328`'s SE1 write ordering, `se2_handle_bad_pin`'s early return, and §5 item 5.
Nothing in this file has run on silicon.

**§7b (phase 3) was AGENT-REPORTED and NOT independently re-run when this paragraph was written;
that is no longer the split, and this read "no second party re-ran them" until 2026-09-18** — which
contradicted §7c, in this same file, 80 lines above. The split as it now stands. §7b's figures were
produced by the implementing agent. Its mutation table was independently RE-RUN by a second agent
(§7c: all 27 re-applied from scratch against the SOURCE rather than the table, 23 reproducing their
claimed verdict, both survived-green source claims reproducing, one further survivor found, 8 new
mutations added) and re-measured by the hardening pass (hal 316 / firmware 191 / sweep 623, ARM
image 380,040 B, `M13 PASS` 3/3). §7d is a third pass, which re-measured the gates again after
fixing seven confirmed review findings. Still not orchestrator-verified as §7 was. The three legs
that are read-verified only are named in §7b's own "Honestly noted" list, and the largest single
gap is unchanged from §7: **nothing has run on silicon.** In particular `MappedPsram`'s ARM
`from_raw_parts`, `Cdc`'s `Wire` impl and `readback_selftest` against real OCTOSPI have never
executed.
