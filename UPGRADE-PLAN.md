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
* `DECISIONS.md` decision 2 still claims `| PIN | none | mandatory, SE1-enforced |`. False for the
  shipped product.

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

**Phase 3 — staging over the existing transport.**
Admit `EnterUpgradeMode` / `PrepareUpgrade2` / chunks; stream 97 × 4,096 B into PSRAM's lower half;
verify the digest on-device before spending anything. Early USB per §3.7. No callgate call yet.
Testable end-to-end on the host through `hostcheck` + `examples/stub.rs`.

**Phase 4 — the coord-contrib gate.** The `SharedKey` check of §1.2. **Needs a wire-size and heap
measurement first** — see §5.

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
   `MEASURED_ARENA_FOOTPRINT_BYTES` is already 60,512 of 65,536. Measure by extending
   `firmware/examples/heap_session.rs` plus a wire-size measurement in the §7 style. **Gates phase 4.**
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

`psram.rs` has **no production caller** — `rg 'psram::' hal/src firmware/src` outside the module
itself returns one doc reference and nothing else — which is why the image did not move.

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

## 8. PROVENANCE

Verified by the orchestrator directly: §1.3, §3.1 (including the field arithmetic), §3.2, §3.3,
§3.4, §3.5, §3.6, §3.7, §3.8, §3.9, §3.10.
Agent-reported and **not** independently verified: the §2 upstream-hardware rows, the ~15 s burn
duration, `pins.c:1328`'s SE1 write ordering, `se2_handle_bad_pin`'s early return, and §5 item 5.
Nothing in this file has run on silicon.
