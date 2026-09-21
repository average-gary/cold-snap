# HARNESS-PLAN — scaling the pre-silicon harness to the declared envelope

**STATUS: TEMPORARY. Not one of the curated four** (`README.md`, `PLAN.md`,
`DECISIONS.md`, `UPGRADE-PLAN.md`). Written 2026-09-21 as the reference for an
agentic workflow. **Delete this file** when phase A and phase B land, folding
their results into `PLAN.md` §7 (the tier ladder) and their measured figures into
`README.md`. Nothing here is evidence; it is a work order. Every number below is
labelled MEASURED (re-derived this session from the tree) or UNVERIFIED.

## 0. The question this answers

*"Is there device emulation we could run before silicon — a desktop coordinator
plus three emulators? What do we lose that only silicon can do?"*

**Answer: no new emulator. Two rigs, and one of them already exists.**
Instruction-level emulation is a dead end here and is already assessed as one:

- **QEMU is closed, and was RUN.** No available machine has both flash at
  `0x0802_0000` and RAM reaching the stack top `0x2009_e000`, so both honest modes
  retire **zero** of our instructions. See the header of `tools/qemu-boot.sh`,
  which is the authority and is not duplicated here. Only a deliberately faked
  `SP` retires any. MEASURED (2026-09-09, qemu 11.1.1).
- **Renode is out of scope for this plan.** `PLAN.md` §7 Tier 4 labels it
  *"assessed, not attempted"*, and `AUDIT-2026-09-10.md` flags PLAN's specific
  Renode capability claims as **unverified** (not installed, no `.repl` in either
  checkout). It cannot reach the two highest-risk items regardless: the callgate
  is PCROP code outside any image we can emulate, and SE1 (one-wire UART4) / SE2
  (I2C2) have no models. **Do not start a Renode port under this plan.**
- **The load-bearing reason, and it is not effort:** an emulator's peripheral
  model is written from the same reference manual the driver was, so it cannot
  catch a misreading — only a disagreement with itself. The in-repo receipt:
  `netduinoplus2` models an `stm32f2xx_spi` at our SPI1 base where `CR2.DS` and
  `SR.FTLVL` do not exist, so writes are accepted, `FTLVL` reads 0, and `drain()`
  returns `Ok` **having verified nothing** (`tools/qemu-boot.sh` header). A green
  run under a model we wrote from the datasheet is evidence about our datasheet
  reading, twice.

## 1. The envelope is 12, and it is already code

MEASURED, `firmware/src/lib.rs`:

| Fact | Anchor |
|---|---|
| `MAX_PARTIES = 12` | `:291` |
| Two refusal sites returning `Refusal::GroupTooLarge` | `:1094`, `:1101` |
| Unit test: n=13 **must** be refused | `:3713` |
| Unit test: n=12 must **not** be refused | `:3735` |

So "more than three devices" is already a device-side fact with tests on both
edges. What is missing is an end-to-end run at 12 against a real coordinator, and
a coordinator's reaction to the refusal at 13. `n >= 13` is out of scope on
purpose (`DECISIONS.md`) — 12 is the ceiling, 13 is a refusal test.

`CertifyPlease` is `195·n + 33·t + 127` (MEASURED, README):

| Roster | Size | Against `FRAME_LIMIT` 4,096 |
|---|---|---|
| 9-of-9 | 2,179 B | fits, 1,917 spare |
| **12-of-12** | **2,863 B** | fits, **1,233 spare** |
| 13-of-13 | 3,091 B | **fits — and must still be REFUSED** |

**The 13 row is the whole point of phase B:** the refusal is a *policy* refusal,
not a size refusal. A size-based check would pass while the policy was broken.

## 2. Two rigs, two jobs — do not merge them

| | `hostcheck/` (exists) | app rig (phase C) |
|---|---|---|
| Role | **assertion** rig | **topology + human** rig |
| Transport | one pty, N sessions in one process | N ptys, 1 session per process |
| Coordinator | `frostsnap_coordinator` as a library | the real Flutter desktop app |
| Asserts | ~15 counted latches | nothing programmatic |
| Bypasses | `UsbSerialManager` entirely (`FramedSerialPort::new` direct, `hostcheck/src/main.rs:1419-1420`) | exercises it |

**Do not move hostcheck's assertions into the app rig.** They only mean anything
because they name an exact roster on one wire; spread across N processes there is
nothing left to count. The app rig's job is the coordinator paths hostcheck
bypasses and the one thing no host test supplies — a person reading the glass.

Topology note, MEASURED: the conch is **off** on this device (`DECISIONS.md:671`
— `Downstream` signals `VERSION_SIGNAL 2`, conch needs 1), so a cold-snap device
is a leaf. N devices means N ports, N magic-byte handshakes, N port state
machines. hostcheck's one-pty/N-sessions shape is a convenience, **not the
shipping topology**.

---

## Phase A — raise `hostcheck` 9 → 12

**STATUS: DONE 2026-09-21, three green runs and one caught mutation. See A.6 for the
measured result and A.5 for the prose queue it leaves behind.** The prediction that this
"needs no new infrastructure" held: it is three constants, plus five stale strings the
change exposed.

The highest-value change, and it needs no new infrastructure.

### A.1 The mechanical part is four lines

```
hostcheck/src/main.rs:872   const N_DEVICES: usize = 9;   -> 12
hostcheck/src/main.rs:873   const THRESHOLD: u16   = 9;   -> 12
firmware/examples/stub.rs:150  const N_DEVICES: usize = 9; -> 12
```
`ALL_DEVICES = N_DEVICES + 1` derives in both files (`hostcheck:891`,
`stub:157`), so the blank device follows automatically and becomes the 13th
*announced* session.

**MEASURED: there are no numeric device-count literals in either file.** Grep for
non-comment `\b(9|10)\b` in both returns nothing, so every count is symbolic and
propagates. That is what makes A.1 small — and it is why the risk lives entirely
in A.2 and A.3, not in the propagation.

**THAT MEASUREMENT WAS TRUE AND INCOMPLETE, and it cost a defect (found 2026-09-21).**
It tested for *numeric* literals and not for **spelled-out** ones. `hostcheck` carried
five `tenth`/`TENTH` strings for the blank device, three of them in `println!` format
strings, so the PASS message asserted "the TENTH device ... left out of the keygen" while
the blank device was the **thirteenth**. No assertion caught it, because a format string
is not a condition — the run was green and its own summary was false. All three printed
sites now derive from `{ALL_DEVICES}` rather than spelling a number, so they cannot go
stale again; the two design comments were reworded to "the BLANK device". The grep that
should have been run alongside the numeric one:
`grep -noiE 'tenth|ninth|nine|\bten\b|eleventh|twelfth|thirteenth'` over both files.

**13 announced / 12 in the roster is legal and is the point.** The envelope binds
the keygen group (the `CertifyPlease` transcript), not the wire. The blank device
is not in the roster, so it does not move either size figure.

### A.2 Traps — each must be looked at, not sed'd

1. **`V1_THRESHOLD` must stay DIFFERENT from `THRESHOLD`.** `hostcheck:1069` sets
   it to 7 deliberately; its own doc (`:546`) records that **at 9 the mutation it
   exists to catch would have passed silently**. 7 is still fine at
   `THRESHOLD = 12`. Do not "tidy" it into `THRESHOLD`.
2. **The counted conditions.** `hostcheck:879-885` says a mechanical rename would
   have "flipped the seven counted conditions that must STAY at 9 and weakened all
   seven at once", and the constant was left un-renamed so that an unconverted
   site keeps the **stricter** count. This session found ~15 count-bearing sites
   across the two files and **did not reproduce the number seven**. Re-derive it
   before touching any of them; do not assume the doc's count is the site count.
   The `N_DEVICES` / `ALL_DEVICES` / `N_DEVICES - 1` distinction is load-bearing
   at every one — the header at `hostcheck:464-706` explains the individual traps
   and is the authority.
3. **The >1 KB pty write path.** `hostcheck:865-871` records that keygen frames stay
   under the ~1 KB point where an undrained pty blocks a write. At 12-of-12
   `CertifyPlease` is 2,863 B (**MEASURED**, A.6), so that sentence is no longer true
   of this harness.

   **THIS ITEM READ "so the writer thread and `WRITE_STALL_LIMIT` go from
   never-exercised-during-keygen to exercised on every keygen. Expect the run to get
   slower" UNTIL 2026-09-21, AND BOTH HALVES WERE WRONG:**
   - **No stall was observed.** Zero `WRITE STALL` lines across three green runs. The
     stub drains from a dedicated thread, so a 2,863 B write does not park. "Crosses the
     1 KB threshold" is not the same claim as "exercises the stall path", and only the
     first is established. The stall path remains unexercised.
   - **The slowdown prediction had the wrong mechanism.** It reasoned that `STUB_CHUNK=1`
     would add ~2.9 s of inter-chunk gap to each 2,863 B `CertifyPlease`. But
     `STUB_CHUNK` chunks the **stub's** writes (device→coordinator); `CertifyPlease` is a
     **coordinator** write and is not chunked by it at all. Measured cost of chunk 1 over
     chunk 64 is ~3.7-4.2 s for the WHOLE keygen, not per frame.
4. **`hostcheck:869` is STALE and must be corrected in the same change.** It reads
   "At 9-of-9 `CertifyPlease` is 2,179 B and does not even fit the device's frame
   limit." True at `FRAME_LIMIT` 2,060, false since decision 7 raised it to 4,096
   (2,179 < 4,096). It is the sentence that makes 9 look like a ceiling.

### A.3 Figures that must be RE-MEASURED, never scaled in prose

- **The randomised-consent distribution.** `COLDSNAP_GLASS_KEYS` is keyed by
  prompt kind, not positional (`stub:278`), so it scales — but the *measurement*
  does not. README currently records `=1yy` producing "8 of 9 devices declining
  (the ninth happened to draw `1`)". That is a 1-in-5 draw per device
  (`stub:302`); at 12 devices it is a different number and it has to come from a
  run.
- Every `9`/`10`/`2,179` in prose in `README.md`, `PLAN.md` §7/§9 and the two
  module headers.
- The 25-word restoration keypress count (README records 198).
- Flash/image size is **not** expected to move — this is harness-only. If it does,
  that is the finding.

### A.4 Verification

```sh
T=aarch64-apple-darwin
cargo build --target $T -p coldsnap_firmware --example stub
(cd hostcheck && cargo run)   # exit 0 + "M1+M2+...+M13 PASS: ..."
```
Take the exit status off the command, never off a pipe (repo convention, and the
reason several counts were wrong before 2026-09-10). Both `STUB_CHUNK` sizes run
on every invocation; `STUB_CHUNK=1` is the adversarial one and must stay green.

**Phase A is not done until one mutation is run and caught:** set
`N_DEVICES = 12` in `hostcheck` but leave the stub at 9 (or vice versa). The run
must fail by name, not hang. A harness that passes with mismatched rosters is a
harness that stopped counting.

### A.5 PROSE DIFFS PENDING — the curated four are still at 9

**NOT APPLIED, deliberately.** `README.md`, `PLAN.md`, `DECISIONS.md` and
`UPGRADE-PLAN.md` carry trajectory rows and retraction notes that a mechanical
find-and-replace would destroy, so this is a queue for a human, not a task for an agent.
The code and the docs therefore DISAGREE right now: the harness runs 12, the prose says 9.

Checklist, roughly in descending risk:

- [ ] `README.md` — the "real coordinator has completed a keygen and a signature" block:
      "9-of-9 keygen over a roster cut from **TEN** announced devices", "all nine",
      "the tenth device is deliberately left blank (M12, 2026-09-12)". **DERIVABLE** to
      12 / THIRTEEN / the thirteenth — but the paragraph also carries its own retraction
      ("This paragraph said 'a 9-of-9 keygen … all nine devices' with no tenth until
      2026-09-12"). That retraction is about the TENTH DEVICE'S EXISTENCE, not about the
      count 9, so it must be preserved verbatim and a new trajectory note added beside it.
- [ ] `README.md` — "all 9/9 device(s) pressed `x` at the signing screen": **REMEASURE.**
      The run now reports 12/12. Quote the new line, keep the old as trajectory.
- [ ] `README.md` — `COLDSNAP_GLASS_KEYS=1yy` "exits 1 with 8 of 9 devices declining (the
      ninth happened to draw `1`)": **REMEASURE, and it cannot be derived.** That is a
      1-in-5 draw per device; at 12 devices the expected count changes and the specific
      outcome must come from a run. NOT YET RUN — see A.7.
- [ ] `README.md` — the 9-of-9 `CertifyPlease` 2,179 B figure and the 12-of-12 = 2,863 B
      "1,233 spare" figure: the second is now **MEASURED on the wire** (A.6), not merely
      computed. Upgrade its status; keep 2,179 as trajectory.
- [ ] `PLAN.md` §7 Tier 3 + §9 — every "nine"/"ten announced" in the Tier-3 description.
- [ ] `PLAN.md` §7 Tier 1 test-count table — unaffected by the roster, do NOT touch.
- [ ] `DECISIONS.md` decision 7's envelope discussion — the `n ≤ 12` envelope text is
      **UNAFFECTED and now corroborated**: 12-of-12 was previously a computed bound and is
      now a measured one.
- [ ] `hostcheck/src/main.rs` module header — 40+ `N_DEVICES` mentions are symbolic and
      fine; the prose figures inside the MUTATION RECORD are historical measurements at
      9 devices and must be PRESERVED, with any new mutation appended rather than merged.

### A.6 RESULT — MEASURED 2026-09-21

Invocation, exactly (status taken off each command, never off a pipe):

```sh
cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub   # exit 0
cd hostcheck && cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub  # exit 0
```
No `COLDSNAP_TIMEOUT_SCALE`. Default 1. **The deadline risk A.2 item 3 was built around
did not materialise** — every bound held on the first attempt.

| Figure | Measured | Bound |
|---|---|---|
| Keygen, `STUB_CHUNK=64` | 3.92 s / 2.84 s / 3.36 s (three runs) | `KEYGEN_DEADLINE` 30 s |
| Keygen, `STUB_CHUNK=1` | 6.99 s / 7.01 s / 7.09 s | `KEYGEN_DEADLINE` 30 s |
| DECLINE pass keygen | 2.20 s / 2.16 s / 2.20 s | — |
| **Largest coordinator→device frame** | **2,863 B** | `FRAME_LIMIT` 4,096, **1,233 B spare** |
| Announce burst, 13 devices | 1,386 B (22 chunks at 64; 1,386 at chunk 1) | — |
| `WRITE STALL` / `DEADLINE` / `WATCHDOG` lines | **zero**, all three green runs | — |

**The 2,863 B is the headline.** `195·n + 33·t + 127` was read out of README prose; the
harness independently reports `largest coordinator->device frame actually written: 2863 B`,
so the formula is now measured rather than quoted, at the top of the declared envelope.
The harness's own annotation on that line: *"old FRAME_LIMIT was 2060, so this keygen was
previously REFUSED"* — decision 7's reversal is what makes a 12-device roster possible at
all, and this run is the first thing to demonstrate it end to end.

What the run asserts at 12 (quoted from its PASS output, not paraphrased): a real
**12-of-12 keygen over a roster cut out of 13 announced devices**; a signature that
**VERIFIES** against the group key; the 4-byte glass code equal to the coordinator's
session hash on **12/12** devices; a 14-char/56-byte previewed name reaching flash on
**12/12** and returning byte-exact; the forged `DataErase` refused by **12/12** which then
still signed; `13/13` `HeldShares2` reports matching; all four restoration flows from real
upstream drivers; the blank 13th device consolidating another device's 25 words onto a
flash that held no share; and `12/12` declining at the signing screen with **not one**
signature share reaching the coordinator.

**Upstream cap check (MEASURED):** no `MAX_PARTIES`-style constant exists in upstream
`frostsnap_core` or `frostsnap_comms` — nothing upstream refuses 12. But upstream's own
tests reference only small rosters (2 devices in `frostsnap_core/tests/share_location.rs`),
so **this harness is now the largest roster either tree has exercised.** Worth knowing
before blaming our side for any future failure at this size.

### A.6b Mutation register — 1 run, 1 caught, 0 survivors

| Mutation | Outcome | Evidence |
|---|---|---|
| Roster mismatch: `hostcheck` at 12, `stub` at 9 | **CAUGHT** | exit **1** at **5.002944541 s**: `DEADLINE (5s) in state WaitingForAnnounces -- magic_writes=5, writes_queued=27, writes_done=27, read_timeouts=0, announced=10, shares=0, acks=0, session_hash=false, ...` |

Failed **by name and bounded**, not by hanging, and the counters localise it exactly —
`announced=10` against the expected 13, before any keygen state was entered. Reverted; the
stub was rebuilt and the tree ends holding the 9→12 change and nothing else, green.

**One mutation is a floor, not a register.** `PLAN.md` §8.2b's lesson is that survivors
cluster in the harness rather than the device, and the two silent-pass mutations the
census was meant to predict were never produced — see A.7.

### A.7 WHAT PHASE A DID NOT ESTABLISH

Honest gaps, so nobody reads A.6 as more than it is:

1. **The `COLDSNAP_GLASS_KEYS=1yy` distribution at 12 devices is NOT re-measured.** The
   README figure ("8 of 9 declining, the ninth drew `1`") is still a 9-device
   measurement. One run supplies it; it was not done here.
2. **The "seven counted conditions" claim is still un-adjudicated.** `hostcheck:894-900`
   asserts a mechanical rename would have flipped *seven* conditions; a grep pass found
   ~15 count-bearing sites and could not reproduce the number seven. The change did not
   need the answer (every count is symbolic), but the doc's number remains unverified.
3. **Only one mutation was run.** Two predicted silent-pass mutations were supposed to come
   out of an adversarial census that did not complete (see §6). Until they exist, "the
   suite would catch a harness that stopped proving 12-of-12" rests on one data point.
4. **No `WRITE_STALL` coverage.** The path is still unexercised; see A.2 item 3.
5. **Nothing here touches silicon, `usb.rs`, `UsbSerialManager`, or the multi-port
   topology.** The pty tier exercises `comms.rs` fully and `usb.rs` not at all, and this
   harness still bypasses `UsbSerialManager` by constructing `FramedSerialPort` directly.
   A reader who concludes "12 devices work" should read §4 and phase C.

---

## Phase B — drive n=13 through a real coordinator

Small, and it closes the one gap the unit tests cannot: the device's refusal is
tested (`firmware/src/lib.rs:3713`), but **nothing proves the coordinator survives
being refused.**

- Roster of 13, expect `Refusal::GroupTooLarge`, assert the coordinator reports a
  clean failure rather than hanging or wedging its own state.
- Assert the refusal happens **on policy, not on size** — 13-of-13 is 3,091 B and
  fits `FRAME_LIMIT` 4,096, so a run that "passes" because a frame was too long is
  a false pass. Log the size and the refusal reason separately.
- Keep it in `hostcheck` as its own pass, alongside the existing decline pass.

---

## Phase C — the multi-port app rig

Only after A. This is the rig for `UsbSerialManager`, the upgrade UI, hot-plug,
and a human reading real screens.

### C.1 The seam is one line

MEASURED in the sibling `../frostsnap` checkout:

- The app picks its transport at `frostsnapp/rust/src/api/init.rs:88` —
  `UsbSerialManager::new(Box::new(DesktopSerial))`.
- The VID/PID filter is in the **manager**, not the impl:
  `frostsnap_coordinator/src/usb_serial_manager.rs:167`, against
  `USB_VID = 12346` / `USB_PID = 4097` (`:2-3`).
- So a dev-only `Serial` impl (~25 lines) that returns
  `PortDesc { id: "/dev/ttysNNN", vid: 12346, pid: 4097 }` and opens by path is
  the entire patch. `DesktopSerial` (`serial_port.rs:209-265`) is the model to
  copy; note its macOS `cu.`/`tty.` dedup, which pty paths do not need.
- **The `FfiSerial` route is NOT usable here.** `frostsnapp/rust/src/api/port.rs`
  panics on anything that is not Linux/Android, and its fd path expects a raw USB
  device for `CdcAcmSerial`, not a pty.
- No protocol or crypto crate is touched, so hostcheck's "unmodified coordinator"
  property is unaffected. The patch lives in the sibling tree, not in `vendor/`.

### C.2 Per-instance identity already exists

`stub.rs:1284` is `fn entropy(salt: u8)` and `stub.rs:1311` builds
`(0..ALL_DEVICES)` independent `FakeFlash`es. One session per process means the
salt comes from an env var instead of a loop index — an env var, not a design.
**Without a distinct salt per process every instance derives the same
`DeviceId`**, and the coordinator would see one device or reject the set.

### C.3 Traps

1. **Polarity.** The coordinator must hold the **slave**: FIONREAD on a darwin pty
   master always returns 0 and `FramedSerialPort::anything_to_read()` is exactly
   that ioctl, so a coordinator on the master reads nothing forever, silently.
   MEASURED, and the reason hostcheck is built the way it is.
2. **Keep the harness's slave handle open.** The harness creates the pair, hands
   the master to the stub, and gives the app the slave *path*. If it drops its own
   slave fd there is a window with no slave open, and the stub can see EOF before
   the app opens the path. Holding the fd (never reading it) closes the window.
   **UNVERIFIED — reasoning, not measured.** Measure it before writing around it.
3. **Do not open 12 SDL windows.** Relay the one or two under observation
   (`tools/sim-window.sh --relay`, which is per-device) and run the rest headless
   with scripted consent.
4. Timeouts: 5 s to match `DesktopSerial`, because a read timeout is turned into a
   port *disconnect* (`usb_serial_manager.rs:302-311`).

### C.4 Unverified prerequisites

The Flutter app has **never been built or run on this machine** in any session
recorded here. Establish that first; if the toolchain is not there, phase C is a
toolchain task before it is a harness task. Do not report C blocked on the harness
when it is blocked on flutter.

---

## 3. Out of scope, with reasons

- **Renode / a QEMU machine model** — §0. Weeks of platform modelling to test our
  own datasheet reading, and it still cannot reach the callgate, the SEs, or PSRAM.
- **Linux `dummy_hcd` + `raw-gadget`** — the only way to get real USB enumeration
  (descriptors, control transfers, the kernel's own `cdc-acm` attaching) without
  silicon. It replaces the register layer, so the OTG_FS **register sequences**
  stay unproven either way. Worth a separate decision; not part of this plan.
- **`Cancel` and legacy `SavePhysicalBackup` (v1)** — admitted by `Session::recv`
  and driven by no harness (README names this exception). Real gaps, but they are
  flow coverage, not device-count work. Do not fold them in here.

## 4. What only silicon can do

An agent working this plan must not report these as closed. From `PLAN.md` §7
("Not testable without hardware, at any tier"), plus what phase 3 added:

SSD1306 init/timing and physical legibility · keypad scan/debounce and its
randomised timing · the callgate in any form · the TRNG's two sources and its
health checks · panic→reset recovery · real STM32 program/erase semantics and
power-loss durability mid-erase · FROST signing latency in `secp256kfun` on a
120 MHz M4F · the OTG_FS register sequences (core reset, FIFO flush, endpoint
enable/NAK, VBUS override) and host-driven enumeration · OCTOSPI/PSRAM behaviour
under the upgrade stager · RDP/PCROP actually engaging.

Note where the pty tier sits in that list: it exercises `comms.rs` fully and
`usb.rs` **not at all**. Neither phase A nor phase C changes that.

## 5. Repo conventions an agent must follow here

Non-negotiable, and this tree enforces them in prose:

1. **MEASURED or it did not happen.** Quote the command and the exit status, taken
   off the command and not off a pipe.
2. **A later figure is a trajectory row, not a correction.** Do not overwrite a
   dated measurement with a newer one as if the old one were wrong; add the new
   one and say what moved. (`PLAN.md` §9's flash row is the worked example.)
3. **Cite symbols, not line numbers**, in anything that lands in the curated four.
   Line numbers are how a check was performed; the symbol is the citation.
4. **Retractions stay visible.** When this plan's assumptions turn out wrong, say
   so in place — "this read X until <date>" — rather than editing the claim away.
5. **A green suite proves nothing about reach** (`PLAN.md` §8.1). Every phase here
   carries at least one mutation that must fail.
6. Do not run a `cargo build` figure from a worktree under `.claude/worktrees/`:
   the longer absolute path inflates `.rodata` via panic `Location` strings.

## 6. Phase A was first attempted as a multi-agent workflow, and it failed

Recorded because the failure is instructive and cheap to repeat by accident.

An 8-lane fan-out (count-site census ×2, wire sizes, deadlines, resources, upstream caps,
prose inventory, adversarial skeptic) → synthesis → apply → run → mutate → 4 verify lenses
was launched before any of the work above. **It produced nothing in ~2 hours.** Journal
evidence: one distinct cache key per lane with 3-4 attempts each and a different agent id
per attempt, i.e. every lane was retried until its budget was gone. Transcripts reached
330-400 KB with 31+ `Bash` calls before dying. Every lane would have returned null and the
synthesis stage would have run on an empty set.

Two causes, both mine:

1. **Unbounded prompts over a very large tree.** Each lane was asked for a "COMPLETE
   census" of a 4,921-line file (plus a 353 KB `PLAN.md` and an 814 KB audit) with a schema
   whose findings array invites a hundred items. That is a context blowout by construction,
   not bad luck. Telling an agent "do not read these end to end" does not bound a task
   whose deliverable is exhaustive.
2. **The task was empirical and was modelled as analytical.** This tree has a harness that
   fails by name with counters, 624 host tests, and a mutation discipline. Changing three
   constants and reading the failure took ~15 minutes and produced better evidence than
   eight readers could: the defect that actually mattered — five spelled-out `TENTH`
   strings — was found by *running the harness and reading its own output*, which no
   amount of static census would have flagged as urgent, because it is a format string and
   not a condition.

**The rule this suggests for this repo:** fan out for breadth over things that cannot be
executed (prose inventories across the curated four, cross-tree constant comparisons, the
silicon-only list). For anything the harness can answer, run the harness. One
`cargo run` that fails by name beats eight agents reasoning about whether it would.

The two adversarial products of that workflow are still WANTED and still missing: the
predicted silent-pass mutations (A.7 item 3). Those are worth a small, bounded fan-out —
"name one mutation to THIS file that keeps the suite green", one file per agent, a
three-field schema — not an open census.
