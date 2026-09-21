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
      ninth happened to draw `1`)": **MEASURED 2026-09-21 at 12 devices — READY TO APPLY,
      text below.** It could not be derived (1-in-5 draw per device); it came from a run,
      with no source change, on `6e29bb6`. Keep the 9-device figure as a trajectory row,
      do not overwrite it.

      Replacement prose, as measured:

      > `COLDSNAP_GLASS_KEYS=1yy` exits **1** with **11 of 12** devices declining at the
      > twelve-device roster of `6e29bb6` — only `035f4007…` drew `1`, the 1-in-5 made
      > visible — and pass `STUB_CHUNK=64` dies on
      > `11 prompt(s) DECLINED but STUB_EXPECT_DECLINES=0`. At the earlier nine-device
      > roster the same variable gave **8 of 9** (the ninth drew `1`); `=9yy` gives 9/9.

      Supporting detail, VERIFIED (status off the command, not a pipe): `cargo run` /
      `hostcheck` exit **1**, child stub exit **2** (`stub exited exit status: 2`),
      failure surfaced in the first pass as `Error: pass STUB_CHUNK=64`. The device-side
      line, verbatim:

      > `stub: FAIL in KeygenInProgress after 7700 bytes read, 0 signature share(s) sent:`
      > `11 prompt(s) DECLINED but STUB_EXPECT_DECLINES=0 -- a declined prompt is a`
      > `FAILURE unless the run declares it`

      The one approval was `DeviceId 035f4007b30d19f3c4a27a8462036643a154d31c3c304bdf6964ae97baff18797a`
      (`CheckKeyGen -> approved on the randomised digit read off the glass`); the other
      eleven each printed `DECLINED CheckKeyGen -- the protocol has no message for a no`
      (prefixes `0212a8d6 0252993f 028f758d 029871dd 02a37833 02bcf5e9 03120f18 031c445e
      032d9c67 033bbd71 0345882f`; full ids in the run log). Tree clean after the run.
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

### A.6b Mutation register — 4 run, 2 caught, 2 survivors

Register grew 2026-09-21: three mutations were added to the original roster-mismatch one,
each predicted BEFORE it ran. Tree verified clean between mutations and at the end
(`git checkout --` exit 0, stub rebuilt exit 0, `git diff --quiet` exit 0, HEAD still
`6e29bb6`).

| # | Mutation | Outcome | Evidence, short form |
|---|---|---|---|
| M-0 | Roster mismatch: `hostcheck` at 12, `stub` at 9 | **CAUGHT** | exit **1** at **5.002944541 s**: `DEADLINE (5s) in state WaitingForAnnounces -- magic_writes=5, writes_queued=27, writes_done=27, read_timeouts=0, announced=10, shares=0, acks=0, session_hash=false, ...` |
| M-1 | `hostcheck/src/main.rs:4285` `if device_hashes.len() != N_DEVICES {` → `> N_DEVICES` | **SURVIVED GREEN** | exit **0**, 18.476 s, all four passes ok. See A.6b-1 |
| M-2 | `hostcheck/src/main.rs:886` `const THRESHOLD: u16 = 12;` → `= 8;` | **CAUGHT**, but late and mis-named | passes 1-2 green and printed `8-of-12`; pass 3 died on `DEADLINE (65s) in state SigningAwaitingShares -- ... sig_shares=0/8`. See below |
| M-3 | `firmware/examples/stub.rs:1998` `if saved.len() == N_DEVICES && !announced_save {` → `saved.len() >= 1` | **SURVIVED GREEN**, and is INERT | exit **0**, all four passes ok, and `saved` is never observed between 0 and 12. See A.6b-2 |

M-0 failed **by name and bounded**, not by hanging, and the counters localise it exactly —
`announced=10` against the expected 13, before any keygen state was entered.

**M-2, the one that was caught — by accident, and in the wrong place.** The prediction was
right about every assertion it analysed: the finalize check (`:3872`) tests device COUNT and
`has_blank` only, never the threshold; the single threshold assertion (`:4261`,
`found.threshold() != THRESHOLD`) compares the coordinator's value against the very const
handed to `BeginKeygen` (`:3349`), so both sides move together; and the signer subset
(`:3985`, `take(THRESHOLD)`) is compared at `:4559` against that same set, so 8 signers
still produce a verified signature. **Passes 1 and 2 went green on an 8-of-12 keygen** and
printed their own confession — `8-of-12 (keygen_id f400927857aaf64114f561baacb37970) after
512.736125ms`, then `pass ok: keygen … FINISHED in 3.061673667s` and `… 6.595876625s`.
What caught it was pass 3, verbatim:

```
Error: pass DECLINE

Caused by:
    DEADLINE (65s) in state SigningAwaitingShares -- magic_writes=1, writes_queued=78,
    writes_done=78, read_timeouts=0, announced=13, shares=12, acks=12, session_hash=true,
    held=12, replenished=12, sign_session=true, sig_shares=0/8, anything_to_read=false,
    elapsed=65.002499708s
```

Mechanism, VERIFIED by counting the log: the coordinator sent exactly 8 `RequestSign`
frames and the stub logged exactly 8 `DECLINED SignatureRequest at the glass` lines, but the
DECLINE pass breaks out on `declined.len() == N_DEVICES` (`:4168`, 12), so it sat out the
full 65 s signing budget. `sig_shares=0/8` shows the mutated threshold on the wire. That
condition is an **accidental** threshold tripwire — the number of devices prompted to sign
IS the threshold — so the suite reports a lowered threshold as a 65 s timeout in pass 3 and
never as a named threshold failure. INFERRED, not verified: had the DECLINE pass compared
against `THRESHOLD` instead of `N_DEVICES`, M-2 would have survived fully.

#### A.6b-1 SURVIVOR: the by-name keygen-agreement check is CORRECT, and no run exercises it

**Edit:** `hostcheck/src/main.rs:4285`, `if device_hashes.len() != N_DEVICES {` →
`if device_hashes.len() > N_DEVICES {`. **Outcome: exit 0, all four passes green.**

**Why it survives (predicted, and confirmed):** on a healthy run `device_hashes.len()` is
exactly `N_DEVICES`, so `> N_DEVICES` is false exactly where `!= N_DEVICES` was false.
Same types, no control flow change, no deadline moved.

**VERIFIED evidence** (`/tmp/m1_run.log`, exit 0, 18.476 s wall):

- `--- pass: STUB_CHUNK=64 ---` → `pass ok: keygen f400927857aaf64114f561baacb37970 FINISHED in 3.298706708s`
- `--- pass: STUB_CHUNK=1 ---` → `pass ok: keygen f400927857aaf64114f561baacb37970 FINISHED in 7.336146208s`
- `--- pass: DECLINE … ---` → ``pass ok: DECLINE -- keygen … FINISHED in 2.16716675s and the glass matched on 12/12 devices, then all 12/12 device(s) pressed `x` at the signing screen and NOT ONE signature share reached the coordinator``
- `--- pass: UPGRADE STAGING (M13) ---` → ``pass ok: M13 -- 262656 B announced as 65 chunks (64 whole plus a 512-byte SHORT tail, so `% 4096 != 0` is under test and not rounded off)``
- Final line: `M1+M2+M3+M5+M7+M8+M9+M12+M13 PASS: real 12-of-12 keygen over a roster cut out of 13 announced devices…`
- Log line 1 is `Compiling hostcheck v0.1.0`, so the mutated coordinator is the binary that
  ran; keygen timings 3.30 s / 7.34 s sit inside the A.6 baselines, so nothing moved.

**THE DEFECT IS THE COVERAGE, NOT THE SHIPPED CONDITION.** `!= N_DEVICES` at HEAD is the
correct strict check, and its own `bail!` text — `only {}/{N_DEVICES} device(s) reported a
session hash` — says which half is the point: the under-count half, with the over-count half
dead weight. Nothing on that line needs fixing. What is missing is any run that would notice
if it were weakened, because **no pass ever presents fewer than 12 hashes**, so the
assertion is **UNEXERCISED**. The following `for (id, got) in &device_hashes` loop iterates
only the hashes that ARRIVED, so under the mutation a run in which **one device — or zero —
reported a session hash** satisfies the harness's own by-name keygen-agreement check
silently. What would then be left covering cross-process transcript agreement is upstream's
in-black-box `ack_session_hash` refusal inside `recv_device_message` — **exactly the
re-vendor hole the comment at `:4276-4279` says this assertion exists to close.**

**Therefore UNPROVEN, if this assertion is ever weakened:** that every device on the roster
reported a session hash to the harness by name. Partial mitigation, VERIFIED: the DECLINE
pass independently prints `the glass matched on 12/12 devices`, so the 12-of-12 count is
still asserted on that separate screen-to-coordinator path. The survivor is a fact about the
harness's **roster bookkeeping**, not about the device — which is precisely the cluster
`PLAN.md` §8.2b predicts survives.

**Closing it needs a negative case, not an edit.** A pass in which one device withholds its
session hash — a stub that skips `ack_session_hash` for exactly one id — so that the strict
check is the thing that ends the run, by name. No pass constructs that today. Decision not
taken, sized nowhere yet.

#### A.6b-2 SURVIVOR: the device side's own arity report is asserted by nobody, and is untestable as written

**Edit:** `firmware/examples/stub.rs:1998`, `if saved.len() == N_DEVICES && !announced_save {`
→ `if saved.len() >= 1 && !announced_save {`. **Outcome: exit 0, all four passes green.**

**VERIFIED evidence:** final line of the mutated run, exit 0 —
`M1+M2+M3+M5+M7+M8+M9+M12+M13 PASS: real 12-of-12 keygen over a roster cut out of 13
announced devices, nonce replenishment and a signature that VERIFIES against the group
key, … and a 262656 B firmware image STAGES into the device's PSRAM over a raw, unframed
65-chunk stream … and NOTHING IS BURNED because no callgate sub-call is bound`. All four
gates ok (`… FINISHED in 3.351037416s`, `… 6.948247667s`, DECLINE with
`the glass matched on 12/12 devices`, `pass ok: M13 -- 262656 B announced as 65 chunks`).
No DEADLINE, no assertion failure, no counter mismatch anywhere in the log.

**Why it survives — VERIFIED, two independent reasons.**

1. *Nobody is reading.* `hostcheck` spawns the stub with `.stderr(Stdio::inherit())` at
   both call sites (`main.rs:2589`, `:2923`) and never parses a stub log line; the stub is
   ended by `kill()` + `wait()` (`Reaped`, `:4933`) with only a premature-exit `try_wait()`
   probe (`:4195`), and this latch body deliberately does not exit. So the device side's own
   report cannot influence the pass/fail decision at all.
2. *The arity is never exercised.* The latch is evaluated once per fd-0 read, AFTER the
   `for id in targets` loop (`:1841-1853`) that calls `drive()`, which is what inserts into
   `saved` (`:1621`). `FinalizeKeyGen` is addressed to all 12 devices in ONE frame, so
   `saved` goes **0 → 12 inside a single read iteration**. Mutated log lines 165-170 show
   the twelve `HOLDS a share … -- N device(s) do now` lines running up to
   `12 device(s) do now`, and only then, at line 180,
   `stub: 12/12 devices saved a share for AccessStructureRef { key_id: KeyId(9f9cb5f2…),
   access_structure_id: AccessStructureId(5dbb0e80…) }` — exactly 3 such lines, one per
   keygen pass, same as an unmutated run.

So `>= 1` and `== N_DEVICES` first become true on the **same** iteration, `refs.len()` is 12
at that moment (not 1), and the printed `12/12` is still true here. **The mutation is not
merely undetected; under this harness it is behaviourally INERT.**

**THE DEFECT IN THE HARNESS, and it is the worse of the two.** The constant `N_DEVICES` on
that line is untested **by construction**, not merely unwatched: no run ever observes
`saved.len()` at any value strictly between 0 and 12. Two device-side checks are therefore
carried as decoration — the `refs.len() != 1` "all shares belong to ONE access structure"
check, which goes vacuous at one share, and the `{N_DEVICES}/{N_DEVICES} devices saved a
share` line, which would become a const-literal lie printed after device #1.

**Therefore UNPROVEN:** that the device side ever agrees with the coordinator about roster
arity. A stub that announced the roster complete after a single share would exit 0 and the
suite would print its full PASS line. Closing it needs both halves — a device-side counter
echoed onto the wire (or a stub exit status the coordinator actually reads) **and** a case
where shares land across separate reads, which today's single all-destinations
`FinalizeKeyGen` frame prevents. Decision not taken; sized nowhere yet.

**What the register now says.** Two survivors on the first real census, both in the
**harness** and neither in the device — `PLAN.md` §8.2b's prediction, confirmed rather than
assumed. Both survivors are roster/arity bookkeeping. Note what this does NOT mean: no
mutation to the device's own behaviour has yet been tried at 12 devices.

### A.7 WHAT PHASE A DID NOT ESTABLISH

Honest gaps, so nobody reads A.6 as more than it is:

1. ~~**The `COLDSNAP_GLASS_KEYS=1yy` distribution at 12 devices is NOT re-measured.**~~
   **CLOSED 2026-09-21.** Measured: **11 of 12** declining, `035f4007…` drew `1`, exit 1 in
   pass `STUB_CHUNK=64`. Prose is queued ready-to-apply in A.5; the 9-device figure stays as
   a trajectory row.
2. **The "seven counted conditions" claim is still un-adjudicated.** `hostcheck:894-900`
   asserts a mechanical rename would have flipped *seven* conditions; a grep pass found
   ~15 count-bearing sites and could not reproduce the number seven. The change did not
   need the answer (every count is symbolic), but the doc's number remains unverified.
3. ~~**Only one mutation was run.**~~ **CLOSED 2026-09-21, and the answer is worse than the
   gap.** Three more mutations ran (A.6b): the two predicted silent-pass mutations now
   exist, both **SURVIVED GREEN** (A.6b-1, A.6b-2), and a third was caught only as a 65 s
   timeout in an unrelated pass. So "the suite would catch a harness that stopped proving
   12-of-12" is now **disproven as stated**: it would not catch either survivor. What
   replaces this gap: no mutation to the DEVICE's behaviour has been tried at 12 devices,
   and neither survivor's coverage gap is closed — in both cases the line at HEAD is the
   correct one and what is missing is a case that exercises it (A.6b-1, A.6b-2).
4. **No `WRITE_STALL` coverage.** The path is still unexercised; see A.2 item 3.
5. **Nothing here touches silicon, `usb.rs`, `UsbSerialManager`, or the multi-port
   topology.** The pty tier exercises `comms.rs` fully and `usb.rs` not at all, and this
   harness still bypasses `UsbSerialManager` by constructing `FramedSerialPort` directly.
   A reader who concludes "12 devices work" should read §4 and phase C.

---

## Phase B — drive n=13 through a real coordinator — RUN 2026-09-21

The original work order (kept, because two of its three bullets were answered and the third
turned out to be a wrong question):

> - Roster of 13, expect `Refusal::GroupTooLarge`, assert the coordinator reports a clean
>   failure rather than hanging or wedging its own state.
> - Assert the refusal happens **on policy, not on size** — 13-of-13 is 3,091 B and fits
>   `FRAME_LIMIT` 4,096, so a run that "passes" because a frame was too long is a false
>   pass. Log the size and the refusal reason separately.
> - Keep it in `hostcheck` as its own pass, alongside the existing decline pass.

**Run 2026-09-21, temporary 13-roster edit plus one-line `MAX_DOWN_B` instrumentation on the
deadline path, both reverted; tree verified CLEAN afterwards. Exit 1, both invocations
identical, 36 s wall.**

### B.1 Is n=13 refused? YES — and by policy, before anything else happens

VERIFIED. `firmware/src/lib.rs:1093`:

```rust
if begin.devices.len() > MAX_PARTIES { return Err(Fault::Refused(Refusal::GroupTooLarge)) }
```

`MAX_PARTIES = 12` (`lib.rs:291`). It fires inside `Session::recv_core` on the
`CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(begin))` arm — i.e. on the **FIRST keygen
message**, before the signer and before any `CertifyPlease` existed. All 13 roster devices
hit it: `stub: <id> REFUSED GroupTooLarge (policy, not an error)` ×13.

The second `GroupTooLarge` site (`lib.rs:1099-1101`, the threshold bound) was **unreachable**:
n=13 > 12 returns first, and t=13 ≤ n=13 would not have tripped it anyway.

### B.2 Policy, not size — and the 3,091 B figure was the wrong thing to watch

**On policy: YES, conclusively**, because the size that would have made a false pass was
never put on the wire.

| Figure | Measured | Note |
|---|---|---|
| Largest coordinator→device frame, 13-roster run | **934 B** (`max_down_b=934`) | the 13-id `Keygen::Begin` frame; high-water of the whole run |
| Same, as fraction of `FRAME_LIMIT` 4,096 | 22.8 % | far below any size-rejection threshold |
| 12-of-12 green-run high-water (A.6) | 2,863 B | the 13-roster run is **smaller**, not larger |
| 13-of-13 `CertifyPlease` | 3,091 B, **never written** | no device answered `Begin`, so the coordinator never advanced to step 2 |

A size rejection would have required `max_down_b ≥ 3,091`. It was 934. Note the trajectory:
the work order assumed the risk lived in the 3,091 B `CertifyPlease`; the refusal lands one
step earlier than that, so `CertifyPlease` at 13 remains **unmeasured on the wire** and
3,091 B is still a computed figure.

Reporting caveat, VERIFIED: the harness's own `largest coordinator->device frame actually
written` line (`hostcheck/src/main.rs:4649`) lives **only in the pass-ok block**, so on a
failing run it never prints — grep of the log returns nothing for it. So 934 B is the ACTUAL
figure and "never reported" is the harness's behaviour.

### B.3 How the coordinator behaved: bounded, correctly named by STATE, WRONG by CAUSE

No hang, no wedge. It terminated on its **own** named bound and **learned nothing from the
refusal**. Verbatim:

```
Error: pass STUB_CHUNK=64

Caused by:
    DEADLINE (35s) in state KeygenAwaitingShares -- magic_writes=1, writes_queued=32,
    writes_done=32, read_timeouts=0, announced=14, shares=0, acks=0, session_hash=false,
    held=0, replenished=0, sign_session=false, sig_shares=0/0, anything_to_read=false,
    elapsed=35.001371334s, max_down_b=934
```

Exit 1. The bound is `HANDSHAKE_DEADLINE` 5 s + `KEYGEN_DEADLINE` 30 s = 35 s and it fired at
35.0014 s. Pass 1 of 4 died; DECLINE and UPGRADE STAGING never ran. The handshake was fully
healthy first: `announced=14/14` in 517 ms, every device acked and previewed its name,
`-> KeyGen to 13 device(s)` went out, `stub: rx Core -> 13 device(s)` came back.

**The defect this exposes.** `hostcheck` DID see the refusal on the wire — it printed
`hostcheck: <id> REFUSED GroupTooLarge (a frame our own coordinator never asked for)` 13
times — and **that parenthetical is FALSE here**: this coordinator had asked for exactly that
frame. The fail-fast branch for a refused frame already exists
(`hostcheck/src/main.rs:3565-3600`) but is scoped to the restore device and the two
backup-save phases (for `Restore::erase_refusals`' reason), so a keygen refusal falls through
to the log-only path and the run sits out the **full 30 s keygen budget with the refusal on
the wire the entire time**. This is the same defect the module note at `main.rs:552-558`
records as found-and-fixed for `SavePhysicalBackup` — **still unfixed for keygen.**

### B.4 Proposed assertion — DECISION NOT TAKEN

Written down so the cost is visible. **Nothing below is implemented.** The assertion is
small; the pass that reaches it is not.

**(a) The latch, ~8 lines, reusing machinery that already exists.** The stub already puts the
refusal on the wire as `DeviceSendBody::Debug { message: "refused=GroupTooLarge" }`
(`stub.rs:1405-1415`) and `hostcheck` already parses it at `main.rs:3565`
(`Some(("refused", what))`):

```rust
// in the `Some(("refused", what))` arm, beside the DataErase set:
if what == "GroupTooLarge" { refused_group.insert(from); }

// once per lap, in the refusal pass only:
if refused_group.len() == ALL_DEVICES {
    // THE POINT: prove it was POLICY, not FRAME_LIMIT. 13-of-13
    // CertifyPlease is 3,091 B and FITS 4,096; a size rejection
    // would have put max_down_b at >= 3,091.
    assert!(MAX_DOWN_B.load(Ordering::Relaxed) < 3_091,
        "refusal came from frame size, not MAX_PARTIES: max_down_b={}",
        MAX_DOWN_B.load(Ordering::Relaxed));
    break Ok(());
}
```

**(b) The half that covers the stated deliverable (untested COORDINATOR behaviour), same arm,
~4 lines** — the keygen twin of the restore-scoped check already at `:3588`:

```rust
else if state == State::KeygenAwaitingShares {
    break Err(anyhow!("{from} REFUSED {what} while this coordinator was \
        in KeygenAwaitingShares WAITING for its share"));
}
```

**(c) COST VERDICT: (b) yes on its own merits; (a)+(c) is its own commit.** `N_DEVICES` and
`THRESHOLD` are `const` with 40+ uses and seven counted latches keyed off them, so a
13-roster pass cannot reuse the shared keygen driver without threading both as parameters.
The lazy route is a 5th pass that reuses only the handshake and then drives
`coordinator.do_keygen(all 13 announced, 13)` itself — but that still needs a new `State`
variant, its `NAMES` entry (with the `EraseRefusal as usize + 1` arithmetic documented at
`:1288` re-derived), a `budget()` arm, a `Pass` variant plus main's dispatch, and its own
pass-ok line: realistically **45-60 lines across five sites** in a 4,900-line harness.

So, judged honestly: **(b) alone is a genuine ~4-line win** that converts today's mis-named
35 s DEADLINE into an immediate named failure, and it is worth doing whether or not a
standing 13-roster pass ever exists. **(a)+(c) is not a small change** and should not ride
along with anything else. Neither is done.

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
