//! M1/M2: a REAL `frostsnap_coordinator` handshakes with cold-snap's REAL device
//! framing over a real pty. M3: the same two processes complete a REAL 9-of-9
//! KEYGEN. Two processes, two workspaces, two independent copies of
//! `frostsnap_core`, real file descriptors.
//!
//! This process is the COORDINATOR. It creates the pty pair, keeps the **SLAVE**
//! and drives an unmodified `FramedSerialPort<Downstream>` over it; the device
//! side is `firmware/examples/stub.rs`, spawned with the **MASTER** as its fd 0/fd 1.
//! It drives `coldsnap_firmware::Session` -- the SAME dispatch the ARM image
//! contains -- over a `FakeFlash` at the shipped geometry, so this run is evidence
//! about our firmware and not just about `frostsnap_core`.
//!
//! TWO of those ports, over one pty: the main loop's is READ-ONLY, and a writer
//! thread owns a second one on a `dup` of the same fd so that a blocked write
//! cannot park the loop. Both are upstream's, unmodified, and every byte is still
//! encoded by its `raw_send`. See `WRITE_STALL_LIMIT` and `spawn_writer`.
//!
//! The slave/master split is not a coin toss: MEASURED on darwin, `FIONREAD` on a
//! pty MASTER always returns 0, and `FramedSerialPort::anything_to_read()` is
//! exactly that ioctl -- so a coordinator holding the master would see an
//! eternally empty port and hang forever, silently.
//!
//! M5 extends the SAME run: one nonce stream per device, then a real 9-of-9
//! signature over `WireSignTask::Test`. It passes only if
//! `CheckedSignTask::verify_final_signatures` returns TRUE against a group key
//! read out of the coordinator's own `CompleteKey` -- see the block at the end of
//! `one_pass`. `Signed` arriving is not a pass; a verified signature is.
//!
//! WHAT M3 PASSES ON, exactly (assert, not "no error"):
//!  1. `finalize_keygen` returned an `AccessStructureRef`, and that ref is
//!     findable afterwards in `coordinator.iter_access_structures()` with
//!     `threshold == 2` and 3 device shares. Both halves are checked: the
//!     returned value AND the coordinator's own persisted view of it.
//!  2. A `SessionHash` was delivered to the user layer (`CheckKeyGen`) -- the
//!     value a human would compare against the device screens.
//!  3. The stub exited 0, which it only does after all THREE `FrostSigner`s
//!     staged a `KeyMutation::SaveShare` for one and the same access structure.
//!     That is the device-side half of the proof and it lives in the other
//!     process, in the other copy of `frostsnap_core`.
//!
//! All of it at BOTH chunk sizes, run back to back by one invocation.
//!
//! WHY IT IS NOT A MOCK: this binary links UPSTREAM `frostsnap_core` (through
//! `frostsnap_coordinator`); the stub links cold-snap's VENDORED copy. Every
//! keygen message is encoded by one tree and decoded by the other. A byte of
//! disagreement anywhere in `message.rs` or the bincode config fails the run --
//! and the mutation tests at the bottom of this comment show it does.
//!
//! MUTATIONS -- each of these was RUN, not reasoned about:
//!  M2 (framing/bound):
//!  - Announce truncated by 4 bytes, sent immediately: `DEADLINE ... in state
//!    WaitingForAnnounce -- read_timeouts=1` at **5.0009 s**. Before M2 this hung
//!    ~10 s and was released by the stub exiting, not by this deadline.
//!  - Same truncation held back to 4.81 s, i.e. the stall lands as the deadline
//!    expires: fails at **5.0639 s**, exactly stall + one `PORT_TIMEOUT`.
//!  - Device silent, then late magic: `WaitingForMagic` at **5.069 s**.
//!  - One magic byte flipped: `WaitingForMagic -- magic_writes=48` at
//!    **5.0004 s** (the scan has no backtracking, so it never links).
//!  - CHUNKING: at the DEFAULT `STUB_CHUNK=64` the stub's writes COALESCE and
//!    reassembly is never exercised -- its "sent" line prints BEFORE the
//!    coordinator's first read. Only `STUB_CHUNK=1` forces it. For one run
//!    `STUB_CHUNK` was an env var that NOTHING set, i.e. a test that could not
//!    fail; `main` now runs both sizes every time.
//!
//!  M3 (keygen). All three RUN, at chunk 64, each restored after:
//!  - One byte flipped in the middle of the device's 318-byte `KeyGenResponse`
//!    frame (`out[len/2] ^= 1`): **`recv_device_message ... in
//!    KeygenAwaitingShares: Invalid message of kind KeyGen: proof-of-possession
//!    signature did not verify`**, exit 1, before the second device even
//!    answered. Note what that proves: the failure came from upstream's
//!    CRYPTO, on a message the vendored tree encoded -- the two trees are
//!    really agreeing, not both being sloppy.
//!  - Device never acks `CheckKeyGen` (the human-confirmation step): `DEADLINE
//!    (35s) in state KeygenAwaitingAcks -- shares=3, acks=0, session_hash=true`
//!    at **35.0000 s**. The counters localise it exactly: hash delivered, zero
//!    acks.
//!  - The coordinator's `Finalize` dropped by the device (4th inbound Core
//!    frame discarded): `DEADLINE (35s) in state KeygenAwaitingDeviceSave --
//!    shares=3, acks=3, session_hash=true` at **35.0007 s**. That is the state
//!    that exists to catch precisely "coordinator thinks it is done, device has
//!    nothing": the coordinator HAD its `AccessStructureRef` and still failed.
//!
//!  M4 (the WRITE path -- `WRITE_STALL_LIMIT`). Stub mutated to send 2,018 B of
//!  Announces and then NEVER read again, so the coordinator has >1 KB queued to a
//!  peer that is not draining -- i.e. the M5 condition, where every signing frame
//!  is over 1 KB. Both runs used the SAME mutated stub; the stub was restored and
//!  `diff`ed clean afterwards.
//!  - BEFORE (write on the loop's own thread, reproduced by making `send_frame`
//!    park its caller until the frame is written): the loop never reaches ANY
//!    deadline check. Killed by the watchdog at **37.021 s**, `exit(5)`, and the
//!    only diagnosis is `state WaitingForAnnounces` -- one announce in, no
//!    counters, no mention of a write, and a process kill rather than an error.
//!    That is 7.4x the budget the failure actually deserved.
//!  - AFTER (writer thread): **5.0035 s**, exit 1, `WRITE STALL (5.003534458s >
//!    5s) in state KeygenAwaitingShares -- frame 2/32 is stuck in
//!    raw_send/tcdrain ... announced=3, shares=0, acks=0`. Note it got FURTHER
//!    than the BEFORE run -- 3 announces and a started keygen instead of 1
//!    announce -- because the read path kept running THROUGH the blocked write.
//!    That is the writer thread's whole value, visible in the log.
//!  - The read path's own bound, re-checked against the same change (stub's
//!    Announce burst truncated by 4 B): `DEADLINE (5s) in state
//!    WaitingForAnnounces -- writes_queued=4, writes_done=4, read_timeouts=1` at
//!    **5.0029 s**, matching M2's 5.0009 s. The new write counters are what
//!    exonerate the writer here, which is the diagnosis M2 could not make.
//!
//!  M5 (nonces + a real signature). MEASURED whole pass, keygen included:
//!  **0.53 s at chunk 64, 1.66 s at chunk 1**. Frame sizes on the wire matched
//!  the predictions exactly: `NonceResponse` 1x30 = **2,040 B** and
//!  `SignatureShare` + full replenish = **2,105 B**, both device->coordinator,
//!  and both crossed at `STUB_CHUNK=1` -- i.e. as 2,040 and 2,105 SEPARATE
//!  one-byte writes -- with no deadlock. Those were the first frames over 1 KB
//!  ever to cross this pty. They work because the traffic is one-directional
//!  there: the coordinator has nothing queued while it reads, so it drains.
//!  All three mutations RUN at chunk 64, stub restored and `diff`ed clean after
//!  each:
//!  - One byte flipped in the middle of the 2,105 B `SignatureShare`
//!    (`out[1052]`, inside the replenish nonces): **`body.decode() ... in
//!    SigningAwaitingShares: OtherString("Invalid 66-byte encoding of a public
//!    binonce")`**, exit 1, at **1.39 s**.
//!  - Same mutation at `out[60]` instead -- inside the message header, so it
//!    lands on `session_id` -- does NOT produce a named failure: UPSTREAM
//!    PANICS. `frostsnap_core/src/coordinator.rs:877`
//!    `active_signing_sessions.get(&session_id).expect("inavariant")`. exit 101
//!    at **1.33 s**. A device-supplied field with no guard: any device can
//!    crash the real coordinator with one `SignatureShare`. NOT worked around
//!    here on purpose -- a harness that swallows a real crash is worse than one
//!    that shows it.
//!  - Device answers `NonceResponse` for a stream id the coordinator never
//!    opened (`segments[0].stream_id.0[0] ^= 1`): the coordinator ACCEPTS it
//!    (`coord_nonces.rs:36` `check_can_extend` returns `Ok(())` for an unknown
//!    stream id) and builds a signing session on it; the failure comes from the
//!    DEVICE refusing the resulting `RequestSign` ("device did not have that
//!    nonce stream id"), surfacing here as `stub exited 2 in
//!    SigningAwaitingShares having reported 3/3 held shares, 3/3 nonce
//!    replenishments and 0/2 signature shares`, exit 1 at **1.21 s**.
//!  - Signing reply dropped entirely (`sign_ack` called, its sends discarded):
//!    `DEADLINE (65s) in state SigningAwaitingShares -- ... held=3,
//!    replenished=3, sign_session=true, sig_shares=0/2` at **65.0001 s**, i.e.
//!    `HANDSHAKE + KEYGEN + SIGN` exactly. `writes_done=17` of
//!    `writes_queued=17` in the same line exonerates the write path.
//!  - AND ONE ON THIS FILE, because none of the three above ever reached
//!    `verify_final_signatures` and so none of them proved the pass GATE is the
//!    verification rather than the arrival of `Signed`. The verify site was
//!    pointed at a `WireSignTask::Test` carrying a different message: **`SIGNATURE
//!    DOES NOT VERIFY: 1 sig(s) over "cold-snap M5" against master_appkey 03c5..`**,
//!    exit 1 at **1.36 s**. Restored and `diff`ed clean.
//!
//!  M6 (LIVE GLASS -- the two new assertions and the timeout scale). THREE passes
//!  now: `STUB_CHUNK=64`, `STUB_CHUNK=1`, then a DECLINE pass in which the stub's
//!  scripted consent (`COLDSNAP_GLASS_KEYS=yx`) presses `x` at every signing
//!  screen. The two signature passes are unchanged in what they assert AND in the
//!  aggregate signature they produce (`sig = 81b118f3dcf2ac15..`, byte-identical
//!  before and after), because the `glass=` report draws no randomness; the only
//!  wire difference is 9 extra `Debug` frames, MEASURED as the stub's first write
//!  growing 1,818 -> 2,286 B.
//!
//!  1. THE GLASS SHOWS THE COORDINATOR'S CODE. The stub renders the real
//!     `CheckKeyGen` screen with the shipped `prompt_screen`, reads the four bytes
//!     back out of the framebuffer with the shipped `ui::Frame::cell_2x`, and
//!     reports them as `Debug{glass=<8 hex>}`; this process compares them against
//!     its own session-hash prefix. This is PLAN.md §9 item 12's OPEN half --
//!     screen-to-coordinator. The core-to-core half already existed, below.
//!  2. A DECLINED PROMPT YIELDS NO SIGNATURE, both halves: 9/9 `declined=` on the
//!     wire AND zero `GotShare` from the coordinator's own accounting.
//!
//!  All RUN at chunk 64, each file restored and `diff`ed byte-identical after:
//!  - ONE NIBBLE of the RENDERED code corrupted (the stub overwrites the drawn 2x
//!    glyph with an `f` after `prompt_screen` returns, i.e. the device verified the
//!    right transcript and drew the wrong code): **`GLASS CODE MISMATCH: <id>
//!    RENDERED f25f9b9b ... session hash starts d25f9b9b`**, exit 1. Note that
//!    every other assertion in the run still passed, which is the point of having
//!    this one.
//!  - THE SCRIPT STOPS READING THE PIXELS (`advertised_key` hardcodes `1`, which is
//!    still correct for the keygen screen and cannot be correct for a randomised
//!    signing digit): stub dies `1 prompt(s) DECLINED but STUB_EXPECT_DECLINES=0`,
//!    surfacing here as `stub exited 2`, exit 1. Same failure with NO source
//!    mutation at all, via `COLDSNAP_GLASS_KEYS=y9`, `=y1` and `=y2` -- a
//!    hardcoded key cannot pass, which is what makes the glass read structural
//!    rather than decorative.
//!  - CONSENT THEATRE (stub declines on the glass and hands over a share anyway):
//!    **`A DECLINED PROMPT PRODUCED A SIGNATURE`**, exit 1, while the two signature
//!    passes still pass -- so the decline pass discriminates rather than just being
//!    fragile.
//!  - Same mutation with the loop's guard disabled: the post-loop half catches it
//!    independently, **`DECLINE IGNORED: 9/9 device(s) declined and yet 9 signature
//!    share(s) arrived`**, exit 1.
//!  - The DECLINE pass stops declining (`yx` -> `yy`): **`A DECLINED PROMPT
//!    PRODUCED A SIGNATURE: 0/9 device(s) reported declining`**, exit 1 -- it
//!    cannot silently degrade into a third signature pass.
//!  - TIMEOUT SCALE. `COLDSNAP_TIMEOUT_SCALE` unset is `Duration * 1`: the default
//!    run's assertions, counts and signature are unchanged, and with the
//!    CheckKeyGen ack dropped the deadline still reads `DEADLINE (35s) in state
//!    KeygenAwaitingAcks ... elapsed=35.000289625s`, matching M3's 35.0000 s
//!    exactly. At `=2` the same mutation reads `DEADLINE (70s) ...
//!    elapsed=70.000580875s`, and `=10` passes all three passes normally.
//!
//!  M7 (THE RESTORATION, BACKUP AND CONSOLIDATION FLOWS, from REAL coordinator
//!  drivers). The device already implemented all four and unit-tested them; no
//!  harness had ever driven one from a coordinator. All four now run inside the two
//!  signature passes, AFTER the signature exists -- at t = n = 9 every device is
//!  needed to sign, and M7e REPLACES the one share record the store keeps.
//!
//!  The coordinator half is UPSTREAM's, unmodified and by path:
//!  `DisplayBackupProtocol`, `CheckBackupProtocol` and `EnterPhysicalBackup`, driven
//!  through the five-call `UiProtocol` lifecycle (`connected` / `poll` /
//!  `process_to_user_message` / `process_comms_message` / `is_complete`). ONE boxed
//!  protocol at a time and deliberately no `UiStack`. Consolidation has no upstream
//!  driver at all, so it goes through the same `queue` the keygen frames do.
//!
//!  1. THE 25 WORDS ON THE GLASS ARE THE SHARE THE DEVICE HOLDS. The device walks its
//!     own reveal, reads all 25 words back OUT OF THE FRAMEBUFFER with the shipped
//!     `ui::Frame::cell`, and reports them; this process re-encodes them with
//!     UPSTREAM's `ShareBackup::from_words` and compares the share image against its
//!     own `expected_share_image`. Two processes, two builds of `frost_backup`.
//!  2. THE QUIZ AND THE REVEAL AGREE, and the quiz is answered ONLY from what the
//!     reveal drew -- never by asking `Session` which candidate is right. A wrong
//!     answer re-asks the same position, so the pass is asserted at EXACTLY 8 answers.
//!  3. THOSE SAME WORDS GO BACK IN through the letter picker, whose candidate letters
//!     are a function of the secret prefix -- so the typing is driven off the pixels
//!     too -- and the coordinator's own `check_physical_backup` accepts the result.
//!  4. THE DESTRUCTIVE WRITE LEAVES A READABLE RECORD: after `Consolidate`, the
//!     device is asked what it holds AGAIN and the reported share IMAGE is compared,
//!     not just the access-structure ref.
//!
//!  All RUN, each file restored and `diff`ed byte-identical after. Wall clock for the
//!  whole M7 phase, MEASURED: **1.4 s at chunk 64, 2.4 s at chunk 1** on top of M5.
//!  - One reveal word replaced with a DIFFERENT valid BIP39 word: **`the 25 words on
//!    <id>'s glass do not decode: Words checksum verification failed`**, exit 1.
//!    `from_words` binds index + scalar + poly checksum under an 11-bit words
//!    checksum, so it catches this before the share-image comparison does.
//!  - A NON-word (`QQQQ`): **`word 3 on <id>'s glass reads "QQQQ", which is not one of
//!    the 2048 BIP39 words -- a layout or font defect, not a crypto one`**, exit 1.
//!  - Word-number labels off by one (`first + i + 1`): **`the reveal put 25 word(s) on
//!    <id>'s glass, not 25: positions [1] were never drawn (got [2, ..., 26])`**, exit 1.
//!  - `BackupPages::len` with `/` for `div_ceil`, i.e. one page short: **`the reveal at
//!    <id> ran off the end of its pages and armed no recorded question, so not every
//!    page was composed`**, exit 1. That is `Session::show_backup`'s `seen_pages ==
//!    all_pages` gate, over a real transport for the first time.
//!  - Word pages draw NO paging legend: **`backup page 1 footer is "" -- it does not
//!    advertise ui::NEXT_KEY ('9')`**, exit 1 -- the `5=next 8=back` class, closed on
//!    the harness side as well as by `hal`'s const asserts.
//!  - `mark_sensitive`'s noise widened by 8 px so it reaches the word gutter:
//!    **`backup page 1 has no legible `NN: WORD` rows`**, exit 1. This is the first
//!    assertion in the tree that the side-channel noise does not destroy legibility.
//!  - Every quiz option labelled with `QUIZ_KEYS[0]`: **`quiz option 2 is labelled "1"
//!    but ui::QUIZ_KEYS says '2', so the key a human presses is not the option they
//!    read`**, exit 1.
//!  - `quiz::Quiz::truth` offset by one position, so the header and the candidates
//!    disagree: **`the reveal's glass drew "ONLY" at word 7 and the quiz offers
//!    ["PROMOTE", "LIFE", "FINAL"] -- two flows over the same share disagree about
//!    it`**, exit 1.
//!  - `quiz::QUIZ_POSITIONS` changed to `BACKUP_WORDS / 5`: **`M7c: <id> reported
//!    Some(5) quiz answer(s), not exactly 8`**, exit 1 -- and note it fails AFTER the
//!    run, because the phase gate does not check the count. That is the one M7
//!    assertion the control flow does not already make.
//!  - `WordEntry::letter_for_key` mis-based by one, so the ruler names a key that types
//!    a different letter: **`the entry screen has "E" typed for word 1, which is not a
//!    prefix of the "FITNESS" the reveal's glass drew`**, exit 1.
//!  - The entry footer stops offering `(y)ok`: **`word 1 reads "FITNESS" in full and
//!    the footer is "(x)del" -- the screen does not offer the key that accepts it`**,
//!    exit 1.
//!  - `prompt_screen_at`'s `ConsolidateBackup` arm made unreachable, i.e. the
//!    destructive flow's consent screen deleted: **`confirm(Consolidate, <id>):
//!    NotConfirmable`**, exit 1, reported here as `stub exited 2 in BackupConsolidate`.
//!  - THE HARDCODED-KEY SCRIPT, with NO source mutation at all:
//!    `COLDSNAP_GLASS_KEYS=yy9` (and `=yy1`) presses a literal key at the restoration
//!    screens instead of the randomised digit the glass printed: **`<id> DECLINED
//!    Reveal`** then `1 prompt(s) DECLINED but STUB_EXPECT_DECLINES=0`, exit 1. So the
//!    reveal, the quiz, the ingest and the consolidation are all behind a digit that
//!    can only be answered by reading the screen.
//!  - AND THREE ON THE SEAM ITSELF, one per lifecycle leg, because a seam nothing
//!    proves is load-bearing is a seam that will be simplified away:
//!      * `poll()` never drained -> `DEADLINE (95s) in state BackupReveal ...
//!        elapsed=95.002023708s`;
//!      * `process_comms_message` never called -> `WARNING no live UiProtocol claimed
//!        BackupRecorded from <id>` then the same 95 s deadline in `BackupReveal`;
//!      * `process_to_user_message` never called -> `DEADLINE (95s) in state
//!        BackupIngest`.
//!
//!    95 s is `HANDSHAKE + KEYGEN + SIGN + RESTORE` exactly, so the new budget lands
//!    to the millisecond like M3's 35 s and M5's 65 s.
//!  - TRAP 4, upstream's, demonstrated by deleting one line: `EnterPhysicalBackup::poll`
//!    returns an EMPTY vec until `connected()` has been called, so without it the
//!    device is never asked to type anything -> `DEADLINE (95s) in state BackupIngest
//!    -- ... elapsed=95.001349792s`.
//!  - TRAP 2, upstream's, made a decision instead of an accident: `CHECK_BACKUP_SINCE`
//!    lowered to 0.2.0 -> **`declared firmware v0.2.0 does not have the check_backup
//!    feature, so CheckBackupProtocol would silently drive the LEGACY physical-backup
//!    path and the quiz would never run`**, exit 1.
//!
//!  WHAT SURVIVED, stated rather than hidden:
//!  - the share-IMAGE comparison in `check_glass_words` is REACHABLE but not
//!    independently demonstrable in this tree. `ShareBackup::from_words` already binds
//!    the index, the scalar and the polynomial checksum under an 11-bit words
//!    checksum, so every single-field corruption of the glass fails THERE first, with a
//!    better message. What the image check catches is the residual: a self-consistent
//!    backup for a DIFFERENT share (another device's 25 words drawn on this glass) and
//!    an 11-bit checksum collision (p = 2^-11). No one-line mutation of this tree
//!    produces either.
//!  - the same is held for M7e's share-image check on the RE-REPORTED record, and this
//!    entry was STALE until M12 swept it. It used to say "this flow consolidates the
//!    device's OWN share back onto itself, so the write is content-preserving and a
//!    record that survived is indistinguishable from one that was never replaced" —
//!    the sentence commit a5922e4 explicitly WITHDREW, on the ground that a record that
//!    was never written would also re-report correctly. That commit corrected
//!    `Phase::Reheld`'s doc and the M7e failure message and did not sweep this entry
//!    with them. The true position, now that M12 exists, is in M12's own WHAT SURVIVED
//!    below: what a blank device makes falsifiable is the `Some`/`None` discrimination
//!    on the re-report, NOT the share-image comparison, which stays over-determined by
//!    upstream's own device-side guard.
//!  - `restore_step`'s `Completion::Abort` arm is a fail-closed guard, not a
//!    demonstrated assertion: all three drivers abort only from `cancel()` or
//!    `disconnected()`, and this harness calls neither. It converts a 95 s hang into an
//!    instant named failure if a future driver ever does.
//!  - `entry_press`'s `ruler.len() != letters.len()` check likewise: `WordEntry::render`
//!    builds both rows from one `letter_for_key` and stops at the same key, so they
//!    cannot differ today.
//!
//!  ONE DETERMINISM LOSS, and it is upstream's: `EnterPhysicalBackup::new` calls
//!  `EnterPhysicalId::new(&mut rand::thread_rng())` inside the constructor
//!  (`enter_physical_backup.rs:23`), so those 16 bytes are NOT reproducible and the
//!  M7d frame differs byte-for-byte between runs. Nothing downstream derives from
//!  them -- the device echoes the id back and the driver matches on it -- so no
//!  assertion, no signature and no share image moves. Accepted rather than worked
//!  around, because forking the constructor to fix it would mean this harness stopped
//!  driving upstream's own code, which is the only thing it is for.
//!
//!  M8 (THE NAMING FLOW -- the last protocol body nothing drove). The device
//!  implemented naming end to end and no coordinator had ever exercised it: this file
//!  printed `hostcheck: ignoring NeedName` nine times a pass, and that count is now
//!  ZERO. The announce those `NeedName`s arrive in is answered with
//!  `CoordinatorSendBody::Naming(NameCommand::Preview)` beside the existing
//!  `AnnounceAck`.
//!
//!  WHERE IT IS SENT IS FORCED, not chosen: `commit_name` fires from `Session::run`'s
//!  `FinalizeKeyGen` arm, i.e. DURING keygen, so the preview must be on the device
//!  BEFORE the coordinator's `Finalize`. A post-signature phase like M7's cannot work,
//!  and the second mutation below is what trying looks like.
//!
//!  WHAT IT ASSERTS: all 9 devices answer `DeviceSendBody::SetName` and the name is
//!  byte-exact. `commit_name` writes flash through `NameStore::save` and pushes
//!  `SetName` only if that returned `Ok` -- persist strictly before ack -- so
//!  **`SetName` ARRIVING IS the evidence the flash write succeeded**; a device that
//!  could not store the name returns before the outbox is touched. The input is bounded
//!  at the corner that matters: `DeviceName` is `FixedString<14>` counted in CHARS, so
//!  the name is 14 four-byte codepoints = **56 bytes = exactly
//!  `DEVICE_NAME_MAX_BYTES`**, the byte bound the device re-applies at the flash
//!  boundary. One char more is truncated on the wire, one byte more is refused
//!  `TooBig`. MEASURED: the preview frame is **97 B** downstream against
//!  `AnnounceAck`'s 37 B, and the aggregate signature is byte-identical to the
//!  pre-M8 run (`sig = 81b118f3dcf2ac15..`), so naming perturbs nothing.
//!
//!  HONEST LIMIT, because the log line reads stronger than the fact: the stub restarts
//!  -- drops every session and rebuilds from the same flash bytes -- immediately after
//!  ANNOUNCING and BEFORE keygen, so there is NO restart after this name is persisted.
//!  This proves the write landed before the ack. It does **not** prove the name survives
//!  a power cycle, and no line of this file should be read as claiming it does. (Nor is
//!  the flow reachable from the shipped app at all: its name field sits behind
//!  `firmwareUpgradeEligibility == upToDate`, which cold-snap's digest can never be. This
//!  harness is the only thing that drives naming anywhere.)
//!
//!  All RUN, each one restored and `diff`ed byte-identical after:
//!  - The preview never sent, i.e. the pre-M8 state in one line: **`only 0/9 device(s)
//!    reported a NAME (SetName: {})`**, exit 1.
//!  - THE SEQUENCING CONSTRAINT, demonstrated rather than merely asserted: the SAME frame
//!    moved to the post-keygen seam the forged `DataErase` uses. Same failure, **`only 0/9
//!    device(s) reported a NAME`**, exit 1, with zero `SetName` lines in the whole run --
//!    a LATE preview is indistinguishable from no preview, because `commit_name` runs once
//!    and takes an empty `pending_name`.
//!  - A 14-char PLAIN ASCII name previewed instead: **`NAME ROUND TRIP IS NOT EXACT: <id>
//!    stored and reported "cold-snap-mk4x" (14 chars, 14 bytes), the coordinator previewed
//!    "..." (14 chars, 56 bytes)`**, exit 1. Same CHAR count, different bytes -- so the
//!    assertion is over bytes, which is the whole distinction the two constants exist for
//!    and the reason the name is not ASCII.
//!  - `DEVICE_NAME` lengthened to 15 chars: **`DEVICE_NAME "..." is not a valid
//!    DeviceName: String too long: max length is 14 but got 15`**, exit 1, before a byte
//!    moves.
//!  - The `NeedName` trigger not recorded: **`<id> reported the name "..." without ever
//!    having sent NeedName -- ... this SetName is an announce-time echo of a name that was
//!    already on flash and NOT evidence that this run committed one`**, exit 1.
//!
//!  WHAT SURVIVED, stated rather than hidden:
//!  - a 15-char name pushed through `DeviceName::truncate` instead of `new` passes
//!    **GREEN**. Upstream's `FixedString::decode` cuts it to 14 chars, the device stores
//!    and reports the cut value, and the round trip is then exact -- so the round-trip
//!    assertion CANNOT see a truncation the harness asked for itself. That is why the
//!    construction uses `new` and bails: bounding the INPUT is the only thing that catches
//!    it, and the 15-char mutation above is the proof that it does.
//!
//!  M9 (`erase_device` MUST NEVER COMPLETE). The one flow whose CORRECT behaviour is to
//!  hang, which is exactly why it needs an explicit assertion: an unasserted hang is
//!  indistinguishable from a harness that forgot to drive anything. Runs as a new
//!  `Phase::Erase` through the same five-call seam M7 uses, FIRST of the phases -- if this
//!  device had obeyed, the share the four backup flows read would be gone and all four
//!  would fail too, so the refusal is corroborated by the rest of the pass.
//!
//!  `EraseDevice::poll` sends `CoordinatorSendBody::DataErase` on its first poll and
//!  reaches `Completion::Success` only on `CommsMisc::EraseConfirmed`. This device answers
//!  `Err(Fault::Refused(Refusal::DataErase))` and never sends that, so upstream's
//!  completion path is UNREACHABLE here. BOTH halves are asserted, because either alone is
//!  ambiguous:
//!   1. `is_complete()` stays `None` for the whole of `ERASE_GRACE` (1 s, scaled by
//!      `timeout_scale()` like every other budget). MEASURED **1.0005 s** at both chunk
//!      sizes.
//!   2. the device reports `Debug{refused=DataErase}` for the frame THIS DRIVER sent,
//!      counted per phase rather than read off the existing `refused_erase` set -- that
//!      set is already full from the forged frame long before, so a `contains` there
//!      would be an assertion that cannot fail.
//!
//!  DIFFERENT from the forged `DataErase` this file already sends, and the comment at the
//!  site says so: that frame is HAND-ROLLED here, so it proves the DEVICE refuses the
//!  body; this drives UPSTREAM'S OWN DRIVER, so it proves the COORDINATOR-side flow cannot
//!  complete -- an app offering "erase this device" sits on that dialog forever. MEASURED,
//!  the driver's frame is the same **39 B** on the wire as the forged one: identical body,
//!  different author.
//!
//!  The new `State::EraseRefusal` shares `RESTORE_DEADLINE`'s cumulative budget, so
//!  `State::longest()` is still 95 s and the stub's own 240 s `DEADLINE` keeps its ~2.5x
//!  contract -- CHECKED, not assumed, and nothing in `firmware/examples/stub.rs` had to
//!  move. Cost is the fixed grace window and nothing else: over 3 runs a signature pass
//!  goes **1.92 s -> 2.51-2.96 s at chunk 64 and 4.14 s -> 5.10-5.14 s at chunk 1**, i.e.
//!  the 1 s window plus this loop's usual run-to-run noise.
//!
//!  Both RUN, each restored and `diff`ed byte-identical after:
//!  - The driver fed a forged `CommsMisc::EraseConfirmed`, i.e. a device that confirms:
//!    **`ERASE COMPLETED: upstream's EraseDevice reached Completion::Success at <id>,
//!    which it only does on CommsMisc::EraseConfirmed`**, exit 1.
//!  - The driver built but never installed in `ui`, so its `DataErase` never reaches the
//!    wire: **`<id> left upstream's EraseDevice open for 1.000026709s without ever
//!    reporting `refused=DataErase` -- silence is not a refusal, it is what a dead device
//!    looks like`**, exit 1. That is the half that makes the hang evidence.
//!
//!  WHAT SURVIVED:
//!  - `connected()` not called on this driver at all: **GREEN**. `EraseDevice` does not
//!    override `UiProtocol::connected`'s empty default and its `poll` sends
//!    unconditionally, so unlike M7d's trap 4 the call is decoration -- kept only so all
//!    five arms drive the identical lifecycle. This measurement is why the comment there
//!    says "no-op" instead of implying it is required.
//!  - dropping the `phase == Phase::Erase` half of the refusal guard: **GREEN**, count
//!    still 1. `Restore` does not exist until a signature does, which is already past the
//!    forged frame, so `restore.as_mut()` alone scopes it today. Kept as belt, and said so
//!    at the field.
//!
//!  M10 (`CoordinatorSendBody::Cancel`, driven from a coordinator for the first time).
//!  `Session::recv` admits `Cancel` and clears SIX pieces of state with it. Read the
//!  scope of this claim carefully, because the obvious version of it is FALSE: FIVE of
//!  those six already have named Tier-1 host tests that assert the DOWNSTREAM REFUSAL and
//!  carry their own MUTATION-VERIFY notes --
//!  `a_reveal_grant_ends_with_its_pages_and_is_revoked_by_cancel`,
//!  `a_cancelled_ceremony_cannot_be_acked_as_recorded`,
//!  `cancel_drops_a_live_quiz_and_a_pass_acks_once`, `cancel_drops_a_half_typed_backup`
//!  and `cancel_is_handled_and_silent`. What had NO assertion anywhere in the tree is the
//!  SIXTH: `pending_name`. Its test
//!  (`a_previewed_name_is_neither_written_nor_announced`) stops at
//!  `pending_name() == None` and never runs the keygen that would have committed it, so
//!  "a cancelled preview is never acked as a `SetName`" was unasserted. M10 is that one
//!  fact, over the wire.
//!
//!  WHERE IT IS SENT IS THE ONLY SAFE WINDOW IN THE RUN, and that is measured rather than
//!  argued: the `Cancel` arm's first statement is `signer.clear_tmp_data()`, which drops
//!  the keygen tmp maps. Sent later it breaks the ceremony every other assertion rests
//!  on, and `firmware/examples/stub.rs` turns a non-`Refused` fault into `die(2, ..)`
//!  rather than a phase failure. Beside the `AnnounceAck`, before `begin_keygen` (which
//!  is gated on `announced.len() == N_DEVICES`), the signer has nothing in flight, so
//!  `clear_tmp_data` is a provable no-op and the frame's ONLY observable effect is
//!  `pending_name = None`. It is also the app's own sequence:
//!  `frostsnapp/lib/device_setup.dart` calls `updateNamePreview` from the name field's
//!  `onChanged` and `sendCancel(id)` when the sheet is popped.
//!
//!  THE ASSERTION IS A DIFFERENTIAL, and without the second half it could not fail for
//!  the right reason. An absent `SetName` proves nothing on its own: M8's own mutation
//!  list above records that a LATE preview is INDISTINGUISHABLE from no preview, so
//!  silence is equally consistent with a preview that never arrived. So TWO devices get
//!  the SAME TWO FRAMES IN OPPOSITE ORDERS and nothing else separates them:
//!   1. `name_cancelled` -- preview, THEN `Cancel` -- must report NO name;
//!   2. `name_recovered` -- `Cancel`, THEN preview -- must report the byte-exact name.
//!
//!  A delivery failure silences BOTH, so the pair cannot pass vacuously. `device_names`
//!  is therefore `N_DEVICES - 1`, checked as an EXACT count AFTER the two named bails so
//!  each failure gets its most specific message, and a second unexplained absence still
//!  fails.
//!
//!  Upstream's own `UiProtocol` drivers DECIDE to send this body --
//!  `DisplayBackupProtocol::cancel()` sets `abort`, and `is_complete()` then reports
//!  `Completion::Abort { send_cancel_to_all_devices: true }` -- but the FRAME is emitted
//!  by `UsbSender::send_cancel{,_all}` in `usb_serial_manager.rs`, which owns real serial
//!  ports this harness does not have. So the body is built here, in the shape
//!  `UsbSender::send_cancel` builds it (`CoordinatorSendMessage::to(id, Cancel)`), and
//!  the claim is about the DEVICE's handling of it, not about a driver's decision.
//!
//!  THREE RUN, each file restored and `diff`ed byte-identical after:
//!  - `self.pending_name = None` deleted from `recv`'s `Cancel` arm: **`A CANCELLED
//!    PREVIEW WAS COMMITTED: <id> was sent Naming(Preview) and then Cancel, and still
//!    reported the name "..."`**, exit 1.
//!  - both devices sent the frames in the SAME order, i.e. the differential made
//!    vacuous: **`THE M10 DIFFERENTIAL IS VACUOUS: <id> was sent the same two frames in
//!    the OTHER order ... and still reported no name`**, exit 1. Tier-1 cannot catch this
//!    class at all -- it is an error in the HARNESS, not the device.
//!  - the `commit_name` call deleted from `run`'s `FinalizeKeyGen` arm: exit 1 on the same
//!    VACUOUS bail, which is the correct diagnosis: with nothing committing, the control
//!    device is silent too.
//!
//!  STATED PLAINLY, because it is the honest accounting: the FIRST mutation is ALSO caught
//!  by Tier-1 -- `a_previewed_name_is_neither_written_nor_announced` fails, measured at
//!  113 passed / 1 failed of the 114 lib tests that existed when the mutation was run
//!  (the count is 115 now; the figure is dated, not stale). M10 does not add mutation coverage of the FIELD. What it adds is the field's
//!  WIRE consequence -- no `SetName`, ever -- which nothing asserted, and the fact that
//!  the `Cancel` discriminant survives encoding by upstream's `frostsnap_comms` and
//!  decoding by the vendored one.
//!
//!  M11 (the LEGACY `SavePhysicalBackup`, v1). The last admitted restoration body nothing
//!  drove. Upstream ALIASES it: the device rebuilds it as a `SavePhysicalBackup2` and
//!  RECURSES (`vendor/.../device/restoration.rs:64-82`), and no coordinator sends v1 --
//!  `tell_device_to_save_physical_backup` builds v2.
//!
//!  THE NAIVE ASSERTION CANNOT FAIL, and finding that out is most of this item's value.
//!  `DeviceRestoration::PhysicalSaved` carries only a `ShareImage`, and
//!  `EnterPhysicalBackup::process_to_user_message` sets `saved = true` on any
//!  `PhysicalBackupSaved` for its device without checking a field. So "v1 produced
//!  PhysicalSaved" and "the driver completed" are both byte-identical to what v2 produces
//!  -- the same shape as the five assertions written and deleted for this reason.
//!
//!  THE ONE FIELD THAT DISTINGUISHES THEM is the threshold. v1's is a NON-OPTIONAL `u16`,
//!  so the rebuild forces `threshold: Some(..)`; the v2 the other pass sends carries
//!  `None`, because `prepare_save_physical_backup` fills it only on a successful trial
//!  recovery and `find_valid_subset` refuses one share image against a threshold of 9.
//!  And it is wire-observable: `held_shares()`' saved-backup iterator reports
//!  `threshold: saved_backup.threshold` verbatim. See [`V1_THRESHOLD`] for why the value
//!  is 7 rather than 9 and why choosing it is safe.
//!
//!  BOTH VARIANTS ARE DRIVEN BY ONE `cargo run`, which is why this is a `save_v1`
//!  parameter and not a replacement: v2 stays coordinator-driven on the chunk-64 pass and
//!  v1 runs on the chunk-1 pass. `Phase::SavedV1` reads the threshold back with
//!  `request_held_shares` BETWEEN the ingest and the consolidation, because consolidating
//!  DELETES the record it reads -- `Phase::Reheld`'s existing read is far too late.
//!  Upstream's own call still runs and its send is REWRITTEN rather than dropped, because
//!  that call is what inserts into `tmp_waiting_save` and without it the device's
//!  `PhysicalSaved` is refused by `recv_device_message`.
//!
//!  THREE RUN, each file restored and `diff`ed byte-identical after:
//!  - the downgrade skipped, so the v1 pass sends v2: **`M11: <id> ... reports the saved
//!    backup with threshold=None`**, exit 1. This is the mutation that shows the assertion
//!    distinguishes the two variants at all.
//!  - the `needs_consolidation` filter dropped from the `HeldShare2` lookup:
//!    **`threshold=Some(9)`**, exit 1 -- the real access structure's entry. This is why
//!    [`V1_THRESHOLD`] is 7: at 9 this mutation would have passed silently.
//!  - the DEVICE made to refuse the v1 body (the arm removed from `recv_core`'s admitted
//!    list): **`<id> REFUSED PhysicalBackup while this coordinator was in Ingest WAITING
//!    for it`**, exit 1 in seconds.
//!
//!  THAT THIRD ONE FOUND A SEPARATE DEFECT AND FIXED IT. Before this pass the refusal was
//!  a LOG LINE only: the run printed `REFUSED PhysicalBackup (a frame our own coordinator
//!  never asked for)` -- which was itself wrong, the coordinator HAD asked for it -- and
//!  then sat out the whole 95 s `BackupIngest` budget to die with `DEADLINE ... in state
//!  BackupIngest`, naming the state and not the cause. A refusal of a frame this
//!  coordinator is waiting on now fails immediately, scoped to the restore device and to
//!  the two phases that wait on a save for [`Restore::erase_refusals`]' reason.
//!
//!  M12 (THE TENTH, BLANK DEVICE -- a restore ONTO A UNIT THAT HOLDS NOTHING).
//!  [`ALL_DEVICES`] devices announce and [`N_DEVICES`] of them do the keygen. The tenth is
//!  cut out of the same expression as the roster (`announced[..N_DEVICES]` /
//!  `announced[N_DEVICES]`) at the `BeginKeygen` site, so it is ASSIGNED and never
//!  inferred: this process owns `BeginKeygen`, so it CREATES the fact rather than trusting
//!  any device about the one thing under test. PLAN.md §9 item 12's correction (a) said the
//!  split "needs a way for hostcheck to IDENTIFY the blank device, which the protocol
//!  cannot supply" -- the premise is true and the conclusion is FALSE, and that error is
//!  most of what made this item look expensive.
//!
//!  It is checked independently, not merely arranged: on the lap `kg.finished` becomes
//!  `Some`, the coordinator's OWN access structure must have `devices().count() ==
//!  N_DEVICES` and must not `contains_device(blank)`. That check lives in the loop and NOT
//!  at PASS, and the reason is the one place this whole item makes an existing assertion
//!  weaker: by PASS the blank device IS a tenth entry in `device_to_share_index`, because
//!  leg 2's `FinishedConsolidation` applies `KeyMutation::NewShare` for it. Changing the
//!  PASS-block count to `ALL_DEVICES` and calling it the roster check would have DELETED
//!  the only check that the keygen finalized with the right roster.
//!
//!  WHAT IT ADDS, precisely ONE assertion, and the other candidates are named below rather
//!  than shipped: the `Some`/`None` discrimination on the RE-REPORT becomes falsifiable.
//!  On leg 1 the device consolidates its OWN share back onto itself, so a consolidation
//!  that acked without ever reaching the signer re-reports correctly and is GREEN. On a
//!  blank device it cannot be: the pre-signature `HeldShares2` says it holds nothing, and
//!  the post-consolidation one says it holds this coordinator's share at leg 1's index.
//!  That pre-report is the one thing here not implied by control flow, so it is the one
//!  thing asserted (`blank_reported_empty`).
//!
//!  THE SHEET IS THE HANDOFF, and it is explicit in both processes. The blank device has
//!  no reveal of its own -- upstream refuses `DisplayBackup` for it COORDINATOR-SIDE, so
//!  no frame is ever sent -- so its 25 words come from leg 1's glass, via the stub's
//!  `sheet_read`. A human carrying a piece of paper between two units is exactly the
//!  modelled event.
//!
//!  MEASURED: `cargo run` 10.11 s -> 12.38 s for all three passes (chunk 64, chunk 1,
//!  DECLINE). No timeout constant moved: no `State` variant was added, `State::longest()`
//!  is still 95 s and the stub's DEADLINE still 240 s, so the documented ~2.53x ratio is
//!  unmoved. `HANDSHAKE_DEADLINE` stays at 5 s and now covers ten announces plus ten
//!  session rebuilds; the tenth announce landed at 199 ms, 64 ms and 305 ms on the three
//!  passes. Zero device code, so the ARM image is unchanged at 377,256 B / .text 0x4deb0.
//!
//!  A DEFECT FOUND ON THE WAY, in the stub and unrelated to the tenth device: the loop
//!  that recorded which devices had saved a share drained
//!  `session.signer.staged_mutations()` looking for `KeyMutation::SaveShare`, and it NEVER
//!  MATCHED ONCE -- probed at 308 calls per run, every one `staged=0`, because
//!  `Session::run`'s first statement is `persist_staged`, which clears the queue. So
//!  `saved` stayed EMPTY and both conditions reading it were vacuous: the latch that
//!  advances `STATE` to `SharesSaved` and runs the "every share belongs to ONE access
//!  structure" check never fired, and a hand run's EOF PASS arm was unreachable, so a
//!  completely successful hand run died `0/9 share(s) saved`. Reading
//!  `signer.held_shares()` instead makes both live for the first time: `saved` now reaches
//!  9 on every pass and 10 on the two signature passes.
//!
//!  NINE MUTATIONS RUN, each file restored and `cmp`ed byte-identical after:
//!  - `BeginKeygen::new(announced.clone(), ..)`: **`THE KEYGEN FINALIZED WITH THE WRONG
//!    ROSTER: ... has 10 device share(s), expected 9, and the device this run left OUT
//!    (...) is in it`**, exit 1 in 1 s.
//!  - the same, with BOTH halves of that check disabled: the 9-of-10 keygen ran the whole
//!    pass -- signature, leg 1's four flows, leg 2's ingest and consolidation -- and died
//!    only at PASS with **`only 10/9 device(s) reported a session hash`**, exit 1 in 3 s.
//!    A far worse diagnosis three seconds later, which is what the in-loop check buys.
//!  - `roster = announced[1..ALL_DEVICES]`, i.e. the right SIZE and the wrong MEMBERS:
//!    **`... has 9 device share(s), expected 9, and the device this run left OUT (...) is
//!    in it`**, exit 1. The `contains_device` half is independently falsifiable; the count
//!    alone cannot see this.
//!  - the pre-signature round trip over `roster` instead of `announced`: **`M12: ...
//!    consolidated a share, but this coordinator never got a HeldShares2 from it reporting
//!    NOTHING beforehand`**, exit 1. This is the mutation `blank_reported_empty` exists
//!    for.
//!  - an EXTRA `request_held_shares(blank)` at the leg-1 handoff, i.e. an empty report
//!    while `restore` is `Some`: **`... reported 0 held share(s), NONE for the access
//!    structure keygen just finished`**, exit 1 -- the untouched fail-closed bail. With
//!    `restore.is_none()` dropped from the loosened arm the SAME edit is **exit 0, GREEN**.
//!    That is the fail-open this guard exists for, and it is why the exemption is scoped by
//!    STATE as well as by identity.
//!  - `restore.is_none()` dropped and a round trip added at ingest-done, where the blank
//!    device holds the saved backup and nothing else: **`... reported 1 held share(s),
//!    NONE for the access structure keygen just finished`**, exit 1. Drop
//!    `shares.is_empty()` too and the same edit is **exit 0, GREEN**. All three clauses of
//!    that guard are load-bearing and none of them is a count.
//!  - the quiz-count bail left reading the live `restore` instead of `sighted`: **`M7c:
//!    <blank> reported None quiz answer(s), not exactly 8`**, exit 1 on the FIRST pass.
//!  - `save_v1` passed to leg 2 unchanged: leg 2 enters `Phase::SavedV1`, reports the
//!    saved backup only, and hits the fail-closed bail -- **`reported 1 held share(s),
//!    NONE for the access structure`**, exit 1 on the chunk-1 pass.
//!  - leg 2 started at `Phase::Erase`: upstream's `EraseDevice` was driven at the BLANK
//!    device and it refused (**`M9 PASS -- <blank> REFUSED the driver's DataErase`**),
//!    which is the tenth `refused_erase` entry that would fail that EXACT count; the run
//!    then died in the NEXT phase with **`1: DisplayBackupProtocol::new / 2: state
//!    inconsistent: device does not have share in key`**, exit 1. That is (d)'s mechanism,
//!    MEASURED, and it is COORDINATOR-side: PLAN.md says it surfaces as `Fault::Signer`
//!    and the stub's `die(2)`, and it does not -- no frame is ever sent.
//!  - the stub's pre-match `paper.entry(id).or_default()` restored in place of
//!    `sheet_read`: the blank device gets an EMPTY sheet and dies at `type_backup`'s **`no
//!    share index was ever read off a reveal page`** (exit 2, state `BackupIngest`) --
//!    the symptom, pointing a reader at the reveal walk instead of at the sheet plumbing.
//!  - `Grant::Reveal` writing to a throwaway `Sheet::default()` so `paper` stays empty:
//!    **`<id> was asked to read a reveal back and there is NO sheet in the room`**, exit 2.
//!
//!  ONE MUTATION SURVIVED GREEN, and it is the more interesting result: reverting the
//!  stub's `acked == ALL_DEVICES` to `== N_DEVICES` leaves the harness at **exit 0** and
//!  the `all 10 devices acked` line still prints. So the ten `AnnounceAck`s do NOT all
//!  arrive in one `recv_timeout` payload on this machine -- `acked` walks up through 9 and
//!  the equality catches it there. `ALL_DEVICES` is still the correct spelling, because at
//!  9 the line asserts "all acked" when one device has not, but the change is
//!  correctness-by-construction and NOT load-bearing at this timing: if the acks ever
//!  coalesce, 9 is skipped, `STATE` never reaches 3 and every later `die` names a stale
//!  stage. That failure would be invisible.
//!
//!  WHAT SURVIVED, stated rather than hidden:
//!  - the SHARE-IMAGE half of M7e is still over-determined and a tenth device does NOT
//!    change that, contrary to PLAN.md §9 item 12. The device's own `Consolidate` handler
//!    refuses a wrong image before any prompt exists (`expected_image != actual_image ||
//!    secret_share.index != consolidate.share_index`, vendored
//!    `device/restoration.rs`), so the coordinator's comparison is a second opinion on
//!    both legs. What a blank device makes falsifiable is the `Some`/`None`
//!    discrimination, which is a different assertion in the same block.
//!  - the `index != r.share_index` bail in `Phase::Ingest` is a fail-closed BOUND, not a
//!    demonstrated assertion, and a tenth device does not promote it.
//!    `check_physical_backup` takes the index FROM `phase.backup.share_image.index` -- the
//!    device's own claim -- and then requires `root_shared_key.share_image(that)` to equal
//!    the typed image, so every one-line corruption is `ShareImageIsWrong` first, with a
//!    better message. The only thing that reaches the bail is handing over the WRONG
//!    SHEET, which needs a second reveal in the room to be possible at all. NOT built: it
//!    would need a third `Restore` leg and a rule, duplicated across both processes, for
//!    which sheet the blank device retypes, and what it buys is a self-check of the
//!    harness rather than device evidence. The stub's `sheet_read` refuses two sheets
//!    instead, so the rule cannot be added by accident.
//!  - the PASS-block `devices.len()` count is control-flow implied on the signature passes
//!    and is kept only as an exact count that would catch a share holder nobody put there.
//!    Its expectation is `sighted.is_some()` rather than a constant, because the DECLINE
//!    pass runs no restoration and therefore has NO tenth holder; a flat `N_DEVICES` there
//!    fails **`expected 9-of-9 with 9 share holder(s) ... coordinator has 9-of-10`**
//!    (MEASURED, exit 1) and a flat `ALL_DEVICES` fails the DECLINE pass.
//!  - FIVE tempting assertions were NOT written, all for the same reason -- each is
//!    already implied by control flow, so each would read like coverage: the blank device
//!    appearing in `device_to_share_indicies()` at leg 1's index (both halves come from
//!    the same `FinishedConsolidation` and from an index the coordinator itself chose);
//!    the blank device reporting no `SetName` (`commit_name` fires only from
//!    `FinalizeKeyGen`, and the exact `device_names.len() == N_DEVICES - 1` already
//!    discriminates); the blank device not being in `refused_erase` (it is never sent the
//!    frame); its `HeldShares2` being empty as a STANDALONE assert -- folded into the
//!    loosened arm's GUARD instead, so anything else falls through to the untouched bail;
//!    and `PhysicalBackupSaved` having arrived, which is M11's already-recorded shape.
//!  - the DECLINE pass is untouched by design and that is the cheapest evidence the tenth
//!    device perturbs nothing: it gets an `AnnounceAck` and a name preview and no prompt
//!    at all -- no `CheckKeyGen`, no forged `DataErase`, no restoration -- so
//!    `STUB_EXPECT_DECLINES` stays at `N_DEVICES` and the pass's own assertions are
//!    byte-for-byte the ones it made before.
//!
//!  M13 (FIRMWARE UPGRADE STAGING -- a RAW, UNFRAMED chunk stream, and a digest verdict
//!  carried by an ack that does not arrive). [`staging_leg`] runs a fifth pass in its own
//!  process, with its own pty and `STUB_UPGRADE=1`, driving the device's
//!  `upgrade::Stager` end to end: magic handshake, `PrepareUpgrade2`,
//!  `EnterUpgradeMode`, then [`STAGE_SIZE`] bytes as 65 unframed chunks with one
//!  `raw_read` of exactly one byte after each.
//!
//!  WHY IT NEEDS ITS OWN EVERYTHING, and why upstream's own driver cannot be used:
//!  `UsbSerialManager::run_firmware_upgrade` iterates a `ready` map populated only from
//!  `available_ports()` filtered on a USB vid/pid, which a pty master with
//!  `port_name: None` can never enter; and `ValidatedFirmwareBin::new` rejects any image
//!  without ESP magic `0xE9` at byte 0, so it could never carry a Cortex-M artifact at
//!  all. `raw_send`/`raw_write`/`raw_read` are public, this file already hand-builds a
//!  `CoordinatorToDeviceMessage` for M11, and `sha2` is already in scope -- so the leg is
//!  hand-rolled, which is the same shape a bench tool will have to be. No writer thread
//!  here on purpose: one `FramedSerialPort` owns both directions, so the ack reads come
//!  off the same `BufReader` the frames went out on and no desync is possible.
//!
//!  WHAT IT PROVES THAT A UNIT TEST CANNOT. (a) The framer BYPASS: the device stops
//!  feeding `Link::poll` for the duration and picks it back up after, which no host test
//!  of `Stager` alone can exercise. (b) The 0x11 accounting against a real
//!  `write_all`-then-`read_exact` lockstep. (c) That the SHORT final chunk is genuinely
//!  short on the wire -- `std::slice::chunks` yields 512 bytes for the 65th, nothing pads
//!  it, and the device must not invent a pad byte the digest would cover.
//!
//!  WHY [`STAGE_SIZE`] IS 262,656 AND NOT 397,312. Every real Mk4 artifact is a multiple
//!  of 4,096 (`cli/signit.py:302-306` re-aligns the body), and 397,312 = 97 x 4,096
//!  exactly -- a run at that size CANNOT fail the ack arithmetic or the tail, so it would
//!  be the vacuous version. 262,656 = 64 x 4,096 + 512 clears the bootloader's 262,144
//!  floor, satisfies the digest's 512 alignment, and is `% 4096 != 0`.
//!
//!  THE NEGATIVE LEG IS FIRST AND IS THE POINT. A device in this window can never send a
//!  frame -- every device-to-coordinator message carries a `DeviceId` derived from an
//!  identity secret the window does not have -- so the ONLY outcome channel is the ack,
//!  and the refusal is an ack that does not arrive. One flipped byte in chunk 40 must earn
//!  exactly 64 acks and then silence; the clean image must earn all 65. Both legs run
//!  against the same child, which also exercises the device's re-prepare-from-`Refused`
//!  transition.
//!
//!  THE THIRD (COALESCED) LEG, AND THE DEFECT THAT PUT IT THERE. Both admission frames
//!  go out in ONE `raw_write`, so `Link::poll` hands the callback BOTH before returning
//!  -- which is exactly what happens on USB, two few-dozen-byte frames against a 64-byte
//!  packet. `upgrade::run` recorded the admitted message in a single `Option` until
//!  2026-09-17, so the second frame OVERWROTE the first and only `EnterUpgradeMode` was
//!  admitted, from `Idle`: `Refuse::OutOfOrder`, and an upgrade that could never start.
//!  MEASURED: with that regression restored, this leg reports `0 ack(s) ... expected 65`.
//!  Fixed by admitting inside the callback.
//!
//!  TWO CLAIMS THIS LEG DOES *NOT* MAKE, both withdrawn by measurement rather than
//!  argued away:
//!  - Its first draft asserted that DELETING the 100 ms sleep after `EnterUpgradeMode`
//!    reddens the positive leg, because cold-snap's buffering `Link::poll` would then eat
//!    chunk 0's head. **MEASURED 2026-09-17: deleting the sleep left every leg GREEN,
//!    exit 0** -- a pty delivers separate writes as separate reads, so the race never
//!    materialises here. The sleep is kept for parity with
//!    `usb_serial_manager.rs:681-682` and is labelled unproven at its call site.
//!  - A fourth leg wrote the two frames AND chunk 0's head together and asserted that no
//!    ack arrived (MEASURED: 0 acks, correct). It was DELETED rather than shipped,
//!    because every device mutation that could make it fire is caught by the NEGATIVE leg
//!    first -- dominated, and it would have read like coverage. The head-loss hazard is
//!    real; what this tree can falsify about it is the coalesced-ADMISSION half.
//!
//!  A THIRD DEFECT, in this file: the handshake loop re-sent magic on every poll, which
//!  is right (the device's `scan_magic` consumes the FIRST magic frame without calling
//!  `on_frame`, so one send never gets a reply) but left the device's SECOND
//!  `MAGIC_REPLY` in the `BufReader`. `read_for_magic_bytes` consumes only to the end of
//!  the first pattern it matches and `anything_to_read()` asks the PORT rather than the
//!  buffer, so nothing could ever consume the leftover -- whose first byte is `0x00`,
//!  read as chunk 0's ack. INTERMITTENT, roughly one run in three. `stage_session` now
//!  drains with `raw_read` until it times out. Only a leg that switches to raw byte
//!  reads can see this; the ordinary event loop decodes both replies through a framer.
//!
//!  NOT PROVEN BY M13, and it is the whole of what phase 3 does not do: no burn, no
//!  callgate sub-call, no signature check, no PIN. `Outcome::Staged` means bytes are in
//!  PSRAM with a matching digest and nothing on this device can install them.
//!
//! Usage: `hostcheck [path-to-stub-binary]`. Build the stub FIRST and pass the
//! artifact -- never `cargo run`: the child's stdout IS the wire, and one stray
//! byte of cargo progress output desynchronises the magic scan permanently.
//!
//!   cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub
//!   cargo run -p hostcheck        # from hostcheck/, default path below

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use frost_backup::bip39_words::BIP39_WORDS;
use frost_backup::ShareBackup;
use frostsnap_coordinator::check_backup::CheckBackupProtocol;
use frostsnap_coordinator::display_backup::{DisplayBackupProtocol, DisplayBackupState};
use frostsnap_coordinator::enter_physical_backup::{EnterPhysicalBackup, EnterPhysicalBackupState};
use frostsnap_coordinator::erase_device::EraseDevice;
use frostsnap_coordinator::frostsnap_comms::{
    CommsMisc, CoordinatorSendBody, CoordinatorSendMessage, DeviceName, DeviceSendBody, Downstream,
    MagicBytes, NameCommand, ReceiveSerial, Sha256Digest, Upstream, BINCODE_CONFIG,
    MAGIC_BYTES_PERIOD,
};
use frostsnap_coordinator::frostsnap_core::coordinator::restoration::{
    PhysicalBackupPhase, ToUserRestoration,
};
use frostsnap_coordinator::frostsnap_core::coordinator::{
    BeginKeygen, CoordinatorSend, CoordinatorToUserKeyGenMessage, CoordinatorToUserMessage,
    CoordinatorToUserSigningMessage, FrostCoordinator,
};
use frostsnap_coordinator::frostsnap_core::device::KeyPurpose;
use frostsnap_coordinator::frostsnap_core::message::{
    // M11: `CoordinatorRestoration` and `CoordinatorToDeviceMessage` are named here only
    // so `downgrade_save` can rebuild the LEGACY v1 body. Nothing else in this file
    // constructs a `CoordinatorToDeviceMessage` -- every other frame comes out of the
    // coordinator's own queue.
    CoordinatorRestoration,
    CoordinatorToDeviceMessage,
    DeviceRestoration,
    DeviceToCoordinatorMessage,
    EncodedSignature,
};
use frostsnap_coordinator::frostsnap_core::schnorr_fun::frost::{Fingerprint, ShareIndex};
use frostsnap_coordinator::frostsnap_core::schnorr_fun::{Schnorr, Signature};
use frostsnap_coordinator::frostsnap_core::{
    sha2, AccessStructureRef, DeviceId, KeygenId, RestorationId, SessionHash, SignSessionId,
    SymmetricKey, WireSignTask,
};
// Not a direct dependency either: `frostsnap_core` re-exports the one `bincode`
// the coordinator decodes with, so the error matched in `is_read_timeout` is the
// same type the coordinator produced.
use frostsnap_coordinator::frostsnap_core::bincode;
use frostsnap_coordinator::frostsnap_core::Gist;
use frostsnap_coordinator::serialport::{SerialPort, TTYPort};
use frostsnap_coordinator::{
    Completion, DeviceMode, FirmwareVersion, FramedSerialPort, Sink, UiProtocol, VersionNumber,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Where `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example
/// stub` puts it. UNCHANGED by the move out of `hal/`: cargo puts every workspace
/// member's examples in one flat `target/<triple>/debug/examples/` directory.
///
/// Freshness IS checked, by `refuse_if_stale` below. It used to be `is_file()` only,
/// which meant a stale artifact from an earlier build got run and reported on -- a
/// fail-open in the one program whose entire job is verification, and the most
/// expensive kind: a green run certifying code that is not in the binary.
const DEFAULT_STUB: &str = "../target/aarch64-apple-darwin/debug/examples/stub";

/// **THE KEYGEN ROSTER, not the number of devices on the wire** — that is
/// [`ALL_DEVICES`]. Everything counted per keygen participant keys off THIS: shares,
/// acks, session hashes, glass codes, `SetName`s, declines, the forged `DataErase`.
///
/// n is not arbitrary: it is what fits the frame bound. MEASURED sizes at n=3 are
/// `CertifyPlease` 778 B, `Check` 646 B, `KeyGenResponse` ~318 B, so nothing crosses
/// the ~1 KB point at which an undrained pty blocks a write. That is now a bound, not
/// a hang (`WRITE_STALL_LIMIT`), but staying under it is still why keygen is fast.
/// At 9-of-9 `CertifyPlease` is
/// 2,179 B and does not even fit the device's frame limit. Do not raise these
/// without re-deriving both bounds. The tenth device does NOT move either figure,
/// because it is not in the roster the certpedpop transcript is built over.
const N_DEVICES: usize = 9;
const THRESHOLD: u16 = 9;

/// Devices on the wire. The tenth is THE BLANK ONE (M12): it announces, gets an
/// `AnnounceAck` and a name preview like the rest, and is then left OUT of
/// `BeginKeygen`, so it reaches the signature holding nothing at all.
///
/// `N_DEVICES` was NOT renamed to `KEYGEN_DEVICES`, deliberately. 40-plus
/// occurrences, most of them inside format strings, and a mechanical rename would
/// have flipped the seven counted conditions that must STAY at 9 into this constant
/// and weakened all seven at once. Leaving `N_DEVICES = 9` means an unconverted site
/// keeps the STRICTER count, which is the fail-closed direction; the cost is that
/// `N_DEVICES` names something narrower than it reads, which is why its doc says so
/// in its first line.
///
/// Which device is blank is DECIDED HERE, not reported by any device: the roster is
/// cut at `announced[..N_DEVICES]` and the blank one is `announced[N_DEVICES]`, both
/// out of one expression on one lap. A harness that asked the devices which of them
/// was blank would be trusting them about the very thing under test.
const ALL_DEVICES: usize = N_DEVICES + 1;

/// ONE nonce stream per device, and this is the whole M5 frame-size decision.
///
/// A `NonceResponse` is one segment per stream, and one 30-nonce segment MEASURED
/// 2,040 B -- the first frame over 1 KB ever to cross this pty, which is the point
/// of M5. Two streams is 4,038 B against a 4,096 bound, i.e. 58 bytes of headroom,
/// and the real flutter app asks for FOUR (`N_NONCE_STREAMS`), ~8 KB, which does
/// not fit at all. The only reason that is not a live bug upstream is that
/// `NonceReplenishProtocol::new` calls `OpenNonceStreams::split()` and asks for one
/// stream at a time; the stub caps at one segment per frame as belt-and-braces
/// against a coordinator that stops splitting. Raising this proves nothing extra
/// about the wire and walks straight into the bound.
const NONCE_STREAMS: usize = 1;

/// The message we sign. `WireSignTask::Test` is the simplest task that yields a
/// verifiable signature: exactly one `SignItem`, no taproot sighash work, no
/// `bdk`, and `AppTweak::TestMessage` so the verification is one `Schnorr::verify`
/// against a key derived from `master_appkey`. A bitcoin task would add PSBT
/// plumbing and prove nothing more about the wire.
const SIGN_MESSAGE: &str = "cold-snap M5";

/// Built twice (once to sign, once to verify) rather than cloned around: it is two
/// words, and building it at the verify site is what makes the verification
/// independent of whatever the signing path did with it.
fn sign_task() -> WireSignTask {
    WireSignTask::Test {
        message: SIGN_MESSAGE.into(),
    }
}

/// Matches the stub's constant. See the long note there: the fingerprint is a
/// coordinator-side grind (`FROST_V0` is 18 bits/coefficient, minutes of CPU in
/// a debug build), it must be equal on both sides because the device verifies
/// it, and it changes which coefficients are chosen -- never how they encode.
/// So it costs this harness nothing it was here to prove.
const TEST_FINGERPRINT: Fingerprint = Fingerprint {
    bits_per_coeff: 2,
    max_bits_total: 6,
    tag: "test",
};

/// The share-encryption key the coordinator persists its own key data under.
/// Constant, like the vendored tier-2 harness: this harness never reloads
/// anything from storage.
const ENCRYPTION_KEY: SymmetricKey = SymmetricKey([42u8; 32]);

/// Fixed seed, so a failing keygen replays exactly. The stub's `Entropy` is
/// fixed-seeded too, so the whole two-process run is deterministic.
const RNG_SEED: [u8; 32] = [7u8; 32];

/// 250 ms -- deliberately NOT `DesktopSerial`'s 5 s (`serial_port.rs:257-260`).
///
/// This timeout is the ONLY thing that can end a blocking read inside
/// `bincode::decode_from_reader`, so it is the slack term on every deadline
/// below: worst-case wall clock is `budget + PORT_TIMEOUT`.
///
/// What is traded, honestly:
///  - Upstream keeps 5 s because a read timeout is a device DISCONNECT
///    (`usb_serial_manager.rs:299-311`) and it must not evict a device that is
///    merely slow. This harness has no device to evict.
///  - Upstream's other reason is WRITES: "10ms is too low and leads to errors
///    when writing", on real USB CDC. 250 ms is 25x that, and this port is a
///    local pty.
///  - What IS given up: this harness cannot distinguish "device thinking for
///    300 ms" from "device stalled". Both become a deadline failure. That is why
///    keygen gets its own, much larger budget -- a debug-build certpedpop keygen
///    across three signers legitimately holds the wire for whole seconds.
const PORT_TIMEOUT: Duration = Duration::from_millis(250);

/// The handshake budget, unchanged from M2 so its measurements still stand: 5 s
/// for magic + 3 Announces. Hard on the read path (`budget + PORT_TIMEOUT`).
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);

/// The keygen budget, on top of `HANDSHAKE_DEADLINE`, and generous on purpose:
/// this is real elliptic-curve work in TWO debug builds, and at `STUB_CHUNK=1`
/// every byte of every frame is a syscall on the device side. MEASURED, whole
/// keygen from magic bytes to the stub's exit, 3 runs after the writer thread
/// landed: **95-120 ms at chunk 64, 1.30-1.33 s at chunk 1** (the difference is
/// the 1 ms-per-chunk gap on the first 64 bytes of each of ~10 frames). Chunk 64
/// halved (265 ms before) because a frame no longer waits for `tcdrain` on the
/// loop's own thread; chunk 1 rose (847 ms before) because the handoff costs a
/// scheduling round-trip per frame and at chunk 1 that no longer hides under the
/// device's own 1 ms gaps. Both directions are noise against the budget, which is
/// the point of having one. 30 s is ~23x the slower case, the right shape for a
/// whose only job is to turn a hang into a named failure -- tightening it to the
/// measurement would make the harness flaky on a loaded machine and prove
/// nothing extra. The two failing mutations above both died on it at 35.000 s,
/// i.e. `HANDSHAKE_DEADLINE + KEYGEN_DEADLINE`, exactly.
const KEYGEN_DEADLINE: Duration = Duration::from_secs(30);

/// M5's budget, on top of the two above, covering nonce replenishment AND signing.
/// One number for both phases deliberately: the deadline message names the state,
/// so splitting the budget would buy a tighter clock and no extra diagnosis.
///
/// 30 s is generous against MEASURED cost -- replenish + sign is 0.10 s at chunk
/// 64 and 1.35 s at chunk 1 -- and the shape is the same as `KEYGEN_DEADLINE`: it
/// exists to turn a hang into a named failure, not to be a performance assertion.
/// The chunk-1 case is the one to watch: three 2,040 B `NonceResponse` frames at
/// one byte per write, plus 30 nonce derivations per stream per device in a debug
/// build.
const SIGN_DEADLINE: Duration = Duration::from_secs(30);

/// M7's budget, on top of the three above, covering all four restoration flows: the
/// backup reveal, the check quiz, the ingest and the consolidation.
///
/// One number for all four, for [`SIGN_DEADLINE`]'s reason: the deadline message names
/// the state, so splitting it buys a tighter clock and no extra diagnosis.
///
/// The device-side cost dominates and is not on the wire at all — eight page renders,
/// eight quiz renders, and roughly 200 letter-picker presses each of which composes a
/// 1,024-byte frame and reads two dozen cells back out of it with a 96-glyph linear
/// scan. Wire traffic is a dozen small frames; nothing here approaches the 1 KB point
/// where an undrained pty blocks a write, so `STUB_CHUNK` barely moves it. 30 s is the
/// same shape as the two budgets above: it exists to turn a hang into a named failure,
/// not to be a performance assertion.
///
/// **The stub's own watchdog is derived from the sum of all four**, so raising this
/// without raising `DEADLINE` in `firmware/examples/stub.rs` would put the stub in
/// charge of killing a slow run and throw the diagnosis away. See the note there.
const RESTORE_DEADLINE: Duration = Duration::from_secs(30);

/// The firmware version this harness DECLARES to `CheckBackupProtocol`, and the one
/// decision trap 2 of the M7 brief demands be made explicitly.
///
/// `CheckBackupProtocol::new` branches on `firmware.features().check_backup`, which is
/// `version >= 0.3.0` (`frostsnap_comms/src/firmware_version.rs:57-61`). This device
/// announces a firmware DIGEST and never a `FirmwareVersion`, so upstream's
/// `FirmwareVersion::new(digest)` leaves `version: None`, and `features()` then FAILS
/// OPEN to `FirmwareFeatures::all()` — which happens to select the modern path, by
/// accident of the digest being unknown rather than by anybody's decision.
///
/// Stating the version instead makes it a decision, and [`Restore`]'s `Phase::Quiz`
/// arm ASSERTS `features().check_backup` before it builds the driver. Without that
/// assert an upstream that moved the threshold would silently drive the LEGACY path —
/// `tell_device_to_load_physical_backup` plus a share-image comparison — which is
/// M7d's flow wearing M7c's name, and the quiz would never run at all.
const CHECK_BACKUP_SINCE: VersionNumber = VersionNumber::new(0, 3, 0);

/// The name of the throwaway restoration M7d opens purely to obtain a
/// [`RestorationId`].
///
/// `EnterPhysicalBackup::is_complete()` is `Success` only on `PhysicalBackupSaved`,
/// which only `tell_device_to_save_physical_backup` can produce, and that call needs a
/// `RestorationId` from `start_restoring_key`. So a coordinator that already HOLDS the
/// key still has to open a restoration to save a physical backup — this is upstream's
/// shape (`frostsnapp/rust/src/coordinator.rs`), not a workaround, and the cost is one
/// `RestorationProgress2` mutation in a coordinator this process throws away at the
/// end of the pass.
const RESTORE_KEY_NAME: &str = "cold-snap M7";

/// M11: the threshold the LEGACY `CoordinatorRestoration::SavePhysicalBackup` (v1) frame
/// carries, and it is **7 rather than [`THRESHOLD`]'s 9 on purpose**.
///
/// v1 is the only admitted restoration body no coordinator sends, so it was the last one
/// nothing drove. Upstream aliases it: the device rebuilds it as a `SavePhysicalBackup2`
/// and RECURSES (`vendor/.../device/restoration.rs:64-82`). That makes the naive
/// assertion useless — `DeviceRestoration::PhysicalSaved` carries only a `ShareImage`, so
/// "v1 produced PhysicalSaved" is byte-identical to what v2 produces and CANNOT FAIL
/// against an accidental v2 in the same slot.
///
/// The one field that does distinguish them is this one. v1's `threshold` is a
/// NON-OPTIONAL `u16`, so the rebuild forces `threshold: Some(threshold)`; the v2 the
/// other pass sends carries `threshold: None`, because
/// `prepare_save_physical_backup` fills it only on a successful trial recovery and
/// `find_valid_subset` refuses one share image against a threshold of 9. And it is
/// wire-observable: `held_shares()`' saved-backup iterator reports
/// `threshold: saved_backup.threshold` VERBATIM.
///
/// 7 and not 9 so the value exists NOWHERE ELSE in the run — at 9 the assertion would
/// also pass on the real access structure's entry, so a lookup that picked the wrong
/// `HeldShare2` would go unnoticed.
///
/// SAFE because it is INERT on the device, which is checked and not assumed:
/// `Consolidate` derives `threshold: root_shared_key.threshold() as u16` from the
/// coordinator's own root shared key (`device/restoration.rs:164`) and never reads
/// `saved_backup.threshold`. So a coordinator-chosen threshold is a reported value and
/// nothing else — which is itself worth pinning, and this is what pins it.
const V1_THRESHOLD: u16 = 7;

/// How many positions the device's check quiz asks, and therefore how many correct
/// answers a pass must take.
///
/// `coldsnap_firmware::quiz::QUIZ_POSITIONS` is `ui::BACKUP_WORDS / 3` — Coldcard's
/// `limited = len(words) // 3` (`shared/backups.py:442`) — and this process cannot
/// import it: the whole point of the two workspaces is that nothing here may reach a
/// `coldsnap_*` crate. Derived from `frost_backup::NUM_WORDS`, which IS shared, so the
/// two arithmetics are over one 25 rather than over two literals; the `/ 3` is the
/// duplicated part, and it is what the run would fail on if the device ever changed it.
const QUIZ_POSITIONS: usize = frost_backup::NUM_WORDS / 3;

/// M8: the name this coordinator PREVIEWS, and it is deliberately not ASCII.
///
/// `DeviceName` is `FixedString<DEVICE_NAME_MAX_LENGTH>` and that 14 counts **chars**,
/// not bytes (`fixed_string.rs:31-40` and `:155`), so the widest name the wire admits
/// is 14 four-byte codepoints = **56 bytes** — which is exactly
/// `coldsnap_firmware::DEVICE_NAME_MAX_BYTES` (`4 * DEVICE_NAME_MAX_LENGTH`), the bound
/// `NameStore::save` re-applies at the flash boundary because upstream's `Decode`
/// builds an unbounded `String` first.
///
/// This name IS that corner: 14 chars, 56 bytes, and every codepoint 4 bytes wide. One
/// CHAR more and upstream's `Decode` silently truncates it on the way in; one BYTE more
/// and the flash write is refused `StoreFault::TooBig`. A plain-ASCII name crosses
/// neither bound and would leave the char-vs-byte distinction those two constants exist
/// for completely untested — 14 ASCII chars are 14 bytes, a quarter of the record.
const DEVICE_NAME: &str = "🧊🔐🧊🔐🧊🔐🧊🔐🧊🔐🧊🔐🧊🔐";

/// The LAST-RESORT bound: a wall-clock watchdog for a stall anywhere in the main
/// loop that is not a read and not a write (both of which are bounded above).
///
/// It owns no I/O, so nothing it watches can stop it; it wakes every 100 ms, and
/// if the current pass has outlived its deadline it prints the state NAME and
/// `exit(5)`s the process. COARSE on purpose: one deadline per pass, set to the
/// pass's MAXIMUM budget, so a stall during the handshake is caught at 37 s
/// rather than at 7 s. VERIFIED by injecting a 60 s sleep inside the loop:
/// `WATCHDOG at 37.028 s -- state WaitingForAnnounces`, exit 5.
///
/// It is no longer the write path's only bound; see `WRITE_STALL_LIMIT`.
const WATCHDOG_SLACK: Duration = Duration::from_secs(2);

/// THE WRITE PATH, bounded.
///
/// `FramedSerialPort::raw_send` -> `flush()` -> serialport-4 -> `tcdrain(fd)`
/// blocks until the peer drains and is NOT subject to `PORT_TIMEOUT`. MEASURED at
/// M2, before this: a device that linked and then stopped reading parked this
/// harness **8.176 s**, released by the STUB's watchdog closing the pty -- the
/// read deadline was bypassed entirely because the loop never got back to it.
/// Every M5 signing frame is over 1 KB (`NonceResponse` 1x30 = 2,040 B,
/// `SignatureShare` + replenish = 2,105 B) and the pty blocks writes past ~1 KB,
/// so under M5 that is the FIRST frame, not a corner case.
///
/// WHAT IS IMPLEMENTED (design (a), a writer thread): every byte this harness
/// sends is written by `spawn_writer`'s thread, which owns a `dup` of the pty
/// slave fd and its own `FramedSerialPort`. The main loop only `send`s on an
/// `mpsc` channel, which never blocks, so a parked `tcdrain` can no longer keep
/// the loop away from its deadline checks. The writer publishes the start time of
/// each `raw_send` in `WRITE_BUSY_SINCE_MS`; the loop reads it every lap and fails
/// by NAME once one write has been in flight longer than this.
///
/// So the bound is honest but INDIRECT: the blocked `tcdrain` itself is still
/// uninterruptible -- that thread stays parked until the pty is drained or the
/// process exits. What is bounded is the RUN. Nothing else needs bounding: the
/// writer thread holds no lock the loop wants, and it is detached, so a leaked
/// parked writer only ever outlives a run that is already failing.
///
/// 5 s: the whole chunk-1 keygen MEASURED 1.33 s, so no single legitimate write
/// comes near it, and it is 1/7 of the keygen deadline, i.e. a write stall is
/// diagnosed as a write stall rather than as a late generic DEADLINE. This is the
/// knob to turn if a real device legitimately stops reading for seconds mid-sign.
const WRITE_STALL_LIMIT: Duration = Duration::from_secs(5);

/// Multiplies every cumulative budget in [`State::budget`] — and so the
/// once-per-pass watchdog too, which is derived from the largest one
/// (`COLDSNAP_TIMEOUT_SCALE`, default **1**).
///
/// Default 1 means `Duration * 1`, so the automated gate's 5 s / 35 s / 65 s bounds
/// and every mutation measurement in the header above are bit-for-bit unchanged.
/// The factor exists for the window: a human takes seconds per screen and there are
/// two consent screens per device back to back, so no single honest budget covers
/// both a human and two debug builds talking to each other. LIVE-GLASS-PLAN §10
/// says exactly that — the gate does not survive "unchanged by a single line", and
/// this is the line.
///
/// The stub inherits this variable (we spawn it) and scales its own 90 s watchdog
/// by it, which is the load-bearing part: that watchdog's contract is being ~2.5x
/// OUR bound, so scaling one side and not the other would put the stub in charge of
/// killing a slow run and throw away the diagnosis.
///
/// NOT scaled, deliberately, and both are budgets in name only:
///  - `PORT_TIMEOUT` — the read path's tick, not a deadline. Scaling it would make
///    every failure up to `scale x 250 ms` late and buy nothing, because a slow
///    human does not make the pty slow.
///  - `WRITE_STALL_LIMIT` — a parked write needs the DEVICE to stop draining fd 0,
///    and the stub drains from a dedicated thread (`spawn_reader`) that a prompt
///    parked on a keypress cannot block. Thinking does not stall a write.
///
/// Read ONCE: `budget()` runs every 2 ms lap.
fn timeout_scale() -> u32 {
    static SCALE: OnceLock<u32> = OnceLock::new();
    *SCALE.get_or_init(|| {
        std::env::var("COLDSNAP_TIMEOUT_SCALE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            // A 0 would make every budget instantly expired, i.e. a typo would
            // look like a device fault.
            .filter(|&n| n > 0)
            .unwrap_or(1)
    })
}

/// What a pass is trying to prove, because there are now two opposite things.
///
/// [`Expect::Decline`] is not "the run may fail": it is a pass with its own
/// assertions, and a signature appearing during it is a FAILURE. LIVE-GLASS-PLAN
/// §10 is explicit that a decline without an explicit expectation must fail the
/// gate, so the expectation is a value the pass carries rather than a log line
/// somebody reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The default gate: 9 consents, a signature that verifies.
    Signature,
    /// Every device presses `x` at the signing screen. Keygen still completes (so
    /// the glass assertion still runs), and then NOTHING may sign.
    Decline,
}

/// How long the decline pass keeps reading after the last device has said no,
/// before it will believe the absence of a signature share.
///
/// It does not need to be long and it is not a guess: a device's `declined=` Debug
/// and a `SignatureShare` it wrongly produced anyway are pushed to the SAME
/// `Outbox` and cross in the same write, so by the time this process has decoded
/// the ninth decline a share is either already decoded or the next thing in the pty
/// buffer. One second is ~500 laps of this loop. Scaled with everything else so a
/// human-latency run does not shorten it relative to the rest.
const DECLINE_GRACE: Duration = Duration::from_secs(1);

/// M9: how long upstream's `EraseDevice` is left OPEN before the absence of a
/// `Completion::Success` is believed.
///
/// [`DECLINE_GRACE`]'s shape, and its reason run over a different message: the device's
/// `refused=DataErase` `Debug` and a `CommsMisc::EraseConfirmed` it wrongly sent anyway
/// would be pushed to the SAME `Outbox` and cross in the same write, so by the time this
/// process has decoded the refusal a confirmation is either already decoded or the next
/// thing in the pty buffer. One second is ~500 laps of this loop. Scaled with everything
/// else so a human-latency run does not shorten it relative to the rest.
///
/// A separate constant rather than reusing [`DECLINE_GRACE`] because the number is the
/// cheap half: the doc is the argument, and these are arguments about two different
/// messages arriving late.
const ERASE_GRACE: Duration = Duration::from_secs(1);

/// Coordinator-side states. [`State::name`] is the single source of truth for the
/// spelling, because both the loop's own error and the watchdog thread (which has only an
/// integer, and goes through [`State::from_index`]) print from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
enum State {
    WaitingForMagic = 0,
    WaitingForAnnounces,
    KeygenAwaitingShares,
    KeygenAwaitingSessionHash,
    KeygenAwaitingAcks,
    KeygenAwaitingDeviceSave,
    /// Waiting for each device to REPORT what it stored, over the wire.
    KeygenAwaitingHeldShares,
    /// M5: `OpenNonceStreams` sent, waiting for every device's `NonceResponse`.
    /// This is where the >1 KB frames are.
    NonceReplenish,
    /// M5: `RequestSign` sent to the threshold subset, waiting for their
    /// `SignatureShare`s and the coordinator's aggregation.
    SigningAwaitingShares,
    /// M7b: upstream's `DisplayBackupProtocol` is driving one device's reveal, and
    /// this process is waiting for the 25 words its GLASS drew plus
    /// `CommsMisc::BackupRecorded`.
    BackupReveal,
    /// M7c: upstream's `CheckBackupProtocol` is driving the check quiz, answered by
    /// the device from what the reveal showed. Waiting for
    /// `CommsMisc::BackupChecked`.
    BackupQuiz,
    /// M7d: upstream's `EnterPhysicalBackup` is driving the letter picker. Waiting
    /// for `PhysicalBackupEntered`, then `PhysicalBackupSaved`.
    BackupIngest,
    /// M7e: `Consolidate` sent — the DESTRUCTIVE one — waiting for
    /// `FinishedConsolidation` and then for the device to report what it holds again.
    BackupConsolidate,
    /// M9: upstream's `EraseDevice` is open at one device and MUST NOT complete.
    /// Waiting out [`ERASE_GRACE`] with `is_complete() == None`, plus the device's
    /// `refused=DataErase` on the wire.
    ///
    /// Shares [`RESTORE_DEADLINE`]'s cumulative budget with the four `Backup*` states
    /// above rather than adding one of its own, which is what keeps [`State::longest`]
    /// — and therefore the stub's own `DEADLINE`, whose contract is being ~2.5x this
    /// harness's 95 s bound — exactly where it was.
    EraseRefusal,
}

/// Every state's spelling, and the ONE definition of it: both the loop's own errors and
/// the watchdog thread print from here.
///
/// AN EXHAUSTIVE `match` AND NOT A PARALLEL ARRAY, which is the whole point. This was
/// `const NAMES: [&str; 14]` indexed by `self as usize` until 2026-09-12, guarded by a
/// `const _: () = assert!(NAMES.len() == State::EraseRefusal as usize + 1)` — and that
/// guard was INVERTED for the only edit anyone makes. Appending a fifteenth variant AFTER
/// `EraseRefusal` leaves that discriminant at 13, so `13 + 1 == 14 == NAMES.len()` and the
/// assert PASSED while `NAMES[14]` panicked out of bounds; adding the variant AND its
/// string made `15 != 14` and FAILED the build. Two reviewers found it independently.
///
/// A `match` with no `_` arm makes the same edit `error[E0004]` at compile time on every
/// target, which is the shape this project already relies on for `keypad::Event`,
/// `Answer` and `Consent`. It also deletes the index, so the watchdog's raw-integer read
/// can no longer be out of bounds at all: it takes a `State` through [`State::from_index`]
/// and says so when the integer is not one.
impl State {
    fn name(self) -> &'static str {
        match self {
            State::WaitingForMagic => "WaitingForMagic",
            State::WaitingForAnnounces => "WaitingForAnnounces",
            State::KeygenAwaitingShares => "KeygenAwaitingShares",
            State::KeygenAwaitingSessionHash => "KeygenAwaitingSessionHash",
            State::KeygenAwaitingAcks => "KeygenAwaitingAcks",
            State::KeygenAwaitingDeviceSave => "KeygenAwaitingDeviceSave",
            State::KeygenAwaitingHeldShares => "KeygenAwaitingHeldShares",
            State::NonceReplenish => "NonceReplenish",
            State::SigningAwaitingShares => "SigningAwaitingShares",
            State::BackupReveal => "BackupReveal",
            State::BackupQuiz => "BackupQuiz",
            State::BackupIngest => "BackupIngest",
            State::BackupConsolidate => "BackupConsolidate",
            State::EraseRefusal => "EraseRefusal",
        }
    }

    /// The watchdog thread's read: it holds only the `usize` [`State::publish`] stored, so
    /// this is where that integer becomes a state again.
    ///
    /// `Option` and not an index: a value that is not a state used to be an out-of-bounds
    /// panic IN THE WATCHDOG THREAD, which would have taken the 95 s bound down silently
    /// and left the harness free to hang past it — a fail-open on the one guard that exists
    /// because the loop can get stuck outside its own deadline check.
    fn from_index(i: usize) -> Option<State> {
        // Walked rather than transmuted, over the same exhaustive list `name` uses, so a
        // new variant that is not added here is missing from the walk and nowhere else.
        [
            State::WaitingForMagic,
            State::WaitingForAnnounces,
            State::KeygenAwaitingShares,
            State::KeygenAwaitingSessionHash,
            State::KeygenAwaitingAcks,
            State::KeygenAwaitingDeviceSave,
            State::KeygenAwaitingHeldShares,
            State::NonceReplenish,
            State::SigningAwaitingShares,
            State::BackupReveal,
            State::BackupQuiz,
            State::BackupIngest,
            State::BackupConsolidate,
            State::EraseRefusal,
        ]
        .into_iter()
        .find(|s| *s as usize == i)
    }


    /// Publish for the watchdog, which cannot see the local variable.
    fn publish(self) {
        STATE.store(self as usize, Ordering::Relaxed);
    }

    /// CUMULATIVE, because it is compared against `started.elapsed()`: each phase
    /// adds its own budget on top of the ones before it, so the handshake keeps
    /// M2's 5 s exactly and keygen's mutations keep dying at 35 s.
    fn budget(self) -> Duration {
        let base = match self {
            State::WaitingForMagic | State::WaitingForAnnounces => HANDSHAKE_DEADLINE,
            State::NonceReplenish | State::SigningAwaitingShares => {
                HANDSHAKE_DEADLINE + KEYGEN_DEADLINE + SIGN_DEADLINE
            }
            State::BackupReveal
            | State::BackupQuiz
            | State::BackupIngest
            | State::BackupConsolidate
            | State::EraseRefusal => {
                HANDSHAKE_DEADLINE + KEYGEN_DEADLINE + SIGN_DEADLINE + RESTORE_DEADLINE
            }
            _ => HANDSHAKE_DEADLINE + KEYGEN_DEADLINE,
        };
        // Step 6. `* 1` by default, so every number above and every measurement in
        // the header stands.
        base * timeout_scale()
    }

    /// The largest cumulative budget any state has, i.e. what the once-per-pass
    /// watchdog is set from.
    ///
    /// A named function rather than the last variant spelled at the call site, because
    /// spelling it there is how the watchdog got set from `SigningAwaitingShares` and
    /// then silently fired 30 s early the moment a later phase existed.
    ///
    /// [`State::EraseRefusal`] TIES with this one — it shares the restoration budget on
    /// purpose — so this is still the true maximum and the number is unmoved at 95 s.
    fn longest() -> Duration {
        State::BackupConsolidate.budget()
    }
}

static STATE: AtomicUsize = AtomicUsize::new(0);
/// Millis since process start at which the watchdog should give up. 0 = idle.
static WATCHDOG_AT_MS: AtomicU64 = AtomicU64::new(0);

/// Millis since process start at which the writer thread entered the `raw_send`
/// it is currently inside. 0 = idle, i.e. every queued frame is on the wire.
static WRITE_BUSY_SINCE_MS: AtomicU64 = AtomicU64::new(0);
/// Largest coordinator->device frame actually put on the wire, in bytes.
///
/// This exists because every downstream figure was ARITHMETIC: the harness logged
/// `msg.gist()` and never a size, so "nothing over 1 KB has crossed
/// coordinator->device" was an inference. It is now measured, and it was WRONG once
/// N_DEVICES reached 9: `CertifyPlease` = 2,179 B and `Check` = 1,624 B cross every
/// run, matching PLAN.md §7's formulas to the byte.
static MAX_DOWN_B: AtomicUsize = AtomicUsize::new(0);

/// Frames that completed `raw_send`. Per pass; reset by `one_pass`.
static WRITES_DONE: AtomicUsize = AtomicUsize::new(0);
/// The writer thread's dying words, since it cannot return a `Result` to the loop.
static WRITE_ERR: Mutex<Option<String>> = Mutex::new(None);

/// The write half of the harness: a thread, a `dup`, and upstream's real encoder.
///
/// The frame type is `ReceiveSerial<Upstream>` because that is what `raw_send`
/// takes, and it covers both things this harness sends -- so magic bytes and
/// message frames go out through ONE queue, in order, from ONE fd. That ordering
/// is not a nicety: two `FramedSerialPort`s writing the same fd would interleave
/// bytes mid-frame, which is why the caller's port must never write again.
///
/// `raw_send` rather than `queue_send`+`poll_send` is the same bytes: with conch
/// disabled (it is -- the device signals version 2) `poll_send` is exactly
/// `raw_send(Message(..))`, and `write_magic_bytes` is exactly
/// `raw_send(MagicBytes(..))`. Upstream still does all the encoding and all the
/// writing; what changed is which thread it blocks.
///
/// The channel is unbounded, which is not the sloppy choice here: a bounded queue
/// would have to block or drop when full, and blocking is the thing being fixed.
/// Depth stays in single digits (keygen queues at most n+1 frames) and it is
/// reported in the deadline message, so a growing queue is visible.
fn spawn_writer(port: TTYPort, t0: Instant) -> Sender<ReceiveSerial<Upstream>> {
    let (tx, rx) = std::sync::mpsc::channel::<ReceiveSerial<Upstream>>();
    std::thread::spawn(move || {
        let mut port: FramedSerialPort<Downstream> =
            FramedSerialPort::new(Box::new(port) as Box<dyn SerialPort>);
        // Ends when the sender drops -- unless parked in `raw_send`, in which case
        // this thread leaks. Deliberate: see WRITE_STALL_LIMIT.
        for frame in rx {
            // Encode a throwaway copy purely to size it, with the same
            // `BINCODE_CONFIG` upstream's `raw_send` uses -- so this is the byte
            // count that lands on the wire, not an estimate.
            if let Ok(bytes) = bincode::encode_to_vec(&frame, BINCODE_CONFIG) {
                MAX_DOWN_B.fetch_max(bytes.len(), Ordering::Relaxed);
                if bytes.len() > 1024 {
                    eprintln!("hostcheck: -> {} B downstream frame", bytes.len());
                }
            }
            WRITE_BUSY_SINCE_MS.store((t0.elapsed().as_millis() as u64).max(1), Ordering::Relaxed);
            let result = port.raw_send(frame);
            WRITE_BUSY_SINCE_MS.store(0, Ordering::Relaxed);
            match result {
                Ok(()) => WRITES_DONE.fetch_add(1, Ordering::Relaxed),
                Err(e) => {
                    *WRITE_ERR.lock().unwrap() = Some(e.to_string());
                    return;
                }
            };
        }
    });
    tx
}

/// Hand one frame to the writer thread. Cannot block; fails only if that thread
/// is gone, which only happens after it has recorded why.
fn send_frame(tx: &Sender<ReceiveSerial<Upstream>>, frame: ReceiveSerial<Upstream>) -> Result<()> {
    tx.send(frame).map_err(|_| {
        anyhow::anyhow!(
            "writer thread is gone: {}",
            WRITE_ERR
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| "no error recorded".into())
        )
    })
}

/// A read timeout is `bincode::error::DecodeError::Io` wrapping
/// `ErrorKind::TimedOut`. It means "nothing more arrived within PORT_TIMEOUT",
/// which for us is not an error but the deadline's tick: keep looping.
///
/// It does NOT mean the stream is recoverable. Whatever bincode already consumed
/// of a partial frame is gone, so the stream is desynced and the run is
/// doomed -- it just now dies on the deadline, promptly and with a state name,
/// instead of surfacing as a mystery decode error.
fn is_read_timeout(e: &bincode::error::DecodeError) -> bool {
    matches!(e, bincode::error::DecodeError::Io { inner, .. }
        if inner.kind() == std::io::ErrorKind::TimedOut)
}

/// Everything the keygen drive needs to remember between laps.
struct Keygen {
    id: KeygenId,
    got_shares: usize,
    acks: usize,
    /// The hash a human compares on the device screens.
    session_hash: Option<SessionHash>,
    /// The completion value, straight out of `finalize_keygen`.
    finished: Option<AccessStructureRef>,
}

/// M5 state. Separate from `Keygen` rather than merged into it because the two
/// phases share nothing: keygen is done and asserted on before any of this starts.
#[derive(Default)]
struct Sign {
    /// `OpenNonceStreams` has been queued (once, for all devices).
    requested_nonces: bool,
    /// Devices whose `NonceResponse` the coordinator ACCEPTED -- i.e. it emitted
    /// `ReplenishedNonces`, which it only does for a segment that extends a stream
    /// it actually opened.
    replenished: std::collections::BTreeSet<DeviceId>,
    /// `Some` once `start_sign` succeeded; that call is also the real check that
    /// the nonces landed (`StartSignError::NotEnoughNoncesForDevice`).
    session_id: Option<SignSessionId>,
    /// The threshold subset asked to sign -- 2 of the 3, so the run also proves
    /// the third device is not needed.
    signers: std::collections::BTreeSet<DeviceId>,
    got_shares: std::collections::BTreeSet<DeviceId>,
    /// The aggregated signatures, decoded. Set from the coordinator's `Signed`
    /// message; VERIFIED (not merely present) before the pass returns.
    signatures: Option<Vec<Signature>>,
}

// ===========================================================================
// M7 — the restoration, backup and consolidation flows, from a REAL coordinator
// ===========================================================================

/// M7's phases, in the only order they can run.
///
/// The order is NOT a preference and is the first of the five traps the M7 brief
/// names: at `t == n == 9` every device is needed to sign, so [`Phase::Ingest`] and
/// [`Phase::Consolidate`] cannot precede the signature — consolidation REPLACES the
/// one share record this device keeps, and a signing pass needs the share that record
/// holds. So the whole of this enum runs after `Sign::signatures` is `Some`.
///
/// [`Phase::Quiz`] after [`Phase::Reveal`] and [`Phase::Ingest`] after both is a data
/// dependency and not merely tidiness: the device answers the quiz and drives the
/// letter picker from the 25 words its own REVEAL drew, so those two flows have
/// nothing to work from until the reveal has happened.
/// M9's addition, [`Phase::Erase`], is the exception to the paragraph above: upstream's
/// `EraseDevice` needs no keygen state, no share and no reveal, so its position is a
/// choice rather than a dependency. It goes FIRST, and that is the choice: if this device
/// ever DID obey a `DataErase`, the share every phase below reads would be gone and all
/// four of them would fail too — so the refusal gets corroborated by the rest of the pass
/// and not only by the `Debug` line it prints.
///
/// M12's SECOND leg does not start at [`Phase::Erase`], and where it does start is
/// [`Restore::new`]'s `start` parameter rather than a constant here. That leg runs at the
/// BLANK device, which holds no share, so the first three phases are all impossible for
/// it — see that parameter's doc for which process refuses each and why. It enters at
/// [`Phase::Ingest`], types in 25 words off ANOTHER device's sheet, and finishes through
/// the same [`Phase::Consolidate`] / [`Phase::Reheld`] pair. No `State` variant was added
/// for it: `Phase::state()` maps it onto the states leg 1 already uses, so
/// `State::budget` and `State::longest()` are untouched at 95 s and the stub's 240 s
/// DEADLINE keeps its documented ~2.53x ratio.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// M9: upstream's `EraseDevice`, which must NEVER reach `Completion::Success`.
    Erase,
    /// M7b: `DisplayBackupProtocol`.
    Reveal,
    /// M7c: `CheckBackupProtocol`.
    Quiz,
    /// M7d: `EnterPhysicalBackup`, then `SavePhysicalBackup2`.
    Ingest,
    /// M11: the device REPORTS the saved backup, so the threshold the LEGACY v1 frame
    /// carried can be read back off the wire. Between [`Phase::Ingest`] and
    /// [`Phase::Consolidate`] and not after, because consolidating DELETES the record
    /// this reads: the `SaveShare` mutation calls `remove_backups_with_share_image`
    /// (`vendor/.../device.rs`), so `Phase::Reheld`'s existing `request_held_shares`
    /// is far too late.
    ///
    /// Only entered when the pass is driving v1 — see `save_v1` on [`one_pass`].
    SavedV1,
    /// M7e: `Consolidate`. DESTRUCTIVE, hence last.
    Consolidate,
    /// M7e's proof: the device reports what it holds, AGAIN, after the write that
    /// replaced its record. A `FinishedConsolidation` on its own says the device
    /// applied the mutation; this says the SIGNER'S STATE after it agrees with this
    /// coordinator's own polynomial at this device's index.
    ///
    /// **NOT a flash read-back, and this doc claimed it was until 2026-09-12.** It read
    /// "this says the record it wrote is one it can read back". `RequestHeldShares` is
    /// answered from `held_shares()`, which iterates the signer's in-RAM `keys`
    /// (`vendor/.../device/restoration.rs`), our arm for it is a pass-through, and the
    /// stub's only restart is PRE-KEYGEN — so no flash read happens between the
    /// consolidation and this report. The flash half is covered at Tier 1 by
    /// `consolidation_persists_the_share_before_it_acks`, which reopens the store after
    /// a real reset; this is the wire half and it is worth having for what it does
    /// compare, which is the signer against the coordinator across two processes.
    Reheld,
    Done,
}

impl Phase {
    fn state(self) -> State {
        match self {
            Phase::Erase => State::EraseRefusal,
            Phase::Reveal => State::BackupReveal,
            Phase::Quiz => State::BackupQuiz,
            // `SavedV1` shares `BackupIngest`'s state deliberately: it is the tail of
            // the same ingest, and a new `State` variant would move `State::longest()`
            // and with it the stub's documented ~2.5x watchdog ratio. Adding one is at
            // least safe now -- `State::name` and `State::from_index` are exhaustive, so
            // it is `error[E0004]` rather than a runtime panic -- but it is still churn
            // this phase does not need.
            Phase::Ingest | Phase::SavedV1 => State::BackupIngest,
            Phase::Consolidate | Phase::Reheld | Phase::Done => State::BackupConsolidate,
        }
    }
}

/// M7 state. Separate from [`Sign`] for [`Sign`]'s own reason: the signature is done
/// and VERIFIED before any of this starts, and nothing here can move it.
struct Restore {
    /// The one device all four flows are driven at. One and not nine, deliberately:
    /// these flows are about the device's dispatch, consent gate and UI, and running
    /// them nine times would multiply the wall clock without adding a claim.
    device: DeviceId,
    /// That device's share index in the finished access structure, out of the
    /// coordinator's own `device_to_share_indicies`. `CheckBackupProtocol` matches its
    /// ack against it, and M7b's `ShareBackup::from_words` needs it.
    share_index: ShareIndex,
    /// The digest that device ANNOUNCED, for the `FirmwareVersion` handed to
    /// `CheckBackupProtocol`. See [`CHECK_BACKUP_SINCE`].
    digest: Sha256Digest,
    phase: Phase,
    /// Has this phase's driver been constructed and `connected()` yet? Trap 4:
    /// `EnterPhysicalBackup` sends NOTHING until `connected()` has been called on it.
    started: bool,
    /// M7b, off the `Debug` back-channel: the share index the device's page 0 DREW.
    glass_index: Option<u32>,
    /// M7b: 1-based position -> the word the device's glass drew at it, recovered over
    /// there with the shipped `ui::Frame::cell`.
    glass_words: BTreeMap<usize, String>,
    /// M7b's completion, and the reason this is an `Arc<AtomicBool>` rather than a
    /// read of the driver.
    ///
    /// **`DisplayBackupProtocol::is_complete()` NEVER returns `Completion::Success`**
    /// — it is `Some` only on `abort` (`display_backup.rs:60-68`). On
    /// `CommsMisc::BackupRecorded` it only pushes `DisplayBackupState { confirmed:
    /// true, close_dialog: true }` into its sink, and every field of that driver is
    /// private with no accessor. So the sink is the ONLY observable, and the M7 brief's
    /// "pass `()` and read state off the concrete protocol type" cannot be done for
    /// this one driver. This is upstream's own `Sink::inspect` combinator over the `()`
    /// blanket impl, which is the whole adapter — no new trait impl, no new type.
    recorded: Arc<AtomicBool>,
    /// M7c: the device's own count of quiz answers, off the `Debug` channel. A pass in
    /// exactly `quiz::QUIZ_POSITIONS` answers means every one was right first time.
    quiz_answers: Option<usize>,
    /// M7c: `CommsMisc::BackupChecked` arrived AND `CheckBackupProtocol` claimed it,
    /// which it only does when the ack's `(access_structure_ref, share_index)` pair is
    /// the one it asked about (`check_backup.rs:136-156`).
    checked: bool,
    /// M7d: `EnterPhysicalBackup`'s sink, which is where its `PhysicalBackupPhase`
    /// comes from — its fields are private, but `EnterPhysicalBackupState`'s are not.
    ingest: Arc<Mutex<Option<EnterPhysicalBackupState>>>,
    /// M7d: the phase the device answered with, once seen.
    entered: Option<PhysicalBackupPhase>,
    /// M7e: `FinishedConsolidation` reached the user layer.
    consolidated: bool,
    /// M7e: the device reported holding the access structure again, after the write.
    reheld: bool,
    /// M7d, for the log: how many keypresses the letter picker took.
    typed: Option<usize>,
    /// M11: the `threshold` the device REPORTS for the saved backup, once it has
    /// reported one. `Some(None)` is a device that answered with no threshold, which is
    /// what a v2 in this slot looks like, so the two are distinguished rather than
    /// collapsed.
    ///
    /// `Option<Option<u16>>` and not `Option<u16>`: the outer layer is "has the device
    /// answered yet", the inner is what it said. Flattening them would make a device
    /// that has not answered indistinguishable from one that answered `None`, and the
    /// second is the failure this field exists to catch.
    saved_v1_threshold: Option<Option<u16>>,
    /// M9: when upstream's `EraseDevice` was opened, i.e. when [`ERASE_GRACE`] starts.
    erase_at: Option<Instant>,
    /// M9: `refused=DataErase` frames from [`Restore::device`] seen **while
    /// [`Phase::Erase`] is live**, and the scoping is the whole point.
    ///
    /// The `refused_erase` SET in `one_pass` cannot be used for this: every device is
    /// already in it from the forged frame sent long before the signature exists, so a
    /// `contains` here would be an assertion that cannot fail — coverage-shaped and
    /// worth nothing. Counting only what arrives during this phase makes it a fact about
    /// the frame UPSTREAM'S DRIVER sent.
    ///
    /// The `phase == Phase::Erase` half of that guard is BELT, and measured to be: this
    /// whole struct is `None` until a signature exists, which is already after the forged
    /// frame, so dropping the phase test leaves the run green and the count at 1. It is
    /// kept because it is what makes the scoping true by construction rather than by the
    /// current position of one other block.
    erase_refusals: usize,
}

impl Restore {
    /// `start` is a parameter and not a constant because M12's leg starts at
    /// [`Phase::Ingest`], never at [`Phase::Erase`] or [`Phase::Reveal`]. Both of those
    /// are impossible for a device holding no share, and BOTH fail in THIS process
    /// rather than on the device — `DisplayBackupProtocol::new` and
    /// `CheckBackupProtocol::new` go through `request_device_{display,check}_backup`,
    /// whose `device_to_share_index.get(..).ok_or(ActionError::StateInconsistent("device
    /// does not have share in key"))` is coordinator-side and sends no frame at all.
    /// MEASURED by starting leg 2 at `Phase::Reveal`: `M7 Reveal: DisplayBackupProtocol
    /// ::new: StateInconsistent("device does not have share in key")`, exit 1. PLAN.md
    /// records this refusal as `Fault::Signer` and the stub's `die(2)`; the device-side
    /// refusals exist but are UNREACHABLE from here.
    ///
    /// `Phase::Erase` is additionally ruled out by an exact count: `refused_erase.len()
    /// != N_DEVICES` at PASS, and driving `EraseDevice` at a tenth device adds a tenth
    /// `refused=DataErase`.
    fn new(device: DeviceId, share_index: ShareIndex, digest: Sha256Digest, start: Phase) -> Self {
        Restore {
            device,
            share_index,
            digest,
            phase: start,
            started: false,
            glass_index: None,
            glass_words: BTreeMap::new(),
            recorded: Arc::new(AtomicBool::new(false)),
            quiz_answers: None,
            checked: false,
            ingest: Arc::new(Mutex::new(None)),
            entered: None,
            consolidated: false,
            reheld: false,
            typed: None,
            saved_v1_threshold: None,
            erase_at: None,
            erase_refusals: 0,
        }
    }

    /// Retire the current driver and move on.
    fn advance(&mut self, ui: &mut Option<Box<dyn UiProtocol>>, next: Phase) {
        *ui = None;
        self.started = false;
        self.phase = next;
    }
}

/// The 25 words the device's GLASS drew, checked three ways.
///
/// This is M7b's assertion and the strongest one in the phase, because it closes a
/// loop through two processes and two independent builds of `frost_backup`:
///
///  1. the device decrypted its own stored share, `frost_backup::ShareBackup::to_words`
///     packed it, `ui::BackupPages::render` drew it, and
///     `ui::Frame::mark_sensitive` noised the same rows;
///  2. the stub read the words back OUT OF THE PIXELS with `ui::Frame::cell` — the
///     exact inverse of the `text` that drew them, not a second implementation of the
///     font — and put them on the `Debug` back-channel;
///  3. this process re-packs them with UPSTREAM's `ShareBackup::from_words` and
///     compares the resulting `share_image` against its own
///     `expected_share_image`, which comes from the coordinator's `root_shared_key`
///     and never from anything the device said.
///
/// Note what the coordinator cannot do and this therefore does not claim: it holds no
/// copy of the device's secret share (`root_shared_key` is the PUBLIC point
/// polynomial, and the coordinator sends only a decryption *contribution*), so it
/// cannot compute the 25 words itself and compare them word for word. The share IMAGE
/// is the strongest thing it can check — and it is enough: a single wrong word fails
/// `from_words`' 11-bit word checksum, and a word list that passes the checksum but
/// encodes a different scalar produces a different image.
///
/// The two weaker checks run first because they NAME the failure: "word 17 is not a
/// BIP39 word" localises a font or layout defect that "the share image does not match"
/// only reports.
fn check_glass_words(
    coordinator: &FrostCoordinator,
    r: &Restore,
    as_ref: AccessStructureRef,
) -> Result<()> {
    // 1. Twenty-five words, at positions 1..=25 and no others.
    let missing: Vec<usize> = (1..=frost_backup::NUM_WORDS)
        .filter(|n| !r.glass_words.contains_key(n))
        .collect();
    if !missing.is_empty() || r.glass_words.len() != frost_backup::NUM_WORDS {
        bail!(
            "the reveal put {} word(s) on {}'s glass, not {}: positions {missing:?} were never \
             drawn (got {:?})",
            r.glass_words.len(),
            r.device,
            frost_backup::NUM_WORDS,
            r.glass_words.keys().collect::<Vec<_>>()
        );
    }
    // 2. Every one of them a word of the vendored list, NAMED on failure. `BIP39_WORDS`
    //    is uppercase and `to_words()` returns entries of it, so this is also the check
    //    that the glyphs came back in the case they were drawn in.
    for (number, word) in &r.glass_words {
        if !BIP39_WORDS.contains(&word.as_str()) {
            bail!(
                "word {number} on {}'s glass reads {word:?}, which is not one of the {} BIP39 \
                 words -- a layout or font defect, not a crypto one",
                r.device,
                BIP39_WORDS.len()
            );
        }
    }
    // 3. THE SHARE IMAGE. Upstream's own decoder, on the words the pixels gave up,
    //    against the coordinator's own polynomial.
    let index = r.glass_index.with_context(|| {
        format!("{}'s reveal never drew a `#N` share index page", r.device)
    })?;
    let ordered: Vec<&str> = r.glass_words.values().map(String::as_str).collect();
    let words: [&str; frost_backup::NUM_WORDS] = ordered
        .try_into()
        .map_err(|_| anyhow::anyhow!("exactly {} words, just checked", frost_backup::NUM_WORDS))?;
    let backup = ShareBackup::from_words(index, words)
        .map_err(|e| anyhow::anyhow!("the 25 words on {}'s glass do not decode: {e}", r.device))?;
    let want = coordinator
        .expected_share_image(as_ref, r.share_index, ENCRYPTION_KEY)
        .with_context(|| format!("no expected share image for {:?}", r.share_index))?;
    if backup.share_image() != want {
        bail!(
            "SHARE IMAGE MISMATCH: the 25 words {} put ON THE GLASS re-encode to share image {:?} \
             at index {index}, but this coordinator's root shared key says {want:?} -- the device \
             drew a backup that is not the share it holds",
            r.device,
            backup.share_image(),

        );
    }
    Ok(())
}

/// Rewrite a `SavePhysicalBackup2` send as the LEGACY v1 body, keeping its
/// `share_image` and its destinations.
///
/// Anything else passes through UNCHANGED, deliberately: a future upstream that returns a
/// second send from `tell_device_to_save_physical_backup` keeps it, where a
/// drop-and-forge would silently lose it. And a v2 that stopped being the body it returns
/// would leave this a no-op rather than a forgery of the wrong thing — which the M11
/// threshold assertion then FAILS on, by name, instead of passing quietly.
///
/// The three synthesised fields are the harness's own and cannot be otherwise: nothing
/// upstream constructs a v1, so there is no upstream value to borrow. See
/// [`V1_THRESHOLD`] for why the threshold is 7 and why it is safe to choose.
fn downgrade_save(send: CoordinatorSend) -> CoordinatorSend {
    match send {
        CoordinatorSend::ToDevice {
            message:
                CoordinatorToDeviceMessage::Restoration(
                    CoordinatorRestoration::SavePhysicalBackup2(held),
                ),
            destinations,
        } => CoordinatorSend::ToDevice {
            message: CoordinatorToDeviceMessage::Restoration(
                CoordinatorRestoration::SavePhysicalBackup {
                    share_image: held.share_image,
                    key_name: RESTORE_KEY_NAME.to_string(),
                    purpose: KeyPurpose::Test,
                    threshold: V1_THRESHOLD,
                },
            ),
            destinations,
        },
        other => other,
    }
}

/// One lap of the M7 drive: build the phase's driver if it has none, then check
/// whether the phase has proven itself and move on.
///
/// One boxed [`UiProtocol`] at a time and deliberately no `UiStack`: the stack exists
/// so a real app can have a keygen and a firmware upgrade in flight at once, and it
/// routes every message to every protocol until one claims it. Here exactly one flow
/// is live at any moment, so a stack would add a dispatch layer between the wire and
/// the driver under test and prove nothing about either.
///
/// `poll()`'s frames are NOT sent from here — the caller owns `wtx` — so this function
/// is where the phase logic lives and nowhere else.
fn restore_step(
    coordinator: &mut FrostCoordinator,
    queue: &mut VecDeque<CoordinatorSend>,
    rng: &mut ChaCha20Rng,
    ui: &mut Option<Box<dyn UiProtocol>>,
    r: &mut Restore,
    as_ref: AccessStructureRef,
    save_v1: bool,
) -> Result<()> {
    // A driver that ABORTED is a failure of the phase and not a quiet ending: every
    // one of the three aborts on `disconnected`, which for this harness means the pty
    // closed under it.
    if let Some(Completion::Abort {
        send_cancel_to_all_devices,
    }) = ui.as_ref().and_then(|p| p.is_complete())
    {
        bail!(
            "the {:?} driver ABORTED (send_cancel_to_all_devices={send_cancel_to_all_devices}) -- \
             it only does that on `cancel()` or `disconnected()`, and this harness calls neither",
            r.phase
        );
    }
    let done = |p: &Option<Box<dyn UiProtocol>>| {
        matches!(
            p.as_ref().and_then(|p| p.is_complete()),
            Some(Completion::Success)
        )
    };

    match r.phase {
        // ============================== M9 ==============================
        // THE ONE FLOW WHOSE CORRECT BEHAVIOUR IS TO HANG, which is exactly why it needs
        // an explicit assertion: without one it proves nothing, because a driver that
        // never completes is indistinguishable from a harness that forgot to drive it.
        //
        // `EraseDevice::poll` sends `CoordinatorSendBody::DataErase` on its FIRST poll
        // and reaches `Completion::Success` only on `CommsMisc::EraseConfirmed`
        // (`erase_device.rs:44-48`, `:66-73`). This device never sends that:
        // `Session::recv` answers `Err(Fault::Refused(Refusal::DataErase))`. So
        // upstream's completion path is UNREACHABLE here — an app offering "erase this
        // device" would sit on that dialog forever, which is the correct outcome for a
        // unit whose shares cannot be reconstructed on this port.
        //
        // DIFFERENT from the forged `DataErase` in the loop above, and the difference is
        // the claim: that frame is HAND-ROLLED here and pushed straight through
        // `send_frame`, so it proves the DEVICE refuses the body. This drives UPSTREAM'S
        // OWN DRIVER through the same five-call seam M7 uses, so it proves the
        // COORDINATOR-side flow cannot complete against this device. Neither subsumes
        // the other: a device could refuse a raw frame and still confirm one that
        // arrived from the real driver, and the driver could have a completion path this
        // device satisfies some other way.
        Phase::Erase => {
            if !r.started {
                r.started = true;
                // `()` for the sink: `EraseDeviceState` only ever says what this process
                // already knows by having polled — `WaitingForConfirmation` is pushed by
                // `poll` itself — and the two facts this phase asserts are
                // `is_complete()` and what came back on the wire.
                *ui = Some(Box::new(EraseDevice::new(r.device, ())));
                // A documented no-op for THIS driver (`UiProtocol::connected`'s default
                // body is empty and `EraseDevice` does not override it), unlike M7d
                // where trap 4 bites. Kept so all five arms drive the identical
                // lifecycle, which is the seam being tested.
                if let Some(p) = ui.as_mut() {
                    p.connected(r.device, DeviceMode::Ready);
                }
                r.erase_at = Some(Instant::now());
                eprintln!(
                    "hostcheck: M9 -- driving UPSTREAM's EraseDevice at {}; it must NEVER \
                     complete",
                    r.device
                );
            }
            // HALF ONE. Nothing but `CommsMisc::EraseConfirmed` can produce this, and the
            // `Completion::Abort` arm at the top of this function covers the other half
            // of `is_complete()`.
            if done(ui) {
                bail!(
                    "ERASE COMPLETED: upstream's EraseDevice reached Completion::Success at \
                     {}, which it only does on CommsMisc::EraseConfirmed -- this device \
                     answered a DataErase it is supposed to refuse outright",
                    r.device
                );
            }
            let waited = r
                .erase_at
                .expect("set on the same lap the driver is built")
                .elapsed();
            if waited > ERASE_GRACE * timeout_scale() {
                // HALF TWO, and BOTH halves are load-bearing: "never completed" is also
                // what a DEAD device looks like, and a refusal line on its own does not
                // prove the driver stayed open.
                if r.erase_refusals == 0 {
                    bail!(
                        "{} left upstream's EraseDevice open for {waited:?} without ever \
                         reporting `refused=DataErase` -- silence is not a refusal, it is \
                         what a dead device looks like, so this proves nothing about the \
                         erase path",
                        r.device
                    );
                }
                eprintln!(
                    "hostcheck: M9 PASS -- {} REFUSED the driver's DataErase ({} time(s)) and \
                     EraseDevice stayed at is_complete()==None for {waited:?}",
                    r.device, r.erase_refusals
                );
                r.advance(ui, Phase::Reveal);
            }
        }

        // ============================== M7b ==============================
        Phase::Reveal => {
            if !r.started {
                r.started = true;
                let recorded = Arc::clone(&r.recorded);
                let proto = DisplayBackupProtocol::new(
                    coordinator,
                    r.device,
                    as_ref,
                    ENCRYPTION_KEY,
                    // Upstream's own combinator over the `()` blanket impl. See
                    // `Restore::recorded` for why a sink is unavoidable here.
                    Sink::<DisplayBackupState>::inspect((), move |state: &DisplayBackupState| {
                        if state.confirmed {
                            recorded.store(true, Ordering::Relaxed);
                        }
                    }),
                )
                .context("DisplayBackupProtocol::new")?;
                eprintln!(
                    "hostcheck: M7b -- asking {} to REVEAL its backup (share index {:?})",
                    r.device, r.share_index
                );
                *ui = Some(Box::new(proto));
                // Trap 4's rule applied uniformly rather than only where it bites:
                // `EnterPhysicalBackup` will not send without it, and for the other two
                // it is what the real driver does anyway (`should_send = true`).
                if let Some(p) = ui.as_mut() {
                    p.connected(r.device, DeviceMode::Ready);
                }
            }
            if r.recorded.load(Ordering::Relaxed) {
                check_glass_words(coordinator, r, as_ref)?;
                eprintln!(
                    "hostcheck: M7b PASS -- {} words off {}'s GLASS re-encode to this \
                     coordinator's own expected share image, and `BackupRecorded` closed the \
                     driver's dialog",
                    r.glass_words.len(),
                    r.device
                );
                r.advance(ui, Phase::Quiz);
            }
        }

        // ============================== M7c ==============================
        Phase::Quiz => {
            if !r.started {
                r.started = true;
                // TRAP 2, made a decision instead of an accident. See CHECK_BACKUP_SINCE.
                let firmware = FirmwareVersion {
                    digest: r.digest,
                    version: Some(CHECK_BACKUP_SINCE),
                };
                if !firmware.features().check_backup {
                    bail!(
                        "declared firmware {} does not have the check_backup feature, so \
                         CheckBackupProtocol would silently drive the LEGACY physical-backup path \
                         and the quiz would never run",
                        firmware.version_name()
                    );
                }
                let proto = CheckBackupProtocol::new(
                    coordinator,
                    r.device,
                    as_ref,
                    r.share_index,
                    ENCRYPTION_KEY,
                    firmware,
                    // `()`: this driver's completion IS `is_complete() == Success`
                    // (`check_backup.rs:108-118`), so there is nothing to read off a
                    // sink and no adapter to write.
                    (),
                )
                .context("CheckBackupProtocol::new")?;
                eprintln!(
                    "hostcheck: M7c -- asking {} to sit the CHECK QUIZ on the same share, \
                     declared firmware {}",
                    r.device,
                    firmware.version_name()
                );
                *ui = Some(Box::new(proto));
                if let Some(p) = ui.as_mut() {
                    p.connected(r.device, DeviceMode::Ready);
                }
            }
            if done(ui) {
                if !r.checked {
                    bail!(
                        "CheckBackupProtocol completed but this loop never saw \
                         CommsMisc::BackupChecked from {} -- the driver was fed something else",
                        r.device
                    );
                }
                r.advance(ui, Phase::Ingest);
            }
        }

        // ============================== M7d ==============================
        Phase::Ingest => {
            if !r.started {
                r.started = true;
                let state = Arc::clone(&r.ingest);
                let proto = EnterPhysicalBackup::new(
                    // A sink again, and for a different reason than M7b's: this
                    // driver's `is_complete()` DOES report success, but the
                    // `PhysicalBackupPhase` it saw is private, and
                    // `check_physical_backup` needs it. `EnterPhysicalBackupState`'s
                    // fields are public, so the sink hands it over.
                    Sink::<EnterPhysicalBackupState>::inspect(
                        (),
                        move |seen: &EnterPhysicalBackupState| {
                            *state.lock().expect("sink mutex") = Some(seen.clone());
                        },
                    ),
                    r.device,
                );
                *ui = Some(Box::new(proto));
                // TRAP 4, and this is the one it bites on: `EnterPhysicalBackup::poll`
                // returns an EMPTY vec until `connected()` has been called
                // (`enter_physical_backup.rs:71-85`), so without this line the device
                // is never asked for anything and the phase hangs to its deadline.
                if let Some(p) = ui.as_mut() {
                    p.connected(r.device, DeviceMode::Ready);
                }
                eprintln!(
                    "hostcheck: M7d -- asking {} to TYPE the same 25 words back in through the \
                     letter picker",
                    r.device
                );
            }
            let seen = r.ingest.lock().expect("sink mutex").clone();
            if let Some(abort) = seen.as_ref().and_then(|s| s.abort.clone()) {
                bail!("the EnterPhysicalBackup driver aborted: {abort}");
            }
            if r.entered.is_none() {
                if let Some(phase) = seen.and_then(|s| s.entered) {
                    // THE COORDINATOR'S OWN SHARE-IMAGE COMPARISON. `Ok` means the
                    // point the device derived from the 25 words a human typed equals
                    // the one this coordinator's root shared key implies at that index;
                    // `Err(ShareImageIsWrong)` is the whole failure mode this flow
                    // exists to catch.
                    let index = coordinator
                        .check_physical_backup(as_ref, phase, ENCRYPTION_KEY)
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "check_physical_backup on the share {} TYPED BACK IN: {e:?} -- the \
                                 letter picker and the reveal disagree, or the words are not this \
                                 device's share",
                                r.device
                            )
                        })?;
                    // A BOUND on data flowing into a destructive write, not a
                    // demonstrated assertion, and it is honest about which. Every
                    // one-line corruption of the typed words fails in
                    // `check_physical_backup` first and with a better message:
                    // that call takes the index FROM `phase.backup.share_image.index`
                    // — the device's own claim — and then requires
                    // `root_shared_key.share_image(that)` to equal the typed image,
                    // so a wrong index with a right scalar is `ShareImageIsWrong`.
                    // The only thing that reaches here is handing over the WRONG
                    // SHEET, which needs a second reveal in the room to be possible
                    // at all (see `sheet_read` in the stub, whose two-or-more arm
                    // refuses rather than picking).
                    //
                    // M12 changed the WORDING and not the guard: for the blank device
                    // `r.share_index` is not an index it holds, it is the index of the
                    // share it is being GIVEN on paper.
                    if index != r.share_index {
                        bail!(
                            "{} typed in a share at index {index:?}, not the {:?} on the sheet it \
                             was handed",
                            r.device,
                            r.share_index
                        );
                    }
                    eprintln!(
                        "hostcheck: M7d -- the share {} TYPED matches this coordinator's expected \
                         image at index {index:?}; telling it to save",
                        r.device
                    );
                    r.entered = Some(phase);
                    // See RESTORE_KEY_NAME: `PhysicalBackupSaved` -- and therefore this
                    // driver's only route to `Completion::Success` -- needs a
                    // RestorationId, and only `start_restoring_key` makes one usable.
                    let restoration_id = RestorationId::new(rng);
                    coordinator.start_restoring_key(
                        RESTORE_KEY_NAME.to_string(),
                        Some(THRESHOLD),
                        KeyPurpose::Test,
                        restoration_id,
                    );
                    // ============================== M11 ==============================
                    // The LEGACY v1 body, on the passes that ask for it. Upstream's
                    // `tell_device_to_save_physical_backup` still RUNS and its send is
                    // REWRITTEN rather than dropped, and that is not a stylistic
                    // preference: the call is what inserts into `tmp_waiting_save`, and
                    // without that entry the device's `PhysicalSaved` is refused by
                    // `recv_device_message` ("coordinator not waiting for that share to
                    // be saved") and kills the pass. Rewriting also passes through any
                    // second send a future upstream adds, where a drop-and-forge would
                    // silently lose it.
                    //
                    // `share_image` is taken from upstream's OWN `HeldShare2`, because
                    // that is the key the recursion's `tmp_loaded_backups.remove` must
                    // hit. The other three fields are this harness's, and they have to
                    // be: nothing upstream builds a v1 at all, so there is no upstream
                    // value to borrow. See [`V1_THRESHOLD`].
                    queue.extend(
                        coordinator
                            .tell_device_to_save_physical_backup(phase, restoration_id)
                            .into_iter()
                            .map(|send| if save_v1 { downgrade_save(send) } else { send }),
                    );
                }
            }
            if done(ui) {
                eprintln!(
                    "hostcheck: M7d PASS -- {} saved the typed share and the driver completed",
                    r.device
                );
                if save_v1 {
                    // Ask what it holds while the saved backup still EXISTS. See
                    // `Phase::SavedV1`: consolidating deletes the record.
                    queue.extend(coordinator.request_held_shares(r.device));
                    r.advance(ui, Phase::SavedV1);
                } else {
                    r.advance(ui, Phase::Consolidate);
                }
            }
        }

        // ============================== M11 ==============================
        // The legacy v1 frame's own observable, and the ONLY one it has: the threshold it
        // carried, reported back by the device. Everything else about v1 is
        // indistinguishable from v2 on the wire, because the v1 arm reaches v2 by
        // recursing into it.
        Phase::SavedV1 => {
            if let Some(got) = r.saved_v1_threshold {
                if got != Some(V1_THRESHOLD) {
                    bail!(
                        "M11: {} was sent the LEGACY SavePhysicalBackup (v1) carrying \
                         threshold={V1_THRESHOLD}, and reports the saved backup with \
                         threshold={got:?}. TWO different failures land here and the value \
                         tells them apart: `None` means a v2 body reached the device instead \
                         of the v1 one -- v1's `threshold` is a non-optional u16 and the \
                         rebuild forces `Some(..)`, so only v2 can report nothing -- while any \
                         OTHER `Some` means this read the wrong `HeldShare2`, and \
                         `Some({THRESHOLD})` specifically is the real access structure's entry \
                         rather than the saved backup's",
                        r.device
                    );
                }
                eprintln!(
                    "hostcheck: M11 PASS -- {} accepted the LEGACY SavePhysicalBackup (v1), \
                     recursed it into a SavePhysicalBackup2, and reports the saved backup with \
                     the threshold={V1_THRESHOLD} that ONLY the v1 body could have carried",
                    r.device
                );
                r.advance(ui, Phase::Consolidate);
            }
        }

        // ============================== M7e ==============================
        // NOT a `UiProtocol`: upstream has none for consolidation, so this goes
        // through the same `queue` every keygen frame does.
        // `TellDeviceConsolidateBackup` is `IntoIterator<Item = CoordinatorSend>`.
        Phase::Consolidate => {
            if !r.started {
                r.started = true;
                let phase = r
                    .entered
                    .context("Consolidate reached with no entered physical backup")?;
                let sends = coordinator
                    .tell_device_to_consolidate_physical_backup(phase, as_ref, ENCRYPTION_KEY)
                    .map_err(|e| {
                        anyhow::anyhow!("tell_device_to_consolidate_physical_backup: {e:?}")
                    })?;
                queue.extend(sends);
                eprintln!(
                    "hostcheck: M7e -- asking {} to CONSOLIDATE, which REPLACES the one share \
                     record it keeps",
                    r.device
                );
            }
            if r.consolidated {
                // Ask again what it holds. A `FinishedConsolidation` says the device
                // applied the mutation; this says the state it is in AFTERWARDS agrees
                // with this coordinator's own polynomial. See `Phase::Reheld` for what
                // that does and does not cover -- it is not a flash read-back, and this
                // comment said it was until 2026-09-12.
                queue.extend(coordinator.request_held_shares(r.device));
                r.advance(ui, Phase::Reheld);
            }
        }

        Phase::Reheld => {
            if r.reheld {
                r.phase = Phase::Done;
            }
        }
        Phase::Done => {}
    }
    Ok(())
}

/// Refuse to certify a stub binary older than the sources it is built from.
///
/// The harness reports on the binary it spawns, not on the working tree, so a stale
/// artifact makes every claim it prints a claim about code that is no longer there.
/// This is deliberately a REFUSAL and not a warning: a warning in a verification tool
/// is read as noise, and the failure it hides is the one that matters most.
///
/// Compares mtimes against **cargo's own depfile** for the artifact, i.e. exactly the
/// sources that went into the binary being spawned -- 56 of them, 37 under `../vendor/`.
/// This doc described a directory walk over "the firmware lib and bin, the stub itself,
/// and the whole HAL" until 2026-09-11, and that was wrong in both directions: it
/// asserted the firmware BIN is checked, when `firmware/src/main.rs` is not a
/// dependency of any example and its presence in the walk produced refusals nothing
/// could clear; and it never mentioned `../vendor/`, which it never looked at. See the
/// long note at the depfile read below. Anything unreadable is SKIPPED rather than
/// fatal: this must not become a reason a correct run fails -- but never SILENTLY, which
/// is the fail-open that cost a green run about a 2020-dated binary.
fn refuse_if_stale(stub: &str) -> Result<()> {
    let built = std::fs::metadata(stub).and_then(|m| m.modified());
    let Ok(built) = built else {
        // No mtime available (an exotic filesystem). Nothing to compare, so say so
        // rather than silently passing -- an unchecked binary is what we just fixed.
        eprintln!("hostcheck: WARNING cannot read stub mtime; freshness UNCHECKED");
        return Ok(());
    };
    let mut newest: Option<(std::time::SystemTime, String)> = None;
    // A nested `fn` and not a closure, and that is load-bearing rather than style: a
    // closure capturing `newest` by `&mut` cannot coexist with READING `newest`, and
    // reading it between the two source-collection passes below is exactly how the
    // fail-open in `newest.is_none()` gets closed.
    fn consider(newest: &mut Option<(std::time::SystemTime, String)>, path: std::path::PathBuf) {
        if path.extension().is_none_or(|x| x != "rs") {
            return;
        }
        if let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) {
            if newest.as_ref().is_none_or(|(t, _)| m > *t) {
                *newest = Some((m, path.display().to_string()));
            }
        }
    }
    // CARGO'S OWN ANSWER, not a guess at which directories matter: the depfile beside
    // the artifact lists every source that went into it. Guessing was wrong in BOTH
    // directions, and both were live on 2026-09-11:
    //
    //  - FAIL-CLOSED BUT UNSATISFIABLE. The scan walked all of `../firmware/src`, which
    //    includes `main.rs` — the ARM bin. No example links it (`stub.d` does not list
    //    it), so cargo correctly does not relink the stub when it changes, its mtime
    //    stays put, and the check then refuses with NOTHING TO REBUILD. Editing one doc
    //    comment in `main.rs` blocked this harness. That is the same defect the comment
    //    here already described for `firmware/examples/simulator.rs` and fixed by
    //    narrowing to two directories — narrowing to the wrong two.
    //  - FAIL-OPEN, AND THIS ONE IS THE EXPENSIVE DIRECTION. It never looked at
    //    `../vendor/` at all. The stub has **37 vendored source dependencies** of its 56
    //    total, `frost_backup/src/share_backup.rs` among them — which is the exact code
    //    M7b's share-image assertion rests on. Editing a vendored source and not
    //    rebuilding produced a GREEN run certifying code that is not in the binary,
    //    which is precisely what this function's own doc calls "the most expensive kind".
    //
    // The depfile is one line, `<artifact>: <src> <src> ...`, absolute paths. It is
    // written by cargo at build time and lists the sources of the artifact that is
    // actually there, so it cannot disagree with the binary being run.
    //
    // ponytail: ceiling named, and this note SAID THE WRONG THING until the fail-open
    // below was found — it claimed a space in the path "degrades to the `WARNING ...
    // UNCHECKED` case rather than to a false pass", which is precisely what it did not
    // do. Cargo escapes a space as `\ ` and this splits on whitespace, so under a
    // checkout path containing a space EVERY absolute dep is mangled, none is readable,
    // and it now falls through to the directory scan below — real checking, minus
    // `../vendor/`. If only SOME deps were mangled the rest still pin freshness and the
    // mangled ones are silently unchecked, which is the residual. Upgrade path is a real
    // unescape; not worth it until someone has such a path.
    let depfile = format!("{stub}.d");
    if let Ok(text) = std::fs::read_to_string(&depfile) {
        let deps = text.split_once(':').map_or("", |(_, rest)| rest);
        for dep in deps.split_whitespace() {
            consider(&mut newest, std::path::PathBuf::from(dep));
        }
    }
    // THE THIRD PATH, and it is the one that made the first version of this fix FAIL
    // OPEN — measured 2026-09-11, an EMPTY `stub.d` beside a stub dated 2020-01-01
    // produced `exit 0` and a printed PASS, with no `STALE`, no `WARNING` and no
    // `UNCHECKED` anywhere. `newest` stayed `None`, so the refusal block below was
    // skipped, so the function returned `Ok(())` having checked precisely nothing. A
    // depfile that exists and yields nothing was strictly WORSE than no depfile at all.
    //
    // So the condition is "did we actually get a source to compare", not "was there a
    // file". Everything that yields nothing — absent, empty, no colon, every path
    // unreadable — lands here and falls back to the directory scan, which checks
    // something real. That scan carries the `main.rs` false-refusal defect described
    // above, and that is the correct trade on this leg: over-strict is recoverable by a
    // human, silently blind is not.
    if newest.is_none() {
        eprintln!(
            "hostcheck: WARNING no usable depfile at {depfile}; falling back to a \
             directory scan, which does NOT cover ../vendor/ and MAY refuse on a \
             ../firmware/src/main.rs edit that cannot affect the stub"
        );
        for dir in ["../firmware/src", "../hal/src"] {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries.flatten() {
                    consider(&mut newest, e.path());
                }
            }
        }
        consider(
            &mut newest,
            std::path::PathBuf::from("../firmware/examples/stub.rs"),
        );
    }
    // And if even that found nothing, SAY SO. This is the one line that makes "this
    // function never passes silently" true by construction rather than by the tree
    // happening to be readable. Same shape and same wording as the unreadable-`built`
    // leg above, because it is the same situation: nothing to compare.
    if newest.is_none() {
        eprintln!(
            "hostcheck: WARNING no source mtime was readable at all; freshness UNCHECKED"
        );
        return Ok(());
    }
    if let Some((t, which)) = newest {
        if t > built {
            bail!(
                "STALE stub binary at {stub}\n  {which} is newer than the built stub, so \
                 this run would report on code that is not in it.\n  rebuild: cargo build \
                 --target aarch64-apple-darwin -p coldsnap_firmware --example stub"
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let stub = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_STUB.into());
    if !std::path::Path::new(&stub).is_file() {
        bail!(
            "no stub binary at {stub}\n  build it first: cargo build --target \
             aarch64-apple-darwin -p coldsnap_firmware --example stub"
        );
    }
    refuse_if_stale(&stub)?;

    // See WATCHDOG_SLACK. This thread does no I/O, which is the only reason it
    // can outlive a blocked write.
    let t0 = Instant::now();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        let at = WATCHDOG_AT_MS.load(Ordering::Relaxed);
        if at != 0 && t0.elapsed().as_millis() as u64 > at {
            eprintln!(
                "hostcheck: WATCHDOG at {:?} -- state {}, the loop is stuck OUTSIDE its own \
                 deadline check (a blocked write is the known way that happens)",
                t0.elapsed(),
                State::from_index(STATE.load(Ordering::Relaxed))
                    .map_or("<not a state>", State::name),
            );
            std::process::exit(5);
        }
    });

    // BOTH chunk sizes, every run, and this is not belt-and-braces -- it is the
    // only thing that makes the reassembly claim mean anything.
    //
    // At 64 (the OTG_FS packet size, so the realistic case) the stub's writes
    // COALESCE and the coordinator decodes whole frames from one buffer. At 1 it
    // provably reassembles across reads. So the realistic setting proves the
    // least, and keygen must pass at 1 as well -- that is the reassembly case for
    // frames an order of magnitude bigger than M1's 59-byte Announce.
    if timeout_scale() != 1 {
        eprintln!(
            "hostcheck: COLDSNAP_TIMEOUT_SCALE={} -- every budget multiplied. This is NOT the \
             automated gate's configuration; it exists so a human at the simulator window can \
             take seconds per screen.",
            timeout_scale()
        );
    }

    for chunk in [64usize, 1] {
        eprintln!("--- pass: STUB_CHUNK={chunk} ---");
        // M11: v2 on the chunk-64 pass (the body a real coordinator sends) and the
        // LEGACY v1 on the chunk-1 pass, so ONE `cargo run` drives BOTH admitted
        // variants from a coordinator. Keyed off the chunk size only because there are
        // exactly two signature passes; the parameter is what the phase reads.
        one_pass(&stub, chunk, &t0, Expect::Signature, chunk == 1)
            .with_context(|| format!("pass STUB_CHUNK={chunk}"))?;
    }
    // THE DECLINE PASS. Same binary, same wire, same keygen; the only difference is
    // that the scripted consent presses `x` at every signing screen. It asserts the
    // half of consent the two passes above cannot: that saying no actually refuses.
    // One chunk size is enough — this pass is about the consent decision, and
    // reassembly is already proven at 1 by the pass above.
    eprintln!("--- pass: DECLINE (every device presses x at the signing screen) ---");
    one_pass(&stub, 64, &t0, Expect::Decline, false).context("pass DECLINE")?;
    // M13. Its own process and its own pty, so nothing above can be destabilised by
    // it — see `staging_leg`.
    eprintln!("--- pass: UPGRADE STAGING (M13) ---");
    staging_leg(&stub).context("pass UPGRADE STAGING")?;
    eprintln!(
        "  pass ok: M13 -- {STAGE_SIZE} B announced as 65 chunks (64 whole plus a 512-byte \
         SHORT tail, so `% 4096 != 0` is under test and not rounded off)\
         \n    negative: the corrupted image earned exactly 64 acks and NO 65th, so the final \
         0x11 IS the digest verdict, recomputed from PSRAM READ-BACK -- and it is the only \
         outcome channel a device with no identity has, since every frame it could send \
         would need a `DeviceId` it does not have\
         \n    positive: the clean image earned all 65 over the same child, so the device \
         re-prepared out of `Refused`\
         \n    coalesced: both admission frames in ONE read still stage, which is the defect \
         a single `Option` in the callback used to hide\
         \n    and NOTHING WAS BURNED: no callgate sub-call is bound, `check_burn_len` has no \
         caller, and `Outcome::Staged` means bytes in PSRAM and nothing more"
    );
    println!(
        "M1+M2+M3+M5+M7+M8+M9+M12+M13 PASS: real {THRESHOLD}-of-{N_DEVICES} keygen over a roster cut \
         out of {ALL_DEVICES} announced devices, nonce replenishment and a \
         signature that VERIFIES against the group key, across the pty at both chunk sizes, \
         including the 1-byte case that forces reassembly; the 4-byte code ON THE GLASS equals the \
         coordinator's session hash on every device; a declined signing prompt yields no signature \
         at all; and all four restoration flows run from their REAL upstream coordinator drivers -- \
         the 25 words read back off the device's own framebuffer re-encode to this coordinator's \
         expected share image, the check quiz passes in exactly {QUIZ_POSITIONS} answers taken \
         only from what that reveal drew, those same words go back in through the letter picker and \
         `check_physical_backup` accepts them, and the destructive consolidation leaves a record \
         the device can still describe; a coordinator-previewed 14-char/56-byte name reaches FLASH \
         on all {N_DEVICES} devices and comes back byte-exact as `SetName`; upstream's own \
         `EraseDevice` driver NEVER completes against this device, which refuses its `DataErase` on \
         the wire; and the TENTH device, which this coordinator left out of the keygen and which \
         reported holding nothing at all, ingested another device's 25 words off its sheet and \
         CONSOLIDATED them onto a flash that held no share; and a {STAGE_SIZE} B firmware image \
         STAGES into the device's PSRAM over a raw, unframed 65-chunk stream that bypasses the \
         framer entirely, with the digest recomputed from PSRAM read-back -- a corrupted image \
         gets 64 acks and silence where the 65th would be, a clean one gets all 65, and NOTHING \
         IS BURNED because no callgate sub-call is bound"
    );
    Ok(())
}

/// M13's announced size: 64 x 4,096 + 512, and every digit of it is chosen hostile.
///
/// `>= 262,144` (the bootloader's floor), `% 512 == 0` (what the device's digest
/// demands of the header's length field), and `% 4096 != 0` — so the stream ends in a
/// 512-byte SHORT final chunk and there are 65 chunks. A 97 x 4,096 exact fit, which
/// is what a real artifact always is, could not fail the ack arithmetic or the tail
/// and would be the vacuous version of this whole leg.
const STAGE_SIZE: u32 = 262_656;

/// Per-ack wall clock. The pty slave's own timeout is [`STAGE_PORT_TIMEOUT`] and
/// `raw_read` is a `read_exact`, so a missing ack surfaces as a timeout error; this
/// is the budget for retrying that before calling the ack absent.
const ACK_DEADLINE: Duration = Duration::from_secs(2);

/// M13's slave timeout. Longer than [`PORT_TIMEOUT`] because the device does a full
/// PSRAM self-test at admission and a 262 KiB read-back at the end, and neither is
/// on this leg's critical path to being correct.
const STAGE_PORT_TIMEOUT: Duration = Duration::from_millis(1_000);

/// A deterministic image of `size` bytes with `size` in its length field.
///
/// The offset is the LITERAL `16_280` and the pattern is this function's own. Neither
/// derives from anything the device computes — and it CANNOT, because `hostcheck`
/// cannot depend on `coldsnap_firmware` at all (one cargo graph will not hold both
/// `coldsnap_hal` and upstream `frostsnap_coordinator`). So M13 is an independent
/// reader of the signed range by CONSTRAINT rather than by care, which is the
/// strongest form of that property available here.
fn synth_image(size: u32) -> Vec<u8> {
    let mut v: Vec<u8> = (0..size as usize).map(|i| (i * 7 + i / 251) as u8).collect();
    v[16_280..16_284].copy_from_slice(&size.to_le_bytes());
    v
}

/// The digest the device must arrive at: sha256 over `[0, 16_320)` then
/// `[16_384, size)`.
///
/// That is the Mk4 bootloader's signed range with the 64-byte RSA signature that sits
/// INSIDE the header punched out. All four numbers are literals here, so a mutation of
/// the device's skip window reddens M13 rather than moving with it.
fn signed_digest(img: &[u8]) -> Sha256Digest {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(&img[..16_320]);
    h.update(&img[16_384..]);
    Sha256Digest(h.finalize().into())
}

/// A fresh `STUB_UPGRADE=1` child, its pty and a completed magic handshake.
///
/// One per LEG, because `upgrade::run` returns on `Outcome::Staged` and the stub then
/// exits — MEASURED 2026-09-17 as a `Broken pipe` on the leg after the positive one.
/// The negative and coalesced legs could share a child; they do not, so that no leg's
/// result can depend on another leg's residue.
fn stage_session(stub: &str) -> Result<(FramedSerialPort<Downstream>, Reaped)> {
    let (master, mut slave) = TTYPort::pair().context("TTYPort::pair for M13")?;
    slave
        .set_timeout(STAGE_PORT_TIMEOUT)
        .context("set_timeout for M13")?;
    let wire_in = unsafe { OwnedFd::from_raw_fd(master.into_raw_fd()) };
    let wire_out = wire_in.as_fd().try_clone_to_owned()?;

    let mut cmd = Command::new(stub);
    cmd.env("STUB_UPGRADE", "1")
        .stdin(Stdio::from(wire_in))
        .stdout(Stdio::from(wire_out))
        .stderr(Stdio::inherit());
    let child = Reaped(cmd.spawn().with_context(|| format!("spawn {stub} for M13"))?);
    drop(cmd);

    let mut port: FramedSerialPort<Downstream> =
        FramedSerialPort::new(Box::new(slave) as Box<dyn SerialPort>);

    // `read_for_magic_bytes` CONSUMES the device's reply out of the very `BufReader`
    // the ack reads come off, which is why it has to happen here and cannot be skipped:
    // an unconsumed `MAGIC_REPLY` byte would be read as chunk 0's ack.
    // MAGIC IS RE-SENT, exactly as a real coordinator does every
    // `MAGIC_BYTES_PERIOD`, and MORE THAN ONE SEND IS REQUIRED. `Link::poll` consumes
    // the FIRST magic frame inside `scan_magic` and returns without calling `on_frame`
    // at all (`hal/src/comms.rs:489-495,530-550`), so the first frame links the device
    // and the SECOND is the one that produces a reply. MEASURED 2026-09-17: sending
    // magic once and then only polling times out at `HANDSHAKE_DEADLINE`, every run.
    let started = Instant::now();
    loop {
        if started.elapsed() > HANDSHAKE_DEADLINE {
            bail!(
                "M13: the upgrade listener never answered the magic handshake in \
                 {HANDSHAKE_DEADLINE:?} -- that reply is what puts a port in a coordinator's \
                 `ready` map, so without it `EnterUpgradeMode` reaches nobody. Delete \
                 `wire.write(&comms::MAGIC_REPLY)` from `upgrade::run` and this is what reddens"
            );
        }
        port.write_magic_bytes().map_err(|e| anyhow::anyhow!("{e}"))?;
        if port
            .read_for_magic_bytes()
            .context("read_for_magic_bytes")?
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(MAGIC_BYTES_PERIOD / 10));
    }

    // NOW DRAIN EVERY BYTE THE DEVICE HAS ALREADY SENT, and this is a bug fix rather
    // than hygiene. Re-sending magic means the device replies more than once, and
    // `read_for_magic_bytes` consumes only up to the END OF THE FIRST PATTERN it
    // matches; a second `MAGIC_REPLY` sitting in the same `BufReader` fill is left
    // there, and `anything_to_read()` is then false (it asks the PORT, not the buffer)
    // so no further call to it will ever consume the leftover. `MAGIC_REPLY`'s first
    // byte is `0x00` (`hal/src/comms.rs:343`, the bincode variant tag), so that
    // leftover is read as chunk 0's ack.
    //
    // MEASURED 2026-09-17: without this drain, `chunk 0 was answered with 0x00` failed
    // roughly one run in three. Nothing in the ordinary event loop can see this,
    // because there both replies go through a framer that decodes them; only a leg that
    // switches to raw byte reads can. `raw_read` empties the `BufReader` AND the port,
    // which `read_for_magic_bytes` structurally cannot.
    //
    // It costs one `STAGE_PORT_TIMEOUT` per session and buys the leg's determinism.
    let mut discard = [0u8; 1];
    loop {
        match port.raw_read(&mut discard) {
            Ok(()) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => bail!("M13: draining the handshake replies failed: {e}"),
        }
    }
    Ok((port, child))
}

/// **M13: the upgrade staging leg.** Drive the device's chunk stream over the pty and
/// assert that the digest verdict is what the final ack means.
///
/// Its own `TTYPort::pair`, its own child (`STUB_UPGRADE=1`) and NO WRITER THREAD.
/// That last one is deliberate: `raw_write` and `raw_read` then share one
/// `FramedSerialPort` and one `BufReader`, so no desync between the write fd and the
/// read fd is possible, and `one_pass`/M1-M12 cannot be destabilised by anything here.
///
/// The negative leg runs FIRST so one process covers both — the device's `admit`
/// resets from `Refused`, which its own
/// `re_preparing_over_a_verified_image_clears_the_verdict_first` pins.
fn staging_leg(stub: &str) -> Result<()> {
    let img = synth_image(STAGE_SIZE);
    let digest = signed_digest(&img);

    // NEGATIVE LEG: one flipped byte in chunk 40, inside the hashed range. Expect 64
    // acks and NO 65th, because the 65th IS the verdict.
    let (mut port, _child) = stage_session(stub)?;
    let mut corrupt = img.clone();
    corrupt[40 * 4096 + 7] ^= 0x80;
    let acks = drive_chunks(&mut port, &corrupt, digest)?;
    if acks != 64 {
        bail!(
            "M13 negative leg: {acks} ack(s) for a corrupted image, expected exactly 64 \
             then silence. A 65th means the digest verdict is NOT gated on the final ack -- \
             move the ack return above `Stager::verify` and this is what reddens"
        );
    }

    // POSITIVE LEG, same child: the clean image, 65 acks. Reusing the child is
    // deliberate — the device must re-prepare out of `Refused`, which is the transition
    // `re_preparing_over_a_verified_image_clears_the_verdict_first` pins in a unit test
    // and this is the only place a coordinator drives it.
    let acks = drive_chunks(&mut port, &img, digest)?;
    if acks != 65 {
        bail!(
            "M13 positive leg: {acks} ack(s) for a clean image, expected exactly 65 \
             (64 whole chunks and a 512-byte tail). Drop the `received == size` case from \
             `Stager::feed`'s `acks_at` and this reddens at 64"
        );
    }

    // COALESCED LEG: both admission frames in ONE `raw_write`, then the whole image.
    //
    // WHY THIS EXISTS, and it is the leg that caught a real defect. A coordinator's
    // `PrepareUpgrade2` and `EnterUpgradeMode` are a few dozen bytes each, so they
    // legitimately arrive in ONE 64-byte read, and `Link::poll` then hands the callback
    // BOTH frames before returning. `upgrade::run` recorded the admitted message in a
    // single `Option` until 2026-09-17, so the second overwrote the first and only
    // `EnterUpgradeMode` was admitted — from `Idle`, i.e. `Refuse::OutOfOrder` and an
    // upgrade that could never start. Fixed by admitting inside the callback.
    //
    // IT MUST BE LAST and it needs its OWN CHILD: the positive leg above ended in
    // `Outcome::Staged`, at which point `upgrade::run` returns and the stub exits
    // (MEASURED as a `Broken pipe` here before this took a fresh session).
    //
    // NOTE WHAT IS *NOT* ASSERTED HERE, per the domination convention. An earlier
    // version of this leg wrote the two frames AND chunk 0's head together, to force
    // the head into `Link`'s private accumulator, and asserted that no ack arrived (it
    // does not — MEASURED 0 acks). It was DELETED rather than shipped: every device
    // mutation that could make it fire is caught by the NEGATIVE leg first, so it was
    // dominated and read like coverage. The head-loss hazard is real and its mitigation
    // is upstream's 100 ms gap plus the digest; what this tree can falsify is the
    // COALESCED-ADMISSION half, which is this leg.
    let (mut port, _child) = stage_session(stub)?;
    let frames = encode_upgrade_frames(img.len() as u32, digest)?;
    port.raw_write(&frames).context("coalesced frame write")?;
    // The same 100 ms upstream leaves after `EnterUpgradeMode`. It is NOT what makes
    // this leg pass -- MEASURED 2026-09-17, deleting it left every M13 leg GREEN,
    // because a pty delivers separate writes as separate reads. Kept for parity with
    // `usb_serial_manager.rs:681-682`, and named as unproven rather than claimed.
    std::thread::sleep(Duration::from_millis(100));
    let acks = stream_chunks(&mut port, &img)?;
    if acks != 65 {
        bail!(
            "M13 coalesced leg: {acks} ack(s) when both admission frames arrived in ONE \
             read, expected 65. Replace `upgrade::run`'s admit-in-callback with a single \
             `let mut msg = None;` set in the callback and this reddens at 0, because only \
             the SECOND frame survives and `EnterUpgradeMode` from `Idle` is refused"
        );
    }

    Ok(())
}

/// The two admission frames as BYTES, so they can be written together with chunk 0.
///
/// `raw_send` encodes straight into the port, one flush per frame, so it cannot
/// produce a coalesced write. This uses the same `BINCODE_CONFIG` the port does.
fn encode_upgrade_frames(size: u32, digest: Sha256Digest) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for body in upgrade_bodies(size, digest) {
        bincode::encode_into_std_write(
            ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
                target_destinations: frostsnap_coordinator::frostsnap_comms::Destination::All,
                message_body: body.into(),
            }),
            &mut out,
            BINCODE_CONFIG,
        )
        .map_err(|e| anyhow::anyhow!("encode upgrade frame: {e}"))?;
    }
    Ok(out)
}

/// `PrepareUpgrade2` then `EnterUpgradeMode`, in the order the coordinator sends them.
fn upgrade_bodies(size: u32, digest: Sha256Digest) -> [CoordinatorSendBody; 2] {
    use frostsnap_coordinator::frostsnap_comms::CoordinatorUpgradeMessage as U;
    [
        CoordinatorSendBody::Upgrade(U::PrepareUpgrade2 {
            size,
            firmware_digest: digest,
        }),
        CoordinatorSendBody::Upgrade(U::EnterUpgradeMode),
    ]
}

/// Read one ack, or report that it did not arrive inside [`ACK_DEADLINE`].
///
/// `Ok(false)` is the REFUSAL CHANNEL and not an error: a device in the pre-Session
/// window can never send a frame, so a missing ack is the only way it can say no.
/// A `bail!` here would make every refusal unobservable.
fn read_ack(port: &mut FramedSerialPort<Downstream>, which: usize) -> Result<bool> {
    let mut byte = [0u8; 1];
    let waited = Instant::now();
    loop {
        match port.raw_read(&mut byte) {
            Ok(()) => {
                if byte[0] != 0x11 {
                    // STRICTER than the real coordinator, which only logs at DEBUG on
                    // an unexpected byte. A wrong value is a device sending something
                    // other than the ready signal, and this leg is the only thing in
                    // the tree that could notice.
                    bail!(
                        "M13: chunk {which} was answered with {:#04x}, not \
                         FIRMWARE_NEXT_CHUNK_READY_SIGNAL (0x11)",
                        byte[0]
                    );
                }
                return Ok(true);
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                if waited.elapsed() > ACK_DEADLINE {
                    return Ok(false);
                }
            }
            // A GONE CHILD IS "NO ACK", not a read error, and that distinction is what
            // makes the count assertions readable. MEASURED 2026-09-17: with `Broken
            // pipe` treated as an error, mutating `Stager::feed`'s `acks_at` was caught
            // — but as `chunk 64 ack read failed: Broken pipe` rather than as `64 ack(s)
            // ... expected exactly 65`, because `upgrade::run` returns on
            // `Outcome::Staged` and the stub exits before the missing ack can time out.
            // Real coverage with the wrong diagnosis; this makes the diagnosis the one
            // the caller's `bail!` was written for.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(false);
            }
            Err(e) => bail!("M13: chunk {which} ack read failed: {e}"),
        }
    }
}

/// Stream `img` as 4,096-byte chunks in write-then-read-one-byte lockstep, stopping
/// at the first ack that does not arrive.
///
/// `chunks(4096)` yields a SHORT final slice and `raw_write` writes exactly its length,
/// so the 65th chunk really is 512 bytes on the wire. Nothing pads it — that is the
/// device's problem, and its answer is to refuse any `size` that would need a pad.
///
/// **This took an `owed: usize` and led with a `for i in 0..owed` ack-collection loop
/// until 2026-09-18.** Both callers passed the literal `0`, so the loop executed in no
/// run and `let i = owed + n` was always `n` — six lines of ack accounting inside the
/// one function M13 exists to falsify, unreachable but reading as covered because the
/// function around it is covered. It was scaffolding for the deleted fourth leg (the
/// module header above), which was the only caller that could ever have owed an ack up
/// front. Deleted with the leg it served.
fn stream_chunks(port: &mut FramedSerialPort<Downstream>, img: &[u8]) -> Result<u32> {
    let mut acks = 0u32;
    for (i, chunk) in img.chunks(4096).enumerate() {
        port.raw_write(chunk)
            .with_context(|| format!("raw_write chunk {i}"))?;
        if !read_ack(port, i)? {
            return Ok(acks);
        }
        acks += 1;
    }
    Ok(acks)
}

/// `PrepareUpgrade2` + `EnterUpgradeMode` + the chunk stream, counting acks.
///
/// Stops as soon as an ack does not arrive within [`ACK_DEADLINE`], which is what
/// makes "the device refused" observable at all: this window's device cannot send a
/// frame — every device-to-coordinator message carries a `DeviceId` derived from an
/// identity secret it may not have — so a MISSING ack is the entire refusal channel.
fn drive_chunks(
    port: &mut FramedSerialPort<Downstream>,
    img: &[u8],
    digest: Sha256Digest,
) -> Result<u32> {
    for body in upgrade_bodies(img.len() as u32, digest) {
        port.raw_send(ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
            // `Destination::All` and NOT `to(device_id, ..)`: this window has no
            // `DeviceId` to address, and `is_destined_to` returns true
            // unconditionally for `All` without consulting one. That is exactly what
            // the real coordinator sends `EnterUpgradeMode` with.
            target_destinations: frostsnap_coordinator::frostsnap_comms::Destination::All,
            // `.into()` is the encapsulation `ReceiveSerial::Message` carries on the
            // wire, and the device's `comms::decode_body` is the matching inner decode.
            message_body: body.into(),
        }))
        .map_err(|e| anyhow::anyhow!("raw_send: {e}"))?;
    }

    // UPSTREAM'S OWN SEPARATION (`usb_serial_manager.rs:681-682`), kept for PARITY and
    // not because this leg proves anything about it. MEASURED 2026-09-17: deleting this
    // sleep left every M13 leg GREEN, because two separate `raw_send` writes reach a pty
    // as two reads. On USB CDC a 64-byte packet really can carry a frame tail and a chunk
    // head together, and cold-snap's `Link::poll` — unlike upstream's byte-at-a-time
    // framer — would swallow that head into a private accumulator. The COALESCED LEG
    // above is what makes that hazard falsifiable; this line is not.
    std::thread::sleep(Duration::from_millis(100));

    // Nothing written yet, so no acks are owed up front and every chunk goes out here.
    stream_chunks(port, img)
}

fn one_pass(
    stub: &str,
    chunk: usize,
    t0: &Instant,
    expect: Expect,
    save_v1: bool,
) -> Result<()> {
    // (master, slave). The master has `port_name: None` and so cannot be
    // reopened by path -- handing it over as the child's stdio is the whole
    // reason this works cross-process.
    let (master, mut slave) = TTYPort::pair().context("TTYPort::pair")?;
    slave.set_timeout(PORT_TIMEOUT).context("set_timeout")?;

    // fd 0 and fd 1 must be separate fds; `Stdio` takes ownership of each.
    // `TTYPort` only offers `IntoRawFd`, so the ownership transfer is manual.
    let wire_in = unsafe { OwnedFd::from_raw_fd(master.into_raw_fd()) };
    let wire_out = wire_in.as_fd().try_clone_to_owned()?;

    let mut cmd = Command::new(stub);
    cmd.env("STUB_CHUNK", chunk.to_string())
        // FAIL CLOSED on the stub's own side: 0 makes it die by name on the first
        // unexpected decline instead of going quiet, and the decline pass below has
        // to declare how many it wants. Set explicitly rather than left to the
        // stub's default so an exported `STUB_EXPECT_DECLINES` in somebody's shell
        // cannot loosen the signature passes.
        .env("STUB_EXPECT_DECLINES", "0")
        .stdin(Stdio::from(wire_in))
        .stdout(Stdio::from(wire_out))
        // Still INHERIT, and that is now a decision rather than a default: the
        // glass assertion crosses the workspace boundary on the WIRE (a
        // `DeviceSendBody::Debug{glass=...}` this loop intercepts), not on stderr,
        // so nothing here needs to parse the child's diagnostics. `hostcheck`
        // cannot depend on `coldsnap_firmware` — one cargo graph will not hold both
        // `coldsnap_hal` and upstream `frostsnap_coordinator` — so only bytes may
        // cross, and the existing `Debug` back-channel is already a bounded,
        // intercepted, protocol-inert one. Piping stderr would have meant a second
        // channel, a second parser and a reader thread to keep it from filling its
        // pipe.
        .stderr(Stdio::inherit());
    if expect == Expect::Decline {
        // `y` at the keygen check (so assertion 1 still runs in this pass), `x` at
        // every signing screen. `COLDSNAP_GLASS_KEYS` is deliberately NOT set for a
        // signature pass: unset is the stub's default `yyy`, which keeps the
        // automated gate on the default path AND lets a human run e.g.
        // `COLDSNAP_GLASS_KEYS=y9 cargo run` to watch a hardcoded-key script fail at
        // the signing screen, or `=yy9` to watch one fail at the BACKUP REVEAL.
        //
        // Two characters and not three, because this pass never reaches the M7
        // restoration flows: it breaks out at `DECLINE_GRACE`, long before a signature
        // exists. The stub's missing third character defaults to `y`.
        cmd.env("COLDSNAP_GLASS_KEYS", "yx")
            .env("STUB_EXPECT_DECLINES", N_DEVICES.to_string());
    }
    // Wrapped so that EVERY exit from this function reaps it -- see [`Reaped`]. The
    // 15 `bail!`s in the PASS block are `return`s that fire BEFORE the reaping.
    let mut child = Reaped(cmd.spawn().with_context(|| format!("spawn {stub}"))?);
    // Drop the parent's copies of the master fds NOW, so the stub exiting gives
    // the slave a clean EOF instead of a port that stays open forever.
    drop(cmd);

    // THE WRITE PATH LIVES OVER THERE, on a `dup` of this fd (`F_DUPFD_CLOEXEC`,
    // so the same file description and the same tty output queue -- a blocked
    // write blocks identically, it just blocks a thread nobody is waiting on).
    // From here on `port` is READ-ONLY; see `spawn_writer` on why writing from
    // both would corrupt frames.
    let wtx = spawn_writer(
        slave.try_clone_native().context("dup pty slave for writer")?,
        *t0,
    );
    WRITES_DONE.store(0, Ordering::Relaxed);
    WRITE_BUSY_SINCE_MS.store(0, Ordering::Relaxed);
    *WRITE_ERR.lock().unwrap() = None;

    let mut port: FramedSerialPort<Downstream> =
        FramedSerialPort::new(Box::new(slave) as Box<dyn SerialPort>);

    // No database: `FrostCoordinator::new()` is the whole state machine, and
    // `Persisted`/rusqlite is opt-in (`frostsnap_core/src/coordinator.rs`).
    let mut coordinator = FrostCoordinator::new();
    coordinator.keygen_fingerprint = TEST_FINGERPRINT;
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED);

    // M8: built with `new` and NOT `truncate`, deliberately. `truncate` would silently
    // cut a mis-edited [`DEVICE_NAME`] to 14 chars, the device would round-trip the cut
    // value faithfully, and the assertion below would pass on it — the exact "pretend the
    // truncation did not happen" failure. This fails by name instead, before a byte moves.
    let preview_name = DeviceName::new(DEVICE_NAME.to_string()).map_err(|e| {
        anyhow::anyhow!(
            "DEVICE_NAME {DEVICE_NAME:?} is not a valid DeviceName: {e} -- 14 CHARS is the \
             wire bound, and its Decode would truncate silently"
        )
    })?;

    let started = Instant::now();
    let mut state = State::WaitingForMagic;
    state.publish();
    WATCHDOG_AT_MS.store(
        (t0.elapsed() + State::longest() + WATCHDOG_SLACK).as_millis() as u64,
        Ordering::Relaxed,
    );
    let mut last_wrote: Option<Instant> = None;
    let mut magic_writes = 0usize;
    let mut writes_queued = 0usize;
    // Devices that have REPORTED holding the finished access structure, over
    // the wire. `held.len() == N_DEVICES` is the pass condition.
    let mut held: std::collections::BTreeSet<DeviceId> = Default::default();
    let mut requested_held = false;
    let mut read_timeouts = 0usize;
    let mut announced: Vec<DeviceId> = Vec::new();
    // ============================== M12 ==============================
    // THE KEYGEN ROSTER AND THE BLANK DEVICE, both cut out of ONE expression on the
    // lap the tenth device announces (see the `BeginKeygen` site). Cutting them
    // together is what makes them unable to disagree: `roster` is
    // `announced[..N_DEVICES]` and `blank` is `announced[N_DEVICES]`, so a device is
    // in exactly one of the two by construction.
    //
    // ASSIGNED, NEVER INFERRED. This process owns `BeginKeygen`, so it CREATES the
    // fact that one device holds nothing rather than discovering it. PLAN.md §9 item
    // 12 recorded that a split "needs a way for hostcheck to IDENTIFY the blank
    // device, which the protocol cannot supply because all ten flashes are blank
    // before keygen" — the premise is true and the conclusion is false, and the
    // difference matters: a harness that asked the devices which one was blank would
    // be trusting them about the very thing under test. The choice is independently
    // checkable from the coordinator's own `contains_device`, which is what the
    // in-loop roster check below does.
    //
    // `blank` stays `None` until then, and every use of it is `Some(x) == blank`
    // rather than an unwrap, so a run that never got ten announces cannot mistake an
    // absent blank device for a match.
    let mut roster: Vec<DeviceId> = Vec::new();
    let mut blank: Option<DeviceId> = None;
    // M12: the blank device answered the pre-signature `RequestHeldShares` with NOTHING
    // — no entry for the access structure keygen just finished. Asserted at PASS
    // because it is NOT implied by control flow: dropping the tenth device from that
    // round trip leaves the run green and this false.
    let mut blank_reported_empty = false;
    // What each device says the keygen session hash is, and which devices refused
    // the forged `DataErase` below. Both arrive as `DeviceSendBody::Debug`, which
    // this loop intercepts and never hands to the `FrostCoordinator` -- so neither
    // can move the protocol along; they can only be compared at PASS.
    let mut device_hashes: std::collections::BTreeMap<DeviceId, String> = Default::default();
    let mut refused_erase: std::collections::BTreeSet<DeviceId> = Default::default();
    // What each device's KEYGEN CHECK SCREEN actually rendered, read back out of
    // the framebuffer on the device side by the shipping `ui::Frame::cell_2x` and
    // sent as `glass=<8 hex>`. Compared at PASS against our own session hash's
    // first four bytes — see the block by that name.
    let mut device_glass: std::collections::BTreeMap<DeviceId, String> = Default::default();
    // M8: the name each device reported STORING, off `DeviceSendBody::SetName`. Not a
    // back-channel: this is the real protocol body the app's `device_names` entry comes
    // from, so the assertion is over the same message a coordinator would act on.
    let mut device_names: std::collections::BTreeMap<DeviceId, String> = Default::default();
    // M10: the two devices of the `Cancel` DIFFERENTIAL. Both get the SAME TWO FRAMES in
    // OPPOSITE ORDERS and nothing else distinguishes them:
    //
    //   `name_cancelled`  preview, THEN `Cancel`  -> must report NO name
    //   `name_recovered`  `Cancel`, THEN preview  -> must report the byte-exact name
    //
    // The second one is what stops the first from being vacuous, and it is not a
    // nicety: PLAN.md §9 item 12 already records that a LATE preview is
    // indistinguishable from NO preview, so "this device sent no `SetName`" on its own
    // is equally consistent with a preview that never landed. Identical frames,
    // identical wire, identical device code path — so a lost preview silences BOTH, and
    // `name_recovered`'s success is what makes `name_cancelled`'s silence a fact about
    // the ORDER of the two frames rather than about their delivery.
    //
    // `Option<DeviceId>` and not an index into `announced`, so every failure message
    // names a device.
    let mut name_cancelled: Option<DeviceId> = None;
    let mut name_recovered: Option<DeviceId> = None;
    // M8: devices that ANNOUNCED having no stored name. `Session::announce` sends exactly
    // one of `SetName` (a name is on flash) or `NeedName` (none is), so this is what makes
    // the `SetName` below evidence of a commit IN THIS RUN rather than an echo of a name
    // that was already there — without it the M8 assertions would also pass on a device
    // whose flash arrived pre-named, and `commit_name` need never have run at all.
    let mut need_name: std::collections::BTreeSet<DeviceId> = Default::default();
    // Devices that DECLINED the signing prompt. Arrives on the same intercepted
    // `Debug` channel, because the protocol has no decline variant — that is a
    // finding of this work, not a shortcut.
    let mut declined: std::collections::BTreeSet<DeviceId> = Default::default();
    // When the last device said no, i.e. when [`DECLINE_GRACE`] starts.
    let mut all_declined_at: Option<Instant> = None;
    let mut lied = false;
    let mut keygen: Option<Keygen> = None;
    let mut sign = Sign::default();
    let mut queue: VecDeque<CoordinatorSend> = VecDeque::new();
    // The firmware digest each device ANNOUNCED, for the `FirmwareVersion` M7c hands
    // `CheckBackupProtocol`. See [`CHECK_BACKUP_SINCE`].
    let mut digests: BTreeMap<DeviceId, Sha256Digest> = BTreeMap::new();
    // ============================= M7a: THE SEAM =============================
    // ONE boxed `UiProtocol` at a time and deliberately no `UiStack`. The five-call
    // lifecycle is wired as: `poll()` -> the existing `send_frame`; the existing decode
    // loop -> `process_to_user_message` / `process_comms_message`; `connected()` at
    // construction; and `is_complete()` as the pass criterion -- except for
    // `DisplayBackupProtocol`, which has none (see [`Restore::recorded`]).
    let mut ui: Option<Box<dyn UiProtocol>> = None;
    // M12: TWO legs through ONE slot. `restore` is always the LIVE leg — every
    // per-message handler does `restore.as_mut()` and therefore follows it with no
    // change, and there is never a second `UiProtocol` alive — and `sighted` is leg 1
    // after it retired.
    //
    // `sighted` is named for what it holds: the device that SAW its own reveal on the
    // glass. Leg 2 is the blank device, which sees nothing, so `sighted` is where every
    // M7b/M7c fact at PASS has to be read from. The quiz-count bail in particular MUST
    // read it: leg 2 never enters `Phase::Quiz`, so leaving that bail on `restore` fires
    // on EVERY GREEN RUN — MEASURED, `M7c: <blank> reported None quiz answer(s), not
    // exactly 8`, exit 1. That is the proof the redirection is load-bearing and not
    // cosmetic.
    let mut restore: Option<Restore> = None;
    let mut sighted: Option<Restore> = None;

    let outcome = loop {
        state.publish();
        if started.elapsed() > state.budget() {
            // The single most important property of this harness: it says where
            // it died. `FramedSerialPort` exposes no byte counter, so the
            // coordinator-side proxies are the magic-write count and whether the
            // port has anything buffered; the stub prints its own counts.
            break Err(anyhow::anyhow!(
                "DEADLINE ({:?}) in state {} -- magic_writes={magic_writes}, \
                 writes_queued={writes_queued}, writes_done={}, \
                 read_timeouts={read_timeouts}, announced={}, shares={}, acks={}, \
                 session_hash={}, held={}, replenished={}, sign_session={}, \
                 sig_shares={}/{}, anything_to_read={}, elapsed={:?}",
                state.budget(),
                state.name(),
                WRITES_DONE.load(Ordering::Relaxed),
                announced.len(),
                keygen.as_ref().map_or(0, |k| k.got_shares),
                keygen.as_ref().map_or(0, |k| k.acks),
                keygen.as_ref().is_some_and(|k| k.session_hash.is_some()),
                held.len(),
                sign.replenished.len(),
                sign.session_id.is_some(),
                sign.got_shares.len(),
                sign.signers.len(),
                port.anything_to_read(),
                started.elapsed()
            ));
        }

        // THE WRITE-PATH DEADLINE. The writer thread cannot report a stall itself
        // (it is inside the stall), so this reads its published start time. Same
        // shape as the read deadline: checked every lap, and the longest this loop
        // can be away from here is one `PORT_TIMEOUT`, so a blocked write is
        // diagnosed within `WRITE_STALL_LIMIT + PORT_TIMEOUT`.
        if let Some(e) = WRITE_ERR.lock().unwrap().take() {
            break Err(anyhow::anyhow!(
                "writer thread failed in state {}: {e}",
                state.name()
            ));
        }
        let busy = WRITE_BUSY_SINCE_MS.load(Ordering::Relaxed);
        if busy != 0 {
            let blocked = t0
                .elapsed()
                .saturating_sub(Duration::from_millis(busy));
            if blocked > WRITE_STALL_LIMIT {
                break Err(anyhow::anyhow!(
                    "WRITE STALL ({blocked:?} > {WRITE_STALL_LIMIT:?}) in state {} -- frame \
                     {}/{writes_queued} is stuck in raw_send/tcdrain, i.e. the DEVICE has \
                     stopped reading (a pty blocks writes past ~1 KB when the peer does not \
                     drain). magic_writes={magic_writes}, read_timeouts={read_timeouts}, \
                     announced={}, shares={}, acks={}, replenished={}, sig_shares={}, \
                     anything_to_read={}, elapsed={:?}",
                    state.name(),
                    WRITES_DONE.load(Ordering::Relaxed) + 1,
                    announced.len(),
                    keygen.as_ref().map_or(0, |k| k.got_shares),
                    keygen.as_ref().map_or(0, |k| k.acks),
                    sign.replenished.len(),
                    sign.got_shares.len(),
                    port.anything_to_read(),
                    started.elapsed()
                ));
            }
        }

        match state {
            State::WaitingForMagic => match port.read_for_magic_bytes() {
                Ok(Some(features)) => {
                    eprintln!(
                        "hostcheck: got device magic bytes (conch_enabled={}) after {:?}",
                        features.conch_enabled,
                        started.elapsed()
                    );
                    // Device signals version 2 => false. A no-op against the
                    // default; kept because it is what the real driver does.
                    port.set_conch_enabled(features.conch_enabled);
                    state = State::WaitingForAnnounces;
                }
                Ok(None) => {
                    if last_wrote.is_none_or(|t| t.elapsed().as_millis() as u64 > MAGIC_BYTES_PERIOD)
                    {
                        if let Err(e) =
                            send_frame(&wtx, ReceiveSerial::MagicBytes(MagicBytes::default()))
                        {
                            break Err(e.context("write_magic_bytes"));
                        }
                        magic_writes += 1;
                        writes_queued += 1;
                        last_wrote = Some(Instant::now());
                    }
                }
                // `fill_buf` can time out here too (a device that sends 1 byte
                // and stops). Same treatment: next lap, deadline re-checked.
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => read_timeouts += 1,
                Err(e) => {
                    break Err(anyhow::anyhow!(
                        "read_for_magic_bytes in {}: {e}",
                        state.name()
                    ))
                }
            },

            // Everything from here on is the same read: decode a device frame,
            // route it. The only difference between the states is what we are
            // still waiting for, which is what the deadline message needs.
            _ => match port.try_read_message() {
                Ok(Some(ReceiveSerial::Message(msg))) => {
                    let from = msg.from;
                    let body = match msg.body.decode() {
                        Ok(body) => body,
                        Err(e) => {
                            break Err(anyhow::anyhow!(
                                "body.decode() from {from} in {}: {e}",
                                state.name()
                            ))
                        }
                    };
                    match body {
                        DeviceSendBody::Announce { firmware_digest } => {
                            // Kept for M7c, which has to hand `CheckBackupProtocol` a
                            // `FirmwareVersion`. The DIGEST is the real thing this
                            // device says about its firmware; the version beside it is
                            // the harness's declaration. See [`CHECK_BACKUP_SINCE`].
                            digests.insert(from, firmware_digest);
                            if !announced.contains(&from) {
                                announced.push(from);
                                eprintln!(
                                    "hostcheck: ANNOUNCE {}/{ALL_DEVICES} from {from} digest \
                                     {firmware_digest} after {:?}",
                                    announced.len(),
                                    started.elapsed()
                                );
                                // M10: assign the differential's two roles on FIRST
                                // announce, and only here, so each device plays exactly
                                // one and a re-announce cannot reassign it.
                                if name_cancelled.is_none() {
                                    name_cancelled = Some(from);
                                } else if name_recovered.is_none() {
                                    name_recovered = Some(from);
                                }
                            }
                            let ack = CoordinatorSendMessage::to(
                                from,
                                CoordinatorSendBody::AnnounceAck,
                            );
                            if let Err(e) = send_frame(&wtx, ReceiveSerial::Message(ack.into())) {
                                break Err(e.context("AnnounceAck"));
                            }
                            writes_queued += 1;
                            // ============================ M8 ============================
                            // THE NAMING FLOW, and this is the only place it can start.
                            // The device commits a previewed name from `Session::run`'s
                            // `FinalizeKeyGen` arm (`firmware/src/lib.rs` `commit_name`),
                            // i.e. DURING keygen — so the preview must be on the device
                            // BEFORE the coordinator's `Finalize`, and a post-signature
                            // phase like M7's would be far too late. Beside the ack is
                            // the earliest lap on which this device's id is known, and
                            // the announce is also what told us it has no name yet: this
                            // arm is what used to print `ignoring NeedName` nine times a
                            // pass.
                            //
                            // A preview commits NOTHING on the device — no flash write,
                            // no prompt, no keypress (the real app calls it once per
                            // typed character) — which is why sending it unprompted is
                            // safe here and why it is not a consent event over there.
                            //
                            // ============================ M10 ===========================
                            // `CoordinatorSendBody::Cancel`, and THIS LAP IS THE ONLY
                            // SAFE WINDOW IN THE RUN for it. `Session::recv`'s `Cancel`
                            // arm calls `signer.clear_tmp_data()`, which drops the keygen
                            // tmp maps; sent any later it would break the ceremony every
                            // other assertion depends on, and the stub turns a
                            // non-`Refused` fault into `die(2, ..)` rather than a phase
                            // failure. Here the signer has no keygen in flight — the
                            // keygen is begun below, gated on `announced.len() ==
                            // N_DEVICES` — so `clear_tmp_data` is a PROVABLE no-op and
                            // the ONLY observable effect of the frame is the one under
                            // test: `self.pending_name = None`.
                            //
                            // This is the app's own sequence, not a harness invention:
                            // `frostsnapp/lib/device_setup.dart` calls
                            // `updateNamePreview` from the name field's `onChanged` and
                            // `sendCancel(id)` when the sheet is popped, so
                            // preview-then-cancel-one-device is what a human abandoning
                            // the naming sheet produces.
                            //
                            // `Cancel` FIRST for the recovered device. It has nothing to
                            // clear yet, so the preview that follows must survive — see
                            // `name_recovered`.
                            if name_recovered == Some(from) {
                                let cancel =
                                    CoordinatorSendMessage::to(from, CoordinatorSendBody::Cancel);
                                if let Err(e) =
                                    send_frame(&wtx, ReceiveSerial::Message(cancel.into()))
                                {
                                    break Err(e.context("Cancel (before the preview)"));
                                }
                                writes_queued += 1;
                            }
                            let preview = CoordinatorSendMessage::to(
                                from,
                                CoordinatorSendBody::Naming(NameCommand::Preview(
                                    preview_name.clone(),
                                )),
                            );
                            if let Err(e) = send_frame(&wtx, ReceiveSerial::Message(preview.into()))
                            {
                                break Err(e.context("Naming(Preview)"));
                            }
                            writes_queued += 1;
                            // And `Cancel` AFTER the preview for the cancelled device:
                            // the same two frames in the other order, which must drop
                            // the name this device would otherwise commit during keygen.
                            if name_cancelled == Some(from) {
                                let cancel =
                                    CoordinatorSendMessage::to(from, CoordinatorSendBody::Cancel);
                                if let Err(e) =
                                    send_frame(&wtx, ReceiveSerial::Message(cancel.into()))
                                {
                                    break Err(e.context("Cancel (after the preview)"));
                                }
                                writes_queued += 1;
                            }
                            // ============================== M12 ==============================
                            // TEN devices on the wire, NINE in the keygen. The gate is
                            // `ALL_DEVICES` so that the roster is a DECISION taken once
                            // all ten ids are known, rather than a race: at
                            // `== N_DEVICES` the roster was whichever nine announced
                            // first, which is deterministic here only because the stub
                            // writes its announces in `DeviceId` order out of a
                            // `BTreeMap` — MEASURED, by running the tenth device against
                            // the old gate: keygen began on the 9th announce and the run
                            // failed at the fail-closed `None =>` arm 1.76 s in.
                            //
                            // The blank device is slot N_DEVICES, and that slot is not
                            // free: M10's differential assigns `name_cancelled` on the
                            // FIRST announce and `name_recovered` on the second, and
                            // requires `cancelled` to report no name. A blank device in
                            // slot 0 never receives a `FinalizeKeyGen`, so it never runs
                            // `commit_name` and would report no name whatever `Cancel`
                            // did — M10's first bail would pass VACUOUSLY and the bail
                            // that exists to catch exactly that (`THE M10 DIFFERENTIAL IS
                            // VACUOUS`) would never fire. Slot 9 is neither subject.
                            //
                            // Deliberately not an `is_blank(id)` predicate: a predicate
                            // makes the slot invisible at this site, and this site is
                            // where the pairing with M10 has to be readable.
                            if announced.len() == ALL_DEVICES && keygen.is_none() {
                                roster = announced[..N_DEVICES].to_vec();
                                blank = announced.get(N_DEVICES).copied();
                                let begin = BeginKeygen::new(
                                    roster.clone(),
                                    THRESHOLD,
                                    "cold-snap M3".to_string(),
                                    KeyPurpose::Test,
                                    &mut rng,
                                );
                                let id = begin.keygen_id;
                                eprintln!(
                                    "hostcheck: begin_keygen {THRESHOLD}-of-{N_DEVICES} \
                                     (keygen_id {id}) after {:?}; M12: {:?} is LEFT OUT and \
                                     stays blank",
                                    started.elapsed(),
                                    blank
                                );
                                match coordinator.begin_keygen(begin, &mut rng) {
                                    Ok(sends) => queue.extend(sends),
                                    Err(e) => break Err(anyhow::anyhow!("begin_keygen: {e}")),
                                }
                                keygen = Some(Keygen {
                                    id,
                                    got_shares: 0,
                                    acks: 0,
                                    session_hash: None,
                                    finished: None,
                                });
                            }
                        }
                        DeviceSendBody::Core(core) => {
                            // THE DEVICE HALF OF THE PROOF, and the reason this
                            // arm exists. Until 2026-08-18 the device's claim to
                            // have stored a share crossed the process boundary as
                            // one bit -- its exit status -- decided by the same
                            // process the claim is about. A stub that read
                            // `Finalize`, persisted nothing and exited 0 PASSED
                            // (mutation d4). Now the coordinator asks, over the
                            // wire, and compares.
                            if let DeviceToCoordinatorMessage::Restoration(
                                DeviceRestoration::HeldShares2(shares),
                            ) = &core
                            {
                                let want = keygen
                                    .as_ref()
                                    .and_then(|k| k.finished)
                                    .expect("HeldShares2 only requested after finalize");
                                // ============================== M11 ==============================
                                // The SAVED BACKUP's own entry, which is a DIFFERENT
                                // `HeldShare2` from the keygen one below and is found by
                                // `needs_consolidation` rather than by the access
                                // structure ref: `held_shares()`' `backups_iter` sets
                                // `access_structure_ref: None` and
                                // `needs_consolidation: true`, so the `find` below
                                // cannot see it and this cannot see the keygen entry.
                                // That separation is what makes the threshold a fact
                                // about the v1 body and not about the real access
                                // structure — see [`V1_THRESHOLD`].
                                if let Some(r) = restore.as_mut() {
                                    if r.phase == Phase::SavedV1 && from == r.device {
                                        r.saved_v1_threshold = Some(
                                            shares
                                                .iter()
                                                .find(|s| s.needs_consolidation)
                                                .and_then(|s| s.threshold),
                                        );
                                    }
                                }
                                match shares
                                    .iter()
                                    .find(|s| s.access_structure_ref == Some(want))
                                {
                                    Some(s) => {
                                        eprintln!(
                                            "hostcheck: {from} REPORTS holding {want:?} \
                                             (threshold={:?}, {} share(s) total)",
                                            s.threshold,
                                            shares.len()
                                        );
                                        held.insert(from);
                                        // ================== M7e's TEETH ==================
                                        // The device describing the record it wrote
                                        // AFTER the consolidation replaced it -- and
                                        // this time the SHARE IMAGE is compared, not
                                        // just the access structure ref.
                                        //
                                        // That distinction is the whole point of asking
                                        // twice. `FinishedConsolidation` says the device
                                        // applied the mutation; the ref alone says it
                                        // wrote a record for the right wallet. Only the
                                        // image says it wrote THIS DEVICE'S share at
                                        // THIS index -- and consolidation is the one
                                        // flow that re-encrypts a share under a fresh
                                        // derivation and overwrites the single record
                                        // the store keeps, so a swap here is a silently
                                        // unspendable wallet with no second copy.
                                        if let Some(r) = restore.as_mut() {
                                            if r.phase == Phase::Reheld && from == r.device {
                                                let expect_image = coordinator
                                                    .expected_share_image(
                                                        want,
                                                        r.share_index,
                                                        ENCRYPTION_KEY,
                                                    );
                                                if expect_image != Some(s.share_image) {
                                                    break Err(anyhow::anyhow!(
                                                        "M7e: after CONSOLIDATING, {from} reports \
                                                         holding share image {:?}, but this \
                                                         coordinator's root shared key says index \
                                                         {:?} is {expect_image:?} -- the signer's \
                                                         state after the consolidation is not this \
                                                         device's share at this index. (This \
                                                         compares the signer over the wire, NOT the \
                                                         flash record: the reply is a RAM read. The \
                                                         message said \"the destructive write \
                                                         replaced the record with the wrong share\" \
                                                         until 2026-09-12, which attributed it to a \
                                                         read that does not happen.)",
                                                        s.share_image,
                                                        r.share_index
                                                    ));
                                                }
                                                r.reheld = true;
                                            }
                                        }
                                    }
                                    // ============================ M12 ============================
                                    // THE ONE PLACE A TENTH DEVICE MAKES AN EXISTING
                                    // ASSERTION WEAKER, loosened as narrowly as it can
                                    // be. Three scopes, all by IDENTITY or by STATE and
                                    // not one of them by count:
                                    //
                                    //  - `Some(from) == blank`: the nine keygen devices
                                    //    keep the untouched bail below, byte for byte.
                                    //    Scoped by the id this run itself left out of
                                    //    `BeginKeygen`, so it cannot drift with a count.
                                    //  - `restore.is_none()`: this is the PRE-SIGNATURE
                                    //    round trip and NOT `Phase::Reheld`'s. The blank
                                    //    device is asked twice, and the SECOND time it
                                    //    MUST report the share it just consolidated —
                                    //    which is the very thing M12 exists to prove, so
                                    //    an exemption keyed only on the id would swallow
                                    //    it and fail OPEN. `restore` is built only once
                                    //    `sign.signatures.is_some()`, so this is true
                                    //    here and false at Reheld; a future edit moving
                                    //    that construction earlier would TIGHTEN this
                                    //    arm, which is the fail-closed direction.
                                    //  - `shares.is_empty()`: a blank device reporting
                                    //    ANYTHING falls through to the bail below. This
                                    //    is the guard rather than a separate assert
                                    //    deliberately — "the blank device's HeldShares2
                                    //    is empty" is unreachable otherwise in this tree
                                    //    (the round trip precedes any
                                    //    `SavePhysicalBackup2`, so `keys` is empty), so
                                    //    as a standalone `bail!` it could not fail and
                                    //    would read like coverage. As a PATTERN it makes
                                    //    every other shape fail closed.
                                    None if Some(from) == blank
                                        && restore.is_none()
                                        && shares.is_empty() =>
                                    {
                                        blank_reported_empty = true;
                                        eprintln!(
                                            "hostcheck: M12 -- {from} was LEFT OUT of the keygen \
                                             and reports holding NOTHING AT ALL (0 shares), so \
                                             the {want:?} it is about to be handed on paper is a \
                                             share it cannot already have"
                                        );
                                    }
                                    None => {
                                        break Err(anyhow::anyhow!(
                                            "{from} reported {} held share(s), NONE for the \
                                             access structure keygen just finished ({want:?}) \
                                             -- the device did not store what it acked",
                                            shares.len()
                                        ))
                                    }
                                }
                            }
                            match coordinator.recv_device_message(from, core) {
                                Ok(sends) => queue.extend(sends),
                                Err(e) => {
                                    break Err(anyhow::anyhow!(
                                        "recv_device_message from {from} in {}: {e}",
                                        state.name()
                                    ))
                                }
                            }
                        }
                        // The device's own report of two things the protocol has no
                        // field for: the session hash it computed, and a refusal.
                        // Parsed here rather than forwarded, so the coordinator's
                        // state machine never sees it.
                        DeviceSendBody::Debug { message } => {
                            match message.split_once('=') {
                                Some(("session_hash", value)) => {
                                    eprintln!("hostcheck: {from} says session_hash={value}");
                                    device_hashes.insert(from, value.to_string());
                                }
                                // ASSERTION 1's raw material: the 8 hex characters
                                // the device's keygen-check SCREEN actually drew,
                                // read back off the framebuffer over there. Not
                                // trusted here — compared at PASS.
                                Some(("glass", value)) => {
                                    eprintln!(
                                        "hostcheck: {from} says its GLASS shows {value}"
                                    );
                                    device_glass.insert(from, value.to_string());
                                }
                                // ASSERTION 2's raw material. The protocol has no
                                // decline variant, so a "no" can only ever arrive
                                // as this plus silence where a share would be —
                                // which is why the pass checks BOTH halves.
                                Some(("declined", what)) => {
                                    eprintln!(
                                        "hostcheck: {from} DECLINED {what} at the glass"
                                    );
                                    if what == "SignatureRequest" {
                                        declined.insert(from);
                                    }
                                }
                                Some(("refused", what)) => {
                                    eprintln!(
                                        "hostcheck: {from} REFUSED {what} (a frame our own \
                                         coordinator never asked for)"
                                    );
                                    if what == "DataErase" {
                                        refused_erase.insert(from);
                                        // M9's second half. Scoped to the phase and the
                                        // device on purpose — see
                                        // [`Restore::erase_refusals`]: the set above is
                                        // already full from the forged frame, so only a
                                        // refusal that arrives WHILE the driver is open
                                        // says anything about the driver.
                                        if let Some(r) = restore.as_mut() {
                                            if r.phase == Phase::Erase && from == r.device {
                                                r.erase_refusals += 1;
                                            }
                                        }
                                    }
                                    // A REFUSAL OF A FRAME THIS COORDINATOR DID ASK FOR
                                    // IS A FAILURE, and until now it was only a log line.
                                    // MEASURED: a device made to refuse the legacy
                                    // `SavePhysicalBackup` printed this and the run then
                                    // sat out the whole 95 s `BackupIngest` budget and
                                    // died with `DEADLINE ... in state BackupIngest`,
                                    // which names the state and not the cause. The
                                    // refusal was on the wire the entire time.
                                    //
                                    // Scoped to the RESTORE DEVICE and to the phases that
                                    // are waiting on a save, for the reason
                                    // [`Restore::erase_refusals`] documents: `DataErase`
                                    // is refused by design and by every device, so an
                                    // unscoped check here could never pass at all.
                                    else if let Some(r) = restore.as_mut() {
                                        if from == r.device
                                            && matches!(
                                                r.phase,
                                                Phase::Ingest | Phase::SavedV1
                                            )
                                        {
                                            break Err(anyhow::anyhow!(
                                                "{from} REFUSED {what} while this coordinator \
                                                 was in {:?} WAITING for it -- the phase can \
                                                 never complete, so failing here rather than \
                                                 at the deadline, which would have named the \
                                                 state and not the cause",
                                                r.phase
                                            ));
                                        }
                                    }
                                }
                                // M7b's raw material: the share index and the 25 words
                                // the device's BACKUP PAGES actually drew, recovered
                                // over there from the framebuffer with the shipped
                                // `ui::Frame::cell` — the exact inverse of the `text`
                                // that drew them. Not trusted here: `check_glass_words`
                                // re-encodes them with UPSTREAM's
                                // `ShareBackup::from_words` and compares the resulting
                                // share image against this coordinator's own.
                                Some(("glassindex", value)) => {
                                    if let Some(r) = restore.as_mut() {
                                        match value.parse::<u32>() {
                                            Ok(index) => r.glass_index = Some(index),
                                            Err(e) => {
                                                break Err(anyhow::anyhow!(
                                                    "{from} drew share index {value:?} on its \
                                                     backup page: {e}"
                                                ))
                                            }
                                        }
                                    }
                                }
                                Some(("glasswords", value)) => {
                                    eprintln!("hostcheck: {from} GLASS drew {value}");
                                    if let Some(r) = restore.as_mut() {
                                        for pair in value.split_whitespace() {
                                            let Some((number, word)) = pair.split_once(':') else {
                                                break;
                                            };
                                            match number.parse::<usize>() {
                                                Ok(n) => {
                                                    r.glass_words.insert(n, word.to_string());
                                                }
                                                // Not fatal here on purpose: the
                                                // position count is checked whole by
                                                // `check_glass_words`, which names the
                                                // gap. A bail here would report a
                                                // parse error where the fact is "the
                                                // reveal did not draw word 17".
                                                Err(_) => eprintln!(
                                                    "hostcheck: {from} drew an unparseable word \
                                                     label {number:?}"
                                                ),
                                            }
                                        }
                                    }
                                }
                                // M7c: the device's own count of quiz answers. A pass
                                // in exactly `quiz::QUIZ_POSITIONS` means every
                                // question was right FIRST TIME, because a wrong
                                // answer re-asks the same position.
                                Some(("quiz", value)) => {
                                    eprintln!("hostcheck: {from} answered {value} quiz question(s)");
                                    if let Some(r) = restore.as_mut() {
                                        r.quiz_answers = value.parse().ok();
                                    }
                                }
                                // M7d, for the log: how many keypresses the letter
                                // picker took. A property of the picker, not a claim.
                                Some(("typed", value)) => {
                                    eprintln!(
                                        "hostcheck: {from} typed the share back in in {value} \
                                         keypress(es)"
                                    );
                                    if let Some(r) = restore.as_mut() {
                                        r.typed = value.parse().ok();
                                    }
                                }
                                _ => eprintln!("hostcheck: device debug from {from}: {message}"),
                            }
                        }
                        // M7a: `CommsMisc` is the only body upstream's `UiProtocol`
                        // takes through `process_comms_message`, and until now this
                        // loop dropped it into the `other` arm below. Both flows that
                        // need it complete on one of these — `BackupRecorded` for the
                        // reveal, `BackupChecked` for the quiz — so an unclaimed one is
                        // a `CommsMisc` no live driver wanted, which is worth a line
                        // rather than a silent drop.
                        DeviceSendBody::Misc(misc) => {
                            eprintln!("hostcheck: {from} MISC {}", misc.gist());
                            if let (Some(r), CommsMisc::BackupChecked { .. }) = (restore.as_mut(), &misc)
                            {
                                r.checked = true;
                            }
                            let claimed = ui
                                .as_mut()
                                .is_some_and(|p| p.process_comms_message(from, misc.clone()));
                            if !claimed {
                                eprintln!(
                                    "hostcheck: WARNING no live UiProtocol claimed {} from {from}",
                                    misc.gist()
                                );
                            }
                        }
                        // ============================== M8 ==============================
                        // `SetName` ARRIVING IS THE EVIDENCE THE FLASH WRITE SUCCEEDED,
                        // and that is a property of the device's ordering rather than an
                        // inference: `commit_name` calls `NameStore::save` and pushes
                        // this body only if that returned `Ok`, persist strictly before
                        // ack (`firmware/src/lib.rs`, and the same ordering the share
                        // uses). A device that acked a name it could not store has no way
                        // to send this at all — the `?` on the save returns first and the
                        // outbox stays empty.
                        //
                        // HONEST LIMIT, stated here because the log line reads stronger
                        // than the fact: the stub restarts — drops every session and
                        // rebuilds them from the same flash bytes — immediately after
                        // ANNOUNCING and BEFORE keygen, so there is no second restart
                        // after this name is persisted. So this proves the write landed
                        // before the ack; it does NOT prove the name survives a power
                        // cycle. That would need a restart the stub does not do, and this
                        // harness may not add one.
                        // M8's trigger, and it stopped being ignored: this is the device
                        // saying it has NO durable name, sent from `Session::announce` in
                        // the same burst as the `Announce` itself.
                        DeviceSendBody::NeedName => {
                            need_name.insert(from);
                        }
                        DeviceSendBody::SetName { name } => {
                            // The device announced `SetName` instead of `NeedName`, i.e.
                            // it read a name off flash at boot. Then this frame is an
                            // announce-time echo and says nothing about `commit_name`, so
                            // the assertions below would be measuring a pre-seeded flash
                            // image. Impossible with today's stub (its `FakeFlash` holds
                            // only the identity), which is exactly why it is worth
                            // pinning: the whole M8 claim rests on it.
                            if !need_name.contains(&from) {
                                break Err(anyhow::anyhow!(
                                    "{from} reported the name {:?} without ever having sent \
                                     NeedName -- `Session::announce` sends one or the other, so \
                                     this SetName is an announce-time echo of a name that was \
                                     already on flash and NOT evidence that this run committed \
                                     one",
                                    name.as_str()
                                ));
                            }
                            eprintln!(
                                "hostcheck: {from} says its NAME is now {:?} ({} chars, {} bytes) \
                                 -- so NameStore::save returned Ok before this frame",
                                name.as_str(),
                                name.as_str().chars().count(),
                                name.as_str().len()
                            );
                            device_names.insert(from, name.as_str().to_string());
                        }
                        other => eprintln!("hostcheck: ignoring {other:?}"),
                    }
                }
                // Extra device MAGIC_REPLYs decode as MagicBytes once linked;
                // Conch/Reset are not errors either.
                Ok(Some(_)) | Ok(None) => {}
                // A frame that never completes stalls inside bincode for the
                // whole PORT_TIMEOUT and surfaces here as an io DecodeError, not
                // as Ok(None). Swallowing it is what makes the deadline hard: the
                // longest this loop can be away from the deadline check is one
                // PORT_TIMEOUT. NOT a recovery -- the partial frame's bytes are
                // already consumed, so the run will fail; it fails on the
                // deadline, by name, within 250 ms of the stall.
                Err(e) if is_read_timeout(&e) => read_timeouts += 1,
                Err(e) => {
                    break Err(anyhow::anyhow!(
                        "try_read_message in {}: {e}",
                        state.name()
                    ))
                }
            },
        }

        // M7a: the `poll()` leg of the five-call lifecycle, fed into the SAME
        // `send_frame` every keygen and signing frame goes through — so a driver's
        // messages are bounded by the same `WRITE_STALL_LIMIT` and counted by the same
        // `writes_queued`. Drained every lap because that is the contract: `poll` is
        // how a `UiProtocol` reaches the wire at all, and two of the three only send on
        // the lap after `connected()`.
        let mut poll_err: Option<anyhow::Error> = None;
        if let Some(p) = ui.as_mut() {
            for msg in p.poll() {
                eprintln!("hostcheck: -> {} (UiProtocol)", msg.gist());
                if let Err(e) = send_frame(&wtx, ReceiveSerial::Message(msg.into())) {
                    poll_err = Some(e);
                    break;
                }
                writes_queued += 1;
            }
        }
        if let Some(e) = poll_err {
            break Err(e.context(format!("UiProtocol frame in {}", state.name())));
        }

        // Drain whatever the coordinator wants to say, then re-derive the state
        // from what it has told the user. Derived in ONE place on purpose: the
        // ordering of `ReceivedShares`/`CheckKeyGen`/`KeyGenAck` is the
        // coordinator's business, not ours.
        if let Some(kg) = keygen.as_mut() {
            if let Err(e) = pump(
                &mut queue,
                &wtx,
                &mut writes_queued,
                &mut coordinator,
                &mut rng,
                kg,
                &mut sign,
                &mut ui,
                &mut restore,
            ) {
                break Err(e.context(format!("pump in {}", state.name())));
            }
            state = if kg.finished.is_some() {
                State::KeygenAwaitingDeviceSave
            } else if kg.session_hash.is_some() || kg.acks > 0 {
                State::KeygenAwaitingAcks
            } else if kg.got_shares == N_DEVICES {
                State::KeygenAwaitingSessionHash
            } else {
                State::KeygenAwaitingShares
            };

            // Keygen has finished coordinator-side. Do NOT take the stub's word
            // for the device half: ask each device what it holds and compare.
            // `request_held_shares` is a real protocol message
            // (`CoordinatorRestoration::RequestHeldShares`), so this is a
            // round-trip, not a harness back-channel -- and it exercises
            // `HeldShares2`, one of the four frames the old 2,060 bound refused.
            if let Some(want) = kg.finished {
                if !requested_held {
                    requested_held = true;
                    // ============================== M12 ==============================
                    // THE ROSTER CHECK, and it lives HERE rather than at PASS because
                    // this is the last lap on which it can still fail. By PASS the
                    // blank device is IN `found.devices()`: leg 2's
                    // `FinishedConsolidation` makes the coordinator apply
                    // `KeyMutation::NewShare { device_id: blank, .. }`, whose apply is
                    // `device_to_share_index.insert`, and `AccessStructure::devices()`
                    // is that map's keys. Changing the PASS-block count to
                    // `ALL_DEVICES` and calling it the roster check would therefore
                    // have DELETED the only check that the keygen finalized with the
                    // right roster — the one silent weakening this whole item risks.
                    //
                    // Both halves are falsifiable, and by the SAME one-line mutation:
                    // pass `announced.clone()` to `BeginKeygen::new` above and this
                    // bails by name at finalize.
                    let found = coordinator
                        .iter_access_structures()
                        .find(|a| a.access_structure_ref() == want);
                    let (n_devices, has_blank) = match found {
                        Some(a) => (
                            a.devices().count(),
                            blank.is_some_and(|b| a.contains_device(b)),
                        ),
                        None => {
                            break Err(anyhow::anyhow!(
                                "{want:?} came out of finalize_keygen and is not in the \
                                 coordinator"
                            ))
                        }
                    };
                    if n_devices != N_DEVICES || has_blank {
                        break Err(anyhow::anyhow!(
                            "THE KEYGEN FINALIZED WITH THE WRONG ROSTER: {want:?} has {n_devices} \
                             device share(s), expected {N_DEVICES}, and the device this run left \
                             OUT ({blank:?}) is{} in it. The roster is this coordinator's own \
                             choice at `BeginKeygen`, so a mismatch means the ceremony ran over a \
                             different set of devices than the one asked for",
                            if has_blank { "" } else { " not" }
                        ));
                    }
                    // OVER ALL TEN, deliberately. This is the ONLY wire evidence that
                    // the tenth device holds nothing, and without it the blank
                    // configuration would be a harness claim rather than a measured
                    // fact. It is also what forces the narrowed `None =>` arm below.
                    for id in &announced {
                        queue.extend(coordinator.request_held_shares(*id));
                    }
                    eprintln!(
                        "hostcheck: keygen FINISHED {want:?} with the {N_DEVICES}-device roster \
                         and WITHOUT {blank:?}; asking {} device(s) what they hold",
                        announced.len()
                    );
                }
                state = State::KeygenAwaitingHeldShares;
            }

            // ============================ M5 ============================
            // Every device has reported the coordinator's own access structure,
            // so keygen is proven at both ends. Now: nonces, then a signature.
            //
            // Nonces FIRST is the protocol's ordering, not a preference:
            // `start_sign` fails outright with `NotEnoughNoncesForDevice` if the
            // cache is empty, so this sequencing is enforced by the coordinator.
            // ==================== THE LYING COORDINATOR ====================
            // A frame the `FrostCoordinator` state machine NEVER produced, pushed
            // through the same seam the `AnnounceAck` above uses
            // (`CoordinatorSendMessage::to` + `send_frame`). No fork of
            // `frostsnap_coordinator` and no byte-patching: upstream's own encoder
            // writes it.
            //
            // `DataErase` is the lie because obeying it destroys the shares the
            // devices JUST reported holding -- so the assertion is two-sided and
            // both sides are load-bearing: every device must report the refusal,
            // AND the signature below must still verify, which it cannot if any
            // device took the frame seriously.
            //
            // Sent here, after `HeldShares2` and before the nonce round trip, so a
            // device that obeyed has already told us it had something to lose.
            //
            // M12: the ROSTER, not all ten. `refused_erase.len() != N_DEVICES` at PASS
            // is an EXACT count and every device refuses `DataErase` unconditionally, so
            // a tenth entry FAILS the run — and the claim this makes is about devices
            // that had something to lose, which the blank one does not. Both halves of
            // the two-sided assertion stay exactly as strong.
            if held.len() == N_DEVICES && !lied {
                lied = true;
                let sent = roster.iter().try_for_each(|id| {
                    send_frame(
                        &wtx,
                        ReceiveSerial::Message(
                            CoordinatorSendMessage::to(*id, CoordinatorSendBody::DataErase).into(),
                        ),
                    )
                });
                if let Err(e) = sent {
                    break Err(e.context("forged DataErase"));
                }
                // `roster.len()` and not `announced.len()`: over-counting by one here
                // corrupts the WRITE STALL message's `frame {}/{writes_queued}`.
                writes_queued += roster.len();
                eprintln!(
                    "hostcheck: FORGED DataErase to {} device(s) -- every one must refuse it \
                     and still be able to sign",
                    roster.len()
                );
            }

            if held.len() == N_DEVICES && !sign.requested_nonces {
                sign.requested_nonces = true;
                // M12: the ROSTER. The blank device has durable nonce slots on its blank
                // flash and would happily replenish, which costs a MEASURED 2,040 B frame
                // plus 30 debug-build nonce derivations and pushes
                // `sign.replenished.len()` to 10 against the `== N_DEVICES` gate below.
                // Both counts stay exact.
                let devices: std::collections::BTreeSet<DeviceId> =
                    roster.iter().copied().collect();
                queue.extend(coordinator.maybe_request_nonce_replenishment(
                    &devices,
                    NONCE_STREAMS,
                    &mut rng,
                ));
                eprintln!(
                    "hostcheck: requesting {NONCE_STREAMS} nonce stream(s) from {} device(s) -- \
                     each reply is a ~2,040 B frame, the first over 1 KB to cross this pty",
                    devices.len()
                );
            }

            // Every device replenished => start signing. `start_sign` is itself
            // the assertion that the nonces landed: it reads the nonce cache the
            // `NonceResponse`s filled, and cannot succeed on an empty one.
            if sign.requested_nonces
                && sign.replenished.len() == N_DEVICES
                && sign.session_id.is_none()
            {
                let want = kg
                    .finished
                    .expect("nonces are only requested after finalize");
                // THRESHOLD of N, not all N: signing with a strict subset is what
                // selects the signer subset; at THRESHOLD == N_DEVICES that is everyone
                // IN THE ROSTER. Taken from `roster` and not `announced`: numerically
                // identical today, and it stays true if THRESHOLD ever drops below
                // N_DEVICES, where `announced` would start admitting the blank device.
                sign.signers = roster.iter().copied().take(THRESHOLD as usize).collect();
                match coordinator.start_sign(want, sign_task(), &sign.signers, &mut rng) {
                    Ok(id) => {
                        eprintln!(
                            "hostcheck: start_sign {id} over {SIGN_MESSAGE:?} with {} of \
                             {N_DEVICES} device(s): {:?}",
                            sign.signers.len(),
                            sign.signers
                        );
                        sign.session_id = Some(id);
                        for device in sign.signers.clone() {
                            queue.push_back(CoordinatorSend::from(
                                coordinator.request_device_sign(id, device, ENCRYPTION_KEY),
                            ));
                        }
                    }
                    Err(e) => break Err(anyhow::anyhow!("start_sign: {e}")),
                }
            }

            // The coordinator has aggregated. Verification happens below, OUTSIDE
            // the loop, and the pass hinges on it -- not on getting here.
            match expect {
                // ============================ M7 ============================
                // The signature EXISTS, so trap 1 is satisfied: the 64 bytes are
                // already fixed and nothing below can change them. Only now may the
                // restoration flows run, because M7e REPLACES the one share record this
                // device keeps and at t == n == 9 the signing pass needed it.
                //
                // The signature is still VERIFIED below, outside the loop, on the same
                // `sign.signatures` -- so the pass still hinges on the verification and
                // not on the arrival of `Signed`, exactly as before.
                Expect::Signature => {
                    if sign.signatures.is_some() {
                        if restore.is_none() && sighted.is_none() {
                            // One device, and the FIRST to announce -- deterministic,
                            // because the stub writes its announces in `DeviceId`
                            // order out of a `BTreeMap`. `roster.first()` and not
                            // `announced.first()`: identical today, and it is the
                            // roster this leg's four flows need a share from.
                            let device = match roster.first() {
                                Some(id) => *id,
                                None => break Err(anyhow::anyhow!("a signature with no devices")),
                            };
                            let want = match kg.finished {
                                Some(want) => want,
                                None => {
                                    break Err(anyhow::anyhow!("a signature with no access structure"))
                                }
                            };
                            let share_index = coordinator
                                .iter_access_structures()
                                .find(|a| a.access_structure_ref() == want)
                                .and_then(|a| a.device_to_share_indicies().get(&device).copied());
                            let share_index = match share_index {
                                Some(index) => index,
                                None => {
                                    break Err(anyhow::anyhow!(
                                        "{device} has no share index in {want:?}"
                                    ))
                                }
                            };
                            let digest = match digests.get(&device) {
                                Some(digest) => *digest,
                                None => {
                                    break Err(anyhow::anyhow!("{device} announced no digest"))
                                }
                            };
                            restore = Some(Restore::new(device, share_index, digest, Phase::Erase));
                        }
                        let r = restore.as_mut().expect(
                            "restore is Some here: it is built above when both legs are unstarted, \
                             and leg 1's `take` below refills it on the same lap",
                        );
                        state = r.phase.state();
                        if let Err(e) = restore_step(
                            &mut coordinator,
                            &mut queue,
                            &mut rng,
                            &mut ui,
                            r,
                            kg.finished.expect("a signature implies an access structure"),
                            // ============================== M12 ==============================
                            // `&& sighted.is_none()` keeps M11's v1 downgrade on LEG 1
                            // only, so leg 2 never enters `Phase::SavedV1` and M11 does
                            // not move at all. Leg 2's restoration is a DIFFERENT one
                            // with a different `RestorationId`, and its `HeldShare2` for
                            // the saved backup carries whatever v2 body it was sent —
                            // MEASURED by passing `save_v1` unchanged, and the OUTCOME is
                            // not the one first recorded here. That said the run "hangs
                            // there to `DEADLINE (95s) in state BackupIngest`"; review
                            // traced it on 2026-09-12 and it does not. Leg 2 enters
                            // `Phase::SavedV1`, reports ONLY the saved backup, and the
                            // UNTOUCHED fail-closed `None =>` arm bails by name —
                            // `reported 1 held share(s), NONE for the access structure
                            // keygen just finished` — exit 1 in 9 s on the chunk-1 pass.
                            // That is `restore.is_none()` doing its job a second time, and
                            // it is a better failure than a deadline: it names the cause.
                            save_v1 && sighted.is_none(),
                        ) {
                            break Err(e.context(format!("M7 {:?}", r.phase)));
                        }
                        // Copied out before the borrow of `restore` ends: the handoff
                        // below moves the whole `Option`.
                        let phase = r.phase;
                        if phase == Phase::Done {
                            if sighted.is_some() {
                                break Ok(());
                            }
                            // ========================= M12 =========================
                            // THE SECOND LEG, and the whole item. Leg 1 is retired into
                            // `sighted` — every M7b/M7c fact at PASS is read from there,
                            // because leg 2 sits no quiz and reads no glass — and
                            // `restore` is rebuilt for the BLANK device at
                            // `Phase::Ingest`.
                            //
                            // ONE SLOT, deliberately: every per-message handler that does
                            // `restore.as_mut()` follows the live leg with no change at
                            // all, and there is no second `UiProtocol` alive at any
                            // moment (the SETTLED "one boxed UiProtocol at a time").
                            //
                            // THE SHEET IS THE HANDOFF. The blank device has no reveal of
                            // its own, so the 25 words it types come from leg 1's — over
                            // there `sheet_read` hands it the single sheet in the room,
                            // which is the harness's stand-in for a human carrying a
                            // piece of paper between two units. That is why leg 2 is
                            // given LEG 1's `share_index`: it is not a share this device
                            // holds, it is the index of the share it is being GIVEN, and
                            // `check_physical_backup` derives the same index from the
                            // words themselves.
                            //
                            // `digest` is leg 2's OWN announced digest, not leg 1's. Only
                            // `Phase::Quiz` reads it and leg 2 never enters that phase,
                            // but the blank device did announce one and the honest value
                            // is cheaper than explaining a borrowed one.
                            // `expect` and not a `bail`, because control flow already makes
                            // it a precondition: standing here needs a signature, which
                            // needs a keygen, and `blank` is cut out of the same
                            // expression as the roster on the lap keygen begins. A bail
                            // here would read like coverage.
                            let blank = blank.expect(
                                "a signature implies a keygen, and the roster and the blank id \
                                 come out of ONE expression on the lap keygen begins",
                            );
                            let digest = match digests.get(&blank) {
                                Some(digest) => *digest,
                                None => break Err(anyhow::anyhow!("{blank} announced no digest")),
                            };
                            let leg1 = restore.take().expect("just borrowed it");
                            let share_index = leg1.share_index;
                            eprintln!(
                                "hostcheck: M12 -- leg 1 at {} is DONE; handing its sheet to the \
                                 BLANK device {blank} and asking IT to type share {share_index:?} \
                                 in, save it and consolidate it onto a flash that holds nothing",
                                leg1.device
                            );
                            sighted = Some(leg1);
                            restore =
                                Some(Restore::new(blank, share_index, digest, Phase::Ingest));
                            // `ui` is already None: `Phase::Consolidate` retired the last
                            // driver through `advance`, and the new `Restore` has
                            // `started: false`, so leg 2 builds its own.
                        }
                    }
                }
                Expect::Decline => {
                    // ASSERTION 2, and this is the sharp end of it: every device
                    // said no and the coordinator aggregated anyway, which means
                    // `x` did not refuse. Caught HERE rather than after the loop
                    // because there is nothing left to wait for.
                    if sign.signatures.is_some() {
                        break Err(anyhow::anyhow!(
                            "A DECLINED PROMPT PRODUCED A SIGNATURE: {}/{N_DEVICES} device(s) \
                             reported declining the SignatureRequest and the coordinator still \
                             aggregated from {} share(s) -- pressing `x` does not refuse",
                            declined.len(),
                            sign.got_shares.len()
                        ));
                    }
                    // Everyone has said no. Keep reading for the grace period
                    // before believing the absence of a share (see DECLINE_GRACE),
                    // then this pass is done -- there is no point sitting out the
                    // 65 s signing budget for a signature that must not come.
                    if declined.len() == N_DEVICES
                        && all_declined_at
                            .get_or_insert_with(Instant::now)
                            .elapsed()
                            > DECLINE_GRACE * timeout_scale()
                    {
                        break Ok(());
                    }
                }
            }
            // `restore` is `Some` only past a verified-able signature, and it owns the
            // state name from then on — the arm above set it from `Phase`. Without this
            // guard the two writers race and the deadline message says
            // `SigningAwaitingShares` for a stall inside the check quiz, which is the
            // wrong diagnosis with the right timestamp.
            if restore.is_none() {
                if sign.session_id.is_some() {
                    state = State::SigningAwaitingShares;
                } else if sign.requested_nonces {
                    state = State::NonceReplenish;
                }
            }

            // A stub that dies before the run is done is still a failure, and must
            // not be waited on forever. It is only allowed to exit at the very
            // end, when WE close the pty -- which by then has already happened,
            // because the pass breaks out of this loop above.
            if let Ok(Some(status)) = child.0.try_wait() {
                break Err(anyhow::anyhow!(
                    "stub exited {status} in {} having reported {}/{N_DEVICES} held shares, \
                     {}/{N_DEVICES} nonce replenishments and {}/{} signature shares",
                    state.name(),
                    held.len(),
                    sign.replenished.len(),
                    sign.got_shares.len(),
                    sign.signers.len(),
                ));
            }
        }

        // Publish again before sleeping: `state` may have advanced during this
        // lap, and the watchdog reports ONLY what was last published. MEASURED
        // that this matters: with the publish at the top of the lap only, a
        // stall injected right after the magic->announce transition was reported
        // as `WaitingForMagic` -- one state stale, i.e. the wrong diagnosis.
        state.publish();

        // The read paths return immediately when the port is empty, so without
        // this the loop is a hot spin.
        std::thread::sleep(Duration::from_millis(2));
    };

    WATCHDOG_AT_MS.store(0, Ordering::Relaxed);

    match outcome {
        Ok(()) => {
            let kg = keygen.expect("PASS implies a keygen was started");
            let as_ref = kg.finished.expect("PASS implies finalize_keygen returned");
            let session_hash = kg
                .session_hash
                .expect("PASS implies the user got a session hash to check");

            // ASSERT ON THE COMPLETION VALUE, not on "no error": the ref
            // `finalize_keygen` returned must be in the coordinator's own view,
            // THRESHOLD-of-N_DEVICES, with every device holding a share.
            let found = coordinator
                .iter_access_structures()
                .find(|a| a.access_structure_ref() == as_ref)
                .with_context(|| {
                    format!("{as_ref:?} came out of finalize_keygen but is not in the coordinator")
                })?;
            //
            // M12: THIS IS NO LONGER THE ROSTER CHECK — that moved into the loop, to the
            // lap `kg.finished` becomes `Some`, and the comment there says why. By here
            // the blank device IS a tenth entry in `device_to_share_index`, because leg
            // 2's `FinishedConsolidation` made the coordinator apply
            // `KeyMutation::NewShare` for it; and reaching PASS on a signature pass
            // REQUIRES `r.consolidated`, which is set from that same message. So on those
            // passes both members below are implied by control flow. It is kept as an
            // EXACT count for the one thing it can still see: a share holder nobody put
            // there.
            //
            // The expectation is `sighted.is_some()` and not a constant, because the
            // DECLINE pass breaks before any restoration and so has NO tenth holder. That
            // asymmetry is itself the statement that leg 2 is what adds the tenth — a
            // flat `ALL_DEVICES` here fails the DECLINE pass outright, and a flat
            // `N_DEVICES` fails the other two.
            let devices: Vec<DeviceId> = found.devices().collect();
            let want_holders = if sighted.is_some() {
                ALL_DEVICES
            } else {
                N_DEVICES
            };
            if found.threshold() != THRESHOLD || devices.len() != want_holders {
                bail!(
                    "expected {THRESHOLD}-of-{N_DEVICES} with {want_holders} share holder(s) \
                     (M12's blank device becomes the tenth once leg 2 consolidates, and only \
                     then), coordinator has {}-of-{}",
                    found.threshold(),
                    devices.len()
                );
            }
            // ============ THE SESSION HASH, COMPARED ACROSS THE PROCESSES ============
            // PLAN.md §9 item 12 says this comparison is manual. It is not any more:
            // the device computed `session_hash` from the transcript IT verified,
            // this process computed its own from coordinator state, and the two
            // copies of `frostsnap_core` are different builds in different
            // processes (upstream via `frostsnap_coordinator` here, vendored in the
            // stub). Upstream's `recv_device_message` already refuses a mismatched
            // `ack_session_hash` -- but that is upstream's check, inside the black
            // box, and a re-vendor that dropped it would fail nothing. This is
            // ours, by name.
            //
            // What it still cannot replace: the HUMAN comparing the 4-byte code
            // against the coordinator app's display. A coordinator that lies about
            // the access structure lies to both sides equally.
            let want = hex(&session_hash.0);
            if device_hashes.len() != N_DEVICES {
                bail!(
                    "only {}/{N_DEVICES} device(s) reported a session hash: {device_hashes:?}",
                    device_hashes.len()
                );
            }
            for (id, got) in &device_hashes {
                if *got != want {
                    bail!(
                        "SESSION HASH MISMATCH: {id} computed {got}, the coordinator computed \
                         {want} -- the device acked a keygen transcript that is not the one \
                         this coordinator built"
                    );
                }
            }

            // ========= ASSERTION 1: THE GLASS SHOWS THE COORDINATOR'S CODE =========
            // PLAN.md §9 item 12's OPEN half. The cross-check above is
            // core-to-core: the hash the device COMPUTED against the one we
            // computed. This is SCREEN-to-coordinator -- the four bytes
            // `ui::keygen_check` actually RENDERED, read back out of the
            // framebuffer by the shipping `ui::Frame::cell_2x` (the exact inverse
            // of the `text_2x` that drew them, not a second implementation of the
            // mapping) and reported as `glass=`.
            //
            // Why it is worth its own assertion when the hash already matches:
            // those four bytes are the ENTIRE anti-MITM defence, because they are
            // what a human reads aloud and compares between devices. A device that
            // verified the right transcript and then drew the wrong code -- a
            // truncation, a nibble swap, the wrong end of the hash, a 1x blit
            // where a 2x one was meant -- passed every check above it.
            //
            // And it is not merely additional: with step 0's randomised confirm
            // digit the scripted consent CANNOT press the right key without
            // reading the same framebuffer, so a device that renders the wrong
            // screen fails this pass whether or not anyone compares these bytes.
            // This assertion names the failure; the gate would fail regardless.
            let want_glass: String = want.chars().take(8).collect();
            if device_glass.len() != N_DEVICES {
                bail!(
                    "only {}/{N_DEVICES} device(s) reported what is ON THE GLASS: \
                     {device_glass:?}",
                    device_glass.len()
                );
            }
            for (id, got) in &device_glass {
                if *got != want_glass {
                    bail!(
                        "GLASS CODE MISMATCH: {id} RENDERED {got} on the screen a human reads \
                         aloud, but this coordinator's session hash starts {want_glass} -- the \
                         device verified the right transcript and drew the wrong code"
                    );
                }
            }

            // ================= THE FORGED DataErase WAS REFUSED =================
            if refused_erase.len() != N_DEVICES {
                bail!(
                    "only {}/{N_DEVICES} device(s) refused the forged DataErase (refused: \
                     {refused_erase:?}) -- a device that neither refused nor died either \
                     obeyed it or dropped it silently",
                    refused_erase.len()
                );
            }

            // ========== M8: THE PREVIEWED NAME REACHED FLASH AND CAME BACK ==========
            // Asserted here, before the decline pass returns, so all THREE passes carry
            // it: keygen completes in every one of them, and keygen is where a name is
            // committed.
            //
            // Two independent facts, neither made true by control flow — nothing above
            // waits for a `SetName` and the run completes a keygen, a signature and four
            // restoration flows without one:
            //  1. every device sent one, i.e. every `NameStore::save` returned `Ok`;
            //  2. the name it stored is EXACTLY the one previewed, all 14 chars and 56
            //     bytes of it. `DeviceName` counts chars, `DEVICE_NAME_MAX_BYTES` counts
            //     bytes, and a name at the byte edge is the only input that can tell a
            //     truncation at either bound from a correct round trip.
            //
            // ONE device is EXPECTED to be missing, and it is named rather than
            // subtracted: see M10 immediately below and `name_cancelled`.
            let cancelled = name_cancelled.context(
                "no device ever announced, so the M10 cancel differential never got a subject",
            )?;
            let recovered = name_recovered.context(
                "fewer than two devices announced, so the M10 cancel differential had no control",
            )?;

            // ============================== M10 ==============================
            // `CoordinatorSendBody::Cancel` DROPS THE PREVIEWED NAME, driven from a
            // coordinator for the first time.
            //
            // `Session::recv`'s `Cancel` arm clears six pieces of state. FIVE of them
            // already have named Tier-1 host tests that assert the DOWNSTREAM REFUSAL and
            // carry their own MUTATION-VERIFY notes —
            // `a_reveal_grant_ends_with_its_pages_and_is_revoked_by_cancel`,
            // `a_cancelled_ceremony_cannot_be_acked_as_recorded`,
            // `cancel_drops_a_live_quiz_and_a_pass_acks_once`,
            // `cancel_drops_a_half_typed_backup`, `cancel_is_handled_and_silent`. The
            // SIXTH, `pending_name`, is the one whose consequence was asserted NOWHERE:
            // `a_previewed_name_is_neither_written_nor_announced` stops at
            // `pending_name() == None` and never runs the keygen that would have
            // committed it. So this is the only clearing whose observable effect — no
            // `SetName`, ever — had no test in the tree, and it is what M10 closes.
            //
            // THE DIFFERENTIAL IS THE ASSERTION. An absent `SetName` on its own proves
            // nothing: PLAN.md §9 item 12 records that a LATE preview is
            // INDISTINGUISHABLE from no preview, so silence is equally consistent with a
            // preview that never arrived. `recovered` got the SAME TWO FRAMES in the
            // OTHER ORDER and must report the byte-exact name, so a delivery failure
            // silences BOTH and the pair cannot pass. What is left when both hold is a
            // fact about the ORDER of the two frames, which is the only thing
            // `pending_name = None` can be evidence of.
            if let Some(name) = device_names.get(&cancelled) {
                bail!(
                    "A CANCELLED PREVIEW WAS COMMITTED: {cancelled} was sent \
                     Naming(Preview) and then Cancel, and still reported the name {name:?} -- \
                     so `Session::recv`'s `self.pending_name = None` either did not run or \
                     did not stick, and a coordinator that abandoned a ceremony can still \
                     name this device from it"
                );
            }
            if !device_names.contains_key(&recovered) {
                bail!(
                    "THE M10 DIFFERENTIAL IS VACUOUS: {recovered} was sent the same two \
                     frames in the OTHER order -- Cancel, THEN Naming(Preview) -- and still \
                     reported no name. So the silence at {cancelled} is not evidence about \
                     `Cancel` dropping a previewed name; it is evidence the preview never \
                     landed at all"
                );
            }
            eprintln!(
                "hostcheck: M10 PASS -- {cancelled} was previewed-then-CANCELLED and committed \
                 NO name, while {recovered} was CANCELLED-then-previewed and committed the \
                 byte-exact one, so the two frames' ORDER is what decided it"
            );

            // The COUNT, checked AFTER the two M10 bails so that each failure gets its
            // most specific message: a missing `recovered` is a vacuous differential and
            // says so, and what reaches here is a device missing for some THIRD reason.
            // The exact count and not `>=`: a second unexplained absence must fail even
            // though `cancelled`'s absence is expected.
            //
            // M12 does NOT move this count and does not weaken it. It counts a
            // `commit_name`, which fires only from `Session::run`'s `FinalizeKeyGen` arm —
            // so the blank device cannot appear here at all, and the exact `N_DEVICES - 1`
            // still catches any THIRD absence. What changed is only the message: with ten
            // devices on the wire TWO are expected to be silent, and both are named rather
            // than subtracted. The blank device is still sent `Naming(Preview)` like every
            // other, deliberately: a preview commits nothing without a `FinalizeKeyGen`, so
            // the announce arm stays free of a per-device exception a future edit could
            // widen, at a cost of one 97 B frame per run.
            if device_names.len() != N_DEVICES - 1 {
                bail!(
                    "{}/{} device(s) reported a NAME (SetName: {device_names:?}) -- \
                     `commit_name` pushes SetName only after NameStore::save returned Ok, so a \
                     device missing here either never took the preview or could not persist it. \
                     TWO of the {ALL_DEVICES} on the wire are expected to be missing: \
                     {cancelled}, whose preview was followed by a `Cancel` (M10), and \
                     {blank:?}, which M12 left OUT of the keygen so it never reached \
                     `FinalizeKeyGen` at all. Anything else absent is a device that failed to \
                     commit",
                    device_names.len(),
                    N_DEVICES - 1,
                );
            }
            for (id, got) in &device_names {
                if got != DEVICE_NAME {
                    bail!(
                        "NAME ROUND TRIP IS NOT EXACT: {id} stored and reported {got:?} ({} \
                         chars, {} bytes), the coordinator previewed {DEVICE_NAME:?} ({} chars, \
                         {} bytes) -- a name is coordinator-chosen and this one is at the byte \
                         edge, so a difference is a truncation at the 14-CHAR wire bound or at \
                         the {}-BYTE flash bound",
                        got.chars().count(),
                        got.len(),
                        DEVICE_NAME.chars().count(),
                        DEVICE_NAME.len(),
                        // The device's own `DEVICE_NAME_MAX_BYTES`, re-derived from the
                        // shared char bound rather than restated as a literal.
                        4 * DeviceName::max_length()
                    );
                }
            }

            // ============ ASSERTION 2: A DECLINED PROMPT YIELDS NO SIGNATURE ============
            // Everything above still had to hold -- keygen completed, the hashes
            // agreed, the glass matched, the forged erase was refused -- so the
            // ONLY difference between this pass and the two before it is the key
            // pressed at the signing screen. That is what makes it evidence about
            // consent rather than about a broken run.
            //
            // BOTH halves, because a refusal has no protocol message and so each
            // half alone is ambiguous: the `declined=` lines could be a device
            // declining everything (which is why keygen had to complete first), and
            // "no signature" alone is also what a dead device looks like.
            if expect == Expect::Decline {
                if declined.len() != N_DEVICES {
                    bail!(
                        "only {}/{N_DEVICES} device(s) reported declining the SignatureRequest \
                         (declined: {declined:?}) -- a device that neither declined nor signed \
                         dropped the prompt, which is not a refusal",
                        declined.len()
                    );
                }
                // The teeth. A device that declines on its screen and hands over a
                // share anyway has performed consent theatre, and this is the only
                // thing that catches it: shares are counted from the coordinator's
                // own `GotShare`, not from anything the device says about itself.
                if !sign.got_shares.is_empty() || sign.signatures.is_some() {
                    bail!(
                        "DECLINE IGNORED: {}/{N_DEVICES} device(s) declined and yet {} signature \
                         share(s) arrived ({:?}), aggregated={} -- the screen said no and the \
                         device signed",
                        declined.len(),
                        sign.got_shares.len(),
                        sign.got_shares,
                        sign.signatures.is_some()
                    );
                }
                std::io::stderr().flush().ok();
                eprintln!(
                    "  pass ok: DECLINE -- keygen {} FINISHED in {:?} and the glass matched on \
                     {}/{N_DEVICES} devices, then all {}/{N_DEVICES} device(s) pressed `x` at \
                     the signing screen and NOT ONE signature share reached the coordinator\
                     \n    so `x` genuinely refuses: the only thing that changed from the \
                     passes above is the key pressed at the glass\
                     \n    M8+M10 also hold here: {}/{} device(s) persisted the previewed name \
                     and reported it back (a name is committed during keygen, which this pass \
                     still completes), and the remaining one -- {cancelled} -- committed NONE \
                     because a `Cancel` followed its preview",
                    kg.id,
                    started.elapsed(),
                    device_glass.len(),
                    declined.len(),
                    device_names.len(),
                    N_DEVICES - 1,
                );
                return Ok(());
            }

            // ===================== M5: THE SIGNATURE MUST VERIFY =====================
            // The pass hinges on THIS, not on reaching it. Nothing above proves a
            // signature: `Signed` only means the coordinator's aggregator ran. The
            // task is rebuilt from `SIGN_MESSAGE` and the key is read out of the
            // coordinator's own persisted `CompleteKey`, so the only thing supplied
            // by the run is the 64 bytes the two processes produced together.
            let sigs = sign
                .signatures
                .as_ref()
                .expect("PASS implies the coordinator aggregated");
            let key = coordinator
                .get_frost_key(as_ref.key_id)
                .with_context(|| format!("no key {:?} in the coordinator", as_ref.key_id))?;
            let master_appkey = key.complete_key.master_appkey;
            let checked = sign_task()
                .check(master_appkey, key.purpose)
                .map_err(|e| anyhow::anyhow!("sign task does not check against the key: {e:?}"))?;
            // Verify-only: this side holds no secret and must not need one.
            let schnorr = Schnorr::<sha2::Sha256>::verify_only();
            if !checked.verify_final_signatures(&schnorr, sigs) {
                bail!(
                    "SIGNATURE DOES NOT VERIFY: {} sig(s) over {SIGN_MESSAGE:?} against \
                     master_appkey {}",
                    sigs.len(),
                    hex(&master_appkey.0)
                );
            }
            // The key `verify` actually used, recomputed here so the log names the
            // thing that was checked rather than its parent.
            let items = checked.sign_items();
            let derived = items[0]
                .app_tweak
                .derive_xonly_key(&master_appkey.to_xpub());
            if sign.got_shares != sign.signers {
                bail!(
                    "signature verified but shares came from {:?}, not the {:?} we asked",
                    sign.got_shares,
                    sign.signers
                );
            }

            // ================ M7: THE ONE ASSERTION LEFT TO MAKE ================
            // Reaching here already proves most of M7, and proves it as CONTROL FLOW
            // rather than as a check: `Phase` only advances on the fact each phase is
            // about, and the loop only breaks `Ok` at `Phase::Done`. So
            // `recorded` / `checked` / `entered` / `consolidated` / `reheld` are
            // preconditions of standing here, and a `bail!` on any of them would be an
            // assertion that cannot fail — which is worse than none, because it reads
            // like coverage. `expect` says the same thing without pretending otherwise,
            // and it is the convention this file already uses for the keygen's own
            // structural facts a few lines up.
            //
            // What the phase gate does NOT check is the quiz COUNT, and that is the one
            // fact left. A wrong answer re-asks the same position, so a pass in exactly
            // `QUIZ_POSITIONS` answers means every question was right FIRST TIME. The
            // number comes off the device's own `Debug` channel and is compared against
            // arithmetic over `frost_backup::NUM_WORDS` here, so a device that answered
            // nine questions to pass eight fails by name.
            //
            // M12: read off `sighted`, i.e. LEG 1. Leg 2 is the blank device and never
            // enters `Phase::Quiz` at all, so its `quiz_answers` is `None` and pointing
            // this at the live `restore` fires on every green run.
            let r = sighted
                .as_ref()
                .expect("PASS implies M7's first leg ran to Phase::Done");
            // M12's own leg, whose facts are read from the still-live `restore`.
            let blank_leg = restore
                .as_ref()
                .expect("PASS implies M12's second leg ran to Phase::Done");
            if r.quiz_answers != Some(QUIZ_POSITIONS) {
                bail!(
                    "M7c: {} reported {:?} quiz answer(s), not exactly {QUIZ_POSITIONS} -- MORE \
                     means a correct answer read off the REVEAL's glass was scored wrong (a wrong \
                     answer re-asks the same position), and FEWER means the device quizzes a \
                     different number of positions than `frost_backup::NUM_WORDS / 3`",
                    r.device,
                    r.quiz_answers
                );
            }
            // ============================== M12 ==============================
            // THE ONE FACT LEG 2 ADDS THAT IS NOT A PRECONDITION OF STANDING HERE.
            //
            // Everything else about leg 2 is control flow, exactly as M7's own phase gate
            // is: reaching `Phase::Done` on the blank device REQUIRES `check_physical_backup`
            // to have accepted the typed words, `PhysicalBackupSaved` to have completed
            // `EnterPhysicalBackup`, `FinishedConsolidation` to have arrived, and the
            // re-report to have matched this coordinator's polynomial at leg 1's index. A
            // `bail!` on any of those would be an assertion that cannot fail.
            //
            // This one CAN fail, and its mutation is one line: change the pre-signature
            // round trip to `for id in &roster` and the blank device is never asked what it
            // holds, so nothing establishes that the share it consolidated is one it did not
            // already have — and that is the entire difference between M12 and leg 1, where
            // the device consolidates its OWN share back onto itself.
            if !blank_reported_empty {
                bail!(
                    "M12: {} consolidated a share, but this coordinator never got a HeldShares2 \
                     from it reporting NOTHING beforehand -- without that report the \
                     consolidation is indistinguishable from leg 1's, where the device already \
                     held the share it was handed, and the `Some`/`None` discrimination on the \
                     re-report proves nothing",
                    blank_leg.device
                );
            }

            std::io::stderr().flush().ok();
            eprintln!(
                "  pass ok: keygen {} FINISHED in {:?}\n    access_structure_ref = {as_ref:?}\
                 \n    session_hash = {session_hash}\n    threshold {}-of-{}, devices {devices:?}\
                 \n    nonces: {} device(s) replenished {NONCE_STREAMS} stream(s) each\
                 \n    SIGNATURE VERIFIES over {SIGN_MESSAGE:?}\
                 \n      sig    = {}\n      key    = {derived}\
                 \n      appkey = {}\n      signers = {:?} ({} of {N_DEVICES})\
                 \n    device half verified over the wire: {}/{ALL_DEVICES} HeldShares2 \
                 reports matched our own access structure -- {N_DEVICES} from the keygen, and \
                 the tenth is M12's blank device AFTER it consolidated (it reported NOTHING \
                 the first time it was asked)\
                 \n    session_hash AGREED device<->coordinator on {}/{N_DEVICES} devices \
                 (two processes, two copies of frostsnap_core)\
                 \n    THE GLASS shows {want_glass} on {}/{N_DEVICES} devices -- the 4 bytes \
                 `ui::keygen_check` RENDERED, read back with `Frame::cell_2x`, equal this \
                 coordinator's session-hash prefix\
                 \n    forged DataErase REFUSED by {}/{N_DEVICES} devices, and they still signed\
                 \n    largest coordinator->device frame actually written: {} B \
                 (old FRAME_LIMIT was 2060, so this keygen was previously REFUSED)\
                 \n    M7 at {}, share index {:?}, all four flows from a REAL coordinator driver:\
                 \n      M7b REVEAL  -- {} words read back OFF THE GLASS with `Frame::cell` \
                 re-encode through upstream's `ShareBackup::from_words` to this coordinator's own \
                 `expected_share_image`; `BackupRecorded` closed `DisplayBackupProtocol`\
                 \n      M7c QUIZ    -- passed in exactly {} answers, every one taken from what \
                 the REVEAL drew and never from asking the device; `BackupChecked` completed \
                 `CheckBackupProtocol`\
                 \n      M7d INGEST  -- the same 25 words typed back through the letter picker in \
                 {} keypresses, `check_physical_backup` ACCEPTED the resulting share image, and \
                 `PhysicalBackupSaved` completed `EnterPhysicalBackup`\
                 \n      M7e CONSOLIDATE -- the DESTRUCTIVE write landed, and the device described \
                 the record it wrote when asked again\
                 \n      M9  ERASE     -- upstream's own EraseDevice driver stayed at \
                 is_complete()==None for the whole grace window and the device REFUSED its \
                 DataErase on the wire, so its completion path is unreachable here\
                 \n    M12 THE TENTH, BLANK DEVICE: {} announced with the other {N_DEVICES} and \
                 was LEFT OUT of BeginKeygen -- a roster this coordinator cut itself and then \
                 checked at finalize against its own contains_device -- and it reported holding \
                 NOTHING AT ALL when asked. It was then handed {}'s SHEET, the same 25 words that \
                 device's glass drew, typed them in through the letter picker in {} keypresses, \
                 saved them, and CONSOLIDATED onto a flash that held no share at all; asked \
                 again, it described the record for share index {:?} to a coordinator that had \
                 never given it one\
                 \n      so the Some/None discrimination on the re-report is FALSIFIABLE here and \
                 is not on leg 1: a consolidation that acked without reaching the signer is green \
                 there, because that device already held the share it was handed\
                 \n    M8 NAME: all {}/{} device(s) persisted and reported {:?} \
                 ({} chars, {} bytes -- the widest name the wire admits), previewed before \
                 keygen and acked only after NameStore::save returned Ok\
                 \n    M10 CANCEL: {cancelled} got Naming(Preview) THEN Cancel and committed no \
                 name at all, while {recovered} got the SAME TWO FRAMES REVERSED and committed \
                 the byte-exact one -- so `Cancel` dropping `pending_name` is what decided it, \
                 not a preview that failed to arrive",
                kg.id,
                started.elapsed(),
                found.threshold(),
                devices.len(),
                sign.replenished.len(),
                hex(&sigs[0].to_bytes()),
                hex(&master_appkey.0),
                sign.signers,
                sign.signers.len(),
                held.len(),
                device_hashes.len(),
                device_glass.len(),
                refused_erase.len(),
                MAX_DOWN_B.load(Ordering::Relaxed),
                r.device,
                r.share_index,
                r.glass_words.len(),
                QUIZ_POSITIONS,
                r.typed.map_or("?".to_string(), |n| n.to_string()),
                // M12's four: the blank device, the sheet's source, its own keypress
                // count and the index it was handed.
                blank_leg.device,
                r.device,
                blank_leg.typed.map_or("?".to_string(), |n| n.to_string()),
                blank_leg.share_index,
                device_names.len(),
                N_DEVICES - 1,
                DEVICE_NAME,
                DEVICE_NAME.chars().count(),
                DEVICE_NAME.len(),
            );
            // Reap on SUCCESS too. This was missing, and the effect was measured:
            // `break Ok(())` above happens before the loop's `try_wait`, so a
            // PASSING run never waited on the child -- both stubs were left
            // orphaned (PPID 1) and still alive tens of seconds later, and none of
            // them ever printed their own PASS line. A harness that leaks a
            // process per run is a harness that will eventually be debugged as
            // "the pty is busy".
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// One drain of the coordinator's outbox.
///
/// `ToDevice` becomes a frame; `ToUser` is auto-accepted, which for keygen means
/// exactly one decision: when the last device has acked the session hash, call
/// `finalize_keygen`. A REAL coordinator shows the session hash to a human first
/// and only finalizes if they confirm it matches every device screen -- that
/// comparison is the defence against a lying coordinator, and it is the step this
/// harness deliberately skips. Drive order mirrors
/// `frostsnap_coordinator/src/keygen.rs` (`process_to_user_message`) and the
/// vendored tier-2 `Env::user_react_to_coordinator`.
// Nine collaborators, and splitting them would be worse: this is one drain of one
// queue, and every parameter is something the drain has to be able to reach on the lap
// it runs. `ui` and `restore` are the M7a seam's `process_to_user_message` leg, which
// has to sit inside the drain because the messages it routes are the ones the drain
// pops.
#[allow(clippy::too_many_arguments)]
fn pump(
    queue: &mut VecDeque<CoordinatorSend>,
    wtx: &Sender<ReceiveSerial<Upstream>>,
    writes_queued: &mut usize,
    coordinator: &mut FrostCoordinator,
    rng: &mut ChaCha20Rng,
    kg: &mut Keygen,
    sign: &mut Sign,
    ui: &mut Option<Box<dyn UiProtocol>>,
    restore: &mut Option<Restore>,
) -> Result<()> {
    while let Some(send) = queue.pop_front() {
        // M7a: the `process_to_user_message` leg. Offered to the live driver FIRST and
        // in the same shape `UiStack::process_to_user_message` uses -- `true` means it
        // claimed the message -- so the arms below stay the coordinator's own
        // keygen/signing accounting and nothing has to know which flow is live.
        //
        // `FinishedConsolidation` is read on the way past rather than after, because no
        // driver claims it: upstream has no `UiProtocol` for consolidation at all.
        if let CoordinatorSend::ToUser(message) = &send {
            if let (
                Some(r),
                CoordinatorToUserMessage::Restoration(ToUserRestoration::FinishedConsolidation {
                    device_id,
                    share_index,
                    ..
                }),
            ) = (restore.as_mut(), message)
            {
                if *device_id == r.device {
                    eprintln!(
                        "hostcheck: {device_id} FINISHED CONSOLIDATION at share index \
                         {share_index:?}"
                    );
                    r.consolidated = true;
                }
            }
            if let Some(p) = ui.as_mut() {
                if p.process_to_user_message(message.clone()) {
                    continue;
                }
            }
        }
        match send {
            CoordinatorSend::ToDevice { .. } => {
                let msg: CoordinatorSendMessage = send
                    .try_into()
                    .map_err(|e: &'static str| anyhow::anyhow!("CoordinatorSend -> wire: {e}"))?;
                let n_dest = match &msg.target_destinations {
                    // `ALL_DEVICES`: this is a claim about the WIRE, and the wire has ten
                    // listeners even though nine of them are the keygen roster.
                    frostsnap_coordinator::frostsnap_comms::Destination::All => ALL_DEVICES,
                    frostsnap_coordinator::frostsnap_comms::Destination::Particular(d) => d.len(),
                };
                // The gist names the frame. It bounds WHICH frames are in the
                // writer's queue when it stalls; the exact one is the index in the
                // WRITE STALL message, since acks are queued from the loop too.
                eprintln!("hostcheck: -> {} to {n_dest} device(s)", msg.gist());
                // Hand off, do not wait: the writer thread has it on the wire
                // within microseconds when the stub is reading, and when the stub
                // is NOT reading this is exactly the call that used to park the
                // whole harness inside `tcdrain`.
                send_frame(wtx, ReceiveSerial::Message(msg.into())).context("keygen frame")?;
                *writes_queued += 1;
            }
            CoordinatorSend::ToUser(CoordinatorToUserMessage::KeyGen { keygen_id, inner }) => {
                if keygen_id != kg.id {
                    bail!("keygen_id {keygen_id} is not the one we started ({})", kg.id);
                }
                match inner {
                    CoordinatorToUserKeyGenMessage::ReceivedShares { from } => {
                        kg.got_shares += 1;
                        eprintln!(
                            "hostcheck: shares {}/{N_DEVICES} (from {from})",
                            kg.got_shares
                        );
                    }
                    CoordinatorToUserKeyGenMessage::CheckKeyGen { session_hash } => {
                        eprintln!("hostcheck: session_hash {session_hash} (auto-accepted)");
                        kg.session_hash = Some(session_hash);
                    }
                    CoordinatorToUserKeyGenMessage::KeyGenAck {
                        from,
                        all_acks_received,
                    } => {
                        kg.acks += 1;
                        eprintln!(
                            "hostcheck: keygen ack {}/{N_DEVICES} (from {from}, all={all_acks_received})"
                            , kg.acks
                        );
                        if all_acks_received {
                            let finalized = coordinator
                                .finalize_keygen(kg.id, ENCRYPTION_KEY, rng)
                                .map_err(|e| anyhow::anyhow!("finalize_keygen: {e}"))?;
                            kg.finished = Some(finalized.access_structure_ref);
                            eprintln!(
                                "hostcheck: FINALIZED {:?}",
                                finalized.access_structure_ref
                            );
                            queue.extend(finalized);
                        }
                    }
                }
            }
            // M5. `ReplenishedNonces` is the coordinator's own acceptance of a
            // `NonceResponse`: it is emitted once per FRAME (not per segment),
            // after `check_can_extend` passed for every segment in it, so a device
            // that sent nonces for a stream nobody opened never reaches here --
            // `recv_device_message` errors instead and the run dies there.
            CoordinatorSend::ToUser(CoordinatorToUserMessage::ReplenishedNonces { device_id }) => {
                sign.replenished.insert(device_id);
                eprintln!(
                    "hostcheck: nonces replenished {}/{N_DEVICES} ({device_id}); available now {:?}",
                    sign.replenished.len(),
                    coordinator.nonces_available(device_id),
                );
            }
            CoordinatorSend::ToUser(CoordinatorToUserMessage::Signing(msg)) => match msg {
                CoordinatorToUserSigningMessage::GotShare { from, session_id } => {
                    if Some(session_id) != sign.session_id {
                        bail!("GotShare for session {session_id}, not the one we started");
                    }
                    sign.got_shares.insert(from);
                    eprintln!(
                        "hostcheck: signature share {}/{} (from {from})",
                        sign.got_shares.len(),
                        sign.signers.len()
                    );
                }
                CoordinatorToUserSigningMessage::Signed {
                    signatures,
                    session_id,
                } => {
                    if Some(session_id) != sign.session_id {
                        bail!("Signed for session {session_id}, not the one we started");
                    }
                    // A 64-byte blob that is not a valid signature encoding is a
                    // failure HERE rather than a `false` from `verify` later,
                    // because the two say different things.
                    let sigs: Vec<Signature> = signatures
                        .into_iter()
                        .map(EncodedSignature::into_decoded)
                        .collect::<Option<_>>()
                        .context("coordinator aggregated a 64-byte blob that is not a signature")?;
                    eprintln!(
                        "hostcheck: SIGNED session {session_id} -- {} signature(s), verifying",
                        sigs.len()
                    );
                    sign.signatures = Some(sigs);
                }
            },
            CoordinatorSend::ToUser(other) => eprintln!("hostcheck: ignoring ToUser {other:?}"),
        }
    }
    Ok(())
}

/// Byte arrays print as `[1, 2, ...]` under `Debug`, which is unreadable for a
/// signature. One line beats a dependency.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A failing harness must not leave the stub parked on a pty forever.
/// Owns the stub child so it is killed and waited on **every** exit from
/// [`one_pass`], and not only the two the function used to spell out.
///
/// A `Drop` impl and not two more `reap` calls, because the leak was not in the paths
/// anyone had thought about. COUNTED, because the first version of this note got it wrong
/// in both the number and the place and review caught it: `one_pass`'s `let outcome = loop`
/// contains **ZERO** `bail!`s — it ends every failing lap with `break Err(..)`, 29 of them,
/// which is precisely why those laps DID reach the reaping. The leak is in the **15**
/// `bail!`s of the PASS block, which sits inside `match outcome`'s `Ok(())` arm and
/// therefore BEFORE that arm's own `reap`; `bail!` expands to `return`, so each of the 15
/// left the function with the child alive. (31 is the FILE-wide count across five
/// functions, and the note said 31 "in the PASS block, inside the loop", which was two
/// errors in one clause.) Add every `?` in the same block and whatever the next assertion
/// brings, and it is exactly the shape that wants an owner rather than a call.
///
/// MEASURED, and the note that used to sit on the success-path reap predicted the
/// symptom without connecting it to this cause: three FAILING runs in a row left three
/// stubs at PPID 1, each holding a pty master until its own 240 s watchdog fired, and
/// the next run died at `TTYPort::pair: No such device or address` — a message that
/// points at the OS rather than at the leak. A harness whose whole job is naming a
/// failure precisely must not mis-diagnose its own.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
