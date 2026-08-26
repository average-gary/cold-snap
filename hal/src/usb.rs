//! `usb` — OTG_FS device mode and CDC-ACM: the byte mover for PLAN.md phase 3.
//!
//! [`crate::comms`] owns what the bytes *mean* — the magic-byte gate, frame
//! reassembly, the [`crate::comms::FRAME_LIMIT`] refusal. This module owns getting
//! them on and off the wire and knows nothing about frostsnap. The two compose in
//! three lines at the call site:
//!
//! ```ignore
//! let n = cdc.poll(&mut packet)?;                       // usb: bytes off the FIFO
//! link.poll::<ReceiveSerial<Upstream>, _>(&packet[..n], |frame| { .. })?;  // comms: meaning
//! cdc.write(&comms::MAGIC_REPLY)?;                      // usb: bytes onto the wire
//! ```
//!
//! There is deliberately no `Cdc`+`Link` wrapper type. The composition is one line
//! per direction, the event loop that owns both does not exist in this tree yet
//! (no bin target, no entry point — see README "Build"), and a wrapper with no
//! caller is the phase-2 `dbank_ok` defect again: a shape nothing exercises.
//! `cdc_packets_reassemble_a_frostsnap_frame` in this module's tests is that
//! composition, driven through [`OtgPort`] on the host.
//!
//! # What is host-tested here, and what cannot be
//!
//! Testable, and tested: every descriptor byte, the SETUP parse, the whole
//! control-request dispatch ([`control_reply`] is pure and takes no hardware), the
//! FIFO partition arithmetic, the `DIEPTSIZ`/`DOEPTSIZ` transfer-size encoding,
//! the `GRXSTSP` decode, and packet I/O through the [`OtgPort`] seam — including
//! the two bounds that matter on an attacker-controlled stream.
//!
//! Bench-only, and marked as such at each site: core reset, the FIFO flushes,
//! `GCCFG`/`GOTGCTL` VBUS-override, endpoint enable/NAK sequencing, and the
//! host-driven enumeration that exercises all of it. Per `lib.rs`, a host model of
//! those registers would be built from the same datasheet reading as the driver,
//! so agreement would prove only self-consistency. **Nothing in this module has
//! ever enumerated against a real host.**
//!
//! # Defects in the reference sources, NOT copied
//!
//! The sequences below follow ST's `stm32l4xx_ll_usb.c` and MicroPython's
//! `ports/stm32/usbd_conf.c` (both read in the Coldcard tree, which vendors them),
//! with four deliberate departures:
//!
//! 1. `USB_ReadPacket` (`stm32l4xx_ll_usb.c:838-852`) writes `(len + 3) / 4`
//!    **whole 32-bit words** to `dest` with no trailing-byte path, clobbering up to
//!    3 bytes past `dest + len`. [`fifo_read`] writes exactly `len` bytes and is
//!    pinned by `fifo_read_does_not_write_past_len`.
//! 2. `USB_REQ_RECIPIENT_MASK` is `0x03` (`usbdev/core/inc/usbd_def.h:78`) where
//!    the spec's `bmRequestType` recipient field is 5 bits, so recipients
//!    `0x04..=0x1F` alias onto valid ones. [`Setup::recipient`] masks `0x1F` and
//!    the reserved values stall; pinned by `reserved_recipients_are_not_aliased`.
//! 3. `USB_SetDevSpeed` (`:433`) ORs the speed in without clearing `DCFG.DSPD`.
//!    `bring_up` clears the field first.
//! 4. ST's `PCD_WriteEmptyTxFifo` compares against a `DTXFSTS` read taken once
//!    before the loop — MicroPython had to patch it to re-read. [`fifo_write`]
//!    re-reads before **every** word.
//!
//! # Genuinely open, and not guessed at
//!
//! * **Polling vs interrupts.** This module polls `GINTSTS`. `GINTMSK` is still
//!   programmed with the device bits (as ST does) while `GAHBCFG.GINT` stays 0 and
//!   the NVIC line is never enabled, so the code is correct whether or not
//!   `GINTSTS` status bits are gated by `GINTMSK` on this core — which is the part
//!   that cannot be settled off silicon. No ISR exists; no vector table exists.
//! * **`MODE_SETTLE_SPINS`** stands in for ST's `HAL_Delay(50)`
//!   (`stm32l4xx_ll_usb.c:236`). This crate has no timer, so it is a spin count.
//!   It is the knob to turn at the bench, not a measured figure.
//! * **`PWREN` state at handoff.** `bring_up` enables `RCC_APB1ENR1.PWREN` only
//!   if it is off and restores it, because whether the bootloader leaves it on is
//!   unverified.
//! * **The 48 MHz clock.** Nothing here programs it, and as of 2026-08-25 that is
//!   confirmed correct rather than merely assumed: the bootloader's `clocks_setup()`
//!   sets `UsbClockSelection = RCC_USBCLKSOURCE_PLLSAI1` at
//!   `stm32/mk4-bootloader/clocks.c:170`, with `:166` documenting
//!   `HSE(8 MHz)/PLLM(2)*PLLSAI1N(24)/PLLSAIQ(2) = 48 MHz`, and `clocks_setup()` runs
//!   unconditionally from `system_startup()` (`main.c:59`) before anything can reach
//!   us. The same PLL feeds the bootloader's own RNG (`RngClockSelection`, `:172`),
//!   which its `rng_setup()` depends on at `main.c:60` — so PLLSAI1 running is not an
//!   assumption about a clock we do not use, it is load-bearing for code that has
//!   already executed. Still unverified ON SILICON; if it is somehow wrong,
//!   enumeration fails at `ENUMDNE` and the fix is one register.

// ---------------------------------------------------------------------------
// Identity, endpoints, packet size
// ---------------------------------------------------------------------------

/// USB vendor ID. Fixed by the coordinator's port filter, not chosen here.
pub const VID: u16 = 0x303A;

/// USB product ID. As [`VID`].
pub const PID: u16 = 0x1001;

/// Full-speed bulk/control maximum packet size. 64 is the only legal value for
/// full-speed bulk endpoints and the largest legal `bMaxPacketSize0`.
pub const MAX_PACKET_SIZE: usize = 64;

/// CDC notification endpoint (interrupt IN). **Declared and never written to.**
///
// ponytail: the notification endpoint carries SERIAL_STATE (DCD/DSR/break). A
// coordinator talking a framed protocol over the data endpoints does not read it,
// and Linux/macOS `cdc-acm` both bind without ever seeing a notification. Upgrade
// path if a host is found that needs it: `fifo_write(EP_NOTIFY_IN, ..)` with the
// 10-byte SERIAL_STATE packet; the FIFO for it is already allocated
// ([`DIEPTXF1`]), which is why it is 16 words rather than 0.
/// Removing it from [`CONFIG_DESCRIPTOR`] is *not* an option: the CDC Union
/// functional descriptor names a control interface, and an interface claiming
/// class 0x02/subclass 0x02 with zero endpoints is rejected by some hosts.
pub const EP_NOTIFY_IN: u8 = 0x81;

/// CDC data endpoint, host → device.
pub const EP_DATA_OUT: u8 = 0x02;

/// CDC data endpoint, device → host.
pub const EP_DATA_IN: u8 = 0x82;

/// Endpoint number of [`EP_DATA_OUT`] / [`EP_DATA_IN`], i.e. the address with the
/// direction bit stripped. The two share a number, as USB requires.
pub const EP_DATA: u8 = 2;

/// Endpoint number of [`EP_NOTIFY_IN`].
pub const EP_NOTIFY: u8 = 1;

const _: () = {
    assert!(EP_DATA_IN & 0x0f == EP_DATA);
    assert!(EP_DATA_OUT & 0x0f == EP_DATA);
    assert!(EP_NOTIFY_IN & 0x0f == EP_NOTIFY);
    // The IN endpoints must be distinct FIFO owners, and endpoint 0 is reserved
    // for control, so neither may be 0.
    assert!(EP_DATA != 0 && EP_NOTIFY != 0 && EP_DATA != EP_NOTIFY);
};

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

/// Device descriptor, 18 bytes (USB 2.0 §9.6.1).
///
/// `bDeviceClass = 0x02` (CDC) so the interface association is discoverable from
/// the device descriptor alone; the coordinator finds the port by class rather
/// than by endpoint number, which is why the endpoint numbers above are free.
pub const DEVICE_DESCRIPTOR: [u8; 18] = [
    0x12, // bLength
    0x01, // bDescriptorType = DEVICE
    0x00, 0x02, // bcdUSB = 2.00
    0x02, // bDeviceClass = CDC
    0x00, // bDeviceSubClass
    0x00, // bDeviceProtocol
    MAX_PACKET_SIZE as u8, // bMaxPacketSize0
    VID.to_le_bytes()[0],
    VID.to_le_bytes()[1],
    PID.to_le_bytes()[0],
    PID.to_le_bytes()[1],
    0x00, 0x01, // bcdDevice = 1.00
    0x01, // iManufacturer
    0x02, // iProduct
    0x03, // iSerialNumber
    0x01, // bNumConfigurations
];

/// The configuration descriptor and everything that follows it in one blob, as a
/// GET_DESCRIPTOR(CONFIGURATION) must return it: config, CDC comm interface with
/// its four functional descriptors and notification endpoint, then the CDC data
/// interface with its two bulk endpoints.
///
/// `wTotalLength` is `0x0043` = 67 = this array's length, which
/// `configuration_descriptor_total_length_matches_its_contents` re-derives by
/// walking the chain rather than trusting the literal.
pub const CONFIG_DESCRIPTOR: [u8; 67] = [
    // -- configuration ----------------------------------------------------
    0x09, // bLength
    0x02, // bDescriptorType = CONFIGURATION
    0x43, 0x00, // wTotalLength = 67
    0x02, // bNumInterfaces
    0x01, // bConfigurationValue
    0x00, // iConfiguration
    0x80, // bmAttributes: bus-powered, no remote wakeup
    0x32, // bMaxPower = 100 mA
    // -- interface 0: CDC communication -----------------------------------
    0x09, 0x04, 0x00, 0x00, 0x01, 0x02, 0x02, 0x01, 0x00,
    // CDC Header functional, bcdCDC = 1.10
    0x05, 0x24, 0x00, 0x10, 0x01,
    // CDC Call Management functional: no call management, data interface 1
    0x05, 0x24, 0x01, 0x00, 0x01,
    // CDC ACM functional: supports Set/Get_Line_Coding + Set_Control_Line_State
    0x04, 0x24, 0x02, 0x02,
    // CDC Union functional: control interface 0, subordinate interface 1
    0x05, 0x24, 0x06, 0x00, 0x01,
    // notification endpoint: interrupt IN, 8 bytes, 16 ms
    0x07, 0x05, EP_NOTIFY_IN, 0x03, 0x08, 0x00, 0x10,
    // -- interface 1: CDC data --------------------------------------------
    0x09, 0x04, 0x01, 0x00, 0x02, 0x0A, 0x00, 0x00, 0x00,
    // bulk OUT, 64 bytes
    0x07, 0x05, EP_DATA_OUT, 0x02, MAX_PACKET_SIZE as u8, 0x00, 0x00,
    // bulk IN, 64 bytes
    0x07, 0x05, EP_DATA_IN, 0x02, MAX_PACKET_SIZE as u8, 0x00, 0x00,
];

/// Build a USB string descriptor: length, type, then UTF-16LE.
///
/// Private, and every caller is a `const` item below, so both `assert!`s are
/// compile-time errors rather than reachable panics. That stops being true the
/// moment a caller is not a `const` item — do not add one.
const fn string_descriptor<const N: usize>(text: &[u8]) -> [u8; N] {
    assert!(N == 2 + 2 * text.len(), "string descriptor length mismatch");
    assert!(N <= 255, "bLength is one byte");
    let mut out = [0u8; N];
    out[0] = N as u8;
    out[1] = 0x03; // STRING
    let mut i = 0;
    while i < text.len() {
        // ASCII only, so one byte is one UTF-16 code unit and the high byte of
        // each unit stays 0. A non-ASCII byte here would encode as Latin-1,
        // which is not what UTF-16LE means.
        assert!(text[i] < 0x80, "string descriptors here are ASCII only");
        out[2 + 2 * i] = text[i];
        i += 1;
    }
    out
}

/// String descriptor 0: supported LANGIDs. `0x0409` = English (US).
pub const STRING_LANGID: [u8; 4] = [0x04, 0x03, 0x09, 0x04];

/// String descriptor 1, `iManufacturer`.
pub const STRING_MANUFACTURER: [u8; 20] = string_descriptor(b"cold-snap");

/// String descriptor 2, `iProduct`.
pub const STRING_PRODUCT: [u8; 34] = string_descriptor(b"Frostsnap Signer");

/// String descriptor 3, `iSerialNumber`.
///
/// Deliberately **fixed**, not derived from the STM32 96-bit UID: the coordinator
/// identifies a port by device path, a UID-derived serial would put a stable
/// hardware identifier of a signing device into every USB descriptor request any
/// program on the host can make, and udev/IOKit will happily enumerate two
/// identical serials.
pub const STRING_SERIAL: [u8; 10] = string_descriptor(b"0001");

// ---------------------------------------------------------------------------
// FIFO partition
// ---------------------------------------------------------------------------

/// Total dedicated FIFO RAM available to OTG_FS, in 32-bit words.
///
/// 320 words = 1.25 KB. Measured reference, not a datasheet reading of ours:
/// MicroPython's own comment for this silicon family says "FS: there are 320x
/// 32-bit words in total to use here"
/// (`ports/stm32/usb.c:123`), and its shipping full-speed CDC plan sums to 240 of
/// them (`usb.c:128`, in units of 4 words).
pub const FIFO_WORDS_TOTAL: u32 = 320;

/// Shared receive FIFO, in words. All OUT endpoints and every SETUP packet land
/// here, so it is the one that must not be starved.
pub const RX_FIFO_WORDS: u32 = 128;

/// Endpoint 0 IN FIFO, in words. 32 words = 128 bytes, which must hold the
/// longest control IN data stage in one shot — see the assert below, and
/// [`ep0_xfer_size`] for the other half of that bound.
pub const TXF0_WORDS: u32 = 32;

/// [`EP_NOTIFY_IN`] FIFO, in words. Allocated but never written to; see
/// [`EP_NOTIFY_IN`].
pub const TXF1_WORDS: u32 = 16;

/// [`EP_DATA_IN`] FIFO, in words. 64 words = 256 bytes = four full packets, so
/// [`fifo_write`] rarely has to wait mid-packet.
pub const TXF2_WORDS: u32 = 64;

/// Encode a `DIEPTXFn` value: size in the high half, start address in the low
/// half, both in words (RM0432 `OTG_DIEPTXFx`).
const fn txf(start_words: u32, size_words: u32) -> u32 {
    (size_words << 16) | start_words
}

/// `DIEPTXF0` — endpoint 0's IN FIFO, immediately above the RX FIFO.
pub const DIEPTXF0: u32 = txf(RX_FIFO_WORDS, TXF0_WORDS);

/// `DIEPTXF1` — [`EP_NOTIFY_IN`]'s FIFO.
pub const DIEPTXF1: u32 = txf(RX_FIFO_WORDS + TXF0_WORDS, TXF1_WORDS);

/// `DIEPTXF2` — [`EP_DATA_IN`]'s FIFO.
pub const DIEPTXF2: u32 = txf(RX_FIFO_WORDS + TXF0_WORDS + TXF1_WORDS, TXF2_WORDS);

const _: () = {
    // The partition must fit the RAM the core has. Overlapping FIFOs corrupt
    // packets in a way that looks like a host-side driver bug for a very long
    // time, so this is a build error rather than a comment.
    assert!(RX_FIFO_WORDS + TXF0_WORDS + TXF1_WORDS + TXF2_WORDS <= FIFO_WORDS_TOTAL);
    // Each TX FIFO must hold at least one maximum-size packet for its endpoint.
    assert!(TXF0_WORDS * 4 >= MAX_PACKET_SIZE as u32);
    assert!(TXF2_WORDS * 4 >= MAX_PACKET_SIZE as u32);
    assert!(TXF1_WORDS * 4 >= 8); // the notification endpoint's wMaxPacketSize
    // Every control IN data stage this module can produce must fit endpoint 0's
    // FIFO in one shot, because there is no continuation state machine: the whole
    // descriptor is pushed and the core splits it into packets.
    assert!(CONFIG_DESCRIPTOR.len() as u32 <= TXF0_WORDS * 4);
    assert!(STRING_PRODUCT.len() as u32 <= TXF0_WORDS * 4);
    // ...and must fit endpoint 0's narrow DIEPTSIZ fields.
    assert!(ep0_xfer_size(DEVICE_DESCRIPTOR.len()).is_some());
    assert!(ep0_xfer_size(CONFIG_DESCRIPTOR.len()).is_some());
    assert!(ep0_xfer_size(STRING_PRODUCT.len()).is_some());
    assert!(ep0_xfer_size(STRING_MANUFACTURER.len()).is_some());
    assert!(ep0_xfer_size(STRING_SERIAL.len()).is_some());
    assert!(ep0_xfer_size(STRING_LANGID.len()).is_some());
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything this module can refuse to do. No variant is a panic, by design:
/// `panic = "abort"` plus RDP=2 makes every reachable panic a brick
/// (DECISIONS.md decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbError {
    /// No OTG_FS peripheral on this target. Returned by every register-touching
    /// entry point on the host so a test cannot fault the runner.
    NotOnThisTarget,
    /// `GRSTCTL` never reported the core reset or a FIFO flush complete.
    CoreResetTimeout,
    /// A TX FIFO never freed space within [`USB_SPIN_LIMIT`]: the host stopped
    /// collecting IN packets.
    FifoTimeout,
    /// `DIEPCTL.EPENA` never cleared, so the previous transfer never finished and
    /// programming `DIEPTSIZ` again would be a spec violation.
    EndpointBusy,
    /// A packet the core reported is longer than the destination, or a transfer is
    /// longer than the `DIEPTSIZ` fields can express. Carries the length so a
    /// caller can log it; the receive FIFO has been drained either way.
    OversizePacket {
        /// The refused length, in bytes.
        len: usize,
    },
    /// A write was attempted before the host completed SET_CONFIGURATION. Writing
    /// to an endpoint the host has not enabled would otherwise sit in the FIFO
    /// until [`USB_SPIN_LIMIT`] expired.
    NotConfigured,
}

// ---------------------------------------------------------------------------
// SETUP packets
// ---------------------------------------------------------------------------

/// A decoded 8-byte SETUP packet (USB 2.0 §9.3). **Every field is
/// attacker-controlled**; nothing here is trusted by anything but
/// [`control_reply`], which bounds each one before use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    /// `bmRequestType`. Direction, type and recipient; use the accessors.
    pub request_type: u8,
    /// `bRequest`.
    pub request: u8,
    /// `wValue`.
    pub value: u16,
    /// `wIndex`.
    pub index: u16,
    /// `wLength`.
    pub length: u16,
}

impl Setup {
    /// Decode the 8 bytes the core delivered. Little-endian, per USB 2.0 §8.1.
    #[must_use]
    pub const fn parse(raw: &[u8; 8]) -> Self {
        Self {
            request_type: raw[0],
            request: raw[1],
            value: u16::from_le_bytes([raw[2], raw[3]]),
            index: u16::from_le_bytes([raw[4], raw[5]]),
            length: u16::from_le_bytes([raw[6], raw[7]]),
        }
    }

    /// Recipient field of `bmRequestType`: bits 4:0.
    ///
    /// **Five bits, not two.** ST's `USB_REQ_RECIPIENT_MASK` is `0x03`
    /// (`usbdev/core/inc/usbd_def.h:78`) while its own dispatcher switches on the
    /// masked value, so a request with recipient `0x04` is handled as if it were
    /// `RECIPIENT_DEVICE`. Masking the spec's full field means the reserved
    /// values fall through to [`Reply::Stall`] instead.
    #[must_use]
    pub const fn recipient(&self) -> u8 {
        self.request_type & 0x1f
    }

    /// Type field of `bmRequestType`: bits 6:5. 0 standard, 1 class, 2 vendor.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        (self.request_type >> 5) & 0x03
    }

    /// Whether the data stage goes device → host.
    #[must_use]
    pub const fn is_in(&self) -> bool {
        self.request_type & 0x80 != 0
    }
}

/// `bmRequestType` recipient: device.
pub const RECIPIENT_DEVICE: u8 = 0x00;
/// `bmRequestType` recipient: interface.
pub const RECIPIENT_INTERFACE: u8 = 0x01;
/// `bmRequestType` recipient: endpoint.
pub const RECIPIENT_ENDPOINT: u8 = 0x02;

/// `bmRequestType` type: standard.
pub const KIND_STANDARD: u8 = 0;
/// `bmRequestType` type: class. The two CDC requests the coordinator issues are
/// class requests to the communication interface.
pub const KIND_CLASS: u8 = 1;

// ---------------------------------------------------------------------------
// Control-request dispatch — pure
// ---------------------------------------------------------------------------

/// The CDC line coding a GET_LINE_CODING reports before any SET_LINE_CODING.
///
/// Built from [`frostsnap_comms::BAUDRATE`] so it cannot drift from the value the
/// coordinator uses on its UART transports (`frostsnap_comms/src/lib.rs:30`, 19200
/// — chosen there because the esp32c3 masks interrupts for ~30 ms during flash
/// erase). Over CDC the rate is cosmetic: there is no UART behind this endpoint.
pub const DEFAULT_LINE_CODING: [u8; 7] = line_coding(frostsnap_comms::BAUDRATE);

/// `dwDTERate` little-endian, then 1 stop bit / no parity / 8 data bits
/// (CDC PSTN 1.2 §6.3.11).
const fn line_coding(baud: u32) -> [u8; 7] {
    let b = baud.to_le_bytes();
    [b[0], b[1], b[2], b[3], 0x00, 0x00, 0x08]
}

/// The only state a control request can read or change.
///
/// `const fn new()` matters: this lives in a `static` in a firmware that never
/// zeroes `.bss` — the bootloader *fills* SRAM1 with `0xdeadbeef`
/// (`mk4-bootloader/main.c:42,47`). See [`crate::singleton`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlState {
    /// The latched CDC line coding, as GET_LINE_CODING must report it.
    pub line_coding: [u8; 7],
    /// Whether SET_CONFIGURATION has selected configuration 1.
    pub configured: bool,
    /// The last SET_CONTROL_LINE_STATE `wValue`: bit 0 DTR, bit 1 RTS.
    pub line_state: u16,
}

impl ControlState {
    /// The post-reset state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            line_coding: DEFAULT_LINE_CODING,
            configured: false,
            line_state: 0,
        }
    }
}

impl Default for ControlState {
    fn default() -> Self {
        Self::new()
    }
}

/// What the hardware side must do about a SETUP packet. Every variant except
/// [`Reply::Data`] and [`Reply::Stall`] is followed by a zero-length IN status
/// stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Send these bytes as the IN data stage. **Already clamped to `wLength`**, so
    /// the hardware side must not clamp again — one clamp, one place.
    Data(&'static [u8]),
    /// Send `usize` bytes of [`ControlState::line_coding`], likewise clamped.
    LineCoding(usize),
    /// No data stage; acknowledge.
    Status,
    /// Accept a 7-byte OUT data stage and latch it as the new line coding.
    AcceptLineCoding,
    /// Program the device address, then acknowledge. Already range-checked.
    SetAddress(u8),
    /// Select (`true`) or deselect (`false`) configuration 1, then acknowledge.
    SetConfiguration(bool),
    /// Latch `u16` as [`ControlState::line_state`], then acknowledge.
    SetLineState(u16),
    /// Refuse: stall endpoint 0.
    Stall,
}

/// Clamp a descriptor to `wLength` and wrap it. The one place a control IN data
/// stage is sized.
fn clamped(bytes: &'static [u8], length: u16) -> Reply {
    let n = if (length as usize) < bytes.len() {
        length as usize
    } else {
        bytes.len()
    };
    Reply::Data(&bytes[..n])
}

/// The descriptor a GET_DESCRIPTOR names, or `None` if we do not have it.
///
/// `wValue` is type in the high byte, index in the low byte. DEVICE_QUALIFIER
/// (`0x06`) and OTHER_SPEED_CONFIGURATION (`0x07`) are absent on purpose: a
/// full-speed-only device must **stall** them, and answering would advertise a
/// high-speed capability this PHY does not have.
fn descriptor(value: u16) -> Option<&'static [u8]> {
    match (value >> 8, value & 0xff) {
        (0x01, _) => Some(&DEVICE_DESCRIPTOR),
        (0x02, 0) => Some(&CONFIG_DESCRIPTOR),
        (0x03, 0) => Some(&STRING_LANGID),
        (0x03, 1) => Some(&STRING_MANUFACTURER),
        (0x03, 2) => Some(&STRING_PRODUCT),
        (0x03, 3) => Some(&STRING_SERIAL),
        _ => None,
    }
}

/// Two zero bytes: the GET_STATUS response for a bus-powered device with no
/// remote wakeup and no halted endpoint.
const STATUS_ZERO: [u8; 2] = [0, 0];

/// Decide what to do about one SETUP packet. **Pure**: touches no register, reads
/// `state` and does not write it, and cannot panic.
///
/// Everything in `setup` came off the wire, so each field is bounded before use:
/// `wValue` for SET_ADDRESS (`> 127` stalls) and SET_CONFIGURATION (`> 1`
/// stalls), `wLength` for SET_LINE_CODING (`!= 7` stalls) and for every IN data
/// stage (clamped), `wIndex` for SET_ADDRESS (`!= 0` stalls). Anything not
/// recognised stalls, which is the fail-closed direction and is legal for every
/// optional request.
#[must_use]
pub fn control_reply(setup: &Setup, state: &ControlState) -> Reply {
    match (setup.kind(), setup.recipient(), setup.request) {
        // ---- standard, device ------------------------------------------
        // GET_STATUS
        (KIND_STANDARD, RECIPIENT_DEVICE, 0x00)
        | (KIND_STANDARD, RECIPIENT_INTERFACE, 0x00)
        | (KIND_STANDARD, RECIPIENT_ENDPOINT, 0x00) => clamped(&STATUS_ZERO, setup.length),

        // CLEAR_FEATURE(ENDPOINT_HALT). Nothing here halts an endpoint, so
        // clearing a halt is a no-op that must still succeed: a host that gets a
        // stall here gives up on the interface.
        (KIND_STANDARD, RECIPIENT_ENDPOINT, 0x01) if setup.value == 0x0000 => Reply::Status,

        // SET_FEATURE. Refused, including ENDPOINT_HALT: halting is not
        // implemented, and answering "done" to a request that did nothing is the
        // failure mode ST's USB_SetFeature has (silent return, no status stage,
        // no stall). Refusing honestly is the fail-closed direction.
        (KIND_STANDARD, _, 0x03) => Reply::Stall,

        // SET_ADDRESS. wValue is the address; 7 bits, and wIndex/wLength must be
        // zero (`usbd_ctlreq.c:412`). ST masks with 0x7F, which silently accepts
        // an out-of-range address; this refuses it.
        (KIND_STANDARD, RECIPIENT_DEVICE, 0x05) => {
            if setup.value > 127 || setup.index != 0 || setup.length != 0 {
                Reply::Stall
            } else {
                Reply::SetAddress(setup.value as u8)
            }
        }

        // GET_DESCRIPTOR
        (KIND_STANDARD, RECIPIENT_DEVICE, 0x06) => match descriptor(setup.value) {
            Some(bytes) => clamped(bytes, setup.length),
            None => Reply::Stall,
        },

        // GET_CONFIGURATION
        (KIND_STANDARD, RECIPIENT_DEVICE, 0x08) => {
            if state.configured {
                clamped(&CONFIG_VALUE_ONE, setup.length)
            } else {
                clamped(&CONFIG_VALUE_ZERO, setup.length)
            }
        }

        // SET_CONFIGURATION. Only 0 and 1 exist (bNumConfigurations = 1).
        (KIND_STANDARD, RECIPIENT_DEVICE, 0x09) => match setup.value {
            0 => Reply::SetConfiguration(false),
            1 => Reply::SetConfiguration(true),
            _ => Reply::Stall,
        },

        // GET_INTERFACE / SET_INTERFACE. Both interfaces have exactly one
        // alternate setting, so a conforming host never sends SET_INTERFACE and
        // GET_INTERFACE is optional. Stalling both is legal and is one less
        // untested path.
        (KIND_STANDARD, RECIPIENT_INTERFACE, 0x0a | 0x0b) => Reply::Stall,

        // ---- CDC class requests (PSTN 1.2 §6.3) ------------------------
        // SET_LINE_CODING. Exactly 7 bytes, or refuse: a wLength of 65535 here
        // would otherwise arm an OUT data stage for a transfer nothing has a
        // buffer for.
        (KIND_CLASS, RECIPIENT_INTERFACE, 0x20) => {
            if setup.length == 7 {
                Reply::AcceptLineCoding
            } else {
                Reply::Stall
            }
        }

        // GET_LINE_CODING. Never issued by the coordinator; answered because a
        // host tool that does issue it deserves the latched value rather than a
        // stall.
        (KIND_CLASS, RECIPIENT_INTERFACE, 0x21) => {
            let n = if (setup.length as usize) < state.line_coding.len() {
                setup.length as usize
            } else {
                state.line_coding.len()
            };
            Reply::LineCoding(n)
        }

        // SET_CONTROL_LINE_STATE. wValue bit 0 DTR, bit 1 RTS; no data stage.
        (KIND_CLASS, RECIPIENT_INTERFACE, 0x22) => Reply::SetLineState(setup.value),

        // SEND_BREAK. Acknowledged and discarded: there is no UART to break.
        (KIND_CLASS, RECIPIENT_INTERFACE, 0x23) => Reply::Status,

        // Everything else, including every vendor request and every reserved
        // recipient.
        _ => Reply::Stall,
    }
}

/// GET_CONFIGURATION response when configured.
const CONFIG_VALUE_ONE: [u8; 1] = [1];
/// GET_CONFIGURATION response when not configured.
const CONFIG_VALUE_ZERO: [u8; 1] = [0];

// ---------------------------------------------------------------------------
// Transfer-size arithmetic — pure
// ---------------------------------------------------------------------------

/// Words a `len`-byte packet occupies in a FIFO. The FIFO is word-addressed, so a
/// partial final word still costs a whole word.
///
/// Written as divide-then-adjust rather than `(len + 3) / 4` because the latter
/// overflows for `len` near `usize::MAX`, and `overflow-checks = false` in
/// `[profile.release]` makes that wrap silently in firmware while panicking in
/// tests — the phase-2 profile-divergence defect. This form cannot overflow.
#[must_use]
pub const fn fifo_words(len: usize) -> usize {
    len / 4 + (len % 4 != 0) as usize
}

/// Encode `DIEPTSIZ`/`DOEPTSIZ` for a non-zero endpoint: packet count in bits
/// 28:19, transfer size in bits 18:0.
///
/// Returns `None` rather than truncating if either field would overflow — a
/// truncated transfer size makes the core send the wrong number of bytes, which
/// on a framed protocol is a desynchronised link and not a visible error.
///
/// `len == 0` is a zero-length packet: one packet, zero bytes.
#[must_use]
pub const fn xfer_size(len: usize, mps: usize) -> Option<u32> {
    if mps == 0 {
        return None;
    }
    let packets = if len == 0 { 1 } else { len / mps + (len % mps != 0) as usize };
    if packets > 0x3ff || len > 0x7_ffff {
        return None;
    }
    Some(((packets as u32) << 19) | len as u32)
}

/// Encode `DIEPTSIZ0`/`DOEPTSIZ0`. Endpoint 0's fields are **narrower** than
/// every other endpoint's: transfer size is bits 6:0 and packet count is bits
/// 20:19, so the largest control transfer this can express is 127 bytes in at
/// most 3 packets (RM0432 `OTG_DIEPTSIZ0`).
///
/// Getting this wrong is invisible on a short descriptor and silently truncates a
/// long one, which is why the `const _` block above proves every descriptor in
/// this module is inside the range.
#[must_use]
pub const fn ep0_xfer_size(len: usize) -> Option<u32> {
    let packets = if len == 0 {
        1
    } else {
        len / MAX_PACKET_SIZE + (len % MAX_PACKET_SIZE != 0) as usize
    };
    if packets > 3 || len > 0x7f {
        return None;
    }
    Some(((packets as u32) << 19) | len as u32)
}

/// A decoded `GRXSTSP` pop (RM0432 `OTG_GRXSTSP`, device mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxStatus {
    /// `EPNUM`, bits 3:0.
    pub ep: u8,
    /// `BCNT`, bits 14:4. Eleven bits, so up to 2047 — larger than any endpoint
    /// here can legally deliver, which is why [`fifo_read`] bounds it against the
    /// destination rather than trusting it.
    pub len: usize,
    /// `PKTSTS`, bits 20:17.
    pub kind: u8,
}

/// `PKTSTS`: global OUT NAK.
pub const PKTSTS_GLOBAL_OUT_NAK: u8 = 0x1;
/// `PKTSTS`: OUT data packet received.
pub const PKTSTS_OUT_DATA: u8 = 0x2;
/// `PKTSTS`: OUT transfer completed.
pub const PKTSTS_OUT_COMPLETE: u8 = 0x3;
/// `PKTSTS`: SETUP transaction completed.
pub const PKTSTS_SETUP_COMPLETE: u8 = 0x4;
/// `PKTSTS`: SETUP data packet received.
pub const PKTSTS_SETUP_DATA: u8 = 0x6;

/// Decode a `GRXSTSP` value. Pure, and the only place these field positions
/// appear.
#[must_use]
pub const fn rx_status(grxstsp: u32) -> RxStatus {
    RxStatus {
        ep: (grxstsp & 0x0f) as u8,
        len: ((grxstsp >> 4) & 0x7ff) as usize,
        kind: ((grxstsp >> 17) & 0x0f) as u8,
    }
}

// ---------------------------------------------------------------------------
// Packet I/O over a three-accessor seam
// ---------------------------------------------------------------------------

/// The FIFO accessors, and nothing else.
///
/// Same reasoning as [`crate::flash::SrPort`]: the two defects that matter here
/// are a destination overrun and an unbounded wait, and neither needs silicon to
/// reproduce — they need a word-addressed queue and a "space available" counter.
/// That is what this abstracts.
///
/// Implementing it grants **nothing**. It cannot produce a [`Cdc`], reset the
/// core or reach a control register; only the private ARM-only `Mmio` does that.
/// So this is a seam on a *mechanism*, not a gate on a refusal — the
/// [`crate::rng`] rule is satisfied.
pub trait OtgPort {
    /// Pop one word from the shared receive FIFO.
    fn read_fifo_word(&mut self) -> u32;
    /// Push one word into endpoint `ep`'s transmit FIFO.
    fn write_fifo_word(&mut self, ep: u8, word: u32);
    /// Words currently free in endpoint `ep`'s transmit FIFO (`DTXFSTS`).
    fn tx_words_free(&mut self, ep: u8) -> u16;
}

/// Iteration bound for [`fifo_write`]. As [`crate::flash::FLASH_SPIN_LIMIT`],
/// this is a count and not a time: there is no timer here, and the only honest
/// statement is "far more iterations than a host that is still collecting IN
/// packets can need". Deliberately not `u32::MAX` — the point is termination.
pub const USB_SPIN_LIMIT: u32 = 1_000_000;

/// Drain one `len`-byte packet out of the receive FIFO into `dest`.
///
/// Reads exactly [`fifo_words`]`(len)` words **on every path, including the
/// refusal**. That is the property the whole function exists for: the receive FIFO
/// is shared by every OUT endpoint and by SETUP, so a packet left half-drained
/// desynchronises every later packet on the device. A refusal that skips the drain
/// is worse than no refusal.
///
/// Writes at most `len` bytes and never more than `dest.len()`. ST's
/// `USB_ReadPacket` writes `(len + 3) / 4` whole words and so clobbers up to 3
/// bytes past `dest + len`; on a `&mut [u8]` in Rust that would be an
/// out-of-bounds write.
///
/// # Errors
///
/// [`UsbError::OversizePacket`] if `len > dest.len()`. `dest` holds the first
/// `dest.len()` bytes and the FIFO is still in step, so the caller may log and
/// continue.
pub fn fifo_read<P: OtgPort>(port: &mut P, len: usize, dest: &mut [u8]) -> Result<usize, UsbError> {
    let mut copied = 0;
    for word in 0..fifo_words(len) {
        let bytes = port.read_fifo_word().to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            let at = word * 4 + i;
            // `at < len` is the trailing-byte path ST omits; `at < dest.len()`
            // is the containment bound.
            if at < len && at < dest.len() {
                dest[at] = b;
                copied += 1;
            }
        }
    }
    if len > dest.len() {
        return Err(UsbError::OversizePacket { len });
    }
    Ok(copied)
}

/// Push `src` into endpoint `ep`'s transmit FIFO, waiting — boundedly — for space.
///
/// `DTXFSTS` is re-read before **every** word. ST's `PCD_WriteEmptyTxFifo` takes
/// one reading before the loop and MicroPython had to patch it; with a 64-word
/// FIFO and a 2 KB frame the unpatched version writes past the space it checked
/// for.
///
/// The final partial word is zero-padded, which is correct: the core sends
/// `XFRSIZ` bytes and ignores the rest of the last word.
///
/// # Errors
///
/// [`UsbError::FifoTimeout`] if the FIFO never freed a word within `spin_limit`.
pub fn fifo_write<P: OtgPort>(
    port: &mut P,
    ep: u8,
    src: &[u8],
    spin_limit: u32,
) -> Result<(), UsbError> {
    let mut spins = spin_limit;
    let mut word = 0;
    // Structurally bounded: each pass either advances `word` towards
    // `fifo_words(src.len())` or spends a spin, and `spins` is a `checked_sub`
    // countdown. A fault in the body can produce a wrong answer; it cannot hang.
    while word < fifo_words(src.len()) {
        if port.tx_words_free(ep) == 0 {
            spins = match spins.checked_sub(1) {
                Some(s) => s,
                None => return Err(UsbError::FifoTimeout),
            };
            continue;
        }
        let mut out = [0u8; 4];
        let start = word * 4;
        for (i, slot) in out.iter_mut().enumerate() {
            if let Some(&b) = src.get(start + i) {
                *slot = b;
            }
        }
        port.write_fifo_word(ep, u32::from_le_bytes(out));
        word += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The capability
// ---------------------------------------------------------------------------

/// The take-once ticket for the OTG_FS peripheral.
///
/// Same split as [`crate::flash::StmFlashToken`], for the same reason: `take` is
/// pure and host-testable, `open` is the only thing that touches a register, and
/// the token implements nothing so a caller cannot move bytes without the
/// bring-up sequence having run.
pub struct UsbToken {
    _private: (),
}

impl UsbToken {
    /// Take the singleton token. `None` on the second and later calls.
    ///
    /// Touches no hardware, so it is callable on any target.
    #[must_use]
    pub fn take() -> Option<Self> {
        // NOT an `AtomicBool`: a `bool` static in `.bss` reads `0xdeadbeef` on
        // this board (`mk4-bootloader/main.c:42,47`) and nothing zeroes `.bss`
        // yet, so `AtomicBool::new(false)` would read `true` and this would
        // return `None` on the FIRST call. See `crate::singleton`.
        static TAKEN: crate::singleton::TakeOnce = crate::singleton::TakeOnce::new();
        if TAKEN.take() {
            Some(Self { _private: () })
        } else {
            None
        }
    }

    /// Run the bring-up sequence and hand back the usable handle.
    ///
    /// Consumes the token by value, so a failed open cannot be retried with the
    /// same token and a successful one cannot be duplicated.
    ///
    /// # Errors
    ///
    /// [`UsbError::NotOnThisTarget`] off ARM; [`UsbError::CoreResetTimeout`] if
    /// the core reset or a FIFO flush never completed.
    ///
    /// # Panics
    ///
    /// Must not, ever. A panic here is a boot-time reset loop (decision 6).
    pub fn open(self) -> Result<Cdc, UsbError> {
        // `return` is load-bearing exactly as in `flash::StmFlashToken::open`: on
        // the host the ARM block below is deleted and a bare `Err(..)` tail in a
        // statement position is a discarded `#[must_use]`, not a return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = &self;
            return Err(UsbError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            let _ = &self;
            bring_up()?;
            Ok(Cdc {
                state: ControlState::new(),
                setup: [0u8; 8],
            })
        }
    }
}

/// A configured CDC-ACM device: bytes in, bytes out.
///
/// Obtainable only from [`UsbToken::open`], which is why holding one means the
/// bring-up sequence ran.
pub struct Cdc {
    state: ControlState,
    /// The SETUP packet currently in flight. The core delivers SETUP as data and
    /// then a separate "SETUP complete" status, so it has to be held across two
    /// pops of `GRXSTSP`.
    #[cfg_attr(not(target_arch = "arm"), allow(dead_code))]
    setup: [u8; 8],
}

impl Cdc {
    /// The latched control state: line coding, configuration, DTR/RTS.
    #[must_use]
    pub const fn control_state(&self) -> &ControlState {
        &self.state
    }

    /// Whether the host has completed SET_CONFIGURATION. [`Cdc::write`] refuses
    /// until it has.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.state.configured
    }

    /// Service at most one receive-FIFO entry.
    ///
    /// Returns the number of [`EP_DATA_OUT`] bytes placed in `packet` — 0 when the
    /// entry was a control transfer, a reset, or nothing at all. Feed
    /// `&packet[..n]` straight to [`crate::comms::Link::poll`]; this function does
    /// not know or care what the bytes mean.
    ///
    /// **Bench-only below the [`fifo_read`] call.** Never run on silicon.
    ///
    /// # Errors
    ///
    /// [`UsbError::NotOnThisTarget`] off ARM. [`UsbError::OversizePacket`] if the
    /// core reported a packet longer than `packet` — the FIFO is drained anyway,
    /// so the link resynchronises on the next packet.
    /// [`UsbError::CoreResetTimeout`] from a reset-triggered FIFO flush.
    pub fn poll(&mut self, packet: &mut [u8; MAX_PACKET_SIZE]) -> Result<usize, UsbError> {
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = (&self.state, packet);
            return Err(UsbError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            let ints = read_reg(GINTSTS);

            if ints & GINTSTS_USBRST != 0 {
                on_reset()?;
                write_reg(GINTSTS, GINTSTS_USBRST);
                self.state = ControlState::new();
                return Ok(0);
            }
            if ints & GINTSTS_ENUMDNE != 0 {
                // EP0 IN maximum packet size: MPSIZ == 0b00 means 64 bytes
                // (`stm32l4xx_ll_usb.c:1124`).
                modify_reg(in_ep(0, EP_CTL), |v| v & !DIEPCTL_MPSIZ_MASK);
                write_reg(GINTSTS, GINTSTS_ENUMDNE);
                return Ok(0);
            }
            if ints & GINTSTS_RXFLVL == 0 {
                return Ok(0);
            }

            let status = rx_status(read_reg(GRXSTSP));
            match status.kind {
                PKTSTS_SETUP_DATA => {
                    let mut raw = [0u8; 8];
                    // The bound is `raw`, not `status.len`: a core reporting a
                    // 2047-byte SETUP still gets drained, and still gets refused.
                    fifo_read(&mut Mmio, status.len, &mut raw)?;
                    self.setup = raw;
                    Ok(0)
                }
                PKTSTS_SETUP_COMPLETE => {
                    let setup = Setup::parse(&self.setup);
                    self.apply(control_reply(&setup, &self.state))?;
                    arm_ep0_out();
                    Ok(0)
                }
                PKTSTS_OUT_DATA if status.ep == 0 => {
                    // The only control OUT data stage we accept is
                    // SET_LINE_CODING's 7 bytes; `AcceptLineCoding` already
                    // refused any other `wLength`.
                    let mut raw = [0u8; 7];
                    let n = fifo_read(&mut Mmio, status.len, &mut raw)?;
                    if n == raw.len() {
                        self.state.line_coding = raw;
                    }
                    ep0_send(&[])?;
                    arm_ep0_out();
                    Ok(0)
                }
                PKTSTS_OUT_DATA if status.ep == EP_DATA => {
                    let n = fifo_read(&mut Mmio, status.len, packet)?;
                    arm_data_out();
                    Ok(n)
                }
                _ => {
                    // Everything else carries BCNT 0, but drain whatever the core
                    // claims regardless: keeping the shared FIFO in step is not
                    // conditional on us recognising the entry.
                    let _ = fifo_read(&mut Mmio, status.len, packet);
                    if status.kind == PKTSTS_OUT_COMPLETE && status.ep == EP_DATA {
                        arm_data_out();
                    }
                    Ok(0)
                }
            }
        }
    }

    /// Send `bytes` on [`EP_DATA_IN`], one packet per transfer.
    ///
    // ponytail: one 64-byte packet per DIEPTSIZ programming, so a full 4096-byte
    // frame is 64 transfers. The FIFO holds four packets, so the ceiling is transfer
    // setup overhead, not bandwidth. Upgrade path if a signing-latency measurement
    // ever shows it: program XFRSIZ for the whole frame and push until DTXFSTS
    // blocks -- `xfer_size` already encodes multi-packet transfers, and
    // `xfer_size_counts_packets_for_a_full_frame` pins the arithmetic.
    ///
    /// No terminating zero-length packet is sent for a payload that is an exact
    /// multiple of [`MAX_PACKET_SIZE`]. A CDC serial stream has no transfer
    /// length for a ZLP to terminate — the host reads what arrives — and
    /// `frostsnap_comms` frames carry no length prefix either, so the receiver
    /// consumes bytes as they come.
    ///
    /// **Bench-only.** Never run on silicon.
    ///
    /// # Errors
    ///
    /// [`UsbError::NotOnThisTarget`] off ARM; [`UsbError::NotConfigured`] before
    /// the host has selected a configuration; [`UsbError::EndpointBusy`] if the
    /// previous transfer never completed; [`UsbError::FifoTimeout`] if the host
    /// stopped collecting; [`UsbError::OversizePacket`] if a chunk cannot be
    /// expressed in `DIEPTSIZ` — unreachable while chunks are
    /// [`MAX_PACKET_SIZE`], and checked rather than asserted because an assert is
    /// a brick.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), UsbError> {
        if !self.state.configured {
            return Err(UsbError::NotConfigured);
        }

        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = bytes;
            return Err(UsbError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            // `chunks` is stdlib and yields nothing for an empty slice, so an
            // empty write is a no-op rather than a stray zero-length packet.
            for chunk in bytes.chunks(MAX_PACKET_SIZE) {
                let tsiz = match xfer_size(chunk.len(), MAX_PACKET_SIZE) {
                    Some(t) => t,
                    None => return Err(UsbError::OversizePacket { len: chunk.len() }),
                };
                wait_ep_idle(in_ep(EP_DATA as usize, EP_CTL))?;
                write_ptr(in_ep(EP_DATA as usize, EP_TSIZ), tsiz);
                modify_reg(in_ep(EP_DATA as usize, EP_CTL), |v| {
                    v | DIEPCTL_CNAK | DIEPCTL_EPENA
                });
                fifo_write(&mut Mmio, EP_DATA, chunk, USB_SPIN_LIMIT)?;
            }
            Ok(())
        }
    }

    /// Carry out a [`Reply`]. ARM-only because every arm ends in a register write;
    /// the decision it acts on is [`control_reply`]'s, and that is pure.
    #[cfg(target_arch = "arm")]
    fn apply(&mut self, reply: Reply) -> Result<(), UsbError> {
        match reply {
            Reply::Data(bytes) => ep0_send(bytes),
            Reply::LineCoding(n) => {
                // `n` came from `control_reply`, which clamped it to
                // `line_coding.len()`; `get` rather than an index so a future
                // change there cannot turn this into a panic.
                match self.state.line_coding.get(..n) {
                    Some(bytes) => ep0_send(bytes),
                    None => {
                        ep0_stall();
                        Ok(())
                    }
                }
            }
            Reply::Status => ep0_send(&[]),
            // The 7 bytes arrive as a separate OUT data packet, handled in
            // `poll`. Nothing to do but let the core accept them.
            Reply::AcceptLineCoding => Ok(()),
            Reply::SetAddress(address) => {
                // Address first, then the status stage — ST's order
                // (`usbd_ctlreq.c:422-423`).
                modify_reg(device(DCFG), |v| {
                    (v & !DCFG_DAD_MASK) | (u32::from(address) << DCFG_DAD_SHIFT)
                });
                ep0_send(&[])
            }
            Reply::SetConfiguration(on) => {
                if on {
                    activate_endpoints();
                } else {
                    deactivate_endpoints();
                }
                self.state.configured = on;
                ep0_send(&[])
            }
            Reply::SetLineState(value) => {
                self.state.line_state = value;
                ep0_send(&[])
            }
            Reply::Stall => {
                ep0_stall();
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Registers. ARM-only, bench-only, every offset cited.
// ---------------------------------------------------------------------------

/// OTG_FS peripheral base (`stm32l4s5xx.h:1482`).
pub const OTG_FS_BASE: usize = 0x5000_0000;

/// Core global registers, offsets from [`OTG_FS_BASE`]
/// (`stm32l4s5xx.h:1163-1192`).
///
/// ARM-only along with everything that reads it: an offset table nothing can
/// dereference is dead weight on the host, and `#[warn(dead_code)]` would say so.
#[cfg(target_arch = "arm")]
mod offset {
    /// `GOTGCTL`.
    pub const GOTGCTL: usize = 0x000;
    /// `GAHBCFG`.
    pub const GAHBCFG: usize = 0x008;
    /// `GUSBCFG`.
    pub const GUSBCFG: usize = 0x00c;
    /// `GRSTCTL`.
    pub const GRSTCTL: usize = 0x010;
    /// `GINTSTS`.
    pub const GINTSTS: usize = 0x014;
    /// `GINTMSK`.
    pub const GINTMSK: usize = 0x018;
    /// `GRXSTSP` — read-and-pop.
    pub const GRXSTSP: usize = 0x020;
    /// `GRXFSIZ`.
    pub const GRXFSIZ: usize = 0x024;
    /// `DIEPTXF0`, doubling as `HNPTXFSIZ` in host mode.
    pub const DIEPTXF0: usize = 0x028;
    /// `GCCFG`.
    pub const GCCFG: usize = 0x038;
    /// `DIEPTXF1`. The array starts at `0x104`, one word per endpoint from 1.
    pub const DIEPTXF1: usize = 0x104;
    /// Device register block.
    pub const DEVICE: usize = 0x800;
    /// IN endpoint block.
    pub const IN_EP: usize = 0x900;
    /// OUT endpoint block.
    pub const OUT_EP: usize = 0xb00;
    /// Endpoint register stride.
    pub const EP_STRIDE: usize = 0x20;
    /// `PCGCCTL`.
    pub const PCGCCTL: usize = 0xe00;
    /// Base of the FIFO access windows.
    pub const FIFO: usize = 0x1000;
    /// Stride between endpoint FIFO windows.
    pub const FIFO_STRIDE: usize = 0x1000;
}

#[cfg(target_arch = "arm")]
use offset::*;

// Everything from here to the end of the non-test code is the register surface,
// and it is bench-only in the sense `lib.rs` defines: it cannot be exercised off
// silicon, and a host model of it would be built from the same datasheet reading
// as the driver, so agreement would prove only self-consistency. `Mmio` and the
// `read_reg`/`write_reg`/`modify_reg` helpers are private, so this is the single
// site in the crate that can reach an OTG_FS register.

/// `DCFG` offset within the device block.
#[cfg(target_arch = "arm")]
const DCFG: usize = 0x00;
/// `DCTL` offset within the device block.
#[cfg(target_arch = "arm")]
const DCTL: usize = 0x04;
/// `DIEPMSK` offset within the device block.
#[cfg(target_arch = "arm")]
const DIEPMSK: usize = 0x10;
/// `DOEPMSK` offset within the device block.
#[cfg(target_arch = "arm")]
const DOEPMSK: usize = 0x14;
/// `DAINTMSK` offset within the device block.
#[cfg(target_arch = "arm")]
const DAINTMSK: usize = 0x1c;

/// `DIEPCTL`/`DOEPCTL` offset within an endpoint block.
#[cfg(target_arch = "arm")]
const EP_CTL: usize = 0x00;
/// `DIEPINT`/`DOEPINT` offset within an endpoint block.
#[cfg(target_arch = "arm")]
const EP_INT: usize = 0x08;
/// `DIEPTSIZ`/`DOEPTSIZ` offset within an endpoint block.
#[cfg(target_arch = "arm")]
const EP_TSIZ: usize = 0x10;
/// `DTXFSTS` offset within an IN endpoint block.
#[cfg(target_arch = "arm")]
const EP_TXFSTS: usize = 0x18;

/// `GINTSTS.RXFLVL`, bit 4 (`stm32l4s5xx.h:18678`).
#[cfg(target_arch = "arm")]
const GINTSTS_RXFLVL: u32 = 1 << 4;
/// `GINTSTS.USBRST`, bit 12 (`:18696`).
#[cfg(target_arch = "arm")]
const GINTSTS_USBRST: u32 = 1 << 12;
/// `GINTSTS.ENUMDNE`, bit 13 (`:18699`).
#[cfg(target_arch = "arm")]
const GINTSTS_ENUMDNE: u32 = 1 << 13;

/// `DIEPCTL.MPSIZ`, bits 10:0 (`:19577`).
#[cfg(target_arch = "arm")]
const DIEPCTL_MPSIZ_MASK: u32 = 0x7ff;
/// `DIEPCTL.USBAEP`, bit 15 (`:19580`).
#[cfg(target_arch = "arm")]
const DIEPCTL_USBAEP: u32 = 1 << 15;
/// `DIEPCTL.EPTYP` shift, bits 19:18 (`:19589`).
#[cfg(target_arch = "arm")]
const DIEPCTL_EPTYP_SHIFT: u32 = 18;
/// `DIEPCTL.STALL`, bit 21 (`:19594`).
#[cfg(target_arch = "arm")]
const DIEPCTL_STALL: u32 = 1 << 21;
/// `DIEPCTL.TXFNUM` shift, bits 25:22 (`:19597`).
#[cfg(target_arch = "arm")]
const DIEPCTL_TXFNUM_SHIFT: u32 = 22;
/// `DIEPCTL.CNAK`, bit 26 (`:19604`).
#[cfg(target_arch = "arm")]
const DIEPCTL_CNAK: u32 = 1 << 26;
/// `DIEPCTL.SNAK`, bit 27 (`:19607`).
#[cfg(target_arch = "arm")]
const DIEPCTL_SNAK: u32 = 1 << 27;
/// `DIEPCTL.SD0PID`, bit 28 (`:19610`).
#[cfg(target_arch = "arm")]
const DIEPCTL_SD0PID: u32 = 1 << 28;
/// `DIEPCTL.EPDIS`, bit 30 (`:19616`).
#[cfg(target_arch = "arm")]
const DIEPCTL_EPDIS: u32 = 1 << 30;
/// `DIEPCTL.EPENA`, bit 31 (`:19619`).
#[cfg(target_arch = "arm")]
const DIEPCTL_EPENA: u32 = 1 << 31;

/// `DCFG.DAD` shift, bits 10:4 (`:19306`).
#[cfg(target_arch = "arm")]
const DCFG_DAD_SHIFT: u32 = 4;
/// `DCFG.DAD` mask.
#[cfg(target_arch = "arm")]
const DCFG_DAD_MASK: u32 = 0x7f << DCFG_DAD_SHIFT;

/// Address of a global register.
#[cfg(target_arch = "arm")]
const fn global(off: usize) -> *mut u32 {
    (OTG_FS_BASE + off) as *mut u32
}
/// Address of a device register.
#[cfg(target_arch = "arm")]
const fn device(off: usize) -> *mut u32 {
    (OTG_FS_BASE + DEVICE + off) as *mut u32
}
/// Address of an IN endpoint register.
#[cfg(target_arch = "arm")]
const fn in_ep(ep: usize, off: usize) -> *mut u32 {
    (OTG_FS_BASE + IN_EP + ep * EP_STRIDE + off) as *mut u32
}
/// Address of an OUT endpoint register.
#[cfg(target_arch = "arm")]
const fn out_ep(ep: usize, off: usize) -> *mut u32 {
    (OTG_FS_BASE + OUT_EP + ep * EP_STRIDE + off) as *mut u32
}

/// Read a global register by offset.
#[cfg(target_arch = "arm")]
fn read_reg(off: usize) -> u32 {
    // SAFETY: `OTG_FS_BASE + off` is a 4-byte-aligned memory-mapped peripheral
    // register from the table above; the clock is enabled by `bring_up` before
    // any caller runs. Reads of these registers have no side effects except
    // `GRXSTSP`, whose pop IS the intended effect. `read_volatile` because the
    // value is not ours and must not be cached or elided.
    unsafe { core::ptr::read_volatile(global(off)) }
}

/// Write a global register by offset.
#[cfg(target_arch = "arm")]
fn write_reg(off: usize, value: u32) {
    // SAFETY: as `read_reg`. The written offsets are all core-configuration or
    // write-1-to-clear status registers; none is in a region another module owns.
    unsafe { core::ptr::write_volatile(global(off), value) }
}

/// Write a register through a pointer.
#[cfg(target_arch = "arm")]
fn write_ptr(reg: *mut u32, value: u32) {
    // SAFETY: `reg` comes from `in_ep`/`out_ep`/`device`, all of which produce
    // 4-byte-aligned addresses inside the OTG_FS window.
    unsafe { core::ptr::write_volatile(reg, value) }
}

/// Read-modify-write a register through a pointer.
#[cfg(target_arch = "arm")]
fn modify_reg(reg: *mut u32, f: impl FnOnce(u32) -> u32) {
    // SAFETY: `reg` comes from `global`/`device`/`in_ep`/`out_ep`, all of which
    // produce 4-byte-aligned addresses inside the OTG_FS window. Read-modify-write
    // is correct here because no OTG register this touches is written by anything
    // else in this crate -- unlike `RCC_AHB2ENR`, which `bring_up` handles
    // separately and says so.
    unsafe {
        let v = core::ptr::read_volatile(reg);
        core::ptr::write_volatile(reg, f(v));
    }
}

/// The real [`OtgPort`]. Private and ARM-only, so it is the single site that can
/// reach a FIFO window.
#[cfg(target_arch = "arm")]
struct Mmio;

#[cfg(target_arch = "arm")]
impl OtgPort for Mmio {
    fn read_fifo_word(&mut self) -> u32 {
        // SAFETY: the receive FIFO is read through endpoint 0's window
        // (`stm32l4xx_ll_usb.c:847` reads `USBx_DFIFO(0)` for every endpoint),
        // 4-byte aligned at `OTG_FS_BASE + 0x1000`. The read pops a word, which
        // is the intended effect, so it must be `read_volatile`.
        unsafe { core::ptr::read_volatile((OTG_FS_BASE + FIFO) as *const u32) }
    }

    fn write_fifo_word(&mut self, ep: u8, word: u32) {
        // SAFETY: endpoint `ep`'s window is `OTG_FS_BASE + 0x1000 + ep * 0x1000`
        // (`stm32l4s5xx.h:1494-1495`). `ep` here is always 0, `EP_DATA` or
        // `EP_NOTIFY`, all < 4, so the address is inside the peripheral. The
        // masking makes that a property of the code rather than of every caller.
        let window = OTG_FS_BASE + FIFO + (ep as usize & 0x0f) * FIFO_STRIDE;
        unsafe { core::ptr::write_volatile(window as *mut u32, word) }
    }

    fn tx_words_free(&mut self, ep: u8) -> u16 {
        // SAFETY: `DTXFSTS` is `IN_EP + ep * 0x20 + 0x18`. `INEPTFSAV` is bits
        // 15:0 (`stm32l4s5xx.h:19675`), so the truncation is the field width.
        let raw = unsafe { core::ptr::read_volatile(in_ep(ep as usize & 0x0f, EP_TXFSTS)) };
        (raw & 0xffff) as u16
    }
}

/// Spin count standing in for ST's `HAL_Delay(50)` after a mode change
/// (`stm32l4xx_ll_usb.c:236`). ~50 ms at 120 MHz if the loop body is a few
/// cycles; this crate has no timer, so it is a count and it is the knob to turn
/// at the bench.
pub const MODE_SETTLE_SPINS: u32 = 6_000_000;

/// Iteration bound for `GRSTCTL` waits. ST uses 200 000 (`:393,415,1171`).
pub const RESET_SPIN_LIMIT: u32 = 200_000;

/// Iteration bound for a `DIEPCTL.EPENA` wait.
pub const EP_IDLE_SPIN_LIMIT: u32 = 1_000_000;

/// Bring the peripheral from cold to connected. **Bench-only: never run.**
#[cfg(target_arch = "arm")]
fn bring_up() -> Result<(), UsbError> {
    enable_clocks();
    configure_pins();

    // 1. Select the embedded full-speed PHY, then reset the core -- in that
    //    order, because the reset is what makes the PHY selection take effect
    //    (`stm32l4xx_ll_usb.c:88-91`).
    modify_reg(global(GUSBCFG), |v| v | GUSBCFG_PHYSEL);
    core_reset()?;

    // 2. Activate the transceiver (`:96`).
    modify_reg(global(GCCFG), |v| v | GCCFG_PWRDWN);

    // 3. No VBUS sensing. The Mk4 has no VBUS-detect pin, so hardware sensing
    //    would leave the core believing the session is invalid and it would never
    //    pull D+ up. Disable `VBDEN` and override the B-session-valid inputs
    //    (`:261-271`; MicroPython takes the same branch whenever
    //    `MICROPY_HW_USB_VBUS_DETECT_PIN` is undefined, `usbd_conf.c:390`). This
    //    is the single most likely bring-up failure point in this function.
    modify_reg(global(GCCFG), |v| v & !GCCFG_VBDEN);
    modify_reg(global(GOTGCTL), |v| v | GOTGCTL_BVALOEN | GOTGCTL_BVALOVAL);

    // 4. Soft-disconnect while the rest is configured, so the host cannot start
    //    enumerating a half-initialised device.
    modify_reg(device(DCTL), |v| v | DCTL_SDIS);

    // 5. Force device mode and set the turnaround time. ST clears both mode bits
    //    before setting one (`:222-231`); TRDT is 0x6 for HCLK >= 32 MHz
    //    (`:170-174`), and this part runs at 120.
    modify_reg(global(GUSBCFG), |v| {
        (v & !(GUSBCFG_FHMOD | GUSBCFG_FDMOD | GUSBCFG_TRDT_MASK))
            | GUSBCFG_FDMOD
            | (6 << GUSBCFG_TRDT_SHIFT)
    });
    settle();

    // 6. Restart the PHY clock and set full speed. ST's `USB_SetDevSpeed` ORs the
    //    field without clearing it (`:433`); clear first.
    write_reg(PCGCCTL, 0);
    modify_reg(device(DCFG), |v| (v & !DCFG_DSPD_MASK) | DCFG_DSPD_FULL);

    // 7. Zero every TX FIFO size register before partitioning, because
    //    `USB_DevInit` does (`:255-258`) and a stale value from the bootloader
    //    would overlap our partition.
    for i in 0..15 {
        write_reg(dieptxf(i), 0);
    }

    // 8. Flush the FIFOs. `TXFNUM = 0x10` means all of them (`:288`).
    flush_tx_all()?;
    flush_rx()?;

    // 9. Interrupt masks. `GINTMSK` is programmed as ST does, but `GAHBCFG.GINT`
    //    stays 0 and the NVIC line is never enabled, so nothing is delivered --
    //    see the module docs on polling. `DAINTMSK` stays 0: `poll` never reads
    //    `DAINT`.
    write_reg(DIEPMSK_G, 0);
    write_reg(DOEPMSK_G, 0);
    write_reg(DAINTMSK_G, 0);
    write_reg(GINTSTS, 0xbfff_ffff); // clear pending (`:353`)
    write_reg(GINTMSK, GINTSTS_RXFLVL | GINTSTS_USBRST | GINTSTS_ENUMDNE);
    modify_reg(global(GAHBCFG), |v| v & !GAHBCFG_GINT);

    // 10. Partition the FIFO RAM. Must come after the zeroing in step 7, and the
    //     RX FIFO must be sized first because every TX start address is relative
    //     to the top of it.
    write_reg(GRXFSIZ, RX_FIFO_WORDS);
    write_reg(DIEPTXF0_G, DIEPTXF0);
    write_reg(dieptxf(EP_NOTIFY as usize), DIEPTXF1);
    write_reg(dieptxf(EP_DATA as usize), DIEPTXF2);

    // 11. Endpoint 0 and the SETUP path.
    reset_endpoints();
    modify_reg(device(DCTL), |v| v | DCTL_CGINAK); // `:1126`
    arm_ep0_out();

    // 12. Connect: release the soft disconnect and un-gate the PHY clock
    //     (`:981-983`).
    modify_reg(PCGCCTL_PTR, |v| v & !(PCGCCTL_STPPCLK | PCGCCTL_GATEHCLK));
    modify_reg(device(DCTL), |v| v & !DCTL_SDIS);
    Ok(())
}

/// `GUSBCFG.PHYSEL`, bit 6 (`stm32l4s5xx.h:18578`).
#[cfg(target_arch = "arm")]
const GUSBCFG_PHYSEL: u32 = 1 << 6;
/// `GUSBCFG.TRDT` shift, bits 13:10 (`:18587`).
#[cfg(target_arch = "arm")]
const GUSBCFG_TRDT_SHIFT: u32 = 10;
/// `GUSBCFG.TRDT` mask.
#[cfg(target_arch = "arm")]
const GUSBCFG_TRDT_MASK: u32 = 0xf << GUSBCFG_TRDT_SHIFT;
/// `GUSBCFG.FHMOD`, bit 29.
#[cfg(target_arch = "arm")]
const GUSBCFG_FHMOD: u32 = 1 << 29;
/// `GUSBCFG.FDMOD`, bit 30 (`:18627`).
#[cfg(target_arch = "arm")]
const GUSBCFG_FDMOD: u32 = 1 << 30;
/// `GCCFG.PWRDWN`, bit 16 (`:18945`).
#[cfg(target_arch = "arm")]
const GCCFG_PWRDWN: u32 = 1 << 16;
/// `GCCFG.VBDEN`, bit 21 (`:18960`).
#[cfg(target_arch = "arm")]
const GCCFG_VBDEN: u32 = 1 << 21;
/// `GOTGCTL.BVALOEN`, bit 6 (`:18520`).
#[cfg(target_arch = "arm")]
const GOTGCTL_BVALOEN: u32 = 1 << 6;
/// `GOTGCTL.BVALOVAL`, bit 7 (`:18523`).
#[cfg(target_arch = "arm")]
const GOTGCTL_BVALOVAL: u32 = 1 << 7;
/// `GAHBCFG.GINT`, bit 0 (`:18551`).
#[cfg(target_arch = "arm")]
const GAHBCFG_GINT: u32 = 1 << 0;
/// `GRSTCTL.CSRST`, bit 0 (`:18635`).
#[cfg(target_arch = "arm")]
const GRSTCTL_CSRST: u32 = 1 << 0;
/// `GRSTCTL.RXFFLSH`, bit 4 (`:18644`).
#[cfg(target_arch = "arm")]
const GRSTCTL_RXFFLSH: u32 = 1 << 4;
/// `GRSTCTL.TXFFLSH`, bit 5 (`:18647`).
#[cfg(target_arch = "arm")]
const GRSTCTL_TXFFLSH: u32 = 1 << 5;
/// `GRSTCTL.TXFNUM` shift, bits 10:6 (`:18650`).
#[cfg(target_arch = "arm")]
const GRSTCTL_TXFNUM_SHIFT: u32 = 6;
/// `GRSTCTL.AHBIDL`, bit 31 (`:18661`).
#[cfg(target_arch = "arm")]
const GRSTCTL_AHBIDL: u32 = 1 << 31;
/// `DCTL.SDIS`, bit 1 (`:19331`).
#[cfg(target_arch = "arm")]
const DCTL_SDIS: u32 = 1 << 1;
/// `DCTL.CGINAK`, bit 8.
#[cfg(target_arch = "arm")]
const DCTL_CGINAK: u32 = 1 << 8;
/// `DCFG.DSPD` mask, bits 1:0 (`:19298`).
#[cfg(target_arch = "arm")]
const DCFG_DSPD_MASK: u32 = 0x3;
/// `DCFG.DSPD` = full speed. `USB_OTG_SPEED_FULL` is 3
/// (`stm32l4xx_ll_usb.h:333`).
#[cfg(target_arch = "arm")]
const DCFG_DSPD_FULL: u32 = 3;
/// `PCGCCTL.STPPCLK`, bit 0 (`:19755`).
#[cfg(target_arch = "arm")]
const PCGCCTL_STPPCLK: u32 = 1 << 0;
/// `PCGCCTL.GATEHCLK`, bit 1 (`:19758`).
#[cfg(target_arch = "arm")]
const PCGCCTL_GATEHCLK: u32 = 1 << 1;
/// `DOEPTSIZ.STUPCNT` = 3 SETUP packets, bits 30:29 (`:19746`).
#[cfg(target_arch = "arm")]
const DOEPTSIZ_STUPCNT_3: u32 = 3 << 29;

/// `PCGCCTL` as a pointer.
#[cfg(target_arch = "arm")]
const PCGCCTL_PTR: *mut u32 = (OTG_FS_BASE + offset::PCGCCTL) as *mut u32;
/// `DIEPMSK` as a global offset.
#[cfg(target_arch = "arm")]
const DIEPMSK_G: usize = offset::DEVICE + DIEPMSK;
/// `DOEPMSK` as a global offset.
#[cfg(target_arch = "arm")]
const DOEPMSK_G: usize = offset::DEVICE + DOEPMSK;
/// `DAINTMSK` as a global offset.
#[cfg(target_arch = "arm")]
const DAINTMSK_G: usize = offset::DEVICE + DAINTMSK;
/// `DIEPTXF0` as a global offset.
#[cfg(target_arch = "arm")]
const DIEPTXF0_G: usize = offset::DIEPTXF0;

/// Offset of `DIEPTXFn`. `n == 0` is the separate `0x028` register; 1..=15 are the
/// array at `0x104` (`stm32l4s5xx.h:1190-1191`).
#[cfg(target_arch = "arm")]
const fn dieptxf(n: usize) -> usize {
    if n == 0 {
        offset::DIEPTXF0
    } else {
        offset::DIEPTXF1 + (n - 1) * 4
    }
}

/// Burn `MODE_SETTLE_SPINS` iterations. Bounded by construction.
#[cfg(target_arch = "arm")]
fn settle() {
    for _ in 0..MODE_SETTLE_SPINS {
        // SAFETY: `nop` touches no memory and no special register.
        unsafe { core::arch::asm!("nop", options(nomem, nostack, preserves_flags)) }
    }
}

/// Wait for AHB idle, then soft-reset the core (`stm32l4xx_ll_usb.c:1164-1190`).
/// ST's waits are bounded by a counter; ours return an error rather than spinning,
/// for the same reason `flash::sr_wait_done` does.
#[cfg(target_arch = "arm")]
fn core_reset() -> Result<(), UsbError> {
    wait_bits(GRSTCTL, GRSTCTL_AHBIDL, true)?;
    modify_reg(global(GRSTCTL), |v| v | GRSTCTL_CSRST);
    wait_bits(GRSTCTL, GRSTCTL_CSRST, false)
}

/// Flush every transmit FIFO (`:288,389`).
#[cfg(target_arch = "arm")]
fn flush_tx_all() -> Result<(), UsbError> {
    write_reg(GRSTCTL, GRSTCTL_TXFFLSH | (0x10 << GRSTCTL_TXFNUM_SHIFT));
    wait_bits(GRSTCTL, GRSTCTL_TXFFLSH, false)
}

/// Flush the receive FIFO (`:411`).
#[cfg(target_arch = "arm")]
fn flush_rx() -> Result<(), UsbError> {
    write_reg(GRSTCTL, GRSTCTL_RXFFLSH);
    wait_bits(GRSTCTL, GRSTCTL_RXFFLSH, false)
}

/// Spin until `bits` in the register at `off` are set (`want`) or clear.
///
/// The countdown is `checked_sub`, so exhausting it returns
/// [`UsbError::CoreResetTimeout`] instead of hanging.
#[cfg(target_arch = "arm")]
fn wait_bits(off: usize, bits: u32, want: bool) -> Result<(), UsbError> {
    let mut spins = RESET_SPIN_LIMIT;
    loop {
        if ((read_reg(off) & bits) != 0) == want {
            return Ok(());
        }
        spins = match spins.checked_sub(1) {
            Some(s) => s,
            None => return Err(UsbError::CoreResetTimeout),
        };
    }
}

/// Wait for `DIEPCTL.EPENA` to clear, so `DIEPTSIZ` can be reprogrammed.
#[cfg(target_arch = "arm")]
fn wait_ep_idle(ctl: *mut u32) -> Result<(), UsbError> {
    let mut spins = EP_IDLE_SPIN_LIMIT;
    loop {
        // SAFETY: `ctl` comes from `in_ep`, inside the OTG_FS window.
        if unsafe { core::ptr::read_volatile(ctl) } & DIEPCTL_EPENA == 0 {
            return Ok(());
        }
        spins = match spins.checked_sub(1) {
            Some(s) => s,
            None => return Err(UsbError::EndpointBusy),
        };
    }
}

/// Return every endpoint to its post-reset state (`stm32l4xx_ll_usb.c:303-345`).
#[cfg(target_arch = "arm")]
fn reset_endpoints() {
    for ep in 0..4usize {
        for (ctl, tsiz, int) in [
            (in_ep(ep, EP_CTL), in_ep(ep, EP_TSIZ), in_ep(ep, EP_INT)),
            (out_ep(ep, EP_CTL), out_ep(ep, EP_TSIZ), out_ep(ep, EP_INT)),
        ] {
            // SAFETY: all three come from `in_ep`/`out_ep`, inside the window.
            unsafe {
                let enabled = core::ptr::read_volatile(ctl) & DIEPCTL_EPENA != 0;
                let value = if !enabled {
                    0
                } else if ep == 0 {
                    DIEPCTL_SNAK
                } else {
                    DIEPCTL_EPDIS | DIEPCTL_SNAK
                };
                core::ptr::write_volatile(ctl, value);
                core::ptr::write_volatile(tsiz, 0);
                core::ptr::write_volatile(int, 0xfb7f);
            }
        }
    }
}

/// Arm endpoint 0 OUT for up to three back-to-back SETUP packets
/// (`stm32l4xx_ll_usb.c:1151-1154`).
#[cfg(target_arch = "arm")]
fn arm_ep0_out() {
    // 3 * 8 bytes, one packet, three SETUPs. A plain write, not a
    // read-modify-write: leaving a stale XFRSIZ ORed in is how a re-arm ends up
    // promising the core more bytes than the buffer holds.
    write_ptr(out_ep(0, EP_TSIZ), DOEPTSIZ_STUPCNT_3 | (1 << 19) | 24);
    modify_reg(out_ep(0, EP_CTL), |v| v | DIEPCTL_CNAK | DIEPCTL_EPENA);
}

/// Arm [`EP_DATA_OUT`] for one maximum-size packet.
///
// ponytail: one packet per transfer, re-armed after each. Costs a transfer setup
// per 64 bytes. Upgrade path if throughput matters: raise PKTCNT and XFRSIZ and
// re-arm every N packets -- `xfer_size` already encodes it.
#[cfg(target_arch = "arm")]
fn arm_data_out() {
    write_ptr(
        out_ep(EP_DATA as usize, EP_TSIZ),
        (1 << 19) | MAX_PACKET_SIZE as u32,
    );
    modify_reg(out_ep(EP_DATA as usize, EP_CTL), |v| {
        v | DIEPCTL_CNAK | DIEPCTL_EPENA
    });
}

/// Send a control IN data or status stage. `bytes` empty is the zero-length
/// status stage.
#[cfg(target_arch = "arm")]
fn ep0_send(bytes: &[u8]) -> Result<(), UsbError> {
    let tsiz = match ep0_xfer_size(bytes.len()) {
        Some(t) => t,
        // Unreachable while every descriptor passes the `const _` assert above,
        // and a `Result` rather than an assert because an assert is a brick.
        None => return Err(UsbError::OversizePacket { len: bytes.len() }),
    };
    wait_ep_idle(in_ep(0, EP_CTL))?;
    write_reg(offset::IN_EP + EP_TSIZ, tsiz);
    modify_reg(in_ep(0, EP_CTL), |v| v | DIEPCTL_CNAK | DIEPCTL_EPENA);
    fifo_write(&mut Mmio, 0, bytes, USB_SPIN_LIMIT)
}

/// Stall endpoint 0 in both directions and re-arm it for the next SETUP
/// (`stm32l4xx_ll_usb.c:860-889`).
#[cfg(target_arch = "arm")]
fn ep0_stall() {
    modify_reg(in_ep(0, EP_CTL), |v| v | DIEPCTL_STALL);
    modify_reg(out_ep(0, EP_CTL), |v| v | DIEPCTL_STALL);
    arm_ep0_out();
}

/// Enable the three configured endpoints (`stm32l4xx_ll_usb.c:473-503`).
#[cfg(target_arch = "arm")]
fn activate_endpoints() {
    // Interrupt IN, 8 bytes, own FIFO.
    modify_reg(in_ep(EP_NOTIFY as usize, EP_CTL), |v| {
        v | 8
            | (3 << DIEPCTL_EPTYP_SHIFT)
            | (u32::from(EP_NOTIFY) << DIEPCTL_TXFNUM_SHIFT)
            | DIEPCTL_SD0PID
            | DIEPCTL_USBAEP
    });
    // Bulk IN.
    modify_reg(in_ep(EP_DATA as usize, EP_CTL), |v| {
        v | MAX_PACKET_SIZE as u32
            | (2 << DIEPCTL_EPTYP_SHIFT)
            | (u32::from(EP_DATA) << DIEPCTL_TXFNUM_SHIFT)
            | DIEPCTL_SD0PID
            | DIEPCTL_USBAEP
    });
    // Bulk OUT, then armed so the host's first packet is accepted.
    modify_reg(out_ep(EP_DATA as usize, EP_CTL), |v| {
        v | MAX_PACKET_SIZE as u32
            | (2 << DIEPCTL_EPTYP_SHIFT)
            | DIEPCTL_SD0PID
            | DIEPCTL_USBAEP
    });
    arm_data_out();
}

/// Disable the three configured endpoints, for SET_CONFIGURATION(0).
#[cfg(target_arch = "arm")]
fn deactivate_endpoints() {
    for ctl in [
        in_ep(EP_NOTIFY as usize, EP_CTL),
        in_ep(EP_DATA as usize, EP_CTL),
        out_ep(EP_DATA as usize, EP_CTL),
    ] {
        modify_reg(ctl, |v| (v | DIEPCTL_SNAK) & !DIEPCTL_USBAEP);
    }
}

/// Handle `GINTSTS.USBRST`: flush, reset endpoints, address 0, re-arm SETUP
/// (RM0432 "USB reset" device-programming sequence).
#[cfg(target_arch = "arm")]
fn on_reset() -> Result<(), UsbError> {
    flush_tx_all()?;
    flush_rx()?;
    reset_endpoints();
    modify_reg(device(DCFG), |v| v & !DCFG_DAD_MASK);
    arm_ep0_out();
    Ok(())
}

/// Turn on the peripheral clock and the USB power supply valid bit.
///
/// The `RCC_AHB2ENR` read-modify-write runs inside
/// [`crate::callgate::with_irq_off`]. Note precisely what that does and does not
/// buy: it stops an interrupt from landing between our read and our write. It does
/// **not** make this mutually exclusive with `rng::enable_rng_clock`, which does
/// an unguarded read-modify-write on bit 18 of the same register
/// (`rng.rs:594-597`) -- both run from boot code, so in the current single-threaded
/// startup they cannot interleave, and if either ever moves into an ISR the other
/// needs the same guard.
#[cfg(target_arch = "arm")]
fn enable_clocks() {
    /// `RCC_AHB2ENR` (`stm32l4s5xx.h`, `RCC` at `0x4002_1000` + `0x4c`).
    const RCC_AHB2ENR: *mut u32 = 0x4002_104c as *mut u32;
    /// `RCC_APB1ENR1`.
    const RCC_APB1ENR1: *mut u32 = 0x4002_1058 as *mut u32;
    /// `PWR_CR2`.
    const PWR_CR2: *mut u32 = 0x4000_7004 as *mut u32;
    /// `RCC_AHB2ENR.OTGFSEN`, bit 12.
    const OTGFSEN: u32 = 1 << 12;
    /// `RCC_APB1ENR1.PWREN`, bit 28.
    const PWREN: u32 = 1 << 28;
    /// `PWR_CR2.USV` -- USB supply valid, bit 10. Without it the transceiver has
    /// no supply and D+ is never pulled up.
    const USV: u32 = 1 << 10;

    // SAFETY: three 4-byte-aligned memory-mapped peripheral registers. Every
    // write is a read-modify-write of a single bit, so none can disable a
    // peripheral another module owns; PWREN is restored to the value found.
    unsafe {
        let apb = core::ptr::read_volatile(RCC_APB1ENR1);
        if apb & PWREN == 0 {
            core::ptr::write_volatile(RCC_APB1ENR1, apb | PWREN);
        }
        let cr2 = core::ptr::read_volatile(PWR_CR2);
        core::ptr::write_volatile(PWR_CR2, cr2 | USV);
        if apb & PWREN == 0 {
            core::ptr::write_volatile(RCC_APB1ENR1, apb);
        }

        crate::callgate::with_irq_off(|| {
            let en = core::ptr::read_volatile(RCC_AHB2ENR);
            core::ptr::write_volatile(RCC_AHB2ENR, en | OTGFSEN);
            // Read back so the clock is live before the first OTG access, as the
            // HAL's own enable macros do.
            let _ = core::ptr::read_volatile(RCC_AHB2ENR);
        });
        core::arch::asm!("dsb", options(nomem, nostack, preserves_flags));
    }
}

/// Put PA11/PA12 on AF10 (`OTG_FS_DM`/`OTG_FS_DP`).
///
/// Read-modify-write on the *nibbles and bit-pairs for these two pins only*, never
/// a whole-register write and never an AHB2 GPIO reset: PA9 holds AF7 for the
/// bootloader's console and PA4-PA8 drive the OLED, and clobbering them takes the
/// display and the log with it.
#[cfg(target_arch = "arm")]
fn configure_pins() {
    /// `GPIOA` base.
    const GPIOA: usize = 0x4800_0000;
    /// `RCC_AHB2ENR.GPIOAEN`, bit 0.
    const GPIOAEN: u32 = 1 << 0;

    // SAFETY: `GPIOA_MODER`/`OSPEEDR`/`AFRH` are 4-byte-aligned memory-mapped
    // registers at GPIOA + 0x00/0x08/0x24. Each write clears and sets only the
    // fields belonging to PA11 and PA12; no other pin's configuration is read or
    // written, which is the point.
    unsafe {
        crate::callgate::with_irq_off(|| {
            let en = core::ptr::read_volatile(0x4002_104c as *mut u32);
            core::ptr::write_volatile(0x4002_104c as *mut u32, en | GPIOAEN);
        });
        // `+ 0x00` kept on purpose: these three lines are a register-offset table
        // and MODER's offset being 0x00 is information, not noise. The lint is
        // right about the arithmetic and wrong about the intent.
        #[allow(clippy::identity_op)]
        let moder = (GPIOA + 0x00) as *mut u32;
        let ospeedr = (GPIOA + 0x08) as *mut u32;
        let afrh = (GPIOA + 0x24) as *mut u32;

        // MODER: 0b10 = alternate function, two bits per pin.
        let v = core::ptr::read_volatile(moder);
        core::ptr::write_volatile(moder, (v & !(0b1111 << 22)) | (0b1010 << 22));
        // OSPEEDR: 0b11 = very high speed, required for full-speed USB.
        let v = core::ptr::read_volatile(ospeedr);
        core::ptr::write_volatile(ospeedr, v | (0b1111 << 22));
        // AFRH: pins 8..15, four bits per pin; PA11 is nibble 3, PA12 nibble 4.
        let v = core::ptr::read_volatile(afrh);
        core::ptr::write_volatile(
            afrh,
            (v & !(0xf << 12) & !(0xf << 16)) | (0xa << 12) | (0xa << 16),
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::*;
    use crate::comms::{self, Link, FRAME_LIMIT};
    use alloc::vec::Vec;
    use frostsnap_comms::{
        CoordinatorSendBody, CoordinatorSendMessage, Destination, MagicBytes, ReceiveSerial,
        Upstream, WireCoordinatorSendBody, BINCODE_CONFIG,
    };

    type FromCoordinator = ReceiveSerial<Upstream>;

    // ---- descriptors -------------------------------------------------------

    #[test]
    fn device_descriptor_is_self_consistent() {
        let d = &DEVICE_DESCRIPTOR;
        assert_eq!(usize::from(d[0]), d.len(), "bLength");
        assert_eq!(d[1], 0x01, "bDescriptorType");
        assert_eq!(usize::from(d[7]), MAX_PACKET_SIZE, "bMaxPacketSize0");
        assert_eq!(u16::from_le_bytes([d[8], d[9]]), VID);
        assert_eq!(u16::from_le_bytes([d[10], d[11]]), PID);
        assert_eq!(d[17], 1, "bNumConfigurations");
        // The three string indices must all resolve, or the host logs an error
        // and shows an unnamed port.
        for index in [d[14], d[15], d[16]] {
            assert!(index > 0, "string index 0 means 'no string'");
            assert!(
                descriptor(0x0300 | u16::from(index)).is_some(),
                "iString {index} does not resolve"
            );
        }
    }

    /// `wTotalLength` re-derived by walking the chain, so a hand-edited
    /// descriptor cannot disagree with its own header.
    #[test]
    fn configuration_descriptor_total_length_matches_its_contents() {
        let c = &CONFIG_DESCRIPTOR;
        assert_eq!(c[1], 0x02, "bDescriptorType");
        assert_eq!(
            usize::from(u16::from_le_bytes([c[2], c[3]])),
            c.len(),
            "wTotalLength disagrees with the array"
        );

        let mut at = 0;
        let mut count = 0;
        while at < c.len() {
            let len = usize::from(c[at]);
            // A zero bLength is how a descriptor walk becomes an infinite loop on
            // the host side, so refuse it here rather than shipping it.
            assert!(len >= 2, "zero-length descriptor at {at}");
            assert!(at + len <= c.len(), "descriptor at {at} runs past the end");
            at += len;
            count += 1;
        }
        assert_eq!(at, c.len(), "the chain does not tile the array");
        assert_eq!(count, 10, "expected 10 descriptors in the configuration");
    }

    /// Every endpoint descriptor in [`CONFIG_DESCRIPTOR`], as
    /// `(bEndpointAddress, transfer type, wMaxPacketSize)`.
    fn advertised_endpoints() -> Vec<(u8, u8, u16)> {
        let c = &CONFIG_DESCRIPTOR;
        let mut found = Vec::new();
        let mut at = 0;
        while at < c.len() {
            let len = usize::from(c[at]);
            if c[at + 1] == 0x05 {
                found.push((
                    c[at + 2],
                    c[at + 3] & 0x03,
                    u16::from_le_bytes([c[at + 4], c[at + 5]]),
                ));
            }
            at += len;
        }
        found
    }

    #[test]
    fn endpoint_descriptors_agree_with_the_endpoint_constants() {
        let c = &CONFIG_DESCRIPTOR;
        let found = advertised_endpoints();
        assert_eq!(
            found,
            alloc::vec![
                (EP_NOTIFY_IN, 3, 8),                        // interrupt
                (EP_DATA_OUT, 2, MAX_PACKET_SIZE as u16),    // bulk
                (EP_DATA_IN, 2, MAX_PACKET_SIZE as u16),     // bulk
            ]
        );
        assert_eq!(c[4], 2, "bNumInterfaces");
    }

    #[test]
    fn string_descriptors_are_utf16le_and_self_length_consistent() {
        for (d, text) in [
            (STRING_MANUFACTURER.as_slice(), "cold-snap"),
            (STRING_PRODUCT.as_slice(), "Frostsnap Signer"),
            (STRING_SERIAL.as_slice(), "0001"),
        ] {
            assert_eq!(usize::from(d[0]), d.len(), "bLength");
            assert_eq!(d[1], 0x03, "bDescriptorType");
            assert_eq!(d.len(), 2 + 2 * text.len());
            for (i, ch) in text.bytes().enumerate() {
                assert_eq!(d[2 + 2 * i], ch);
                assert_eq!(d[3 + 2 * i], 0, "high byte of a UTF-16LE unit");
            }
        }
        assert_eq!(STRING_LANGID.as_slice(), &[0x04, 0x03, 0x09, 0x04]);
    }

    // ---- FIFO partition ----------------------------------------------------

    #[test]
    fn the_fifo_partition_fits_and_does_not_overlap() {
        let plan = [
            (0u32, RX_FIFO_WORDS, "rx"),
            (DIEPTXF0 & 0xffff, DIEPTXF0 >> 16, "txf0"),
            (DIEPTXF1 & 0xffff, DIEPTXF1 >> 16, "txf1"),
            (DIEPTXF2 & 0xffff, DIEPTXF2 >> 16, "txf2"),
        ];
        let mut expected_start = 0;
        for (start, size, name) in plan {
            assert_eq!(start, expected_start, "{name} starts in the wrong place");
            assert!(size > 0, "{name} has no space");
            expected_start = start + size;
        }
        assert!(
            expected_start <= FIFO_WORDS_TOTAL,
            "partition needs {expected_start} words, the core has {FIFO_WORDS_TOTAL}"
        );

        // Each IN FIFO must hold one maximum-size packet for its endpoint -- and
        // "maximum-size" means what the descriptor PROMISES the host, not what
        // this module's constants happen to say. A FIFO smaller than the
        // advertised wMaxPacketSize is a host that sends a legal packet the
        // device cannot hold. Endpoint 0's size is `bMaxPacketSize0` in the
        // device descriptor rather than an endpoint descriptor.
        let fifo_bytes = |txf: u32| (txf >> 16) * 4;
        assert!(
            fifo_bytes(DIEPTXF0) >= u32::from(DEVICE_DESCRIPTOR[7]),
            "txf0 cannot hold a bMaxPacketSize0 packet"
        );
        for (address, _, mps) in advertised_endpoints() {
            if address & 0x80 == 0 {
                continue; // OUT endpoints draw on the shared RX FIFO.
            }
            let txf = match address {
                EP_NOTIFY_IN => DIEPTXF1,
                EP_DATA_IN => DIEPTXF2,
                other => panic!("endpoint {other:#04x} is advertised with no TX FIFO"),
            };
            assert!(
                fifo_bytes(txf) >= u32::from(mps),
                "endpoint {address:#04x} advertises {mps} bytes, its FIFO holds {}",
                fifo_bytes(txf)
            );
        }
        // The shared RX FIFO must hold the largest packet any OUT endpoint
        // advertises, plus the core's own per-packet status word.
        let largest_out = advertised_endpoints()
            .iter()
            .filter(|(a, _, _)| a & 0x80 == 0)
            .map(|&(_, _, mps)| u32::from(mps))
            .max()
            .expect("there is at least one OUT endpoint");
        assert!(RX_FIFO_WORDS * 4 >= largest_out + 4);
    }

    // ---- SETUP parsing -----------------------------------------------------

    #[test]
    fn setup_parse_is_little_endian() {
        let s = Setup::parse(&[0x81, 0x06, 0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a]);
        assert_eq!(s.request_type, 0x81);
        assert_eq!(s.request, 0x06);
        assert_eq!(s.value, 0x1234);
        assert_eq!(s.index, 0x5678);
        assert_eq!(s.length, 0x9abc);
        assert!(s.is_in());
        assert_eq!(s.kind(), KIND_STANDARD);
        assert_eq!(s.recipient(), RECIPIENT_INTERFACE);
    }

    /// ST masks the recipient field with `0x03`, so `bmRequestType = 0x04`
    /// (recipient 4, reserved) is dispatched as `RECIPIENT_DEVICE`. Five bits
    /// means those fall through to a stall instead.
    #[test]
    fn reserved_recipients_are_not_aliased() {
        for recipient in 0x04..=0x1fu8 {
            let s = Setup::parse(&[recipient, 0x00, 0, 0, 0, 0, 2, 0]);
            assert_eq!(s.recipient(), recipient);
            assert_eq!(
                control_reply(&s, &ControlState::new()),
                Reply::Stall,
                "recipient {recipient:#x} was answered"
            );
        }
    }

    // ---- control dispatch --------------------------------------------------

    /// Build an IN standard device request.
    fn get(request: u8, value: u16, length: u16) -> Setup {
        Setup {
            request_type: 0x80,
            request,
            value,
            index: 0,
            length,
        }
    }

    #[test]
    fn get_descriptor_returns_the_right_bytes_clamped_to_wlength() {
        let state = ControlState::new();
        for (value, want) in [
            (0x0100u16, DEVICE_DESCRIPTOR.as_slice()),
            (0x0200, CONFIG_DESCRIPTOR.as_slice()),
            (0x0300, STRING_LANGID.as_slice()),
            (0x0301, STRING_MANUFACTURER.as_slice()),
            (0x0302, STRING_PRODUCT.as_slice()),
            (0x0303, STRING_SERIAL.as_slice()),
        ] {
            assert_eq!(
                control_reply(&get(0x06, value, 0xffff), &state),
                Reply::Data(want),
                "{value:#06x} full read"
            );
            // The host's first GET_DESCRIPTOR asks for 8 bytes, and answering
            // more than wLength is a protocol error the host reports as a
            // babble.
            assert_eq!(
                control_reply(&get(0x06, value, 8), &state),
                Reply::Data(&want[..core::cmp::min(8, want.len())]),
                "{value:#06x} short read"
            );
            assert_eq!(
                control_reply(&get(0x06, value, 0), &state),
                Reply::Data(&[]),
                "{value:#06x} zero-length read"
            );
        }
    }

    /// A full-speed-only device must stall DEVICE_QUALIFIER and
    /// OTHER_SPEED_CONFIGURATION. Answering them advertises a high-speed
    /// capability this PHY does not have, and Linux logs it as a bad descriptor.
    #[test]
    fn unsupported_descriptor_types_stall() {
        let state = ControlState::new();
        for value in [0x0600u16, 0x0700, 0x0f00, 0x0201, 0x0304, 0x0000] {
            assert_eq!(
                control_reply(&get(0x06, value, 64), &state),
                Reply::Stall,
                "{value:#06x} was answered"
            );
        }
    }

    #[test]
    fn set_address_is_range_checked_rather_than_masked() {
        let state = ControlState::new();
        let set_address = |value: u16, index: u16, length: u16| {
            control_reply(
                &Setup {
                    request_type: 0x00,
                    request: 0x05,
                    value,
                    index,
                    length,
                },
                &state,
            )
        };
        assert_eq!(set_address(0, 0, 0), Reply::SetAddress(0));
        assert_eq!(set_address(127, 0, 0), Reply::SetAddress(127));
        // ST masks with 0x7F, which would turn 128 into address 0 and 255 into
        // 127. Both are silent, and both leave the host and device disagreeing
        // about the address.
        for value in [128u16, 129, 255, 256, 0xffff] {
            assert_eq!(set_address(value, 0, 0), Reply::Stall, "{value} accepted");
        }
        assert_eq!(set_address(5, 1, 0), Reply::Stall, "nonzero wIndex");
        assert_eq!(set_address(5, 0, 1), Reply::Stall, "nonzero wLength");
    }

    #[test]
    fn set_configuration_accepts_only_the_one_configuration_that_exists() {
        let state = ControlState::new();
        let set_config = |value: u16| {
            control_reply(
                &Setup {
                    request_type: 0x00,
                    request: 0x09,
                    value,
                    index: 0,
                    length: 0,
                },
                &state,
            )
        };
        assert_eq!(set_config(1), Reply::SetConfiguration(true));
        assert_eq!(set_config(0), Reply::SetConfiguration(false));
        for value in [2u16, 3, 0xffff] {
            assert_eq!(set_config(value), Reply::Stall, "{value} accepted");
        }
    }

    #[test]
    fn get_configuration_reports_the_latched_value() {
        let mut state = ControlState::new();
        assert_eq!(
            control_reply(&get(0x08, 0, 1), &state),
            Reply::Data(&[0]),
            "not configured"
        );
        state.configured = true;
        assert_eq!(
            control_reply(&get(0x08, 0, 1), &state),
            Reply::Data(&[1]),
            "configured"
        );
    }

    #[test]
    fn get_status_is_two_zero_bytes_and_clamped() {
        let state = ControlState::new();
        for recipient in [RECIPIENT_DEVICE, RECIPIENT_INTERFACE, RECIPIENT_ENDPOINT] {
            let s = Setup {
                request_type: 0x80 | recipient,
                request: 0x00,
                value: 0,
                index: 0,
                length: 2,
            };
            assert_eq!(control_reply(&s, &state), Reply::Data(&[0, 0]));
        }
        let s = Setup {
            request_type: 0x80,
            request: 0x00,
            value: 0,
            index: 0,
            length: 1,
        };
        assert_eq!(control_reply(&s, &state), Reply::Data(&[0]));
    }

    /// Halting is not implemented, so SET_FEATURE(ENDPOINT_HALT) must be
    /// refused. ST's `USB_SetFeature` returns silently for any wValue other than
    /// DEVICE_REMOTE_WAKEUP -- no status stage and no stall -- which leaves the
    /// host waiting on a control transfer that will never complete.
    #[test]
    fn set_feature_is_refused_and_clear_feature_is_not() {
        let state = ControlState::new();
        let feature = |request: u8, recipient: u8, value: u16| {
            control_reply(
                &Setup {
                    request_type: recipient,
                    request,
                    value,
                    index: 0,
                    length: 0,
                },
                &state,
            )
        };
        // SET_FEATURE, every recipient, halt and remote wakeup alike.
        for recipient in [RECIPIENT_DEVICE, RECIPIENT_INTERFACE, RECIPIENT_ENDPOINT] {
            for value in [0x0000u16, 0x0001, 0x0002] {
                assert_eq!(feature(0x03, recipient, value), Reply::Stall);
            }
        }
        // CLEAR_FEATURE(ENDPOINT_HALT) is a no-op that must still succeed.
        assert_eq!(feature(0x01, RECIPIENT_ENDPOINT, 0x0000), Reply::Status);
        // ...but not any other feature selector.
        assert_eq!(feature(0x01, RECIPIENT_ENDPOINT, 0x0001), Reply::Stall);
    }

    // ---- the two CDC requests the coordinator actually issues --------------

    #[test]
    fn the_two_mandatory_class_requests_are_answered() {
        let state = ControlState::new();
        // SET_LINE_CODING, host -> device, exactly 7 bytes.
        let set_line_coding = Setup {
            request_type: 0x21,
            request: 0x20,
            value: 0,
            index: 0,
            length: 7,
        };
        assert_eq!(
            control_reply(&set_line_coding, &state),
            Reply::AcceptLineCoding
        );
        // SET_CONTROL_LINE_STATE, no data stage.
        let set_line_state = Setup {
            request_type: 0x21,
            request: 0x22,
            value: 0x0003,
            index: 0,
            length: 0,
        };
        assert_eq!(
            control_reply(&set_line_state, &state),
            Reply::SetLineState(0x0003)
        );
    }

    /// SET_LINE_CODING's `wLength` is attacker-controlled and arms an OUT data
    /// stage. Only 7 exists; anything else is refused before a buffer is
    /// promised.
    #[test]
    fn set_line_coding_with_a_wrong_length_is_refused() {
        let state = ControlState::new();
        for length in [0u16, 1, 6, 8, 64, 2060, 0xffff] {
            let s = Setup {
                request_type: 0x21,
                request: 0x20,
                value: 0,
                index: 0,
                length,
            };
            assert_eq!(control_reply(&s, &state), Reply::Stall, "wLength {length}");
        }
    }

    #[test]
    fn get_line_coding_returns_the_latched_value_clamped() {
        let state = ControlState::new();
        let get_line_coding = |length: u16| {
            control_reply(
                &Setup {
                    request_type: 0xa1,
                    request: 0x21,
                    value: 0,
                    index: 0,
                    length,
                },
                &state,
            )
        };
        assert_eq!(get_line_coding(7), Reply::LineCoding(7));
        assert_eq!(get_line_coding(64), Reply::LineCoding(7));
        assert_eq!(get_line_coding(3), Reply::LineCoding(3));
        assert_eq!(get_line_coding(0), Reply::LineCoding(0));
    }

    /// The default line coding is derived from the vendored constant, so this
    /// pins the CDC encoding of it rather than a literal.
    #[test]
    fn the_default_line_coding_is_the_frostsnap_baud_rate() {
        assert_eq!(frostsnap_comms::BAUDRATE, 19_200);
        assert_eq!(DEFAULT_LINE_CODING, [0x00, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x08]);
        assert_eq!(
            u32::from_le_bytes([
                DEFAULT_LINE_CODING[0],
                DEFAULT_LINE_CODING[1],
                DEFAULT_LINE_CODING[2],
                DEFAULT_LINE_CODING[3],
            ]),
            frostsnap_comms::BAUDRATE
        );
        assert_eq!(DEFAULT_LINE_CODING[6], 8, "bDataBits");
    }

    #[test]
    fn vendor_requests_are_refused() {
        let state = ControlState::new();
        for request in [0x00u8, 0x01, 0x40, 0xff] {
            let s = Setup {
                request_type: 0x40, // vendor, device
                request,
                value: 0,
                index: 0,
                length: 0,
            };
            assert_eq!(control_reply(&s, &state), Reply::Stall);
        }
    }

    // ---- transfer-size arithmetic -----------------------------------------

    #[test]
    fn xfer_size_counts_packets_for_a_full_frame() {
        // A zero-length packet is one packet of zero bytes, not zero packets.
        assert_eq!(xfer_size(0, 64), Some(1 << 19));
        assert_eq!(xfer_size(1, 64), Some((1 << 19) | 1));
        assert_eq!(xfer_size(64, 64), Some((1 << 19) | 64));
        assert_eq!(xfer_size(65, 64), Some((2 << 19) | 65));
        // The whole frame ceiling, if `write` is ever changed to program it in
        // one transfer.
        assert_eq!(
            xfer_size(FRAME_LIMIT, MAX_PACKET_SIZE),
            Some((64 << 19) | FRAME_LIMIT as u32),
            "4096 = 64 * 64 exactly, so no short final packet"
        );
        assert_eq!(xfer_size(10, 0), None, "mps 0 must not divide");
    }

    #[test]
    fn xfer_size_refuses_a_transfer_it_cannot_express() {
        assert_eq!(xfer_size(0x8_0000, 64), None, "xfrsiz is 19 bits");
        assert!(xfer_size(0x7_ffff, 64).is_none(), "pktcnt is 10 bits");
        assert!(xfer_size(0x3ff * 64, 64).is_some(), "1023 packets fit");
        assert_eq!(xfer_size(0x400 * 64, 64), None, "1024 packets do not");
    }

    /// Endpoint 0's `DIEPTSIZ` fields are 7 and 2 bits wide. Getting this wrong
    /// is invisible on a short descriptor and silently truncates a long one.
    #[test]
    fn ep0_xfer_size_is_narrower_than_every_other_endpoint() {
        assert_eq!(ep0_xfer_size(0), Some(1 << 19));
        assert_eq!(ep0_xfer_size(18), Some((1 << 19) | 18));
        assert_eq!(ep0_xfer_size(67), Some((2 << 19) | 67));
        assert_eq!(ep0_xfer_size(127), Some((2 << 19) | 127));
        assert_eq!(ep0_xfer_size(128), None, "xfrsiz is 7 bits on endpoint 0");
        assert_eq!(ep0_xfer_size(2060), None);
        // ...and every descriptor this module can send is inside it. The `const _`
        // block asserts the same thing at build time; this is the runnable half.
        for d in [
            DEVICE_DESCRIPTOR.as_slice(),
            CONFIG_DESCRIPTOR.as_slice(),
            STRING_LANGID.as_slice(),
            STRING_MANUFACTURER.as_slice(),
            STRING_PRODUCT.as_slice(),
            STRING_SERIAL.as_slice(),
        ] {
            assert!(ep0_xfer_size(d.len()).is_some(), "{} bytes", d.len());
        }
    }

    #[test]
    fn rx_status_decodes_the_reference_manual_fields() {
        // EPNUM 2, BCNT 64, PKTSTS OUT_DATA, DPID 0.
        let raw = 2 | (64 << 4) | (u32::from(PKTSTS_OUT_DATA) << 17);
        assert_eq!(
            rx_status(raw),
            RxStatus {
                ep: 2,
                len: 64,
                kind: PKTSTS_OUT_DATA
            }
        );
        // A SETUP packet on endpoint 0.
        let raw = (8 << 4) | (u32::from(PKTSTS_SETUP_DATA) << 17);
        assert_eq!(
            rx_status(raw),
            RxStatus {
                ep: 0,
                len: 8,
                kind: PKTSTS_SETUP_DATA
            }
        );
        // BCNT is 11 bits, so the core can report 2047 -- larger than any
        // endpoint here can legally deliver. The decode must not truncate it,
        // because `fifo_read` needs the real figure to keep the FIFO in step.
        let raw = (2047 << 4) | (u32::from(PKTSTS_OUT_DATA) << 17) | (0xf << 21);
        assert_eq!(rx_status(raw).len, 2047);
        assert_eq!(rx_status(raw).kind, PKTSTS_OUT_DATA, "DPID leaked into PKTSTS");
    }

    // ---- packet I/O --------------------------------------------------------

    /// Words the simulated FIFOs hold. Enough for a whole [`FRAME_LIMIT`]-byte
    /// frame plus slack, so a test cannot pass because the fixture ran out of
    /// room. (1,024 words is the 4,096-byte frame exactly.)
    const SIM_WORDS: usize = 1280;

    /// A word-addressed FIFO pair.
    ///
    /// Strict where the hardware is strict, per the `lib.rs` rule that a test
    /// double must be no more permissive than the part it stands in for:
    /// reading past what was pushed is a driver bug and asserts here rather than
    /// quietly returning zero, which is what would let a `fifo_read` that drains
    /// the wrong number of words pass.
    struct SimPort {
        rx: [u32; SIM_WORDS],
        rx_len: usize,
        rx_pos: usize,
        tx: [u32; SIM_WORDS],
        tx_len: usize,
        tx_ep: Vec<u8>,
        /// Words the TX FIFO reports free. `None` = never any room.
        free: Option<u16>,
    }

    impl SimPort {
        fn new() -> Self {
            Self {
                rx: [0; SIM_WORDS],
                rx_len: 0,
                rx_pos: 0,
                tx: [0; SIM_WORDS],
                tx_len: 0,
                tx_ep: Vec::new(),
                free: Some(u16::MAX),
            }
        }

        /// A FIFO that never has room, for the timeout path.
        fn wedged() -> Self {
            let mut p = Self::new();
            p.free = None;
            p
        }

        /// Push `bytes` as the core would: little-endian words, final word padded.
        fn push(&mut self, bytes: &[u8]) {
            for chunk in bytes.chunks(4) {
                let mut w = [0u8; 4];
                w[..chunk.len()].copy_from_slice(chunk);
                assert!(self.rx_len < SIM_WORDS, "SimPort rx overflow");
                self.rx[self.rx_len] = u32::from_le_bytes(w);
                self.rx_len += 1;
            }
        }

        /// Words consumed so far.
        fn consumed(&self) -> usize {
            self.rx_pos
        }

        /// Everything written, as bytes.
        fn written(&self) -> Vec<u8> {
            self.tx[..self.tx_len]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect()
        }
    }

    impl OtgPort for SimPort {
        fn read_fifo_word(&mut self) -> u32 {
            assert!(
                self.rx_pos < self.rx_len,
                "read {} words from a {}-word packet: the FIFO is now out of step",
                self.rx_pos + 1,
                self.rx_len
            );
            let w = self.rx[self.rx_pos];
            self.rx_pos += 1;
            w
        }

        fn write_fifo_word(&mut self, ep: u8, word: u32) {
            assert!(
                self.free.is_some_and(|f| f > 0),
                "wrote a word with no FIFO space"
            );
            assert!(self.tx_len < SIM_WORDS, "SimPort tx overflow");
            self.tx[self.tx_len] = word;
            self.tx_len += 1;
            self.tx_ep.push(ep);
        }

        fn tx_words_free(&mut self, _ep: u8) -> u16 {
            self.free.unwrap_or(0)
        }
    }

    /// THE ST DEFECT. `USB_ReadPacket` writes `(len + 3) / 4` whole words to
    /// `dest`, so a 5-byte packet clobbers `dest[5..8]`. In Rust that is an
    /// out-of-bounds write, not just a surprise.
    #[test]
    fn fifo_read_does_not_write_past_len() {
        for len in 1..=16usize {
            let mut port = SimPort::new();
            let payload: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x5a).collect();
            port.push(&payload);

            // One sentinel byte past `len`, which a whole-word write would hit
            // whenever `len % 4 != 0`.
            let mut dest = [0xffu8; 20];
            let n = fifo_read(&mut port, len, &mut dest).expect("fits");

            assert_eq!(n, len);
            assert_eq!(&dest[..len], payload.as_slice());
            assert!(
                dest[len..].iter().all(|&b| b == 0xff),
                "len {len} wrote past the end: {:?}",
                &dest[len..]
            );
            assert_eq!(port.consumed(), fifo_words(len), "wrong number of words");
        }
    }

    /// The refusal must still drain. The receive FIFO is shared by every OUT
    /// endpoint and by SETUP, so a packet left half-read desynchronises every
    /// later packet -- a refusal that skips the drain is worse than none.
    #[test]
    fn fifo_read_drains_the_whole_packet_even_when_it_refuses() {
        for len in [65usize, 100, 2047] {
            let mut port = SimPort::new();
            port.push(&alloc::vec![0xa5u8; len]);
            let mut dest = [0u8; MAX_PACKET_SIZE];

            assert_eq!(
                fifo_read(&mut port, len, &mut dest),
                Err(UsbError::OversizePacket { len })
            );
            assert_eq!(
                port.consumed(),
                fifo_words(len),
                "len {len} left the FIFO out of step"
            );
            assert!(dest.iter().all(|&b| b == 0xa5), "the prefix was still kept");
        }
    }

    #[test]
    fn fifo_write_pads_the_final_partial_word() {
        for len in 0..=9usize {
            let mut port = SimPort::new();
            let payload: Vec<u8> = (0..len).map(|i| 0xc0 | i as u8).collect();
            fifo_write(&mut port, EP_DATA, &payload, USB_SPIN_LIMIT).expect("has room");

            let written = port.written();
            assert_eq!(written.len(), fifo_words(len) * 4, "word count for {len}");
            assert_eq!(&written[..len], payload.as_slice());
            assert!(
                written[len..].iter().all(|&b| b == 0),
                "the pad must be zero, not stale stack"
            );
            assert!(
                port.tx_ep.iter().all(|&e| e == EP_DATA),
                "words went to the wrong FIFO"
            );
        }
    }

    /// A host that stops collecting IN packets must not hang the device. This is
    /// the same bound as `flash::FLASH_SPIN_LIMIT`, and a hang here is a hang in
    /// the USB poll loop where nothing else will ever notice.
    #[test]
    fn fifo_write_gives_up_instead_of_spinning_when_the_fifo_never_drains() {
        let mut port = SimPort::wedged();
        assert_eq!(
            fifo_write(&mut port, EP_DATA, &[1, 2, 3, 4], 32),
            Err(UsbError::FifoTimeout)
        );
        assert_eq!(port.written().len(), 0, "wrote into a full FIFO");
        // An empty write needs no space at all, so it must succeed even wedged --
        // otherwise a zero-length status stage would time out.
        assert_eq!(fifo_write(&mut port, 0, &[], 0), Ok(()));
    }

    // ---- the composition ---------------------------------------------------

    fn enc<T: bincode::Encode>(v: &T) -> Vec<u8> {
        bincode::encode_to_vec(v, BINCODE_CONFIG).expect("encodes")
    }

    /// The phase-3 deliverable in one test: bytes arrive as 64-byte USB packets,
    /// [`fifo_read`] takes them off the FIFO, and [`crate::comms::Link`] turns
    /// them into frames -- gated on the magic-byte handshake, with frames
    /// straddling packet boundaries.
    ///
    /// This is the seam a register model could not test and the reason `usb` and
    /// `comms` are separate modules. It is deliberately *not* a second copy of
    /// `comms`'s own framing tests: the only thing asserted here that they do not
    /// already cover is that packetisation does not lose or duplicate bytes.
    #[test]
    fn cdc_packets_reassemble_a_frostsnap_frame() {
        let frame = FromCoordinator::Message(CoordinatorSendMessage {
            target_destinations: Destination::All,
            message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::AnnounceAck),
        });

        // What a coordinator puts on the wire: its magic bytes, then frames.
        let mut stream = enc(&FromCoordinator::MagicBytes(MagicBytes::default()));
        let one = enc(&frame);
        assert!(one.len() < MAX_PACKET_SIZE, "the fixture must fit a packet");
        // Derived, not a literal: enough frames to span at least five packets
        // whatever this frame encodes to, so a change in `frostsnap_comms` cannot
        // quietly shrink the stream until every frame lands inside one packet and
        // the reassembly this test exists for stops being exercised.
        let frames = 5 * MAX_PACKET_SIZE / one.len() + 1;
        for _ in 0..frames {
            stream.extend_from_slice(&one);
        }
        assert!(stream.len() > 4 * MAX_PACKET_SIZE);

        let mut port = SimPort::new();
        let mut link = Link::new();
        let mut got = 0usize;

        for packet in stream.chunks(MAX_PACKET_SIZE) {
            port.push(packet);
            let mut buf = [0u8; MAX_PACKET_SIZE];
            let n = fifo_read(&mut port, packet.len(), &mut buf).expect("a packet fits");
            assert_eq!(n, packet.len());
            link.poll::<FromCoordinator, _>(&buf[..n], |_| got += 1)
                .expect("the stream is well formed");
        }

        assert!(link.is_linked(), "never linked");
        assert_eq!(got, frames, "lost or duplicated a frame across packets");
        assert_eq!(link.pending(), 0, "bytes left buffered");

        // ...and the handshake reply goes back out through the same seam, whole.
        fifo_write(&mut port, EP_DATA, &comms::MAGIC_REPLY, USB_SPIN_LIMIT).expect("has room");
        assert_eq!(port.written().as_slice(), comms::MAGIC_REPLY.as_slice());
    }

    /// A frame at [`crate::comms::FRAME_LIMIT`] arrives as 64 packets. Nothing in
    /// `usb` knows the limit; this is here for the short-final-packet case a
    /// whole-word/whole-packet assumption breaks on — which at 4,096 is **not** the
    /// full-size frame any more (4096 = 64 × 64 exactly, where 2,060 left 12 bytes
    /// over), so the odd size is exercised explicitly rather than for free.
    #[test]
    fn a_full_size_frame_survives_its_packets() {
        assert_eq!(FRAME_LIMIT % MAX_PACKET_SIZE, 0, "4096 = 64 * 64");
        for len in [FRAME_LIMIT, FRAME_LIMIT - MAX_PACKET_SIZE + 12] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

            let mut port = SimPort::new();
            let mut seen: Vec<u8> = Vec::new();
            for packet in payload.chunks(MAX_PACKET_SIZE) {
                port.push(packet);
                let mut buf = [0u8; MAX_PACKET_SIZE];
                let n = fifo_read(&mut port, packet.len(), &mut buf).expect("a packet fits");
                seen.extend_from_slice(&buf[..n]);
            }
            assert_eq!(seen, payload, "{len}-byte frame did not survive");
            assert_eq!(port.consumed(), port.rx_len, "words left in the FIFO");
        }
    }

    // ---- the singleton -----------------------------------------------------

    #[test]
    fn the_peripheral_is_handed_out_once() {
        assert!(UsbToken::take().is_some());
        for _ in 0..4 {
            assert!(UsbToken::take().is_none(), "handed OTG_FS out twice");
        }
    }

    #[test]
    fn open_refuses_on_a_non_device_target() {
        // Not via `take()`: that is a once-per-process singleton and the test
        // above owns it.
        let token = UsbToken { _private: () };
        assert_eq!(token.open().err(), Some(UsbError::NotOnThisTarget));
    }
}
