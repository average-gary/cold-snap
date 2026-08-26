#!/usr/bin/env python3
"""Prove the window's pixels, end to end, with COLDCARD's OWN decoder.

The gated Rust checks cover the two halves separately: `hal/src/ui.rs`
(`mono_vlsb_corner_pixels_map_to_exact_bytes`) pins the MONO_VLSB mapping, and
`firmware/examples/simulator.rs` (`check_display_stream`) pins the wire contract
against a *transcription* of the parent's decoder. Both are ours. This runs the
real thing instead:

  1. spawn `examples/simulator` the way `unix/simulator.py:926` spawns its child
     -- four inherited pipe fds as decimal argv -- and capture the raw bytes that
     land on the display fd for a real scene (screen 2, `ui::keygen_check`: large
     solid text plus fine glyph detail, so a transpose cannot hide);
  2. decode those bytes by EXECUTING `OLEDSimulator.new_contents` lifted verbatim
     out of the Coldcard tree at runtime (no import, so no PySDL2, no libngu);
  3. get the ground truth from the SAME binary's terminal front-end, whose
     half-block art is a lossless read-back of `ui::Frame::pixel`;
  4. corrupt the frame six ways and require every one to be caught.

Run: tools/pixel-check.py        (add -v to dump the decoded screen)

GATE-ABLE, with one caveat: it needs python3 (stdlib only) and cargo, but the
reference decoder lives in the read-only Coldcard checkout. If that checkout is
absent it SKIPs with exit 0 -- so it can sit in the gate list, it just cannot be
the only thing standing between us and a mapping bug on a fresh machine.
Nothing here writes to, or needs anything built in, the Coldcard tree.
"""

import os
import re
import select
import subprocess
import sys
import textwrap
from types import SimpleNamespace

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC = os.environ.get("COLDCARD_REPO", os.path.expanduser("~/repos/coldcard-firmware"))
SIM_PY = os.path.join(CC, "unix", "simulator.py")
BIN = os.environ.get(
    "COLDSNAP_SIM_BIN",
    os.path.join(REPO, "target", "aarch64-apple-darwin", "debug", "examples", "simulator"),
)
SCENE = "2 keygen check"  # non-blank, non-uniform, and its name pins the fixture
W, H = 128, 64
FRAME = W * H // 8
LOG = "/tmp/coldsnap-pixel-check.log"


def skip(why):
    print(f"SKIP: {why}")
    sys.exit(0)


def die(why):
    print(f"FAIL: {why}")
    sys.exit(1)


# --------------------------------------------------------------------------
# 1. their decoder, lifted at runtime
# --------------------------------------------------------------------------


def their_decoder():
    """`OLEDSimulator.new_contents` as a callable, straight from their source.

    Text extraction, not `import`: their module does `from sdl2.scancode import *`
    at import time and PySDL2 is not installed. Lifting the method keeps their
    `buf[-1024:]` backlog rule and their `assert len(buf) == 1024` -- the two
    things that decide whether a split or padded frame is loud or silent.
    """
    src = open(SIM_PY).read().splitlines()
    try:
        top = src.index("class OLEDSimulator(SimulatedScreen):")
        start = next(
            i for i in range(top, len(src)) if src[i].strip().startswith("def new_contents(")
        )
    except (ValueError, StopIteration):
        skip(f"{SIM_PY} no longer has OLEDSimulator.new_contents -- their decoder moved")
    end = next(
        (
            i
            for i in range(start + 1, len(src))
            if src[i].strip() and re.match(r"^ {0,4}(def |class |@)", src[i])
        ),
        len(src),
    )
    body = textwrap.dedent("\n".join(src[start:end]))
    ns = {}
    exec(compile(body, SIM_PY, "exec"), ns)  # noqa: S102 -- that is the point
    print(f"  their decoder: {SIM_PY} lines {start + 1}-{end}, {end - start} lines exec'd")
    return ns["new_contents"]


def decode(new_contents, data):
    """Their decode of `data` -> grid[y][x] of bool. Raises AssertionError like they do."""
    me = SimpleNamespace(mv=[[False] * W for _ in range(H)], fg=True, bg=False, movie=None)
    new_contents(me, SimpleNamespace(read=lambda _n: data))
    return me.mv


# --------------------------------------------------------------------------
# 2. ground truth: the terminal front-end, i.e. ui::Frame::pixel
# --------------------------------------------------------------------------

ART = {"█": (1, 1), "▀": (1, 0), "▄": (0, 1), " ": (0, 0)}


def truth():
    """(scene number, [grid per page]) from `art()`, which reads `Frame::pixel`."""
    r = subprocess.run(
        [BIN],
        input="q\n",  # the menu, then out
        capture_output=True,
        text=True,
        timeout=240,
    )
    if r.returncode != 0:
        die(f"terminal front-end exited {r.returncode}:\n{r.stderr[-800:]}")
    m = re.search(r"^\s*(\d+)\s+" + re.escape(SCENE), r.stdout, re.M)
    if not m:
        die(f'scene "{SCENE}" is not in the menu any more')
    n = m.group(1)
    r = subprocess.run(
        [BIN],
        input="".join(f"{k}\n" for k in [n, "8", "8", "q"]),
        capture_output=True,
        text=True,
        timeout=240,
    )
    pages = []
    for _p, art in re.findall(r"page (\d+)/\d+\n(\+-+\+\n(?:\|.*\|\n)+\+-+\+\n)", r.stdout):
        rows = [ln[1:-1] for ln in art.splitlines()[1:-1]]
        g = [[False] * W for _ in range(H)]
        for ry, row in enumerate(rows):
            for x, ch in enumerate(row):
                hi, lo = ART[ch]
                g[ry * 2][x], g[ry * 2 + 1][x] = bool(hi), bool(lo)
        pages.append(g)
    if not pages:
        die("terminal front-end printed no art blocks")
    return n, pages


# --------------------------------------------------------------------------
# 3. the wire: what actually lands on simulator.py's display fd
# --------------------------------------------------------------------------


def wire(scene, keys):
    """Spawn the child exactly as `unix/simulator.py:926` does; return the frames.

    One frame per redraw, read in lockstep, so nothing is lost to their
    `buf[-1024:]` and a split write would show up as a short read here.
    """
    display_r, display_w = os.pipe()
    numpad_r, numpad_w = os.pipe()
    led_r, led_w = os.pipe()
    data_r, data_w = os.pipe()
    fds = [display_w, numpad_r, led_w, data_r]
    argv = [BIN, "-X", "heapsize=9m", "-i", "sim_boot.py"] + [str(i) for i in fds] + ["--mk4"]
    log = open(LOG, "w")
    child = subprocess.Popen(
        argv, pass_fds=fds, stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True
    )
    for fd in fds:
        os.close(fd)
    frames = []
    try:
        for k in [None] + list(keys):
            if k is not None:
                os.write(numpad_w, k.encode() + b"\0")  # a click sends key then all-up
            buf = b""
            while len(buf) < FRAME:
                if not select.select([display_r], [], [], 20)[0]:
                    die(f"no frame within 20s after key {k!r} (got {len(buf)} B)")
                chunk = os.read(display_r, FRAME - len(buf))
                if not chunk:
                    die(f"child closed the display fd after key {k!r}; see {LOG}")
                buf += chunk
                if len(buf) < FRAME:
                    die(f"SPLIT WRITE: {len(buf)} B then more -- the parent's assert would fire")
            frames.append(buf)
    finally:
        os.close(numpad_w)  # numpad EOF is the documented quit path
        try:
            child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            child.kill()
            die(f"child did not exit on numpad EOF -- orphan risk; see {LOG}")
        for fd in (display_r, led_r, data_w):  # data_r went with `fds` above
            os.close(fd)
        log.close()
    if child.returncode != 0:
        die(f"child exited {child.returncode}; see {LOG}")
    return frames


# --------------------------------------------------------------------------
# 4. corruptions -- every one of these renders, so "not blank" proves nothing
# --------------------------------------------------------------------------


def vlsb(px):
    """MONO_VLSB encode of a pixel function -- the mapping `Frame::as_bytes` claims."""
    return bytes(
        sum((1 << b) for b in range(8) if px(x, (page * 8) + b))
        for page in range(H // 8)
        for x in range(W)
    )


def corruptions(buf, g):
    """Each entry: (name, bytes the buggy build would emit). `g` is the true grid."""
    return [
        # a 64-wide x 128-tall framebuffer: correct encoder, swapped axes
        ("transposed axes", vlsb(lambda x, y: x < H and g[x][y % H] if y < W else False)),
        ("bit order reversed", bytes(int(f"{b:08b}"[::-1], 2) for b in buf)),
        # MONO_HLSB: 16 bytes per row, top row first
        (
            "row-major not column-page",
            bytes(
                sum((1 << (7 - b)) for b in range(8) if g[y][byte * 8 + b])
                for y in range(H)
                for byte in range(W // 8)
            ),
        ),
        ("page off by one", buf[W:] + buf[:W]),
        ("fg/bg inverted", bytes(b ^ 0xFF for b in buf)),
        # both transport bugs the parent sees: one is loud, one is silent
        ("frame split in two writes", buf[: FRAME // 2]),
        ("one stray byte on the fd", buf + b"\n"),
    ]


def main():
    verbose = "-v" in sys.argv
    if not os.path.exists(SIM_PY):
        skip(f"no Coldcard checkout at {CC} (set COLDCARD_REPO); their decoder is the reference")
    print("building examples/simulator ...")
    subprocess.run(
        [
            "cargo",
            "build",
            "--target",
            "aarch64-apple-darwin",
            "-p",
            "coldsnap_firmware",
            "--features",
            "coldsnap_hal/test-seam",
            "--example",
            "simulator",
        ],
        cwd=REPO,
        check=True,
        timeout=540,
        stdout=subprocess.DEVNULL,
    )
    dec = their_decoder()
    n, pages = truth()
    print(f'  ground truth: scene {n} "{SCENE}", {len(pages)} pages, via art()/Frame::pixel')

    # menu page (n-1)//5, then entry (n-1)%5+1, then one '8' per extra page
    hops = ["8"] * ((int(n) - 1) // 5) + [str((int(n) - 1) % 5 + 1)] + ["8"] * (len(pages) - 1)
    frames = wire(n, hops)[-len(pages) :]
    print(f"  wire: {len(frames)} frames of {FRAME} B, one write each, off the display fd\n")

    bad = 0
    for i, (buf, g) in enumerate(zip(frames, pages), 1):
        lit = sum(map(sum, g))
        theirs = decode(dec, buf)
        wrong = [(x, y) for y in range(H) for x in range(W) if theirs[y][x] != g[y][x]]
        if wrong:
            bad += 1
            print(f"page {i}: MISMATCH at {len(wrong)} px, first {wrong[0]} -- THE WINDOW LIES")
            continue
        enc = "ok" if vlsb(lambda x, y: g[y][x]) == buf else "DIFFERS"
        print(f"page {i}: {lit:5d} lit px agree with their decoder (8192/8192); re-encode {enc}")
        if enc != "ok":
            bad += 1
        if verbose:
            # THEIR pixels, half-blocked: if this is not readable text, stop here.
            for y in range(0, H, 2):
                print(
                    "  |"
                    + "".join(" ▄▀█"[(theirs[y][x] << 1) | theirs[y + 1][x]] for x in range(W))
                    + "|"
                )
        for name, cbuf in corruptions(buf, g):
            try:
                cg = decode(dec, cbuf)
                d = sum(cg[y][x] != g[y][x] for y in range(H) for x in range(W))
                caught = f"caught: {d} px wrong ({sum(map(sum, cg))} lit, renders)" if d else None
            except AssertionError as e:
                caught = f"caught: their own assert fired (len {e})"
            print(f"    {name:<28} {caught or 'MISSED -- decodes identically'}")
            bad += caught is None

    print("\n" + ("FAIL" if bad else "PASS: their decoder and Frame::pixel agree; all 7 caught"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
