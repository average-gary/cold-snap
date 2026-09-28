#!/usr/bin/env python3
"""cold-snap software-readiness runner: every implemented hardware-free check, in
dependency order, with each child's real exit status.

    python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness
    python3 tools/check-software-readiness.py --profile core     # cold-snap only, labeled as such
    python3 tools/check-software-readiness.py --list             # print the plan, run nothing

Exit status: 0 every stage in the profile passed; 1 a stage failed or timed out;
a consumed artifact older than any of its inputs (cargo's own .d list, or the
packager's inputs) is STALE and fails without running the stage; source drift in any repo
during the run, or leftover processes, also fail the run;
2 nothing failed but a stage was unavailable (missing prerequisite, SKIP output, or an
upstream stage that did not pass) or BLOCKED; 130/143 interrupted. There is no status
that turns a missing check into a pass.

The best label this runner can print is "software/pre-bench checks passed". It is never
"hardware verified" or "safe for funds": no stage touches a physical port, installs an
image, provisions a key or reaches a real callgate. Installation is mocked at best
(fake gate / fake flash), and every such stage says so in its title.

Every child runs in its own session (process group) with stdin closed and a timeout.
On timeout, on runner interruption, and after every normal exit, the whole group is
sent SIGTERM, given a grace period (app-rig.py tears down its stubs and regtest node on
SIGTERM), then SIGKILL. Logs are one .out and one .err file per stage.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

HOME = os.path.expanduser('~')
CS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FS = os.environ.get('FROSTSNAP_REPO', os.path.join(HOME, 'repos', 'frostsnap'))
FA = os.path.join(FS, 'frostsnapp')
REF = os.environ.get('COLDCARD_TREE', os.path.join(HOME, 'repos', 'coldcard-firmware'))
FLUTTER_BIN = os.path.join(FA, '.fvm', 'flutter_sdk', 'bin')
BITCOIN_BIN = os.path.join(HOME, 'repos', 'implementations', 'bitcoin-v31.1', 'build', 'bin')
LLVM = '/opt/homebrew/opt/llvm/bin'
HOST = 'aarch64-apple-darwin'
ARM = 'thumbv7em-none-eabihf'
SW = os.path.join(CS, 'target', 'software-only')
PKG = os.path.join(SW, 'package')
ART = os.path.join(PKG, 'firmware-signed.bin')
DFU = os.path.join(PKG, 'coldsnap-6.0.0cs.dfu')
FIX = os.path.join(SW, 'fixtures')
STUB = os.path.join(CS, 'target', HOST, 'debug', 'examples', 'stub')
ELF = os.path.join(CS, 'target', ARM, 'release', 'coldsnap_firmware')
VENV_PY = os.path.join(CS, 'target', 'pack-venv', 'bin', 'python')
REGISTRY = os.path.join(FS, 'frostsnap_coordinator', 'src', 'coldsnap-mk4-registry.txt')
PY = sys.executable

GROUPS = [  # prompt work item 2, in order
    ('host', 'focused host suites'),
    ('arm', 'ARM dev/release checks and build'),
    ('reference', 'reference/ELF validation'),
    ('package', 'packaging/signature/checkfw'),
    ('pixel-heap', 'pixel and heap checks'),
    ('coordinator', 'coordinator interop'),
    ('compat', 'compatibility/mixed-port tests'),
    ('app', 'real-app Bitcoin workflows (virtual devices, regtest)'),
    ('upgrade-erase', 'dev-key updater/controller and erase interruption (mocked install)'),
]
GROUP_ORDER = {g: i for i, (g, _) in enumerate(GROUPS)}

TESTS_RAN = r'test result: ok\. [1-9]\d* passed'   # a cargo run that tested nothing is not a pass
GRACE = 30.0                                          # SIGTERM -> SIGKILL


# ---------------------------------------------------------------- prerequisites

def _exists(p):
    return (os.path.exists(p), p)


def _which(name):
    w = shutil.which(name, path=_env()['PATH'])
    return (w is not None, w or f'{name} not on PATH')


def _rust_target(t):
    try:
        root = subprocess.run(['rustc', '--print', 'sysroot'], capture_output=True,
                              text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return (False, f'rustc: {e}')
    p = os.path.join(root, 'lib', 'rustlib', t)
    return (os.path.isdir(p), p)


def _pinned_flutter():
    try:
        want = json.load(open(os.path.join(FA, '.fvmrc')))['flutter']
    except (OSError, ValueError, KeyError) as e:
        return (False, f'.fvmrc unreadable: {e}')
    exe = os.path.join(FLUTTER_BIN, 'flutter')
    if not os.path.exists(exe):
        return (False, f'{exe} missing (pinned {want})')
    try:
        out = subprocess.run([exe, '--version'], capture_output=True, text=True, timeout=120,
                             env=_env()).stdout
    except (OSError, subprocess.SubprocessError) as e:
        return (False, f'flutter --version: {e}')
    m = re.search(r'Flutter (\S+)', out)
    got = m.group(1) if m else None
    return (got == want, f'.fvmrc pins {want}, {exe} reports {got}')


def _venv_ecdsa():
    if not os.path.exists(VENV_PY):
        return (False, f'{VENV_PY} missing')
    r = subprocess.run([VENV_PY, '-c', 'import ecdsa'], capture_output=True, timeout=30)
    return (r.returncode == 0, f'{VENV_PY} import ecdsa -> {r.returncode}')


PREREQS = {
    'cargo': lambda: _which('cargo'),
    'rust-host': lambda: _rust_target(HOST),
    'rust-arm': lambda: _rust_target(ARM),
    'llvm': lambda: _exists(os.path.join(LLVM, 'llvm-readelf')),
    'clang': lambda: _exists(os.path.join(LLVM, 'clang')),
    'reference': lambda: _exists(os.path.join(REF, 'stm32', 'keys', '00.pem')),
    'signit': lambda: _exists(os.path.join(REF, 'cli', 'signit.py')),
    'pack-venv': _venv_ecdsa,
    'frostsnap': lambda: _exists(os.path.join(FS, 'Cargo.toml')),
    'pinned-flutter': _pinned_flutter,
    'just': lambda: _which('just'),
    'frb-codegen': lambda: _which('flutter_rust_bridge_codegen'),
    'bitcoin-node': lambda: _exists(os.path.join(BITCOIN_BIN, 'bitcoin-node')),
    'fixture-bad-signature': lambda: _exists(os.path.join(FIX, 'bad-signature.bin')),
    'fixture-bad-layout': lambda: _exists(os.path.join(FIX, 'bad-layout.elf')),
    'fixture-05-misaligned': lambda: _exists(os.path.join(FIX, '05', 'misaligned-397824.bin')),
    'fixture-05-wrong-family': lambda: _exists(os.path.join(FIX, '05', 'wrong-family-mk5-only.bin')),
    'fixture-06-local-build': lambda: _exists(os.path.join(FIX, '06', 'local-build', 'firmware-signed.bin')),
    'registry': lambda: _exists(REGISTRY),
}


# ---------------------------------------------------------------- freshness

def _depinfo(artifact):
    """The sources cargo itself recorded for `artifact` (its `.d` file)."""
    head = open(artifact + '.d').read().split('\n', 1)[0].split(': ', 1)[1]
    return [x.replace('\\ ', ' ') for x in re.split(r'(?<!\\) ', head.strip()) if x]


# The signed header's timestamp lies inside the announced-digest range, and pack-signed.py
# defaults it to the ELF's mtime, so every relink of byte-identical code moved the digest off
# the registry. Pinned to the header timestamp of the registered image (c86392bc, 2026-09-25
# 19:56:33Z); SOURCE_DATE_EPOCH overrides. Re-pin it when a code change registers a new image.
PACK_EPOCH = os.environ.get('SOURCE_DATE_EPOCH') or '1790366193'
PACK_INPUTS = lambda: [ELF, os.path.join(CS, 'tools', 'pack-signed.py'),
                       os.path.join(REF, 'cli', 'signit.py'), os.path.join(REF, 'stm32', 'keys', '00.pem')]
BUILT = {  # artifact -> what it is built from; an artifact older than any input is STALE
    ELF: lambda: _depinfo(ELF),
    STUB: lambda: _depinfo(STUB),
    ART: PACK_INPUTS,
    DFU: PACK_INPUTS,
    os.path.join(FIX, 'bad-signature.bin'): lambda: [ART],   # minted by test-pack-signed.py
    os.path.join(FIX, 'bad-layout.elf'): lambda: [ELF],       # minted by test-pack-signed.py
}
DECLARED = [  # fixtures with no build rule here: recorded by hash, never called fresh
    os.path.join(FIX, '05', 'misaligned-397824.bin'),
    os.path.join(FIX, '05', 'wrong-family-mk5-only.bin'),
    os.path.join(FIX, '06', 'local-build', 'firmware-signed.bin'),
    os.path.join(FIX, '06', 'local-build', 'coldsnap-6.0.1lb.dfu'),
]


def _sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def freshness(artifact, built=None):
    """sha256 of `artifact` and of its inputs, and whether any input is newer than it."""
    built = BUILT if built is None else built
    r = dict(path=artifact, exists=os.path.exists(artifact))
    if not r['exists']:
        return r
    r.update(sha256=_sha(artifact), mtime=os.path.getmtime(artifact))
    if artifact not in built:
        r['rule'] = 'declared fixture: hash recorded, no freshness rule'
        return r
    try:
        inputs = sorted(built[artifact]())
    except (OSError, IndexError) as e:
        r.update(stale=[f'input list unreadable: {e}'])
        return r
    h, stale = hashlib.sha256(), []
    for i in inputs:
        if not os.path.exists(i):
            stale.append(f'{i} missing')
            continue
        h.update(f'{i} {_sha(i)}\n'.encode())
        if os.path.getmtime(i) > r['mtime']:
            stale.append(f'{i} is newer')
    r.update(inputs=len(inputs), inputs_sha256=h.hexdigest(), stale=stale)
    return r


# ---------------------------------------------------------------- stages

class Stage:
    def __init__(self, name, group, title, cwd, argv, *, core=False, timeout=600, needs=(),
                 after=(), env=None, unset=(), expect_rc=0, must=(), skip_re=None,
                 rc_status=None, blocked_re=None, stdout_in_registry=False,
                 tree_unchanged=None, metrics=None, note=None, consumes=()):
        self.name, self.group, self.title, self.cwd, self.argv = name, group, title, cwd, argv
        self.core, self.timeout, self.needs, self.after = core, timeout, tuple(needs), tuple(after)
        self.env, self.unset = env or {}, tuple(unset)
        self.expect_rc, self.must, self.skip_re = expect_rc, tuple(must), skip_re
        self.rc_status = rc_status or {}          # rc -> status for tools with an exit contract
        self.blocked_re = blocked_re              # failure whose cause is protected user work
        self.stdout_in_registry = stdout_in_registry
        self.tree_unchanged = tree_unchanged      # repo whose working tree must not change
        self.metrics = metrics or {}              # name -> regex with one group, parsed fresh
        self.note = note
        self.consumes = tuple(consumes)           # artifacts whose freshness is checked first

    def command(self):
        pre = [f'{k}={v}' for k, v in self.env.items()] + [f'-u {k}' for k in self.unset]
        return (('env ' + ' '.join(pre) + ' ') if pre else '') + shlex.join(self.argv)


def cargo_test(*args):
    return ['cargo', 'test', '--target', HOST, *args]


def stages(out):
    refjson = os.path.join(out, 'refcheck', 'result.json')
    cr = dict(COLDSNAP_REPO=CS)
    S = Stage
    L = [
        # 1 focused host suites (README "Test"; bare --workspace does not compile)
        S('host-frostsnap-macros', 'host', 'vendored frostsnap_macros', CS,
          cargo_test('-p', 'frostsnap_macros'), core=True, needs=['cargo', 'rust-host'], must=[TESTS_RAN]),
        S('host-frostsnap-embedded-std', 'host', 'vendored frostsnap_embedded with std (log tests)', CS,
          cargo_test('-p', 'frostsnap_embedded', '--features', 'std'), core=True,
          needs=['cargo', 'rust-host'], must=[TESTS_RAN]),
        S('host-frostsnap-comms', 'host', 'vendored frostsnap_comms', CS,
          cargo_test('-p', 'frostsnap_comms', '--features', 'coordinator'), core=True,
          needs=['cargo', 'rust-host'], must=[TESTS_RAN]),
        S('host-frostsnap-core', 'host', 'vendored frostsnap_core', CS,
          cargo_test('-p', 'frostsnap_core', '--features', 'coordinator'), core=True,
          needs=['cargo', 'rust-host'], must=[TESTS_RAN]),
        S('host-frost-backup', 'host', 'vendored frost_backup (supported targets only)', CS,
          cargo_test('-p', 'frost_backup', '--lib', '--test', 'proptest', '--test', 'specification_tests',
                     '--test', 'recovery_tests', '--test', 'error_handling', '--test', 'checksum_statistics'),
          core=True, needs=['cargo', 'rust-host'], must=[TESTS_RAN]),
        S('host-coldsnap-firmware', 'host', 'coldsnap_firmware host tests', CS,
          cargo_test('-p', 'coldsnap_firmware'), core=True, needs=['cargo', 'rust-host'], must=[TESTS_RAN]),
        S('host-coldsnap-hal', 'host', 'coldsnap_hal with fake-flash,test-seam', CS,
          cargo_test('-p', 'coldsnap_hal', '--features', 'fake-flash,test-seam'), core=True,
          needs=['cargo', 'rust-host'], must=[TESTS_RAN]),

        # 2 ARM
        S('arm-clippy-dev', 'arm', 'clippy thumbv7em dev', CS,
          ['cargo', 'clippy', '--target', ARM, '-p', 'coldsnap_hal', '-p', 'coldsnap_firmware'],
          core=True, needs=['cargo', 'rust-arm', 'clang'],
          note='exit status only; vendored-crate warnings are not gated on a count'),
        S('arm-clippy-release', 'arm', 'clippy thumbv7em release', CS,
          ['cargo', 'clippy', '--release', '--target', ARM, '-p', 'coldsnap_hal', '-p', 'coldsnap_firmware'],
          core=True, needs=['cargo', 'rust-arm', 'clang']),
        S('arm-build-release', 'arm', 'release ELF build', CS, ['cargo', 'build', '--release'],
          core=True, needs=['cargo', 'rust-arm', 'clang']),

        # 3 reference / ELF
        S('refcheck', 'reference', 'Coldcard reference contracts vs release ELF (runs pixel-check)', CS,
          [PY, 'tools/check-reference-contracts.py', '--json', refjson], core=True, timeout=300,
          needs=['reference', 'clang', 'llvm'], after=['arm-build-release'],
          rc_status={2: 'unavailable'}, skip_re=r'(?m)^\s*SKIP\b', consumes=[ELF],
          metrics={'covered': r'(?m)^\s*COVERED\s+(\d+)\s*$', 'failed': r'(?m)^\s*FAILED\s+(\d+)\s*$',
                   'unavailable': r'(?m)^\s*UNAVAILABLE\s+(\d+)\s*$'}),
        S('refcheck-negatives', 'reference', 'reference-contract checker negatives', CS,
          [PY, 'tools/test-reference-contracts.py'], core=True, timeout=600,
          needs=['reference', 'clang', 'llvm'], after=['arm-build-release'],
          note='its no-simulator case provokes a SKIP on purpose, so SKIP text is not scanned here'),

        # 4 packaging / signature / checkfw
        S('pack', 'package', 'key-0 signed package from this run\'s ELF', CS,
          [PY, 'tools/pack-signed.py', '--pubkey-num', '0', '--epoch', PACK_EPOCH, '--out', PKG], core=True, timeout=300,
          needs=['reference', 'signit', 'pack-venv', 'llvm'], after=['arm-build-release'], consumes=[ELF]),
        S('pack-tests', 'package', 'packaging tests', CS, [PY, 'tools/test-pack-signed.py'], core=True,
          timeout=300, needs=['reference', 'signit', 'pack-venv', 'llvm'], after=['pack'],
          consumes=[ELF, ART]),
        S('pack-negative-bad-layout', 'package', 'pack refuses a bad-layout ELF', CS,
          [PY, 'tools/pack-signed.py', '--elf', os.path.join(FIX, 'bad-layout.elf'),
           '--out', os.path.join(out, 'bad-layout-out'), '--no-dfu'], core=True, timeout=300,
          needs=['reference', 'signit', 'pack-venv', 'fixture-bad-layout'], expect_rc=1,
          after=['pack-tests'], consumes=[os.path.join(FIX, 'bad-layout.elf')],
          # `(Abort)` is the deliberate refusal class; a crash also exits 1 via pack-signed.py's
          # catch-all, but as `ABORT (KeyError)` etc. or a traceback, which must not count.
          must=[r'(?m)^ABORT \(Abort\): firmware0\.bin would load at 0x08180000, not 0x08020000:']),
        S('checkfw-bin', 'package', 'image geometry/installation validation of firmware-signed.bin', CS,
          ['cargo', 'run', '--release', '--target', HOST, '-p', 'coldsnap_firmware', '--example', 'checkfw',
           '--', ART], core=True, needs=['cargo', 'rust-host'], after=['pack'], consumes=[ART],
          must=[r'(?m)^RESULT: ACCEPT\b'], metrics={'verdict': r'(?m)^RESULT: (ACCEPT\W+\d+/\d+)'}),
        S('checkfw-dfu', 'package', 'validation of the .dfu', CS,
          ['cargo', 'run', '--release', '--target', HOST, '-p', 'coldsnap_firmware', '--example', 'checkfw',
           '--', DFU], core=True, needs=['cargo', 'rust-host'], after=['pack'], consumes=[DFU],
          must=[r'(?m)^RESULT: ACCEPT\b']),
        S('checkfw-negative-signature', 'package', 'checkfw refuses a corrupted signature (R12)', CS,
          ['cargo', 'run', '--release', '--target', HOST, '-p', 'coldsnap_firmware', '--example', 'checkfw',
           '--', os.path.join(FIX, 'bad-signature.bin')], core=True,
          needs=['cargo', 'rust-host', 'fixture-bad-signature'], expect_rc=1,
          after=['pack-tests'], consumes=[os.path.join(FIX, 'bad-signature.bin')],
          # Only the signature-verification line: R12's other [FAIL] variant, "signature (range
          # unusable)", is a refusal for a length reason and must not count.
          must=[r'(?m)^RESULT: REFUSE\b', r'(?m)^\s*\[FAIL\] R12 signature over double-SHA256\(signed range\): ']),
        S('checkfw-negative-misaligned', 'package', 'checkfw refuses a misaligned image (R8)', CS,
          ['cargo', 'run', '--release', '--target', HOST, '-p', 'coldsnap_firmware', '--example', 'checkfw',
           '--', os.path.join(FIX, '05', 'misaligned-397824.bin')], core=True,
          needs=['cargo', 'rust-host', 'fixture-05-misaligned'], expect_rc=1,
          must=[r'(?m)^RESULT: REFUSE\b', r'(?m)^\s*\[FAIL\] R8 ']),
        S('checkfw-negative-family', 'package', 'checkfw refuses a wrong hw family (R13)', CS,
          ['cargo', 'run', '--release', '--target', HOST, '-p', 'coldsnap_firmware', '--example', 'checkfw',
           '--', os.path.join(FIX, '05', 'wrong-family-mk5-only.bin')], core=True,
          needs=['cargo', 'rust-host', 'fixture-05-wrong-family'], expect_rc=1,
          must=[r'(?m)^RESULT: REFUSE\b', r'(?m)^\s*\[FAIL\] R13 ']),

        # 5 pixel / heap
        S('pixel-check', 'pixel-heap', 'display pixels vs Coldcard decoder', CS, [PY, 'tools/pixel-check.py'],
          core=True, timeout=300, needs=['reference'], skip_re=r'(?m)^\s*SKIP\b', must=[r'(?m)^PASS\b']),
        S('heap-session', 'pixel-heap', 'measured heap headroom (includes install phase)', CS,
          ['cargo', 'run', '--release', '--target', HOST, '-p', 'coldsnap_firmware', '--example', 'heap_session',
           '--features', 'coldsnap_hal/test-seam,frostsnap_core/coordinator'], core=True,
          needs=['cargo', 'rust-host'], must=[r'FITS'],
          metrics={'fits_slack_bytes': r'FITS, slack (\d+) B',
                   'footprint': r'FOOTPRINT high-water\s*:\s*(\d+ B of \d+ B)',
                   'footprint_spare_bytes': r'\((\d+) B spare\)',
                   'nulls': r'NULLS:\s*(\d+)'}),

        # 6 coordinator interop
        S('stub-build', 'coordinator', 'virtual-device stub build', CS,
          ['cargo', 'build', '--target', HOST, '-p', 'coldsnap_firmware', '--example', 'stub'],
          needs=['cargo', 'rust-host']),
        # No `needs`: a missing or non-git frostsnap is this stage's own named failure, not
        # 'unavailable'. Exit 3 (frostsnap ahead of the pin, or its crates edited) fails too:
        # the report must describe the recorded pair (hostcheck/frostsnap.rev).
        S('frostsnap-pin', 'coordinator', 'frostsnap HEAD is the revision hostcheck is pinned to', CS,
          ['sh', 'hostcheck/check-frostsnap-pin.sh', FS], timeout=60,
          must=[r'(?m)^FROSTSNAP PIN: OK: HEAD is the pin']),
        S('hostcheck-tests', 'coordinator', 'hostcheck unit + golden vector', os.path.join(CS, 'hostcheck'),
          ['cargo', 'test', '--target', HOST], needs=['cargo', 'frostsnap'], must=[TESTS_RAN]),
        S('hostcheck-run', 'coordinator', 'real coordinator vs stub over a pty', os.path.join(CS, 'hostcheck'),
          ['cargo', 'run', '--', os.path.relpath(STUB, os.path.join(CS, 'hostcheck'))], timeout=600,
          needs=['cargo', 'frostsnap'], after=['stub-build'], skip_re=r'(?m)^\s*SKIP\b', consumes=[STUB]),
        S('coordinator-verbatim', 'coordinator', 'frostsnap_coordinator, every target', FS,
          cargo_test('-p', 'frostsnap_coordinator'), needs=['cargo', 'frostsnap'], must=[TESTS_RAN],
          blocked_re=r'tests/coldcard_msg_len\.rs',
          note='blocked_re names the user\'s untracked tests/coldcard_msg_len.rs, never edited by this '
               'runner; its E0308 was fixed in place by follow-up fix 1 (036b945), so this stage runs'),
        S('coordinator-scoped', 'coordinator', 'frostsnap_coordinator lib/bins + named tests', FS,
          cargo_test('-p', 'frostsnap_coordinator', '--lib', '--bins', '--test', 'device_profile_test',
                     '--test', 'firmware_digest_test', '--test', 'mk4_firmware_artifacts',
                     '--test', 'mk4_updater_stub', '--test', 'mock_port_upgrade_routing', '--test', 'real_psbts'),
          needs=['cargo', 'frostsnap'], must=[TESTS_RAN],
          note='substitute for coordinator-verbatim; excludes tofu_tests (public Electrum TLS)'),
        # ponytail: no doctest stage; frostsnap_coordinator has 0 doctests, so one would pass by
        # construction. Add it back with must=[TESTS_RAN] once the crate grows a doctest.
        S('rust-lib-frostsnapp', 'coordinator', 'app bridge crate', FS, cargo_test('-p', 'rust_lib_frostsnapp'),
          needs=['cargo', 'frostsnap'], must=[TESTS_RAN]),
        S('register-self-check', 'coordinator', 'registration tool golden self-check', FS,
          [PY, 'frostsnap_coordinator/tools/register-mk4-firmware.py', '--self-check'], needs=['frostsnap']),
        S('registry-matches-artifact', 'coordinator', 'announced digest of this run\'s artifact is registered', FS,
          [PY, 'frostsnap_coordinator/tools/register-mk4-firmware.py', '--print', ART],
          needs=['frostsnap', 'registry'], after=['pack'], stdout_in_registry=True, consumes=[ART],
          note='compatibility for wallet workflows, not installation permission; the runner never edits '
               'the registry: run task 02\'s register-mk4-firmware.py <image> <label> after a firmware change'),

        # 7 compatibility / mixed port / app static checks
        S('flutter-analyze', 'compat', 'flutter analyze (pinned SDK)', FA, ['flutter', 'analyze'],
          needs=['pinned-flutter'], timeout=600),
        S('flutter-test', 'compat', 'flutter unit tests (pinned SDK)', FA, ['flutter', 'test'],
          needs=['pinned-flutter'], timeout=600),
        S('bridge-gen-reproducible', 'compat', 'just gen leaves the frostsnap tree unchanged', FS,
          ['just', 'gen'], needs=['pinned-flutter', 'just', 'frb-codegen'], timeout=900, tree_unchanged=FS),
        S('build-runner-reproducible', 'compat', 'just build-runner leaves the frostsnap tree unchanged', FS,
          ['just', 'build-runner'], needs=['pinned-flutter', 'just'], timeout=900, tree_unchanged=FS),

        # 8 real app
        S('app-rig', 'app', 'real desktop app vs 4 virtual devices + regtest', CS,
          ['tools/app-rig-test.sh', '--dir', os.path.join(out, 'app-rig')], timeout=1500,
          needs=['pinned-flutter', 'bitcoin-node', 'frostsnap'], after=['stub-build', 'pack'],
          consumes=[STUB, ART],
          unset=['COLDSNAP_RIG_DECLINE_SIGNING'], must=[r'All tests passed!']),

        # 9 updater / controller / erase
        S('updater-stub-ignored', 'upgrade-erase', 'Mk4 host updater CLI vs stub (stages only)', FS,
          cargo_test('-p', 'frostsnap_coordinator', '--test', 'mk4_updater_stub', '--', '--ignored'),
          env=cr, needs=['cargo', 'frostsnap'], after=['stub-build', 'pack'], must=[TESTS_RAN],
          consumes=[STUB, ART]),
        S('updater-lib-ignored', 'upgrade-erase', 'coordinator mk4_upgrade vs stub', FS,
          cargo_test('-p', 'frostsnap_coordinator', '--lib', 'mk4_upgrade', '--', '--ignored'),
          env=cr, needs=['cargo', 'frostsnap'], after=['stub-build', 'pack'], must=[TESTS_RAN],
          consumes=[STUB, ART]),
        S('updater-local-artifact', 'upgrade-erase', 'valid local artifact outside the registry is accepted', FS,
          cargo_test('-p', 'frostsnap_coordinator', '--test', 'mk4_firmware_artifacts', '--', '--ignored'),
          env=cr, needs=['cargo', 'frostsnap', 'fixture-06-local-build'], after=['pack'], must=[TESTS_RAN],
          consumes=[ART, DFU]),
        S('app-bridge-ignored', 'upgrade-erase', 'app bridge staging vs stub', FS,
          cargo_test('-p', 'rust_lib_frostsnapp', '--lib', '--', '--ignored'),
          env=cr, needs=['cargo', 'frostsnap'], after=['stub-build', 'pack'], must=[TESTS_RAN],
          consumes=[STUB, ART]),
        S('controller-erase-fake', 'upgrade-erase', 'upgrade controller + resumable erase (fake flash, fake gate)',
          CS, cargo_test('-p', 'coldsnap_hal', '-p', 'coldsnap_firmware', '--features',
                         'coldsnap_hal/fake-flash,coldsnap_hal/test-seam'), core=True,
          needs=['cargo', 'rust-host'], must=[TESTS_RAN]),
        S('install-xproc', 'upgrade-erase', 'cross-process install request vs fake callgate', CS,
          [VENV_PY, 'tools/install-xproc.py'], timeout=600, needs=['pack-venv', 'reference', 'cargo'],
          after=['pack'], must=[r'(?m)^PASS'], consumes=[ART],
          note='not core: builds frostsnap_coordinator for the updater side'),
    ]
    return L


# ---------------------------------------------------------------- execution

def _env(extra=None, unset=()):
    e = dict(os.environ)
    e['PATH'] = FLUTTER_BIN + os.pathsep + e.get('PATH', '')   # the pinned SDK, never the system one
    e.pop('CARGO_TARGET_DIR', None)       # stages locate the stub/ELF under the repo's own target/
    for k in unset:
        e.pop(k, None)
    e.update(extra or {})
    return e


def _kill_group(pgid, grace=GRACE, proc=None):
    """SIGTERM the group, wait up to `grace`, then SIGKILL. Returns True if anything was alive.
    `proc` (the group leader) is polled so its zombie does not keep the group looking alive."""
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    end = time.monotonic() + grace
    while time.monotonic() < end:
        if proc is not None:
            proc.poll()
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError):
            return True
        time.sleep(0.1)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    return True


def _tree_state(repo):
    s = subprocess.run(['git', '-C', repo, 'status', '--porcelain=v1', '-uall'], capture_output=True).stdout
    d = subprocess.run(['git', '-C', repo, 'diff', 'HEAD', '--binary'], capture_output=True).stdout
    return hashlib.sha256(s + b'\0' + d).hexdigest()


_current = {'pgid': None, 'proc': None}


def run_stage(st, logdir, results, scale=1.0, grace=GRACE):
    r = dict(name=st.name, group=st.group, title=st.title, cwd=st.cwd, command=st.command(),
             argv=st.argv, core=st.core, timeout_s=round(st.timeout * scale, 1), note=st.note,
             prereqs=[], status=None, rc=None, elapsed_s=None, reason=None, metrics={})
    for dep in st.after:
        ds = results.get(dep, {}).get('status')
        if ds != 'passed':
            r.update(status='unavailable', reason=f'upstream stage {dep} is {ds or "not run"}; '
                                                  f'no cached artifact is substituted')
            return r
    for n in st.needs:
        try:
            ok, detail = PREREQS[n]()
        except Exception as e:  # a prerequisite probe that crashes is a missing prerequisite
            ok, detail = False, f'{type(e).__name__}: {e}'
        r['prereqs'].append(dict(name=n, ok=ok, detail=str(detail)))
        if not ok:
            r.update(status='unavailable', reason=f'missing prerequisite {n}: {detail}')
            return r
    if not os.path.isdir(st.cwd):
        r.update(status='unavailable', reason=f'working directory {st.cwd} missing')
        return r
    r['consumes'] = [freshness(a) for a in st.consumes]
    for f in r['consumes']:
        if not f['exists']:
            r.update(status='unavailable', reason=f"missing artifact {f['path']}")
            return r
        if f.get('stale'):
            r.update(status='failed', reason=f"STALE artifact {f['path']}: {'; '.join(f['stale'][:3])}; "
                                             f"rebuild it, a cached artifact is not evidence for a changed tree")
            return r
    before = _tree_state(st.tree_unchanged) if st.tree_unchanged else None
    outp, errp = (os.path.join(logdir, f'{st.name}.{x}') for x in ('out', 'err'))
    r.update(stdout_log=outp, stderr_log=errp)
    r['started'] = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    t0 = time.monotonic()
    timed_out = False
    with open(outp, 'wb') as fo, open(errp, 'wb') as fe:
        try:
            p = subprocess.Popen(st.argv, cwd=st.cwd, env=_env(st.env, st.unset), stdin=subprocess.DEVNULL,
                                 stdout=fo, stderr=fe, start_new_session=True)
        except OSError as e:
            r.update(status='unavailable', reason=f'could not start: {e}', elapsed_s=0.0)
            return r
        _current['pgid'], _current['proc'] = p.pid, p
        try:
            p.wait(timeout=st.timeout * scale)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            leftover = _kill_group(p.pid, grace, p)   # also reaps grandchildren of a child that exited
            if p.poll() is None:
                p.wait()
            _current['pgid'] = None
    r['elapsed_s'] = round(time.monotonic() - t0, 2)
    r['rc'] = p.returncode
    if leftover and not timed_out:
        r['leftover_children_killed'] = True
    text = (open(outp, errors='replace').read() + '\n' + open(errp, errors='replace').read())
    for k, rx in st.metrics.items():
        m = re.search(rx, text)
        r['metrics'][k] = m.group(1) if m else None
    r['status'], r['reason'] = _classify(st, p.returncode, timed_out, text, outp)
    if st.tree_unchanged and r['status'] == 'passed' and _tree_state(st.tree_unchanged) != before:
        r['status'], r['reason'] = 'failed', f'{st.tree_unchanged} working tree changed (not reproducible)'
    return r


ERR_LOC = re.compile(r'(?m)^error(?:\[E\d+\])?:[^\n]*\n\s*-->\s*(\S+)')


def _only_blocked_cause(blocked_re, text):
    """True only if the failure is compile errors located in the blocked file and nothing else:
    cargo's routine 'Running tests/<that file>' line, or a mention next to another target's
    error or a failing test, is not attribution."""
    locs = ERR_LOC.findall(text)
    if not locs or not all(re.search(blocked_re, loc) for loc in locs):
        return False
    if re.search(r'\bFAILED\b|panicked at', text):
        return False
    headers = [ln for ln in re.findall(r'(?m)^error\b[^\n]*', text)
               if not ln.startswith('error: could not compile')]
    return len(headers) == len(locs)   # no unlocated error (linker, doctest, ...) either


def _classify(st, rc, timed_out, text, outp):
    if timed_out:
        return 'timed_out', f'killed after {st.timeout} s (x scale)'
    if rc < 0:
        return 'failed', f'killed by signal {-rc}'
    if st.skip_re and re.search(st.skip_re, text):
        return 'unavailable', 'tool reported SKIP (exit %d); a skip is not a pass' % rc
    if rc in st.rc_status:
        return st.rc_status[rc], f'exit {rc} per the tool\'s exit contract'
    if rc != st.expect_rc:
        if st.blocked_re and _only_blocked_cause(st.blocked_re, text):
            return 'blocked', f'exit {rc}; every error is located in /{st.blocked_re}/ (protected user work)'
        return 'failed', f'exit {rc}, expected {st.expect_rc}'
    for rx in st.must:
        if not re.search(rx, text):
            return 'failed', f'exit {rc} but output lacks /{rx}/'
    if st.stdout_in_registry:
        got = open(outp).read().strip()
        try:
            reg = {ln.split()[0] for ln in open(REGISTRY) if ln.strip() and not ln.startswith('#')}
        except OSError as e:
            return 'unavailable', f'registry unreadable: {e}'
        if got not in reg:
            return 'failed', (f'announced digest {got} is not in {REGISTRY}; re-run task 02\'s '
                              f'register-mk4-firmware.py <image> <label> (never bypassed here)')
    return 'passed', None


# ---------------------------------------------------------------- report

def overall(results, profile):
    st = [r['status'] for r in results]
    if not st:
        return 2, 'no stages ran'
    if any(s in ('failed', 'timed_out') for s in st):
        code = 1
    elif any(s != 'passed' for s in st):
        code = 2
    else:
        code = 0
    if code:
        bad = [f"{r['name']}={r['status']}" for r in results if r['status'] != 'passed']
        return code, 'NOT PASSED: ' + ', '.join(bad)
    if profile == 'core':
        return 0, ('core-only software/pre-bench checks passed (scope: cold-snap host, ARM, reference, '
                   'packaging, pixel, heap and fake-flash controller/erase stages; frostsnap coordinator, '
                   'registry, Flutter, app rig, updater and cross-process install stages NOT run)')
    return 0, 'software/pre-bench checks passed'


def _cmd(argv, cwd=None, lines=False):
    # lines=True keeps leading whitespace: porcelain's ' M' (unstaged) must not become 'M' (staged).
    try:
        out = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=60, env=_env()).stdout
        return out.splitlines() if lines else out.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return f'unavailable: {e}'


def identity():
    repos = {}
    for n, p in (('cold-snap', CS), ('frostsnap', FS), ('coldcard-firmware', REF)):
        repos[n] = dict(path=p, head=_cmd(['git', '-C', p, 'rev-parse', 'HEAD']),
                        branch=_cmd(['git', '-C', p, 'rev-parse', '--abbrev-ref', 'HEAD']),
                        dirty=_cmd(['git', '-C', p, 'status', '--porcelain=v1'], lines=True))
    tools = dict(rustc=_cmd(['rustc', '-V']), cargo=_cmd(['cargo', '-V']), python=sys.version.split()[0],
                 flutter=_cmd([os.path.join(FLUTTER_BIN, 'flutter'), '--version']).splitlines()[:1])
    return dict(repos=repos, tools=tools)


def _snapshot_pids():
    pat = r'examples/stub|app-rig\.py|bitcoin-node.*-regtest|flutter_tools|Frostsnap\.app'
    out = subprocess.run(['pgrep', '-fl', pat], capture_output=True, text=True).stdout
    return {ln.split(None, 1)[0]: ln for ln in out.splitlines() if ln.strip() and 'testnet4' not in ln}


COVERAGE = [  # what each kind of stage does and does not exercise
    'Verified software behaviour (real code, run on this host or built for thumbv7em): host unit/integration '
    'suites, ARM clippy and release build, reference contracts (C side compiled from Coldcard headers and read '
    'back, never executed), key-0 packaging and checkfw image validation, pixel decode, the heap model, the real '
    'frostsnap coordinator (hostcheck, coordinator tests) and the real desktop app (app-rig) against virtual '
    'devices over ptys with a disposable regtest node.',
    'MOCKED effects, never real ones: every install request goes to a fake callgate (FakeGate, install-xproc); '
    'flash writes and the resumable erase run on FakeFlash; staging runs on fake PSRAM; the virtual device is a '
    'host build of the firmware logic (examples/stub), not the ARM image. A passing mocked stage says nothing '
    'about the bootloader actually installing, resetting or erasing.',
    'Excluded from every gate: tools/qemu-boot.sh (diagnostic with a substituted stack/map), and '
    'coordinator tofu_tests (they open TLS to public Electrum servers).',
]
UNEXECUTED = [  # software checks that do not exist yet; none is counted as passed
    'app restart and reload of wallet state from its database (task 04 criterion 3)',
    'stub process restart (FakeFlash state lives in memory)',
    'completion signal for an erase interrupted and finished at boot (task 08 criterion 2)',
    'InstallRequested -> install -> verified reconnect end to end (06 -> 07; 07 runs only against a fake gate)',
    'hostcheck M13 interop driven end to end (task 05)',
    'Flutter UI never pumped (API level only); the Dart coldsnapTool timeout branch',
]
BENCH_ONLY = [  # real-hardware questions no software stage can answer
    'real USB enumeration and CDC timing', 'keypad timing and the SSD1306 display', 'TRNG/entropy',
    'SE1/SE2 and callgate 18/0, 18/2, 18/7 behaviour', 'OTP version floor, RDP and PCROP',
    'STM32 erase physics, power loss mid-burn or mid-erase', 'PSRAM retention', 'SRAM wipe on soft reset',
    'actual installation and reset by the bootloader',
    "task 01's U1 world checksum, U2 OTP floor, U3 RDP, U4 install-path existence",
]
RUN_JSON = os.path.join(SW, 'evidence', 'run.json')


def earlier_tasks():
    """Earlier tasks' recorded status and open findings, carried as recorded, never re-labelled."""
    try:
        return [dict(task=t['task'], slug=t.get('slug'), status=t.get('status'),
                     open_confirmed=t.get('open_confirmed', [])) for t in json.load(open(RUN_JSON))]
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [dict(task='?', slug=None, status=f'UNREADABLE: {e}', open_confirmed=[])]


def artifacts():
    return [freshness(a) for a in BUILT] + [freshness(a) for a in DECLARED]


def _cell(x):
    return str('' if x is None else x).replace('|', '/').replace('\n', ' ')


def write_report(out, doc):
    tmp = os.path.join(out, 'results.json.tmp')
    with open(tmp, 'w') as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, os.path.join(out, 'results.json'))
    L = [f"# Software readiness: {doc['label']}", '',
         f"profile `{doc['profile']}`, exit {doc['exit']}, started {doc['started']}, "
         f"finished {doc.get('finished', '-')}", '',
         f"command: `{' '.join(map(shlex.quote, doc['argv']))}` (cwd {CS}); full detail in results.json, "
         f"logs in logs/.", '',
         'The strongest claim this report can make is "software/pre-bench checks passed". It is never '
         '"hardware verified" or "safe for funds". **Real installation is untested**, whatever the mocked '
         'install stages say.', '',
         '## Stages', '', '| # | stage | group | status | rc | s | reason |', '|---|---|---|---|---|---|---|']
    for i, r in enumerate(doc['stages'], 1):
        L.append(f"| {i} | {r['name']} | {r['group']} | {r['status']} | {_cell(r['rc'])} | "
                 f"{_cell(r['elapsed_s'])} | {_cell(r['reason'])} |")
    L += ['', '## Measured this run (parsed from this run\'s output; blank = stage did not produce it)', '']
    for r in doc['stages']:
        for k, v in r['metrics'].items():
            L.append(f"- {r['name']}.{k}: {v if v is not None else '(not found)'}")
    ids = doc['identity']
    L += ['', '## Inputs', '']
    for n, rp in ids['repos'].items():
        L.append(f"- {n} `{rp['head'][:12]}` on {rp['branch']}, {len(rp['dirty'])} dirty path(s)"
                 + (f": {', '.join(rp['dirty'])}" if len(rp['dirty']) <= 8 else ''))
    L.append(f"- tools: {ids['tools']}")
    drift = doc.get('source_drift')
    if drift is not None:
        L.append(f"- source drift during the run: {drift or 'none'}")
    L += ['', '| artifact | sha256 | inputs | freshness |', '|---|---|---|---|']
    for a in doc.get('artifacts', []):
        fr = ('missing' if not a['exists'] else a.get('rule') or
              ('STALE: ' + '; '.join(a['stale'][:2]) if a.get('stale') else 'fresh'))
        L.append(f"| {os.path.relpath(a['path'], CS)} | {a.get('sha256', '-')[:16]} | "
                 f"{a.get('inputs', '-')} ({a.get('inputs_sha256', '-')[:12]}) | {_cell(fr)} |")
    L += ['', '## Coverage', ''] + [f'- {c}' for c in COVERAGE]
    L += ['', '## Not executed by any stage (not passed)', ''] + [f'- {u}' for u in UNEXECUTED]
    L += ['', '## Bench-only, untested here', ''] + [f'- {b}' for b in BENCH_ONLY]
    L += ['', f'## Earlier tasks, as recorded in {os.path.relpath(RUN_JSON, CS)} (not re-judged here)', '']
    for t in doc.get('earlier_tasks', []):
        L.append(f"- {t['task']} {t['slug']}: **{t['status']}**, {len(t['open_confirmed'])} open confirmed finding(s)")
        L += [f"  - {_cell(f)[:220]}" for f in t['open_confirmed']]
    with open(os.path.join(out, 'summary.md'), 'w') as f:
        f.write('\n'.join(L) + '\n')


def run(plan, profile, out, scale=1.0, grace=GRACE, argv=None, repos=None):
    """`repos`: working trees that must not change while the run is in progress (source drift
    or a concurrent edit means the stages did not all test one tree)."""
    repos = [CS, FS, REF] if repos is None else repos
    logdir = os.path.join(out, 'logs')
    os.makedirs(logdir, exist_ok=True)
    doc = dict(profile=profile, argv=argv or sys.argv, output_dir=out, exit=None, label='running',
               started=datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
               identity=identity(), earlier_tasks=earlier_tasks(), stages=[])
    trees = {r: _tree_state(r) for r in repos if os.path.isdir(r)}
    doc['tree_state_at_start'] = trees
    pre = _snapshot_pids()
    by = {}

    def on_signal(sig, _):
        raise KeyboardInterrupt(sig)
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, on_signal)
    try:
        for st in sorted(plan, key=lambda s: GROUP_ORDER[s.group]):   # stable: keeps order within a group
            print(f'[{st.group}] {st.name}: {st.command()}  (cwd {st.cwd})', flush=True)
            r = run_stage(st, logdir, by, scale, grace)
            by[st.name] = r
            doc['stages'].append(r)
            print(f'    -> {r["status"]} rc={r["rc"]} {r["elapsed_s"] or 0}s {r["reason"] or ""}', flush=True)
            write_report(out, doc)
        orphans = {k: v for k, v in _snapshot_pids().items() if k not in pre}
        doc['orphans_after_run'] = list(orphans.values())
        code, label = overall(doc['stages'], profile)
        drift = [r for r, h in trees.items() if _tree_state(r) != h]
        doc['source_drift'] = drift
        extra = ([f'SOURCE DRIFT DURING RUN in {drift}: results mix trees'] if drift else []) + \
                ([f'ORPHAN PROCESSES LEFT: {list(orphans.values())}'] if orphans else [])
        if extra:
            code = max(code, 1)
            label = (label if label.startswith('NOT PASSED') else 'NOT PASSED') + '; ' + '; '.join(extra)
    except KeyboardInterrupt as e:
        sig = e.args[0] if e.args and isinstance(e.args[0], int) else signal.SIGINT
        if _current['pgid']:
            _kill_group(_current['pgid'], grace, _current['proc'])
        code, label = 128 + int(sig), f'INTERRUPTED by signal {int(sig)}; not a readiness result'
    doc['artifacts'] = artifacts()
    doc.update(exit=code, label=label,
               finished=datetime.datetime.now().astimezone().isoformat(timespec='seconds'))
    write_report(out, doc)
    print(label, flush=True)
    return code


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--profile', choices=('full', 'core'), default='full')
    ap.add_argument('--output-dir', default='target/software-readiness',
                    help='relative paths resolve against the cold-snap repo (default %(default)s)')
    ap.add_argument('--timeout-scale', type=float, default=1.0,
                    help='multiply every stage timeout (default %(default)s)')
    ap.add_argument('--list', action='store_true', help='print the plan and exit')
    a = ap.parse_args()
    out = a.output_dir if os.path.isabs(a.output_dir) else os.path.join(CS, a.output_dir)
    plan = [s for s in stages(out) if a.profile == 'full' or s.core]
    if a.list:
        for s in sorted(plan, key=lambda s: GROUP_ORDER[s.group]):
            print(f'{s.group:14} {s.name:30} cwd={s.cwd}  {s.command()}')
        return 0
    return run(plan, a.profile, out, a.timeout_scale)


if __name__ == '__main__':
    sys.exit(main())
