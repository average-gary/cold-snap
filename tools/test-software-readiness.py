#!/usr/bin/env python3
"""Failure-path checks for tools/check-software-readiness.py, against deliberate
synthetic child tools (no cargo, no device): failing, hung, TERM-ignoring, SKIP-printing,
missing-prerequisite, upstream-failed, blocked, zero-test, tree-mutating, unregistered,
leaked-grandchild and runner-interrupted. Each must end in a non-success status and a
nonzero overall exit. Output under target/software-readiness-selftest/.

    python3 tools/test-software-readiness.py      # exit 0 iff every case behaves
"""
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CS = os.path.dirname(HERE)
OUT = os.path.join(CS, 'target', 'software-readiness-selftest')
sys.dont_write_bytecode = True   # keep tools/__pycache__ as the user left it
spec = importlib.util.spec_from_file_location('csr', os.path.join(HERE, 'check-software-readiness.py'))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

GRACE = 1.0
fails = []


def check(name, cond, detail=''):
    print(('ok   ' if cond else 'FAIL ') + name + (f'  ({detail})' if detail and not cond else ''))
    if not cond:
        fails.append(name)


def sh(name, script, **kw):
    return R.Stage(name, kw.pop('group', 'host'), name, OUT, ['/bin/sh', '-c', script], **kw)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def pidfile(n):
    return os.path.join(OUT, f'{n}.pid')


def one(st, results=None):
    return R.run_stage(st, os.path.join(OUT, 'logs'), results or {}, 1.0, GRACE)


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(os.path.join(OUT, 'logs'))

    r = one(sh('fails', 'echo boom >&2; exit 3'))
    check('failing child -> failed with its own rc', r['status'] == 'failed' and r['rc'] == 3, r)

    t0 = time.monotonic()
    r = one(sh('hung', f'sleep 300 & echo $! > {pidfile("hung")}; wait', timeout=1))
    gc = int(open(pidfile('hung')).read())
    time.sleep(0.2)
    check('hung child -> timed_out', r['status'] == 'timed_out', r)
    check('hung child grandchild killed with its group', not alive(gc), gc)
    check('hung child bounded', time.monotonic() - t0 < 1 + GRACE + 3)

    t0 = time.monotonic()
    r = one(sh('ignores-term', 'trap "" TERM; sleep 300', timeout=1))
    check('TERM-ignoring child -> timed_out, SIGKILLed after grace',
          r['status'] == 'timed_out' and time.monotonic() - t0 < 1 + GRACE + 3, r)

    r = one(sh('skips', 'echo "SKIP: reference missing"; exit 0', skip_re=r'(?m)^\s*SKIP\b'))
    check('exit-0 SKIP -> unavailable, not passed', r['status'] == 'unavailable', r)

    r = one(sh('refuses-2', 'exit 2', rc_status={2: 'unavailable'}))
    check('exit-contract 2 -> unavailable', r['status'] == 'unavailable', r)

    R.PREREQS['never-there'] = lambda: R._exists(os.path.join(OUT, 'no-such-tool'))
    r = one(sh('needs-missing', f'touch {os.path.join(OUT, "ran")}', needs=['never-there']))
    check('missing prerequisite -> unavailable and never executed',
          r['status'] == 'unavailable' and not os.path.exists(os.path.join(OUT, 'ran'))
          and 'never-there' in r['reason'], r)

    r = one(sh('downstream', 'exit 0', after=['fails']), {'fails': {'status': 'failed'}})
    check('upstream failed -> dependent unavailable', r['status'] == 'unavailable', r)
    r = one(sh('downstream2', 'exit 0', after=['never-ran']))
    check('upstream not run -> dependent unavailable', r['status'] == 'unavailable', r)

    r = one(sh('neg-ok', 'echo "REFUSE R12"; exit 1', expect_rc=1, must=['R12']))
    check('negative with expected rc and reason -> passed', r['status'] == 'passed', r)
    r = one(sh('neg-wrong-reason', 'echo "REFUSE R8"; exit 1', expect_rc=1, must=['R12']))
    check('negative refusing for the wrong reason -> failed', r['status'] == 'failed', r)
    r = one(sh('neg-accepts', 'echo ACCEPT; exit 0', expect_rc=1, must=['R12']))
    check('negative that accepts -> failed', r['status'] == 'failed', r)

    # The real stage's rule, not a copy: a crash that also exits 1 must not pass as a refusal.
    bl = next(s for s in R.stages(OUT) if s.name == 'pack-negative-bad-layout')
    real = ('ABORT (Abort): firmware0.bin would load at 0x08180000, not 0x08020000: signit lays the '
            'vectors, header and body down at fixed offsets')
    for nm, script, want in [
            ('bad-layout-refusal', f'echo; echo "{real}" >&2; exit 1', 'passed'),
            ('bad-layout-traceback', 'echo "Traceback (most recent call last):" >&2; '
             'echo "KeyError: \'.vector_table\'" >&2; exit 1', 'failed'),
            ('bad-layout-crash-abort', 'echo "ABORT (KeyError): \'.vector_table\'" >&2; exit 1', 'failed')]:
        r = one(sh(nm, script, expect_rc=bl.expect_rc, must=bl.must))
        check(f'pack-negative-bad-layout rule: {nm} rc 1 -> {want}', r['status'] == want, r)

    # The real stage's rule on checkfw's real lines (target/software-only/fix7/checkfw-*.log):
    # R12 has a second [FAIL] variant, "range unusable", which is a refusal for a length reason.
    sig = next(s for s in R.stages(OUT) if s.name == 'checkfw-negative-signature')
    res = 'RESULT: REFUSE — 1 of 14 rules failed. Read each citation:'
    for nm, line, want in [
            ('sig-verify-failed', '  [FAIL] R12 signature over double-SHA256(signed range): expected valid '
             'under approved_pubkeys[0], actual signature failed verification; fw_check 265f  [verify.c:226+232]',
             'passed'),
            ('sig-range-unusable', '  [FAIL] R12 signature (range unusable): expected firmware_digest() -> Some, '
             'actual None: one of length >= 262144 / length % 512 == 0 / length <= 397312 failed  '
             '[coldsnap_firmware::firmware_digest]', 'failed'),
            ('sig-passed-other-refusal', '  [PASS] R12 signature over double-SHA256(signed range): expected valid '
             'under approved_pubkeys[0], actual valid (S normalized); fw_check 265f  [verify.c:226+232]', 'failed')]:
        r = one(sh(nm, f"printf '%s\\n%s\\n' '{line}' '{res}'; exit 1", expect_rc=sig.expect_rc, must=sig.must))
        check(f'checkfw-negative-signature rule: {nm} rc 1 -> {want}', r['status'] == want, r)

    r = one(sh('zero-tests', 'echo "test result: ok. 0 passed; 0 failed"', must=[R.TESTS_RAN]))
    check('cargo run testing nothing -> failed', r['status'] == 'failed', r)

    BRE = r'tests/coldcard_msg_len\.rs'
    E0308 = ('printf "error[E0308]: mismatched types\\n   --> frostsnap_coordinator/tests/coldcard_msg_len.rs:97:56\\n'
             'error: could not compile \\`frostsnap_coordinator\\` (test \\"coldcard_msg_len\\") due to 1 previous error\\n" >&2')
    r = one(sh('blocked', E0308 + '; exit 101', blocked_re=BRE))
    check('failure caused by protected user work -> blocked', r['status'] == 'blocked', r)
    r = one(sh('not-blocked', 'echo "error in src/lib.rs" >&2; exit 101', blocked_re=BRE))
    check('unrelated failure with a blocked_re -> failed, not blocked', r['status'] == 'failed', r)
    r = one(sh('running-line', 'echo "     Running tests/coldcard_msg_len.rs (target/x)"; echo "test result: ok. 3 passed"; '
               'echo "     Running tests/real_psbts.rs (target/y)"; echo "test r ... FAILED"; '
               'echo "test result: FAILED. 1 passed; 1 failed"; exit 101', blocked_re=BRE))
    check('cargo Running line for the blocked file + a real test failure -> failed', r['status'] == 'failed', r)
    r = one(sh('also-other', E0308 + '; printf "error[E0425]: x\\n  --> frostsnap_coordinator/src/lib.rs:1:1\\n" >&2; exit 101',
               blocked_re=BRE))
    check('blocked file error beside another target\'s error -> failed', r['status'] == 'failed', r)

    r = one(sh('leaks', f'sleep 300 & echo $! > {pidfile("leaks")}; exit 0'))
    gc = int(open(pidfile('leaks')).read())
    time.sleep(0.2)
    check('grandchild left by a passing child is killed', not alive(gc) and r.get('leftover_children_killed'), r)

    repo = os.path.join(OUT, 'repo')
    os.makedirs(repo)
    subprocess.run(['git', 'init', '-q', repo], check=True)
    open(os.path.join(repo, 'f'), 'w').write('a\n')
    subprocess.run(['git', '-C', repo, 'add', 'f'], check=True)
    subprocess.run(['git', '-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'i'], check=True)
    r = one(sh('regen-same', f'printf "a\\n" > {repo}/f', tree_unchanged=repo))
    check('regeneration leaving the tree identical -> passed', r['status'] == 'passed', r)
    r = one(sh('regen-drift', f'echo b > {repo}/f', tree_unchanged=repo))
    check('regeneration changing the tree -> failed', r['status'] == 'failed', r)

    reg = os.path.join(OUT, 'registry.txt')
    open(reg, 'w').write('# comment\n' + 'a' * 64 + ' label\n')
    R.REGISTRY = reg
    r = one(sh('registered', 'echo ' + 'a' * 64, stdout_in_registry=True))
    check('registered digest -> passed', r['status'] == 'passed', r)
    r = one(sh('unregistered', 'echo ' + 'b' * 64, stdout_in_registry=True))
    check('unregistered digest -> failed, never bypassed', r['status'] == 'failed', r)

    # overall exit and labels, through run() so results.json/summary.md are exercised
    ok = [sh('p1', 'exit 0'), sh('p2', 'exit 0', group='arm')]
    for prof, bad, want_code in (('full', None, 0), ('core', None, 0), ('full', sh('f', 'exit 1'), 1),
                                 ('full', sh('t', 'sleep 5', timeout=0.5), 1),
                                 ('full', sh('s', 'echo SKIP: x', skip_re=r'(?m)^SKIP'), 2),
                                 ('full', sh('b', E0308 + '; exit 101', blocked_re=BRE), 2)):
        d = os.path.join(OUT, f'run-{prof}-{bad.name if bad else "ok"}')
        code = R.run(ok + ([bad] if bad else []), prof, d, 1.0, GRACE, argv=['selftest'], repos=[])
        doc = json.load(open(os.path.join(d, 'results.json')))
        tag = f'{prof}/{bad.name if bad else "all-pass"}'
        check(f'overall {tag} exits {want_code}', code == want_code == doc['exit'], (code, doc['label']))
        if want_code:
            check(f'overall {tag} carries no success label', 'passed' not in doc['label'].split(':')[0]
                  and doc['label'].startswith('NOT PASSED'), doc['label'])
        elif prof == 'full':
            check('full success label is exactly the scoped one', doc['label'] == 'software/pre-bench checks passed')
        else:
            check('core success label names its scope', doc['label'].startswith('core-only ')
                  and 'NOT run' in doc['label'], doc['label'])
        check(f'{tag} stages ordered by group', [s['group'] for s in doc['stages']] ==
              sorted((s['group'] for s in doc['stages']), key=R.GROUP_ORDER.get))
        md = open(os.path.join(d, 'summary.md')).read()
        check(f'{tag} summary.md says real installation is untested and lists bench-only/unexecuted',
              all(x in md for x in ('Real installation is untested', '## Bench-only', '## Not executed',
                                    'MOCKED effects', 'qemu-boot.sh')))
        check(f'{tag} earlier tasks carried as recorded, none restated as PASS',
              [t['status'] for t in doc['earlier_tasks']] == [t['status'] for t in json.load(open(R.RUN_JSON))]
              and 'PASS' not in {t['status'] for t in doc['earlier_tasks']}, doc['earlier_tasks'])
        check(f'{tag} artifacts hashed in results.json', doc['artifacts'] and all(
            'sha256' in a for a in doc['artifacts'] if a['exists']))

    # stale input: a consumed artifact older than one of its inputs never feeds a stage
    art, inp, ran = (os.path.join(OUT, n) for n in ('art.bin', 'input.rs', 'stale-ran'))
    open(inp, 'w').write('src\n')
    open(art, 'w').write('built\n')
    now = time.time()
    os.utime(inp, (now - 10, now - 10))
    R.BUILT[art] = lambda: [inp]
    r = one(sh('fresh', 'exit 0', consumes=[art]))
    check('artifact newer than its inputs -> passed, hashes recorded', r['status'] == 'passed'
          and r['consumes'][0]['sha256'] == R._sha(art) and r['consumes'][0]['inputs'] == 1, r)
    os.utime(inp, (now + 10, now + 10))
    r = one(sh('stale', f'touch {ran}', consumes=[art]))
    check('input newer than artifact -> failed STALE, stage never executed',
          r['status'] == 'failed' and 'STALE' in r['reason'] and not os.path.exists(ran), r)
    os.remove(inp)
    r = one(sh('input-gone', f'touch {ran}', consumes=[art]))
    check('artifact whose input vanished -> STALE', r['status'] == 'failed' and 'missing' in r['reason'], r)
    r = one(sh('no-artifact', f'touch {ran}', consumes=[os.path.join(OUT, 'never-built')]))
    check('missing artifact -> unavailable, never executed',
          r['status'] == 'unavailable' and not os.path.exists(ran), r)
    d = os.path.join(OUT, 'run-stale')
    code = R.run([sh('p0', 'exit 0'), sh('stale2', 'exit 0', consumes=[art])], 'full', d, 1.0, GRACE,
                 argv=['selftest'], repos=[])
    check('stale artifact -> overall full exit 1, not passed', code == 1 and
          json.load(open(os.path.join(d, 'results.json')))['label'].startswith('NOT PASSED'), code)
    decl = R.freshness(art, built={})
    check('declared fixture is hashed, never called fresh', 'stale' not in decl and 'declared' in decl['rule'])
    dep = os.path.join(OUT, 'a b')
    open(dep + '.d', 'w').write(f'{OUT}/a\\ b: /x/one.rs /x/two\\ words.rs\n\n/x/one.rs:\n')
    check('cargo dep-info parsed, escaped spaces kept', R._depinfo(dep) == ['/x/one.rs', '/x/two words.rs'],
          R._depinfo(dep))

    # source drift: a tree that changes while the run is in progress
    d = os.path.join(OUT, 'run-drift')
    code = R.run([sh('edits-tree', f'echo c > {repo}/f')], 'full', d, 1.0, GRACE, argv=['selftest'],
                 repos=[repo])
    lab = json.load(open(os.path.join(d, 'results.json')))['label']
    check('source drift during a run -> exit 1, named, no success label',
          code == 1 and 'SOURCE DRIFT' in lab and lab.startswith('NOT PASSED'), lab)

    # frostsnap pin: the real stage, pointed at synthetic checkouts and its own pin file
    pin_st = next(s for s in R.stages(OUT) if s.name == 'frostsnap-pin')
    r = R.run_stage(pin_st, os.path.join(OUT, 'logs'), {}, 1.0, GRACE)
    check('frostsnap-pin on the real checkout -> passed', r['status'] == 'passed', r)
    fs = os.path.join(OUT, 'fs')
    g = lambda *a: subprocess.run(['git', '-C', fs, '-c', 'user.name=t', '-c', 'user.email=t@t', *a],
                                  check=True, capture_output=True, text=True).stdout.strip()
    os.makedirs(os.path.join(fs, 'frostsnap_coordinator'))
    subprocess.run(['git', 'init', '-q', fs], check=True)
    for n in ('a', 'b'):
        open(os.path.join(fs, 'frostsnap_coordinator', 'lib.rs'), 'w').write(n)
        g('add', '-A'), g('commit', '-qm', n)
    a, b = g('rev-parse', 'HEAD~1'), g('rev-parse', 'HEAD')
    pinf = os.path.join(OUT, 'frostsnap.rev')
    open(pinf, 'w').write(f'# comment\n{b}\n')

    def pin(tree=fs, pinfile=pinf):
        st = R.Stage('pin', 'coordinator', 'pin', pin_st.cwd, pin_st.argv[:-1] + [tree, pinfile],
                     must=pin_st.must)
        res = one(st)
        return res, open(res['stdout_log']).read() if res.get('stdout_log') else ''

    r, o = pin()
    check('pin: HEAD is the pin -> passed', r['status'] == 'passed', o)
    g('checkout', '-q', a)
    r, o = pin()
    check('pin: HEAD older than the pin -> failed rc 1, both SHAs and the fix printed',
          r['status'] == 'failed' and r['rc'] == 1 and 'OLDER' in o and a in o and b in o and 'bump' in o, o)
    g('checkout', '-q', b), g('commit', '-q', '--allow-empty', '-m', 'c')
    r, o = pin()
    check('pin: HEAD ahead of the pin -> failed rc 3 (AHEAD), not passed',
          r['status'] == 'failed' and r['rc'] == 3 and 'AHEAD' in o, o)
    g('checkout', '-q', a), g('commit', '-q', '--allow-empty', '-m', 'd')
    r, o = pin()
    check('pin: diverged -> failed rc 1', r['status'] == 'failed' and r['rc'] == 1 and 'diverged' in o, o)
    g('checkout', '-q', b)
    open(os.path.join(fs, 'frostsnap_coordinator', 'lib.rs'), 'w').write('edited')
    r, o = pin()
    check('pin: tracked edit in a pinned crate -> failed rc 3 (EDITED)',
          r['status'] == 'failed' and r['rc'] == 3 and 'EDITED' in o, o)
    g('checkout', '-q', '--', '.')
    open(pinf, 'w').write('0' * 40 + '\n')
    r, o = pin()
    check('pin: pinned commit absent -> failed rc 1', r['status'] == 'failed' and 'not in this checkout' in o, o)
    r, o = pin(pinfile=os.path.join(OUT, 'no-such.rev'))
    check('pin: unreadable pin file -> failed', r['status'] == 'failed' and 'unreadable' in o, o)
    r, o = pin(tree=os.path.join(OUT, 'no-such-frostsnap'))
    check('pin: frostsnap missing -> failed by name, not unavailable', r['status'] == 'failed' and 'missing' in o, o)
    plain = os.path.join(OUT, 'plain')
    os.makedirs(plain)
    r, o = pin(tree=plain)
    check('pin: a directory that is not its own git checkout -> failed',
          r['status'] == 'failed' and 'not its own git checkout' in o, o)

    # the runner itself interrupted mid-stage
    d = os.path.join(OUT, 'run-interrupted')
    pf = pidfile('intr')
    code = ('import importlib.util,sys;s=importlib.util.spec_from_file_location("c",sys.argv[1]);'
            'R=importlib.util.module_from_spec(s);s.loader.exec_module(R);'
            'st=R.Stage("hang","host","hang",sys.argv[2],["/bin/sh","-c",'
            '"sleep 300 & echo $! > "+sys.argv[3]+"; wait"],timeout=300);'
            'sys.exit(R.run([st],"full",sys.argv[2],1.0,1.0,argv=["selftest"]))')
    p = subprocess.Popen([sys.executable, '-B', '-c', code, os.path.join(HERE, 'check-software-readiness.py'), d, pf],
                         stdout=subprocess.DEVNULL, start_new_session=True)
    for _ in range(900):   # the run hashes the reference tree first (about 15 s)
        if os.path.exists(pf) and os.path.getsize(pf):
            break
        time.sleep(0.1)
    time.sleep(0.3)
    p.send_signal(signal.SIGTERM)
    rc = p.wait(timeout=30)
    gc = int(open(pf).read())
    time.sleep(0.2)
    doc = json.load(open(os.path.join(d, 'results.json')))
    check('SIGTERM to runner -> exit 143', rc == 143, rc)
    check('SIGTERM to runner -> results.json says INTERRUPTED', doc['label'].startswith('INTERRUPTED'), doc['label'])
    check('SIGTERM to runner -> running child group killed', not alive(gc), gc)

    print(f'\n{"FAIL" if fails else "PASS"}: {len(fails)} failed case(s)' + (f': {fails}' if fails else ''))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
