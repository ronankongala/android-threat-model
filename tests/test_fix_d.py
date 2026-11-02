"""Offline tests for the two-app dynamic scenario (dynamic_analyzer.run_two_app)
and the --dynamic-two-app flag of ate.py. The adb layer (_adb) is replaced by a
fake device, so no emulator is needed."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import ate  # noqa: E402
import dynamic_analyzer  # noqa: E402

BENIGN = 'edu.ksu.cs.benign'
MAL = 'edu.ksu.cs.malicious'

STACK_BENIGN_ONLY = '''ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  Stack #1:
    Task id #11
      * TaskRecord{b2c3d4 #11 A=edu.ksu.cs.benign U=0 StackId=1 sz=1}
        affinity=edu.ksu.cs.benign
        * Hist #0: ActivityRecord{f6a7b8 u0 edu.ksu.cs.benign/.LoginActivity t11}
    mResumedActivity: ActivityRecord{f6a7b8 u0 edu.ksu.cs.benign/.LoginActivity t11}
'''

STACK_HIJACKED = '''ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  Stack #1:
    Task id #11
      * TaskRecord{b2c3d4 #11 A=edu.ksu.cs.benign U=0 StackId=1 sz=2}
        affinity=edu.ksu.cs.benign
        * Hist #1: ActivityRecord{e5f6a7 u0 edu.ksu.cs.malicious/.MalActivity t11}
        * Hist #0: ActivityRecord{f6a7b8 u0 edu.ksu.cs.benign/.LoginActivity t11}
    mResumedActivity: ActivityRecord{e5f6a7 u0 edu.ksu.cs.malicious/.MalActivity t11}
'''

STACK_SEPARATE = '''ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  Stack #1:
    Task id #12
      * TaskRecord{a1b2c3 #12 A=edu.ksu.cs.malicious U=0 StackId=1 sz=1}
        affinity=edu.ksu.cs.malicious
        * Hist #0: ActivityRecord{d4e5f6 u0 edu.ksu.cs.malicious/.MalActivity t12}
    Task id #11
      * TaskRecord{b2c3d4 #11 A=edu.ksu.cs.benign U=0 StackId=1 sz=1}
        affinity=edu.ksu.cs.benign
        * Hist #0: ActivityRecord{f6a7b8 u0 edu.ksu.cs.benign/.LoginActivity t11}
    mResumedActivity: ActivityRecord{d4e5f6 u0 edu.ksu.cs.malicious/.MalActivity t12}
'''

DENIAL = ('11-01 10:00:01.000  2000  2000 W ActivityManager: Permission Denial: starting Intent '
          '{ cmp=edu.ksu.cs.benign/.HomeActivity } from ProcessRecord{1 3000:edu.ksu.cs.malicious/u0a90} '
          'not exported from uid 10089')


class FakeDevice:
    """Answers the adb calls run_two_app makes. Files of the benign app change
    in three phases: before the benign start, after it, after the malicious start."""

    def __init__(self, after_stack=STACK_HIJACKED, files=None, logcat='', find_fails=False,
                 run_as_fails=False, install_fails_for=None):
        self.after_stack = after_stack
        self.files = files or ({'files/secret.txt'},
                               {'files/secret.txt', 'shared_prefs/p.xml'},
                               {'shared_prefs/p.xml', 'files/pwned.txt'})
        self.logcat = logcat
        self.find_fails = find_fails
        self.run_as_fails = run_as_fails
        self.install_fails_for = install_fails_for
        self.phase = 0  # 0 nothing started, 1 benign started, 2 malicious started
        self.calls = []

    def __call__(self, adb, args, timeout=dynamic_analyzer.TIMEOUT):
        args = list(args)
        self.calls.append(args)
        if args[0] == 'devices':
            return 0, 'List of devices attached\nemulator-5554\tdevice\n'
        if args[0] == 'install':
            if self.install_fails_for and self.install_fails_for in args[-1]:
                return 1, 'Failure [INSTALL_FAILED]'
            return 0, 'Success'
        if args[0] == 'uninstall':
            return 0, 'Success'
        if args[0] == 'logcat':
            return 0, self.logcat if '-d' in args else ''
        if args[0] != 'shell':
            return 1, ''
        sh = args[1:]
        if sh[:2] == ['am', 'start']:
            self.phase = 1 if sh[-1].startswith(BENIGN + '/') else 2
            return 0, 'Starting: Intent'
        if sh[0] == 'monkey':
            self.phase = 1 if sh[2] == BENIGN else 2
            return 0, 'Events injected: 1'
        if sh[:3] == ['dumpsys', 'activity', 'activities']:
            return 0, STACK_BENIGN_ONLY if self.phase < 2 else self.after_stack
        if sh[0] == 'run-as':
            if self.run_as_fails:
                return 1, 'run-as: package not debuggable: ' + sh[1]
            files = self.files[self.phase]
            if sh[2] == 'find':
                if self.find_fails:
                    return 1, 'find: not found'
                root = sh[3]
                prefix = './' if root == '.' else root + '/'
                return 0, '\n'.join(prefix + f for f in sorted(files))
            if sh[2] == 'ls':
                return 0, '  '.join(sorted(f[6:] for f in files if f.startswith('files/')))
        if sh[:2] == ['cmd', 'package']:
            return 0, 'priority=0\n%s/.Main\n' % sh[-1]
        return 0, ''


@pytest.fixture
def fake(monkeypatch):
    def install(**kw):
        dev = FakeDevice(**kw)
        monkeypatch.setattr(dynamic_analyzer, '_adb', dev)
        monkeypatch.setattr(dynamic_analyzer.time, 'sleep', lambda s: None)
        return dev
    return install


def _run(**kw):
    return dynamic_analyzer.run_two_app('benign.apk', 'mal.apk', BENIGN, MAL, adb='adb', **kw)


def _issues(findings):
    return sorted({f['issue'] for f in findings})


def test_hijack_files_and_denial(fake):
    dev = fake(logcat=DENIAL)
    found = _run(benign_activity='.LoginActivity', malicious_activity='.MalActivity')
    assert _issues(found) == ['dynamic-file-created', 'dynamic-file-deleted',
                              'dynamic-foreground-foreign-activity',
                              'dynamic-permission-denial-observed', 'dynamic-task-hijack']
    for f in found:
        assert f['cwe'] == dynamic_analyzer.ISSUES[f['issue']]
        assert set(f) == {'component', 'component_type', 'issue', 'cwe', 'confidence', 'evidence'}
    hijack = [f for f in found if f['issue'] == 'dynamic-task-hijack']
    assert any('edu.ksu.cs.malicious/.MalActivity' in f['evidence'] for f in hijack)
    assert all(f['cwe'] == 'CWE-1021' for f in hijack)
    fg = [f for f in found if f['issue'] == 'dynamic-foreground-foreign-activity']
    assert len(fg) == 1 and 'task #11' in fg[0]['evidence']
    created = [f['evidence'] for f in found if f['issue'] == 'dynamic-file-created']
    deleted = [f['evidence'] for f in found if f['issue'] == 'dynamic-file-deleted']
    # shared_prefs/p.xml came from the benign app's own start-up: not reported
    assert len(created) == 1 and created[0].startswith('files/pwned.txt')
    assert len(deleted) == 1 and deleted[0].startswith('files/secret.txt')
    # order: install both, start benign then malicious, uninstall both at the end
    starts = [c[-1] for c in dev.calls if c[1:3] == ['am', 'start']]
    assert starts == [BENIGN + '/.LoginActivity', MAL + '/.MalActivity']
    assert [c[1] for c in dev.calls if c[0] == 'install'] == ['-r', '-r']
    assert sorted(c[1] for c in dev.calls if c[0] == 'uninstall') == sorted([BENIGN, MAL])
    assert dev.calls[-1][0] == 'uninstall'


def test_separate_task_is_clean(fake):
    fake(after_stack=STACK_SEPARATE,
         files=({'files/a'}, {'files/a'}, {'files/a'}))
    assert _run() == []


def test_malicious_task_with_benign_affinity(fake):
    stack = STACK_SEPARATE.replace('A=edu.ksu.cs.malicious', 'A=edu.ksu.cs.benign') \
                          .replace('affinity=edu.ksu.cs.malicious', 'affinity=edu.ksu.cs.benign')
    fake(after_stack=stack, files=({'files/a'},) * 3)
    found = _run()
    assert _issues(found) == ['dynamic-foreground-foreign-activity', 'dynamic-task-hijack']


def test_malicious_task_with_declared_benign_affinity(fake):
    # TaskAffinity-ActivityHijack: MalActivity takes the affinity of the benign ImageEditor
    affinity = 'edu.ksu.santos.benign.editImage'
    stack = STACK_SEPARATE.replace('A=edu.ksu.cs.malicious', 'A=' + affinity)                           .replace('affinity=edu.ksu.cs.malicious', 'affinity=' + affinity)
    fake(after_stack=stack, files=({'files/a'},) * 3)
    assert _run() == []
    found = _run(benign_affinities=[affinity, BENIGN])
    assert _issues(found) == ['dynamic-task-hijack']
    assert affinity in found[0]['evidence'] and found[0]['confidence'] == 'medium'


def test_ate_task_affinities():
    manifest = {'application': {'taskAffinity': None},
                'components': [{'type': 'activity', 'task_affinity': 'x.edit'},
                               {'type': 'activity', 'task_affinity': None},
                               {'type': 'receiver'}]}
    assert ate.task_affinities(manifest) == ['x.edit']


def test_find_fallback_to_relative_path(fake, monkeypatch):
    dev = fake(after_stack=STACK_SEPARATE)
    refused = []

    def no_abs(adb, args, timeout=dynamic_analyzer.TIMEOUT):
        args = list(args)
        if args[:2] == ['shell', 'run-as'] and args[3:5] == ['find', '/data/data/' + BENIGN]:
            refused.append(args)
            return 1, 'find: /data/data/%s: Permission denied' % BENIGN
        return dev(adb, args, timeout)
    monkeypatch.setattr(dynamic_analyzer, '_adb', no_abs)
    found = _run()
    assert refused
    assert any(c[3:5] == ['find', '.'] for c in dev.calls if c[:2] == ['shell', 'run-as'])
    assert _issues(found) == ['dynamic-file-created', 'dynamic-file-deleted']


def test_ls_fallback_when_find_missing(fake):
    fake(after_stack=STACK_SEPARATE, find_fails=True)
    found = _run()
    # ls only sees files/, so shared_prefs/ is not compared
    assert sorted(f['evidence'].split()[0] for f in found) == ['files/pwned.txt', 'files/secret.txt']


def test_no_run_as_means_no_file_diff(fake):
    fake(run_as_fails=True)
    found = _run()
    assert not [f for f in found if f['issue'].startswith('dynamic-file-')]
    assert 'dynamic-task-hijack' in _issues(found)


def test_monkey_when_no_launcher(fake, monkeypatch):
    dev = fake()
    monkeypatch.setattr(dynamic_analyzer, '_resolve_main_activity', lambda adb, pkg: None)
    _run()
    monkeys = [c for c in dev.calls if c[1:2] == ['monkey']]
    assert [c[3] for c in monkeys] == [BENIGN, MAL]


def test_install_failure_still_uninstalls(fake):
    dev = fake(install_fails_for='mal.apk')
    assert _run() == []
    assert sorted(c[1] for c in dev.calls if c[0] == 'uninstall') == sorted([BENIGN, MAL])
    assert not [c for c in dev.calls if c[1:3] == ['am', 'start']]


def test_exception_still_uninstalls(fake, monkeypatch):
    dev = fake()

    def boom(*a, **k):
        raise RuntimeError('device went away')
    monkeypatch.setattr(dynamic_analyzer, 'parse_logcat', boom)
    assert _run() == []
    assert sorted(c[1] for c in dev.calls if c[0] == 'uninstall') == sorted([BENIGN, MAL])


def test_no_device_skips(monkeypatch, caplog):
    monkeypatch.setattr(dynamic_analyzer, '_adb', lambda adb, args, timeout=0: (0, 'List of devices attached\n'))
    with caplog.at_level('WARNING'):
        assert _run() == []
    assert 'skipping two-app dynamic analysis' in caplog.text


def test_no_adb_skips(monkeypatch):
    monkeypatch.setattr(dynamic_analyzer, 'find_adb', lambda: None)
    assert dynamic_analyzer.run_two_app('b.apk', 'm.apk', BENIGN, MAL) == []


# ate.py --dynamic-two-app

def test_ate_flag(monkeypatch, tmp_path, capsys):
    benign_manifest = {'package': BENIGN, 'components': []}
    mal_manifest = {'package': MAL, 'components': []}
    decoded = []

    def decode(path, workdir=None):
        decoded.append(path)
        return dict(mal_manifest if path == 'mal.apk' else benign_manifest)
    calls = []

    def run_two_app(b_apk, m_apk, b_pkg, m_pkg, **kw):
        calls.append((b_apk, m_apk, b_pkg, m_pkg))
        return [dynamic_analyzer._finding(b_pkg, 'application', 'dynamic-task-hijack', 'high', 'x')]
    monkeypatch.setattr(ate.apk, 'decode', decode)
    monkeypatch.setattr(ate.surface, 'find', lambda m: [])
    monkeypatch.setattr(ate.dynamic_analyzer, 'find_adb', lambda: 'adb')
    monkeypatch.setattr(ate.dynamic_analyzer, 'device_available', lambda adb: True)
    monkeypatch.setattr(ate.dynamic_analyzer, 'run_two_app', run_two_app)
    assert ate.main(['--apk', 'benign.apk', '--out', str(tmp_path), '--dynamic-two-app', 'mal.apk']) == 0
    assert calls == [('benign.apk', 'mal.apk', BENIGN, MAL)]
    md = (tmp_path / 'benign-report.md').read_text(encoding='utf-8')
    assert 'dynamic-task-hijack' in md and 'skipped' not in md
    assert '1 findings' in capsys.readouterr().out


def test_ate_flag_without_device(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ate.apk, 'decode', lambda p, w=None: {'package': BENIGN, 'components': []})
    monkeypatch.setattr(ate.surface, 'find', lambda m: [])
    monkeypatch.setattr(ate.dynamic_analyzer, 'find_adb', lambda: 'adb')
    monkeypatch.setattr(ate.dynamic_analyzer, 'device_available', lambda adb: False)
    assert ate.main(['--apk', 'benign.apk', '--out', str(tmp_path), '--dynamic-two-app', 'mal.apk']) == 0
    assert 'dynamic analysis skipped' in capsys.readouterr().err
