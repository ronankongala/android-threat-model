"""Tests for A3-2: task-affinity-shared (CWE-1021, high) in two-APK mode, and
the --second-apk option of src/ate.py."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import apk as apkmod  # noqa: E402
import ate  # noqa: E402
import surface  # noqa: E402

ISSUE = 'task-affinity-shared'
LAUNCH = [{'actions': ['android.intent.action.MAIN'],
           'categories': ['android.intent.category.LAUNCHER'], 'data': [], 'priority': None}]


def _act(name, affinity=None, launcher=False):
    return {'name': name, 'type': 'activity', 'exported': launcher, 'exported_attr': None,
            'intent_filters': LAUNCH if launcher else [], 'permission': None,
            'task_affinity': affinity, 'launch_mode': None}


def _app(package, activities, app_affinity=None):
    return {'package': package, 'components': activities,
            'application': {'taskAffinity': app_affinity}}


BENIGN = _app('edu.ksu.cs.benign', [_act('edu.ksu.cs.benign.Main', launcher=True),
                                    _act('edu.ksu.cs.benign.Other')])


def _hits(first, second):
    return [f for f in surface.find(first, second=second) if f['issue'] == ISSUE]


def test_explicit_match_on_launcher():
    mal = _app('m', [_act('m.Mal', 'edu.ksu.cs.benign', launcher=True)])
    hits = _hits(BENIGN, mal)
    assert [(f['component'], f['cwe'], f['confidence']) for f in hits] == [
        ('edu.ksu.cs.benign.Main', 'CWE-1021', 'high')]
    assert 'default: the package name' in hits[0]['evidence']
    assert 'm.Mal (explicit android:taskAffinity)' in hits[0]['evidence']


def test_second_app_inherited_affinity():
    mal = _app('m', [_act('m.Mal', launcher=True)], app_affinity='edu.ksu.cs.benign')
    assert len(_hits(BENIGN, mal)) == 1


def test_first_app_application_affinity():
    first = _app('a', [_act('a.Main', launcher=True)], app_affinity='shared.task')
    mal = _app('m', [_act('m.Mal', 'shared.task')])
    hits = _hits(first, mal)
    assert len(hits) == 1 and 'inherited from <application' in hits[0]['evidence']


def test_explicit_empty_application_affinity_never_matches():
    # Ghera Secure apps: <application android:taskAffinity="">, same package as Benign.
    secure = _app('edu.ksu.cs.benign', [_act('edu.ksu.cs.benign.Main', launcher=True)],
                  app_affinity='')
    mal = _app('m', [_act('m.Mal', 'edu.ksu.cs.benign', launcher=True), _act('m.Empty', '')])
    assert _hits(secure, mal) == []


def test_explicit_empty_activity_affinity_never_matches():
    first = _app('a', [_act('a.Main', '', launcher=True)])
    assert _hits(first, _app('m', [_act('m.Mal', 'a'), _act('m.E', '')])) == []


def test_no_match():
    mal = _app('m', [_act('m.Mal', launcher=True)])   # default affinity "m"
    assert _hits(BENIGN, mal) == []


def test_same_package_skipped():
    assert _hits(BENIGN, BENIGN) == []


def test_non_launcher_explicit_affinity():
    first = _app('a', [_act('a.Main', launcher=True), _act('a.Editor', 'x.edit')])
    hits = _hits(first, _app('m', [_act('m.Mal', 'x.edit')]))
    assert [f['component'] for f in hits] == ['a.Editor']


def test_without_second_apk_silent():
    assert [f for f in surface.find(BENIGN) if f['issue'] == ISSUE] == []


def test_ate_parses_second_apk():
    assert ate.parse_args(['--apk', 'a.apk', '--second-apk', 'm.apk']).second_apk == 'm.apk'
    assert ate.parse_args(['--apk', 'a.apk']).second_apk is None


def test_evaluate_passes_second_apk(monkeypatch, tmp_path):
    import evaluate
    seen = {}

    class R:
        returncode = 1
        stdout = stderr = 'x'

    def run(cmd, **kw):
        seen['cmd'] = cmd
        return R()
    apk_file = tmp_path / 'a.apk'
    apk_file.write_text('')
    monkeypatch.setattr(evaluate.subprocess, 'run', run)
    evaluate.run_tool(str(apk_file), str(tmp_path / 'out'), second_apk='m.apk')
    assert seen['cmd'][-2:] == ['--second-apk', 'm.apk']
    evaluate.run_tool(str(apk_file), str(tmp_path / 'out'))
    assert '--second-apk' not in seen['cmd']


BENCHES = ['TaskAffinity-ActivityHijack-Lean', 'TaskAffinity-LauncherActivity-PhishingAttack-Lean',
           'TaskAffinity-PhishingAttack-Lean', 'TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean']


def _decode_or_skip(bench, variant):
    path = os.path.join(ROOT, 'benchmarks', 'ghera', 'ICC', bench, variant, 'app', 'build',
                        'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
    if not os.path.isfile(path):
        pytest.skip('%s %s api27 APK not built' % (bench, variant))
    try:
        apkmod.find_java()
    except apkmod.ApkError:
        pytest.skip('java not available for apktool')
    return apkmod.decode(path)


@pytest.mark.parametrize('bench', BENCHES)
def test_benchmarks(bench):
    mal = _decode_or_skip(bench, 'Malicious')
    hits = [f for f in surface._task_affinity_shared(_decode_or_skip(bench, 'Benign'), mal)]
    assert hits and all(f['cwe'] == 'CWE-1021' for f in hits)
    assert surface._task_affinity_shared(_decode_or_skip(bench, 'Secure'), mal) == []
