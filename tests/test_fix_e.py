"""Tests for tools/readme_runner.py (Fix E: replay README exploit steps).

Parsing and planning only; no device is touched (dry_run=True or adb missing).
Real Ghera READMEs are read, never modified, and skipped when absent.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import readme_runner as rr  # noqa: E402

GHERA = os.path.join(ROOT, 'benchmarks', 'ghera')

SYNTHETIC = """# Summary
Something.

## steps to Build the sample apps and exploit the vulnerability

1. Start emulator:

    `$ emulator -avd <avd_name>`

2. Build and install *Benign*:

    `$ cd Benign`

    `$ ./gradlew installApi[VERSION]Debug`

3.  Open *Benign* in the emulator. Click on "Take Picture" button.
    Then press back.

4. Launch *Malicious* and click on the button labelled *Steal*. It will start *Benign's* activity.

5. Check log:
    `$ adb -s emulator-5554 logcat -d | grep "Malicious"`

6. Clean up: `$ rm -rf /` and `$ adb shell ls ; reboot`

7. Verify the file: `$ adb install missing/app.apk`

8. You will see a message.

## References

1. Not a step.
"""


def _write_bench(tmp_path):
    bench = tmp_path / 'Cat' / 'Bench-Lean'
    for app, pkg in (('Benign', 'edu.ksu.cs.benign'), ('Malicious', 'edu.ksu.cs.malicious')):
        d = bench / app / 'app'
        (d / 'src' / 'main').mkdir(parents=True)
        (d / 'build.gradle').write_text('android { defaultConfig { applicationId "%s" } }' % pkg)
        (d / 'src' / 'main' / 'AndroidManifest.xml').write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="%s">'
            '<application><activity android:name=".MainActivity"><intent-filter>'
            '<action android:name="android.intent.action.MAIN"/>'
            '<category android:name="android.intent.category.LAUNCHER"/>'
            '</intent-filter></activity></application></manifest>' % pkg)
    apk = bench / 'Benign' / rr.APK_REL
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b'not really an apk')
    readme = bench / 'README.md'
    readme.write_text(SYNTHETIC)
    return readme


# ------------------------------------------------------------------ parsing

def test_parse_synthetic_steps():
    steps = rr.parse_steps(SYNTHETIC)
    assert [s['step'] for s in steps] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert 'Then press back.' in steps[2]['text']
    assert all('Not a step' not in s['text'] for s in steps)


@pytest.mark.parametrize('heading', [
    '# Steps to build the sample apps and to exploit the vulnerability',
    '### STEPS TO BUILD THE SAMPLE APPS AND EXPLOIT THE VULNERABILITY',
    '## Steps to build sample app and to exploit vulnerability:',
    '**Steps to build the sample apps and to exploit the vulnerability**',
])
def test_heading_variants(heading):
    text = 'intro\n\n%s\n\n1. Launch *Benign*\n2. Click *Go*\n\n# References\n1. x\n' % heading
    assert [s['step'] for s in rr.parse_steps(text)] == [1, 2]


def test_no_heading_gives_no_steps():
    assert rr.parse_steps('# Summary\n1. one\n2. two\n') == []


REAL = [
    ('ICC', 'HighPriority-ActivityHijack-Lean'),
    ('Storage', 'InternalStorage-DirectoryTraversal-Lean'),
    ('ICC', 'NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean'),
]


@pytest.mark.parametrize('cat,bench', REAL)
def test_parse_real_readme(cat, bench):
    path = os.path.join(GHERA, cat, bench, 'README.md')
    if not os.path.exists(path):
        pytest.skip('benchmark README absent')
    with open(path, encoding='utf-8') as f:
        steps = rr.parse_steps(f.read())
    assert len(steps) >= 7
    assert steps[0]['step'] == 1
    assert any('install' in s['text'].lower() for s in steps)


def test_real_highpriority_plan():
    path = os.path.join(GHERA, 'ICC', 'HighPriority-ActivityHijack-Lean', 'README.md')
    if not os.path.exists(path):
        pytest.skip('benchmark README absent')
    obs = rr.run_readme(path, dry_run=True)
    by_step = {o['step']: o for o in obs}
    assert by_step[1]['action'].startswith('skipped')
    types = [(a['type'], a['target']) for a in by_step[7]['actions']]
    assert types[0] == ('launch', 'Benign')
    assert ('tap', 'Take Picture') in types and ('tap', 'Done') in types
    assert by_step[9]['actions'][0]['target'] == 'Malicious'
    if os.path.exists(os.path.join(os.path.dirname(path), 'Benign', rr.APK_REL)):
        assert by_step[5]['actions'][0]['type'] == 'install'
        assert any('app-api27-debug.apk' in c for c in by_step[5]['commands'])


def test_real_run_as_plan():
    path = os.path.join(GHERA, 'Storage', 'InternalStorage-DirectoryTraversal-Lean', 'README.md')
    if not os.path.exists(path):
        pytest.skip('benchmark README absent')
    obs = {o['step']: o for o in rr.run_readme(path, dry_run=True)}
    assert obs[7]['actions'][0]['type'] == 'launch'
    assert obs[8]['actions'][0]['type'] == 'back'
    assert 'adb shell run-as edu.ksu.cs.benign ls -l cache' in obs[9]['commands']


# ------------------------------------------------------------------ planning

def test_dry_run_plan_synthetic(tmp_path):
    obs = rr.run_readme(str(_write_bench(tmp_path)), dry_run=True)
    by = {o['step']: o for o in obs}
    assert len(obs) == 8

    assert by[1]['action'].startswith('skipped')
    assert not by[1]['automatable']

    a2 = by[2]['actions']
    assert [a['type'] for a in a2] == ['install']
    assert a2[0]['target'] == 'Benign'
    assert by[2]['commands'][0].startswith('adb install -r -t ')

    t3 = [(a['type'], a['target']) for a in by[3]['actions']]
    assert t3 == [('launch', 'Benign'), ('tap', 'Take Picture'), ('back', 'BACK')]
    assert 'adb shell am start -W -n edu.ksu.cs.benign/edu.ksu.cs.benign.MainActivity' \
        in by[3]['commands']
    assert 'adb shell input keyevent 4' in by[3]['commands']

    # "It will start *Benign's*" is descriptive: only Malicious is launched
    t4 = [(a['type'], a['target']) for a in by[4]['actions']]
    assert t4 == [('launch', 'Malicious'), ('tap', 'Steal')]

    # -s device flag stripped, grep applied in Python, logcat made non-blocking
    a5 = [a for a in by[5]['actions'] if a['type'] == 'adb'][0]
    assert a5['grep'] == 'Malicious'
    assert by[5]['commands'] == ['adb logcat -d']

    # non-adb and shell metacharacters are refused
    assert by[6]['action'].startswith('skipped')
    assert all(a['status'].startswith('skipped') for a in by[6]['actions'])
    assert by[6]['commands'] == []

    # adb install of a missing path with no built APK in context
    assert by[7]['actions'][0]['status'].startswith('skipped')

    assert by[8]['action'] == 'skipped: no automatable action'
    for o in obs:
        assert o['returncodes'] == [] and o['logcat'] == [] and o['foreground_activity'] is None


def test_no_device_marks_skipped(tmp_path):
    readme = _write_bench(tmp_path)
    obs = rr.run_readme(str(readme), adb=str(tmp_path / 'no-such-adb.exe'))
    auto = [o for o in obs if o['automatable']]
    assert auto
    for o in auto:
        assert o['action'] == 'skipped: adb not found'
        assert all(a['status'].startswith('skipped') for a in o['actions'])


def test_missing_readme_returns_empty(tmp_path):
    assert rr.run_readme(str(tmp_path / 'README.md'), dry_run=True) == []


def test_plan_adb_rejects_non_adb():
    ctx = {'cwd': None}
    assert rr._plan_adb('rm -rf /', ctx, '.', {})['status'].startswith('skipped')
    assert rr._plan_adb('adb shell ls > out', ctx, '.', {})['status'].startswith('skipped')
    assert rr._plan_adb('adb shell ls | sh', ctx, '.', {})['status'].startswith('skipped')
    ok = rr._plan_adb('adb -s emulator-5554 shell pm list packages', ctx, '.', {})
    assert ok['argv'] == [['shell', 'pm', 'list', 'packages']]


# ------------------------------------------------------------------ uiautomator

UI_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" class="android.widget.FrameLayout" package="edu.ksu.cs.benign"
        content-desc="" clickable="false" bounds="[0,0][1080,1794]">
    <node index="0" text="Take a picture of the cheque" class="android.widget.TextView"
          package="edu.ksu.cs.benign" content-desc="" clickable="false" bounds="[40,200][1040,260]"/>
    <node index="1" text="TAKE PICTURE" class="android.widget.Button" package="edu.ksu.cs.benign"
          content-desc="" clickable="true" bounds="[100,300][500,420]"/>
    <node index="2" text="" class="android.widget.ImageButton" package="edu.ksu.cs.benign"
          content-desc="Done" clickable="true" bounds="[900,1600][1060,1760]"/>
    <node index="3" text="image" class="android.widget.TextView" package="edu.ksu.cs.benign"
          content-desc="" clickable="true" bounds="[10,500][211,601]"/>
  </node>
</hierarchy>"""


def test_bounds_center():
    assert rr.parse_bounds('[100,300][500,420]') == (100, 300, 500, 420)
    assert rr.bounds_center('[100,300][500,420]') == (300, 360)
    assert rr.bounds_center('[10,500][211,601]') == (110, 550)
    assert rr.bounds_center('') is None
    assert rr.bounds_center('garbage') is None


def test_find_node_by_text_case_insensitive():
    n = rr.find_node(UI_XML, 'Take Picture')
    assert n['class'] == 'android.widget.Button'
    assert rr.bounds_center(n['bounds']) == (300, 360)


def test_find_node_by_content_desc():
    n = rr.find_node(UI_XML, 'Done')
    assert rr.bounds_center(n['bounds']) == (980, 1680)


def test_find_node_generic_button_and_missing():
    assert rr.find_node(UI_XML, '')['text'] == 'TAKE PICTURE'
    assert rr.find_node(UI_XML, 'image')['text'] == 'image'
    assert rr.find_node(UI_XML, 'Nonexistent') is None
    assert rr.find_node('not xml', 'x') is None


# ------------------------------------------------------------------ capture parsing

def test_foreground_and_signals():
    dump = ('  mResumedActivity: ActivityRecord{1a2b u0 edu.ksu.cs.malicious/.MalActivity t12}\n')
    assert rr.foreground_activity(dump) == 'edu.ksu.cs.malicious/.MalActivity'
    assert rr.foreground_activity('') is None
    log = ('11-01 10:00:00.000  123  123 E AndroidRuntime: FATAL EXCEPTION: main\n'
           '11-01 10:00:00.001  123  123 E AndroidRuntime: Process: edu.ksu.cs.benign, PID: 123\n'
           '11-01 10:00:00.002  500  510 W ActivityManager: Permission Denial: starting Intent '
           '{ cmp=edu.ksu.cs.benign/.Secret } from ProcessRecord\n'
           '11-01 10:00:00.003  600  600 D Chatty: unrelated\n'
           '11-01 10:00:00.004  700  700 I Malicious: leaked password\n')
    log += '11-01 10:00:00.005  800  800 E AudioFlinger: unrelated system error\n'
    pids = rr.app_pids(log, ['edu.ksu.cs.benign'])
    assert pids == {123}
    # without the pid the FATAL EXCEPTION header (no package name) is dropped
    assert len(rr.relevant_logcat(log, ['Malicious', 'edu.ksu.cs.benign'])) == 3
    lines = rr.relevant_logcat(log, ['Malicious', 'edu.ksu.cs.benign'], pids)
    assert len(lines) == 4 and all('unrelated' not in l for l in lines)
    sig = rr.classify_logcat(lines)
    assert len(sig['crashes']) == 2
    assert len(sig['permission_denials']) == 1


def test_coverage_summary(tmp_path):
    readme = str(_write_bench(tmp_path))
    cov = rr.coverage({readme: rr.run_readme(readme, dry_run=True)})
    assert cov['readmes'] == 1 and cov['with_steps'] == 1 and cov['steps'] == 8
    assert 0 < cov['automatable_fraction'] < 1
    assert cov['emulator_setup_steps'] == 1


# ---------------------------------------------------------------- evaluate.py --auto-readme

def test_evaluate_readme_findings():
    import evaluate
    apps = {'Benign': {'package': 'edu.ksu.cs.benign'}, 'Malicious': {'package': 'edu.ksu.cs.malicious'}}
    obs = [
        {'step': 5, 'text': 'Launch Benign', 'foreground_activity': 'edu.ksu.cs.malicious/.MalActivity',
         'actions': [{'type': 'launch', 'target': 'Benign', 'status': 'ok'}], 'signals': {}},
        {'step': 6, 'text': 'Click DOS in Malicious', 'foreground_activity': 'edu.ksu.cs.benign/.MainActivity',
         'actions': [{'type': 'tap', 'target': 'Malicious', 'status': 'ok'}],
         'signals': {'crashes': ['E AndroidRuntime: Process: edu.ksu.cs.benign, PID: 1']}},
    ]
    issues = {f['issue']: f['cwe'] for f in evaluate.readme_findings(obs, apps)}
    assert issues == {'readme-foreground-hijack': 'CWE-1021',
                      'readme-benign-crash': 'CWE-248',
                      'readme-foreground-crossover': 'CWE-926'}


def test_evaluate_readme_findings_blocked_exploit_is_not_a_finding():
    import evaluate
    apps = {'Benign': {'package': 'edu.ksu.cs.benign'}, 'Malicious': {'package': 'edu.ksu.cs.malicious'}}
    obs = [{'step': 3, 'text': 'x', 'foreground_activity': 'edu.ksu.cs.malicious/.Main',
            'actions': [{'type': 'tap', 'target': 'Malicious', 'status': 'ok'}],
            'signals': {'permission_denials': ['Permission Denial: edu.ksu.cs.benign']}}]
    assert evaluate.readme_findings(obs, apps) == []
