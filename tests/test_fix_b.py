"""Fix B: ordered_broadcast_priority (CWE-927) also fires for any
BroadcastReceiver subclass whose onReceive changes or aborts the broadcast
result, whatever the manifest priority. Uses synthetic smali in a tmp dir."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import code_analyzer  # noqa: E402

PATTERN = 'ordered_broadcast_priority'

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application>
{receivers}
    </application>
</manifest>
"""

RECEIVER_XML = """        <receiver android:exported="true" android:name="{name}">
            <intent-filter{prio}>
                <action android:name="a.b.ACTION"/>
            </intent-filter>
        </receiver>"""


def _smali(name, sup, body):
    return """.class public L{name};
.super {sup}

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, {sup}-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 2
    const-string v1, "x"
{body}
    return-void
.end method
""".format(name=name, sup=sup, body=body)


def _call(owner, method='setResultData', op='invoke-virtual'):
    sig = {'setResultData': '(Ljava/lang/String;)V', 'abortBroadcast': '()V',
           'setResult': '(ILjava/lang/String;Landroid/os/Bundle;)V',
           'setResultExtras': '(Landroid/os/Bundle;)V'}[method]
    regs = '{p0, v1}' if method == 'setResultData' else '{p0}'
    return '    %s %s, %s->%s%s' % (op, regs, owner, method, sig)


def _build(tmp_path, classes, receivers=()):
    """classes: {slash name: (super descriptor, onReceive body)};
    receivers: [(dotted name, priority or None)]."""
    for name, (sup, body) in classes.items():
        path = tmp_path / 'smali' / (name + '.smali')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_smali(name, sup, body), encoding='utf-8')
    xml = '\n'.join(RECEIVER_XML.format(
        name=n, prio='' if p is None else ' android:priority="%d"' % p) for n, p in receivers)
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST.format(receivers=xml), encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == PATTERN]


RECV = 'Landroid/content/BroadcastReceiver;'


def test_fires_without_priority(tmp_path):
    found = _build(tmp_path, {'a/b/R': (RECV, _call('La/b/R;'))}, [('a.b.R', None)])
    assert len(found) == 1
    f = found[0]
    assert f['component'] == 'a.b.R'
    assert f['component_type'] == 'class'
    assert f['file'] == 'smali/a/b/R.smali'
    assert f['confidence'] == 'medium'
    assert f['cwe'] == 'CWE-927'
    assert f['issue'] == PATTERN
    assert 'setResultData' in f['evidence']
    lines = (tmp_path / 'smali' / 'a' / 'b' / 'R.smali').read_text().splitlines()
    assert lines[f['line'] - 1].strip() == f['evidence']


def test_fires_when_not_in_manifest_and_on_broadcastreceiver_owner(tmp_path):
    for i, method in enumerate(code_analyzer.RESULT_CALLS):
        d = tmp_path / str(i)
        d.mkdir()
        found = _build(d, {'a/b/R': (RECV, _call(RECV, method))})
        assert [f['evidence'].split('->')[1].split('(')[0] for f in found] == [method]


def test_fires_through_app_superclass(tmp_path):
    classes = {
        'a/b/Base': (RECV, ''),
        'a/b/Child': ('La/b/Base;', _call('La/b/Base;', 'abortBroadcast')),
    }
    found = _build(tmp_path, classes)
    assert [f['component'] for f in found] == ['a.b.Child']


def test_priority_zero_still_fires(tmp_path):
    found = _build(tmp_path, {'a/b/R': (RECV, _call('La/b/R;'))}, [('a.b.R', 0)])
    assert len(found) == 1


def test_no_duplicate_when_priority_also_matches(tmp_path):
    found = _build(tmp_path, {'a/b/R': (RECV, _call('La/b/R;'))}, [('a.b.R', 100)])
    assert len(found) == 1
    assert found[0]['confidence'] == 'medium'


def test_no_duplicate_when_priority_rule_hits_other_line(tmp_path):
    # The priority rule takes any setResult* call; the new rule needs one on the
    # receiver. Only one finding per receiver, the priority match.
    body = _call('La/b/Other;', 'setResultData') + '\n' + _call('La/b/R;', 'abortBroadcast')
    found = _build(tmp_path, {'a/b/R': (RECV, body)}, [('a.b.R', 5)])
    assert len(found) == 1
    assert 'La/b/Other;' in found[0]['evidence']


def test_priority_rule_unchanged_for_other_owner(tmp_path):
    body = _call('La/b/Other;', 'setResultData')
    assert len(_build(tmp_path, {'a/b/R': (RECV, body)}, [('a.b.R', 5)])) == 1


def test_not_fired_for_other_owner_without_priority(tmp_path):
    body = _call('La/b/Other;', 'setResultData')
    assert _build(tmp_path, {'a/b/R': (RECV, body)}, [('a.b.R', None)]) == []


def test_not_fired_for_non_receiver(tmp_path):
    found = _build(tmp_path, {'a/b/R': ('Ljava/lang/Object;', _call('La/b/R;'))})
    assert found == []


def test_not_fired_without_result_call(tmp_path):
    body = '    invoke-virtual {p0}, La/b/R;->getResultData()Ljava/lang/String;'
    assert _build(tmp_path, {'a/b/R': (RECV, body)}) == []


def test_not_fired_for_invoke_super(tmp_path):
    body = _call(RECV, 'abortBroadcast', op='invoke-super')
    assert _build(tmp_path, {'a/b/R': (RECV, body)}) == []
