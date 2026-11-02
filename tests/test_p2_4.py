"""P2-4: sticky_broadcast_receiver (CWE-927), a receiver in the app that
consumes a sticky broadcast the app sends without checking it. The existing
sticky_broadcast pattern is unchanged.

Synthetic smali in a tmp dir, plus ICC/StickyBroadcast-DataInjection-Lean
(skipped if not built), whose Benign app sends a sticky broadcast but has no
receiver of its own: sticky_broadcast fires there, the new pattern does not."""
import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import code_analyzer  # noqa: E402

PATTERN = 'sticky_broadcast_receiver'
ACTION = 'a.b.STICKY'
BENCH = ('ICC', 'StickyBroadcast-DataInjection-Lean')
APK_REL = ('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application>
{receivers}
    </application>
</manifest>
"""

RECEIVER_XML = """        <receiver android:exported="true" android:name="a.b.Recv"{perm}>
            <intent-filter>
                <action android:name="{action}"/>
            </intent-filter>
        </receiver>"""

SENDER = """.class public La/b/Main;
.super Landroid/app/Activity;

.method public onResume()V
    .locals 3
{send}
{register}
    return-void
.end method
"""

SEND_SET_ACTION = """    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V
    const-string v1, "%s"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;
    invoke-virtual {p0, v0}, La/b/Main;->sendStickyBroadcast(Landroid/content/Intent;)V"""

SEND_CTOR = """    new-instance v0, Landroid/content/Intent;
    const-string v1, "%s"
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    invoke-virtual {p0, v0}, La/b/Main;->sendStickyBroadcast(Landroid/content/Intent;)V"""

REGISTER = """    new-instance v0, La/b/Recv;
    invoke-direct {v0}, La/b/Recv;-><init>()V
    new-instance v1, Landroid/content/IntentFilter;
    const-string v2, "%s"
    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V
    invoke-virtual {p0, v0, v1}, La/b/Main;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;"""

REGISTER_PERM = """    new-instance v0, La/b/Recv;
    invoke-direct {v0}, La/b/Recv;-><init>()V
    new-instance v1, Landroid/content/IntentFilter;
    invoke-direct {v1}, Landroid/content/IntentFilter;-><init>()V
    const-string v2, "%s"
    invoke-virtual {v1, v2}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V
    const-string v2, "a.b.PERM"
    const/4 v3, 0x0
    invoke-virtual {p0, v0, v1, v2, v3}, La/b/Main;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;"""

RECV = """.class public La/b/Recv;
.super Landroid/content/BroadcastReceiver;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 2
%s
    return-void
.end method
"""

USE_EXTRA = """    const-string v0, "phone"
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, La/b/Recv;->dial(Ljava/lang/String;)V"""

NULL_CHECK = """    const-string v0, "phone"
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    if-eqz v0, :cond_0
    invoke-static {v0}, La/b/Recv;->dial(Ljava/lang/String;)V
    :cond_0"""

INITIAL_CHECK = """    invoke-virtual {p0}, La/b/Recv;->isInitialStickyBroadcast()Z
    move-result v1
""" + USE_EXTRA

ACTION_CHECK = """    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v1
    const-string v0, "a.b.STICKY"
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
""" + USE_EXTRA


def _build(tmp_path, send=SEND_SET_ACTION % ACTION, register='', onreceive=USE_EXTRA,
           manifest_action=None, manifest_perm=''):
    files = {'a/b/Main': SENDER.format(send=send, register=register),
             'a/b/Recv': RECV % onreceive}
    for name, text in files.items():
        path = tmp_path / 'smali' / (name + '.smali')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    receivers = '' if manifest_action is None else RECEIVER_XML.format(
        action=manifest_action, perm=manifest_perm)
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST.format(receivers=receivers),
                                                  encoding='utf-8')
    return code_analyzer.analyze(str(tmp_path))


def _hits(found):
    return [f for f in found if f['pattern'] == PATTERN]


def test_dynamic_receiver_flagged(tmp_path):
    found = _build(tmp_path, register=REGISTER % ACTION)
    hits = _hits(found)
    assert len(hits) == 1
    f = hits[0]
    assert f['component'] == 'a.b.Recv'
    assert f['component_type'] == 'class'
    assert f['cwe'] == 'CWE-927'
    assert f['confidence'] == 'medium'
    assert f['evidence'].startswith('.method public onReceive')
    # The original pattern still fires on the send.
    assert [x['pattern'] for x in found if x['pattern'] == 'sticky_broadcast'] == ['sticky_broadcast']


def test_manifest_receiver_flagged_with_ctor_action(tmp_path):
    assert len(_hits(_build(tmp_path, send=SEND_CTOR % ACTION, manifest_action=ACTION))) == 1


def test_manifest_receiver_with_permission_skipped(tmp_path):
    found = _build(tmp_path, manifest_action=ACTION,
                   manifest_perm=' android:permission="a.b.PERM"')
    assert _hits(found) == []


def test_other_action_not_flagged(tmp_path):
    assert _hits(_build(tmp_path, register=REGISTER % 'a.b.OTHER')) == []
    d = tmp_path / 'm'
    d.mkdir()
    assert _hits(_build(d, manifest_action='a.b.OTHER')) == []


def test_registered_with_permission_not_flagged(tmp_path):
    assert _hits(_build(tmp_path, register=REGISTER_PERM % ACTION)) == []


@pytest.mark.parametrize('body', [NULL_CHECK, INITIAL_CHECK, ACTION_CHECK])
def test_checked_receiver_not_flagged(tmp_path, body):
    assert _hits(_build(tmp_path, register=REGISTER % ACTION, onreceive=body)) == []


def test_no_sticky_send_not_flagged(tmp_path):
    send = (SEND_SET_ACTION % ACTION).replace('sendStickyBroadcast', 'sendBroadcast')
    assert _hits(_build(tmp_path, send=send, register=REGISTER % ACTION)) == []


@pytest.fixture(scope='module')
def decoded_bench():
    root = tempfile.mkdtemp(prefix='ate-p24-')
    cache = {}

    def get(variant):
        path = os.path.join(ROOT, 'benchmarks', 'ghera', *BENCH, variant, *APK_REL)
        if not os.path.exists(path):
            pytest.skip('fixture APK not built: %s' % os.path.relpath(path, ROOT))
        if variant not in cache:
            work = os.path.join(root, variant)
            os.makedirs(work)
            cache[variant] = apk.decode(path, work)['decoded_dir']
        return cache[variant]
    yield get
    shutil.rmtree(root, ignore_errors=True)


def test_benchmark_sticky_patterns(decoded_bench):
    benign = code_analyzer.analyze(decoded_bench('Benign'))
    assert any(f['pattern'] == 'sticky_broadcast' for f in benign)
    assert _hits(benign) == []   # no receiver for the action inside the app
    secure = code_analyzer.analyze(decoded_bench('Secure'))
    assert not any(f['pattern'] in ('sticky_broadcast', PATTERN) for f in secure)
