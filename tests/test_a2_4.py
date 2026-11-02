"""A2-4: dynamic_receiver_no_permission (CWE-926, high). Context.registerReceiver
with no broadcastPermission (absent or null), skipped for LocalBroadcastManager
and for RECEIVER_NOT_EXPORTED. Synthetic smali in a tmp dir, plus
ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean (skipped if not built):
Benign registers with the 2-arg overload, Secure with a permission."""
import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import code_analyzer  # noqa: E402

PATTERN = 'dynamic_receiver_no_permission'
BENCH = ('ICC', 'DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean')
APK_REL = ('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
BR_IF = 'Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;'

MAIN = """.class public La/b/Main;
.super Landroid/app/Activity;

.method public onResume(I)V
    .locals 5
    new-instance v0, La/b/Recv;
    invoke-direct {v0}, La/b/Recv;-><init>()V
    new-instance v1, Landroid/content/IntentFilter;
    const-string v2, "a.b.ACTION"
    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V
%s
    return-void
.end method
"""

TWO_ARG = ('    invoke-virtual {p0, v0, v1}, La/b/Main;->registerReceiver(%s)Landroid/content/Intent;'
           % BR_IF)
FLAGS = ('    const/4 v2, %s\n'
         '    invoke-virtual {p0, v0, v1, v2}, La/b/Main;->registerReceiver(%sI)Landroid/content/Intent;')
FLAGS_PARAM = ('    invoke-virtual {p0, v0, v1, p1}, La/b/Main;->registerReceiver(%sI)'
               'Landroid/content/Intent;' % BR_IF)
PERM = ('%s\n    const/4 v3, 0x0\n'
        '    invoke-virtual {p0, v0, v1, v2, v3}, La/b/Main;->registerReceiver('
        + BR_IF + 'Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;')
PERM_FLAGS = ('    move-object v5, p0\n    move-object v6, v0\n    move-object v7, v1\n'
              '    const/4 v8, 0x0\n    const/4 v9, 0x0\n    const/4 v10, %s\n'
              '    invoke-virtual/range {v5 .. v10}, La/b/Main;->registerReceiver('
              + BR_IF + 'Ljava/lang/String;Landroid/os/Handler;I)Landroid/content/Intent;')
LOCAL = ('    invoke-static {p0}, Landroidx/localbroadcastmanager/content/LocalBroadcastManager;'
         '->getInstance(Landroid/content/Context;)Landroidx/localbroadcastmanager/content/'
         'LocalBroadcastManager;\n    move-result-object v3\n'
         '    invoke-virtual {v3, v0, v1}, Landroidx/localbroadcastmanager/content/'
         'LocalBroadcastManager;->registerReceiver(%sV' % (BR_IF + ')'))

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application/>
</manifest>
"""


def _hits(tmp_path, call):
    path = tmp_path / 'smali' / 'a' / 'b' / 'Main.smali'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MAIN % call, encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == PATTERN]


def test_two_arg_overload_fires(tmp_path):
    hits = _hits(tmp_path, TWO_ARG)
    assert len(hits) == 1
    f = hits[0]
    assert f['cwe'] == 'CWE-926'
    assert f['confidence'] == 'high'
    assert f['component'] == 'a.b.Main'
    assert f['component_type'] == 'class'
    assert 'registerReceiver' in f['evidence']
    assert 'no broadcastPermission argument' in f['evidence']


def test_null_permission_fires(tmp_path):
    hits = _hits(tmp_path, PERM % '    const/4 v2, 0x0')
    assert len(hits) == 1
    assert 'null broadcastPermission' in hits[0]['evidence']


def test_permission_given_skips(tmp_path):
    assert _hits(tmp_path, PERM % '    const-string v2, "a.b.PERM"') == []


def test_flags_overload(tmp_path):
    exported = tmp_path / 'e'
    exported.mkdir()
    assert len(_hits(exported, FLAGS % ('0x2', BR_IF))) == 1      # RECEIVER_EXPORTED
    assert _hits(tmp_path, FLAGS % ('0x4', BR_IF)) == []          # RECEIVER_NOT_EXPORTED


def test_unknown_flags_medium(tmp_path):
    hits = _hits(tmp_path, FLAGS_PARAM)
    assert [f['confidence'] for f in hits] == ['medium']


def test_permission_and_flags_overload(tmp_path):
    other = tmp_path / 'o'
    other.mkdir()
    assert len(_hits(other, PERM_FLAGS % '0x0')) == 1
    assert _hits(tmp_path, PERM_FLAGS % '0x4') == []


def test_local_broadcast_manager_skipped(tmp_path):
    assert _hits(tmp_path, LOCAL) == []


@pytest.fixture(scope='module')
def decoded_bench():
    root = tempfile.mkdtemp(prefix='ate-a24-')
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


def test_benchmark(decoded_bench):
    benign = [f for f in code_analyzer.analyze(decoded_bench('Benign')) if f['pattern'] == PATTERN]
    assert [f['component'] for f in benign] == ['edu.ksu.cs.benign.MainActivity']
    assert benign[0]['confidence'] == 'high'
    secure = [f for f in code_analyzer.analyze(decoded_bench('Secure')) if f['pattern'] == PATTERN]
    assert secure == []
