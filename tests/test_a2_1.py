"""A2-1: pending_intent_mutable (CWE-927, high). A PendingIntent factory call
whose flags argument is a known constant with neither FLAG_IMMUTABLE nor
FLAG_MUTABLE (required for apps targeting API 31+). Flags the register model
cannot resolve are not reported. Synthetic smali in a tmp dir."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import code_analyzer  # noqa: E402

PATTERN = 'pending_intent_mutable'

MAIN = """.class public La/b/Main;
.super Landroid/app/Activity;

.method public make(I)V
    .locals 5
    new-instance v0, Landroid/content/Intent;
    const-class v1, La/b/Main;
    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    const/4 v2, 0x0
%s
    invoke-static {p0, v2, v0, v3}, Landroid/app/PendingIntent;->%s(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
"""

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application/>
</manifest>
"""


def _run(tmp_path, flags_line, factory='getActivity', target=None):
    path = tmp_path / 'smali' / 'a' / 'b' / 'Main.smali'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MAIN % (flags_line, factory), encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    if target is not None:
        (tmp_path / 'apktool.yml').write_text(
            "sdkInfo:\n  minSdkVersion: '19'\n  targetSdkVersion: '%d'\n" % target,
            encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == PATTERN]


@pytest.mark.parametrize('factory', ['getActivity', 'getBroadcast', 'getService',
                                     'getForegroundService'])
def test_no_mutability_flag_fires(tmp_path, factory):
    hits = _run(tmp_path, '    const/high16 v3, 0x8000000', factory, target=31)
    assert len(hits) == 1
    f = hits[0]
    assert f['cwe'] == 'CWE-927'
    assert f['confidence'] == 'high'
    assert f['component'] == 'a.b.Main'
    assert 'PendingIntent;->%s' % factory in f['evidence']
    assert 'flags 0x8000000' in f['evidence']
    assert 'API 31' in f['evidence'] and 'targetSdkVersion 31' in f['evidence']


def test_zero_flags_fire(tmp_path):
    assert len(_run(tmp_path, '    const/4 v3, 0x0')) == 1


@pytest.mark.parametrize('value', ['0x4000000', '0xc000000', '0x2000000', '0xa000000'])
def test_immutable_or_mutable_flag_skips(tmp_path, value):
    assert _run(tmp_path, '    const/high16 v3, %s' % value) == []


def test_unknown_flags_skipped(tmp_path):
    # Flags from the method parameter: not a constant, not reported.
    assert _run(tmp_path, '    move v3, p1') == []


def test_get_activities(tmp_path):
    path = tmp_path / 'smali' / 'a' / 'b' / 'Main.smali'
    path.parent.mkdir(parents=True)
    path.write_text(""".class public La/b/Main;
.super Landroid/app/Activity;

.method public make([Landroid/content/Intent;)V
    .locals 3
    const/4 v0, 0x0
    const/high16 v1, 0x8000000
    invoke-static {p0, v0, p1, v1}, Landroid/app/PendingIntent;->getActivities(Landroid/content/Context;I[Landroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
""", encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    found = code_analyzer.analyze(str(tmp_path))
    assert [f['pattern'] for f in found] == [PATTERN]
