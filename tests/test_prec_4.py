"""P-4: pending_intent_mutable only when targetSdkVersion is 31 or more (or
unknown). Shaped after EmptyPendingIntent-PrivEscalation-Lean and
ImplicitPendingIntent-IntentHijack-Lean, whose apps target API 27 and pass
FLAG_UPDATE_CURRENT (0x8000000) without FLAG_IMMUTABLE."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import code_analyzer  # noqa: E402

SMALI = """.class public La/b/Main;
.super Landroid/app/Activity;

.method public go()V
    .locals 5
    new-instance v2, Landroid/content/Intent;
    const-class v0, La/b/Svc;
    invoke-direct {v2, p0, v0}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    const/4 v1, 0x0
    const/high16 v3, 0x8000000
    invoke-static {p0, v1, v2, v3}, Landroid/app/PendingIntent;->getService(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
"""


def _mutable(tmp_path, yml_target=None, manifest_target=None):
    (tmp_path / 'smali' / 'a' / 'b').mkdir(parents=True)
    (tmp_path / 'smali' / 'a' / 'b' / 'Main.smali').write_text(SMALI, encoding='utf-8')
    uses = ('<uses-sdk android:minSdkVersion="19" android:targetSdkVersion="%d"/>' % manifest_target
            if manifest_target is not None else '')
    (tmp_path / 'AndroidManifest.xml').write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android='
        '"http://schemas.android.com/apk/res/android" package="a.b">%s<application/></manifest>'
        % uses, encoding='utf-8')
    if yml_target is not None:
        (tmp_path / 'apktool.yml').write_text(
            "sdkInfo:\n  minSdkVersion: '19'\n  targetSdkVersion: '%d'\n" % yml_target,
            encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == 'pending_intent_mutable']


@pytest.mark.parametrize('target', [23, 27, 30])
def test_below_31_not_flagged(tmp_path, target):
    assert _mutable(tmp_path, yml_target=target) == []


@pytest.mark.parametrize('target', [31, 34])
def test_31_and_up_flagged(tmp_path, target):
    hits = _mutable(tmp_path, yml_target=target)
    assert [f['confidence'] for f in hits] == ['high']
    assert 'targetSdkVersion %d' % target in hits[0]['evidence']


def test_unknown_target_flagged(tmp_path):
    assert len(_mutable(tmp_path)) == 1


def test_target_from_decoded_manifest(tmp_path):
    assert _mutable(tmp_path, manifest_target=27) == []


def test_manifest_fallback_31(tmp_path):
    assert len(_mutable(tmp_path, manifest_target=33)) == 1
