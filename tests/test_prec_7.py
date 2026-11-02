"""P-7: broadcasts sent with a receiver permission are not implicit_broadcast
findings, and the manifest implicit-intent rule skips permission-protected
components. (The ordered broadcast part of P-7 is tested in test_fix_b.py.)"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk as apkmod  # noqa: E402
import code_analyzer  # noqa: E402
import surface  # noqa: E402

MANIFEST = ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
            '<application/></manifest>')
HEAD = """.class public La/b/Main;
.super Landroid/app/Activity;

.field private static PERM:Ljava/lang/String;

.method public send()V
    .locals 4
    new-instance v0, Landroid/content/Intent;
    const-string v1, "a.b.ACTION"
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
"""
TAIL = """    return-void
.end method
"""

CALLS = {
    'none': '    invoke-virtual {p0, v0}, La/b/Main;->sendBroadcast(Landroid/content/Intent;)V\n',
    'null': ('    const/4 v2, 0x0\n'
             '    invoke-virtual {p0, v0, v2}, La/b/Main;->sendBroadcast(Landroid/content/Intent;'
             'Ljava/lang/String;)V\n'),
    'const': ('    const-string v2, "a.b.RECEIVE"\n'
              '    invoke-virtual {p0, v0, v2}, La/b/Main;->sendBroadcast(Landroid/content/Intent;'
              'Ljava/lang/String;)V\n'),
    'field': ('    sget-object v2, La/b/Main;->PERM:Ljava/lang/String;\n'
              '    invoke-virtual {p0, v0, v2}, La/b/Main;->sendBroadcast(Landroid/content/Intent;'
              'Ljava/lang/String;)V\n'),
    'ordered': ('    const-string v2, "a.b.RECEIVE"\n'
                '    invoke-virtual {p0, v0, v2}, La/b/Main;->sendOrderedBroadcast('
                'Landroid/content/Intent;Ljava/lang/String;)V\n'),
    'as_user': ('    invoke-static {}, Landroid/os/Process;->myUserHandle()Landroid/os/UserHandle;\n'
                '    move-result-object v3\n'
                '    const-string v2, "a.b.RECEIVE"\n'
                '    invoke-virtual {p0, v0, v3, v2}, La/b/Main;->sendBroadcastAsUser('
                'Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;)V\n'),
    'as_user_null': ('    invoke-static {}, Landroid/os/Process;->myUserHandle()Landroid/os/UserHandle;\n'
                     '    move-result-object v3\n'
                     '    const/4 v2, 0x0\n'
                     '    invoke-virtual {p0, v0, v3, v2}, La/b/Main;->sendBroadcastAsUser('
                     'Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;)V\n'),
}


def _implicit(tmp_path, call):
    (tmp_path / 'smali' / 'a' / 'b').mkdir(parents=True)
    (tmp_path / 'smali' / 'a' / 'b' / 'Main.smali').write_text(HEAD + CALLS[call] + TAIL,
                                                               encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == 'implicit_broadcast']


@pytest.mark.parametrize('call', ['none', 'null', 'as_user_null'])
def test_no_permission_flagged(tmp_path, call):
    assert len(_implicit(tmp_path, call)) == 1


@pytest.mark.parametrize('call', ['const', 'field', 'ordered', 'as_user'])
def test_permission_given_not_flagged(tmp_path, call):
    assert _implicit(tmp_path, call) == []


def _manifest(tmp_path, attrs):
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
           '<permission android:name="x.SIG" android:protectionLevel="signature"/><application>'
           '<receiver android:name=".R" %s><intent-filter>'
           '<action android:name="a.b.ACTION"/></intent-filter></receiver>'
           '</application></manifest>') % attrs
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(xml, encoding='utf-8')
    return [f for f in surface.find(apkmod.parse_manifest(str(path)))
            if f['issue'] == 'implicit-intent']


def test_manifest_implicit_intent_without_permission(tmp_path):
    assert [f['confidence'] for f in _manifest(tmp_path, '')] == ['medium']


def test_manifest_implicit_intent_with_permission_skipped(tmp_path):
    assert _manifest(tmp_path, 'android:permission="x.SIG"') == []
