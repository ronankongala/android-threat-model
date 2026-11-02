"""Tests for P2-2: inter-component taint analysis, using synthetic smali and a
synthetic AndroidManifest.xml in tmp_path.

Sender reads user input, puts it into an Intent and starts another component;
the receiving component reads the extra with a getter that is not a plain
source (getCharSequenceExtra, Bundle.get) and reaches a SQL sink.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import taint_analyzer  # noqa: E402

PKG = 'com/example/app'

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
  <application>
    <activity android:name=".Sender" android:exported="true"/>
    <activity android:name=".Receiver" android:exported="false"/>
    <activity android:name=".Other" android:exported="false"/>
    <service android:name=".Svc" android:exported="false">
      <intent-filter><action android:name="com.example.app.DO"/></intent-filter>
    </service>
  </application>
</manifest>
"""

INIT = """
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
"""

# Reads EditText input into v0 (needs .locals >= 3).
READ_INPUT = """
    const v0, 0x7f010001
    invoke-virtual {p0, v0}, Lcom/example/app/Sender;->findViewById(I)Landroid/view/View;
    move-result-object v0
    check-cast v0, Landroid/widget/EditText;
    invoke-virtual {v0}, Landroid/widget/EditText;->getText()Landroid/text/Editable;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v0
"""

EXPLICIT_SEND = """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
%s
    new-instance v1, Landroid/content/Intent;
    const-class v2, Lcom/example/app/Receiver;
    invoke-direct {v1, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    const-string v2, "q"
    invoke-virtual {v1, v2, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    invoke-virtual {p0, v1}, Lcom/example/app/Sender;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
""" % READ_INPUT

CONSTANT_SEND = EXPLICIT_SEND.replace(READ_INPUT, '\n    const-string v0, "fixed"\n')

IMPLICIT_SEND = """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
%s
    new-instance v3, Landroid/os/Bundle;
    invoke-direct {v3}, Landroid/os/Bundle;-><init>()V
    const-string v2, "k"
    invoke-virtual {v3, v2, v0}, Landroid/os/Bundle;->putString(Ljava/lang/String;Ljava/lang/String;)V
    new-instance v1, Landroid/content/Intent;
    const-string v2, "com.example.app.DO"
    invoke-direct {v1, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    invoke-virtual {v1, v3}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;
    invoke-virtual {p0, v1}, Lcom/example/app/Sender;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    return-void
.end method
""" % READ_INPUT

DYNAMIC_SEND = """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    new-instance v1, Lcom/example/app/Recv;
    invoke-direct {v1}, Lcom/example/app/Recv;-><init>()V
    new-instance v2, Landroid/content/IntentFilter;
    const-string v3, "com.example.app.PING"
    invoke-direct {v2, v3}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V
    invoke-virtual {p0, v1, v2}, Lcom/example/app/Sender;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;
%s
    new-instance v1, Landroid/content/Intent;
    invoke-direct {v1}, Landroid/content/Intent;-><init>()V
    const-string v2, "com.example.app.PING"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;
    move-result-object v1
    const-string v2, "q"
    invoke-virtual {v1, v2, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    invoke-virtual {p0, v1}, Lcom/example/app/Sender;->sendBroadcast(Landroid/content/Intent;)V
    return-void
.end method
""" % READ_INPUT

# Receiver activity: getCharSequenceExtra is not a plain source.
RECEIVER_CS = """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    invoke-virtual {p0}, Lcom/example/app/Receiver;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "q"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getCharSequenceExtra(Ljava/lang/String;)Ljava/lang/CharSequence;
    move-result-object v0
    invoke-interface {v0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;
    move-result-object v0
    const/4 v2, 0x0
    invoke-virtual {v2, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
    return-void
.end method
"""

# Receiver activity: getStringExtra is already a plain source.
RECEIVER_STR = RECEIVER_CS.replace(
    'getCharSequenceExtra(Ljava/lang/String;)Ljava/lang/CharSequence;',
    'getStringExtra(Ljava/lang/String;)Ljava/lang/String;')

SERVICE = """
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 3
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;
    move-result-object v0
    const-string v1, "k"
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->get(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Ljava/lang/String;
    const/4 v2, 0x0
    invoke-virtual {v2, v0, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    const/4 v0, 0x1
    return v0
.end method
"""

RECV = """
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 3
    const-string v1, "q"
    invoke-virtual {p2, v1}, Landroid/content/Intent;->getCharSequenceExtra(Ljava/lang/String;)Ljava/lang/CharSequence;
    move-result-object v0
    invoke-interface {v0}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;
    move-result-object v0
    const/4 v2, 0x0
    invoke-virtual {v2, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
    return-void
.end method
"""


def _cls(name, sup, *methods):
    text = '.class public L%s/%s;\n.super %s\n\n' % (PKG, name, sup)
    return text + '\n'.join(m.strip('\n') + '\n' for m in (INIT,) + methods)


def _write(tmp_path, classes, manifest=MANIFEST):
    decoded = tmp_path / 'decoded'
    root = decoded / 'smali' / PKG
    root.mkdir(parents=True)
    if manifest:
        (decoded / 'AndroidManifest.xml').write_text(manifest)
    for name, (sup, methods) in classes.items():
        (root / (name + '.smali')).write_text(_cls(name, sup, *methods))
    return str(decoded)


ACT = 'Landroid/app/Activity;'


def _in(findings, cls):
    return [f for f in findings if f['component'] == 'com.example.app.' + cls]


def test_explicit_intent_to_non_exported_activity(tmp_path):
    decoded = _write(tmp_path, {'Sender': (ACT, [EXPLICIT_SEND]),
                                'Receiver': (ACT, [RECEIVER_CS])})
    found = _in(taint_analyzer.analyze(decoded), 'Receiver')
    assert len(found) == 1
    f = found[0]
    assert f['pattern'] == 'taint:icc:getCharSequenceExtra->execSQL'
    assert f['cwe'] == 'CWE-89'
    assert f['confidence'] == 'medium'
    assert f['file'].endswith('Receiver.smali')
    assert f['evidence'].startswith(
        'icc com.example.app.Sender.onCreate L')
    assert '(startActivity) -> com.example.app.Receiver | source L' in f['evidence']


def test_sender_flow_still_reported(tmp_path):
    decoded = _write(tmp_path, {'Sender': (ACT, [EXPLICIT_SEND]),
                                'Receiver': (ACT, [RECEIVER_CS])})
    sent = _in(taint_analyzer.analyze(decoded), 'Sender')
    assert [f['pattern'] for f in sent] == ['taint:getText->startActivity']


def test_implicit_intent_bundle_extras_to_service(tmp_path):
    decoded = _write(tmp_path, {'Sender': (ACT, [IMPLICIT_SEND]),
                                'Svc': ('Landroid/app/Service;', [SERVICE])})
    found = _in(taint_analyzer.analyze(decoded), 'Svc')
    assert len(found) == 1
    assert found[0]['pattern'] == 'taint:icc:getExtras->rawQuery'
    assert '(startService) -> com.example.app.Svc' in found[0]['evidence']


def test_dynamic_receiver_by_action(tmp_path):
    decoded = _write(tmp_path, {
        'Sender': (ACT, [DYNAMIC_SEND]),
        'Recv': ('Landroid/content/BroadcastReceiver;', [RECV])})
    found = _in(taint_analyzer.analyze(decoded), 'Recv')
    assert len(found) == 1
    assert found[0]['pattern'] == 'taint:icc:getCharSequenceExtra->execSQL'
    assert '(sendBroadcast) -> com.example.app.Recv' in found[0]['evidence']


def test_untainted_intent_adds_nothing(tmp_path):
    decoded = _write(tmp_path, {'Sender': (ACT, [CONSTANT_SEND]),
                                'Receiver': (ACT, [RECEIVER_CS])})
    assert taint_analyzer.analyze(decoded) == []


def test_unmatched_action_adds_nothing(tmp_path):
    send = IMPLICIT_SEND.replace('"com.example.app.DO"', '"com.example.app.NONE"')
    decoded = _write(tmp_path, {'Sender': (ACT, [send]),
                                'Svc': ('Landroid/app/Service;', [SERVICE])})
    assert _in(taint_analyzer.analyze(decoded), 'Svc') == []


def test_existing_sink_not_duplicated(tmp_path):
    decoded = _write(tmp_path, {'Sender': (ACT, [EXPLICIT_SEND]),
                                'Receiver': (ACT, [RECEIVER_STR])})
    found = _in(taint_analyzer.analyze(decoded), 'Receiver')
    assert len(found) == 1
    assert found[0]['pattern'] == 'taint:getStringExtra->execSQL'
    assert found[0]['confidence'] == 'high'


def test_no_manifest_still_resolves_explicit(tmp_path):
    decoded = _write(tmp_path, {'Sender': (ACT, [EXPLICIT_SEND]),
                                'Receiver': (ACT, [RECEIVER_CS])}, manifest=None)
    found = _in(taint_analyzer.analyze(decoded), 'Receiver')
    assert [f['pattern'] for f in found] == ['taint:icc:getCharSequenceExtra->execSQL']
