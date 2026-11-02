"""A2-5: clipboard_sensitive (CWE-200, medium) with layout analysis. Password
fields are read from res/layout*/*.xml (inputType *Password or
password="true"), mapped to resource ints with res/values/public.xml, and the
text of findViewById(id) -> getText -> toString is followed to
ClipData.newPlainText and setPrimaryClip. Synthetic decoded folders in a tmp
dir, plus System/ClipboardUse-InformationExposure-Lean (skipped if not built)."""
import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import code_analyzer  # noqa: E402

PATTERN = 'clipboard_sensitive'
BENCH = ('System', 'ClipboardUse-InformationExposure-Lean')
APK_REL = ('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application/>
</manifest>
"""

LAYOUT = """<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android">
    <EditText android:id="@id/pwd" %s />
    <EditText android:id="@id/name" android:inputType="text" />
</LinearLayout>
"""

PUBLIC = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <public type="layout" name="main" id="0x7f0a0001" />
    <public type="id" name="pwd" id="0x7f070010" />
    <public type="id" name="name" id="0x7f070011" />
</resources>
"""

COPY = """    invoke-virtual {v0}, Landroid/widget/EditText;->getText()Landroid/text/Editable;
    move-result-object v1
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v1
    const-string v2, "label"
    invoke-static {v2, v1}, Landroid/content/ClipData;->newPlainText(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;
    move-result-object v1
    const-string v2, "clipboard"
    invoke-virtual {p0, v2}, La/b/Main;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v2
    check-cast v2, Landroid/content/ClipboardManager;
    invoke-virtual {v2, v1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V"""

SAME_METHOD = """.class public La/b/Main;
.super Landroid/app/Activity;

.method public copy()V
    .locals 3
    const v0, %s
    invoke-virtual {p0, v0}, La/b/Main;->findViewById(I)Landroid/view/View;
    move-result-object v0
    check-cast v0, Landroid/widget/EditText;
""" + COPY + """
    return-void
.end method
"""

VIA_FIELD = """.class public La/b/Main;
.super Landroid/app/Activity;

.field private et:Landroid/widget/EditText;

.method public onClick()V
    .locals 3
    iget-object v0, p0, La/b/Main;->et:Landroid/widget/EditText;
""" + COPY + """
    return-void
.end method

.method public onCreate()V
    .locals 1
    const v0, 0x7f070010
    invoke-virtual {p0, v0}, La/b/Main;->findViewById(I)Landroid/view/View;
    move-result-object v0
    check-cast v0, Landroid/widget/EditText;
    iput-object v0, p0, La/b/Main;->et:Landroid/widget/EditText;
    return-void
.end method
"""


def _run(tmp_path, smali, attrs='android:inputType="textPassword"'):
    files = {
        os.path.join('smali', 'a', 'b', 'Main.smali'): smali,
        os.path.join('res', 'layout', 'main.xml'): LAYOUT % attrs,
        os.path.join('res', 'values', 'public.xml'): PUBLIC,
        'AndroidManifest.xml': MANIFEST,
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == PATTERN]


def _named(hits):
    return [f for f in hits if "password field 'pwd'" in f['evidence']]


def test_password_fields_parsed(tmp_path):
    _run(tmp_path, SAME_METHOD % '0x7f070010')
    fields = code_analyzer._password_fields(str(tmp_path))
    assert list(fields) == [0x7f070010]
    assert "'pwd'" in fields[0x7f070010] and 'textPassword' in fields[0x7f070010]


def test_password_field_to_clipboard(tmp_path):
    named = _named(_run(tmp_path, SAME_METHOD % '0x7f070010'))
    assert len(named) == 2   # newPlainText and setPrimaryClip
    for f in named:
        assert f['cwe'] == 'CWE-200'
        assert f['confidence'] == 'medium'
        assert f['component'] == 'a.b.Main'
    assert any('newPlainText' in f['evidence'] and 'put in ClipData' in f['evidence']
               for f in named)
    assert any('setPrimaryClip' in f['evidence'] and 'copied to the clipboard' in f['evidence']
               for f in named)


@pytest.mark.parametrize('attrs', ['android:inputType="numberPassword"',
                                   'android:inputType="text|textWebPassword"',
                                   'android:password="true"'])
def test_other_password_attributes(tmp_path, attrs):
    assert len(_named(_run(tmp_path, SAME_METHOD % '0x7f070010', attrs))) == 2


def test_plain_field_keeps_old_behavior(tmp_path):
    hits = _run(tmp_path, SAME_METHOD % '0x7f070011')
    assert _named(hits) == []
    # The existing input field rule still reports the setPrimaryClip.
    assert len(hits) == 1
    assert hits[0]['evidence'].endswith('setPrimaryClip(Landroid/content/ClipData;)V')


def test_view_kept_in_field(tmp_path):
    named = _named(_run(tmp_path, VIA_FIELD))
    assert len(named) == 2


@pytest.fixture(scope='module')
def decoded_bench():
    root = tempfile.mkdtemp(prefix='ate-a25-')
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
    # The SSN field is a plain EditText (no password inputType), so only the
    # existing input field rule fires on Benign, and nothing on Secure.
    benign = decoded_bench('Benign')
    assert code_analyzer._password_fields(benign) == {}
    hits = [f for f in code_analyzer.analyze(benign) if f['pattern'] == PATTERN]
    assert [f['component'] for f in hits] == ['edu.ksu.cs.benign.MainActivity$1']
    secure = decoded_bench('Secure')
    assert [f for f in code_analyzer.analyze(secure) if f['pattern'] == PATTERN] == []
