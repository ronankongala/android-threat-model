"""P1-2: fragment_injection (CWE-470).

Fixture: the Benign api27 APK of ICC/FragmentInjection-PrivEscalation-Lean
(skipped if not built), which loads a fragment by a name read from an intent
extra. The other tests use synthetic smali in a tmp dir."""
import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import code_analyzer  # noqa: E402

PATTERN = 'fragment_injection'
BENCH = ('ICC', 'FragmentInjection-PrivEscalation-Lean')
APK_REL = ('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
PREF = 'Landroid/preference/PreferenceActivity;'

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application/>
</manifest>
"""

VALID_TRUE = """.method protected isValidFragment(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
"""

VALID_CHECK = """.method protected isValidFragment(Ljava/lang/String;)Z
    .locals 1
    const-string v0, "a.b.SafeFragment"
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    return v0
.end method
"""


def _cls(name, sup, methods=''):
    return """.class public L{name};
.super {sup}

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, {sup}-><init>()V
    return-void
.end method

{methods}""".format(name=name, sup=sup, methods=methods)


def _build(tmp_path, classes, target_sdk=None):
    """classes: {slash name: smali text}."""
    for name, text in classes.items():
        path = tmp_path / 'smali' / (name + '.smali')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    if target_sdk is not None:
        (tmp_path / 'apktool.yml').write_text(
            "sdkInfo:\n  minSdkVersion: '15'\n  targetSdkVersion: '%d'\n" % target_sdk,
            encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == PATTERN]


def test_preference_activity_without_check_flagged(tmp_path):
    found = _build(tmp_path, {'a/b/Settings': _cls('a/b/Settings', PREF)})
    assert len(found) == 1
    f = found[0]
    assert f['component'] == 'a.b.Settings'
    assert f['component_type'] == 'class'
    assert f['cwe'] == 'CWE-470'
    assert f['confidence'] == 'high'
    assert f['line'] == 2
    assert f['evidence'] == '.super ' + PREF


def test_target_sdk_19_lowers_confidence(tmp_path):
    found = _build(tmp_path, {'a/b/Settings': _cls('a/b/Settings', PREF)}, target_sdk=27)
    assert [f['confidence'] for f in found] == ['medium']


def test_preference_activity_through_app_superclass(tmp_path):
    classes = {'a/b/Base': _cls('a/b/Base', PREF),
               'a/b/Child': _cls('a/b/Child', 'La/b/Base;')}
    assert sorted(f['component'] for f in _build(tmp_path, classes)) == ['a.b.Base', 'a.b.Child']


def test_check_in_superclass_counts(tmp_path):
    classes = {'a/b/Base': _cls('a/b/Base', PREF, VALID_CHECK),
               'a/b/Child': _cls('a/b/Child', 'La/b/Base;')}
    assert _build(tmp_path, classes) == []


def test_real_check_not_flagged(tmp_path):
    assert _build(tmp_path, {'a/b/S': _cls('a/b/S', PREF, VALID_CHECK)}) == []


def test_always_true_check_flagged_medium(tmp_path):
    found = _build(tmp_path, {'a/b/S': _cls('a/b/S', PREF, VALID_TRUE)})
    assert [f['confidence'] for f in found] == ['medium']
    assert 'isValidFragment' in found[0]['evidence']


def test_non_preference_activity_ignored(tmp_path):
    assert _build(tmp_path, {'a/b/S': _cls('a/b/S', 'Landroid/app/Activity;')}) == []


LOAD = """.method public onResume()V
    .locals 2
    invoke-virtual {p0}, La/b/Main;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "fname"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
%s
    invoke-static {p0, v0}, Landroid/app/Fragment;->instantiate(Landroid/content/Context;Ljava/lang/String;)Landroid/app/Fragment;
    return-void
.end method
"""

CHECK_CALL = """    invoke-direct {p0, v0}, La/b/Main;->isValidName(Ljava/lang/String;)Z"""


def test_fragment_from_intent_name_flagged(tmp_path):
    found = _build(tmp_path, {'a/b/Main': _cls('a/b/Main', 'Landroid/app/Activity;', LOAD % '')})
    assert len(found) == 1
    assert found[0]['confidence'] == 'medium'
    assert 'Fragment;->instantiate' in found[0]['evidence']


def test_fragment_from_intent_name_with_check_not_flagged(tmp_path):
    found = _build(tmp_path, {'a/b/Main': _cls('a/b/Main', 'Landroid/app/Activity;',
                                               LOAD % CHECK_CALL)})
    assert found == []


@pytest.fixture(scope='module')
def decoded_bench():
    root = tempfile.mkdtemp(prefix='ate-p12-')
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


def test_benign_fixture_flagged(decoded_bench):
    found = [f for f in code_analyzer.analyze(decoded_bench('Benign')) if f['pattern'] == PATTERN]
    assert found
    assert any('getFragmentInstance' in f['evidence'] for f in found)


def test_secure_fixture_reported(decoded_bench):
    # Reported only: the Secure app checks the name with isValidFragment.
    found = [f for f in code_analyzer.analyze(decoded_bench('Secure')) if f['pattern'] == PATTERN]
    print('Secure FragmentInjection flagged: %s' % bool(found))
