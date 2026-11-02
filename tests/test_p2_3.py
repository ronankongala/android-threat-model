"""P2-3: webview_js_interface (CWE-749), sensitive methods of an object
exposed to JavaScript with WebView.addJavascriptInterface.

Synthetic smali in a tmp dir. The Web benchmarks that call
addJavascriptInterface (WebView-NoUserPermission-InformationExposure-Lean and
WebViewInterceptRequest-MITM-Lean) expose location and SharedPreferences
reads, which are not in the sensitive list, so they are checked here only to
report (not assert) what the rule does on them."""
import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import code_analyzer  # noqa: E402

PATTERN = 'webview_js_interface'
APK_REL = ('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
WEB_BENCHES = ('WebView-NoUserPermission-InformationExposure-Lean', 'WebViewInterceptRequest-MITM-Lean')

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application/>
</manifest>
"""

ANNOT = """    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
"""

ACTIVITY = """.class public La/b/Main;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 3
    const/4 v0, 0x0
{create}
    const-string v2, "Bridge"
    invoke-virtual {{v0, v1, v2}}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    return-void
.end method
{extra}"""

NEW_BRIDGE = """    new-instance v1, La/b/Bridge;
    invoke-direct {v1}, La/b/Bridge;-><init>()V"""

BRIDGE = """.class public La/b/Bridge;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

{methods}"""


def _method(name, body, annotated=True, access='public'):
    return """.method %s %s()V
    .locals 2
%s%s
    return-void
.end method
""" % (access, name, ANNOT if annotated else '', body)


READ_FILE = """    new-instance v0, Ljava/io/FileInputStream;
    const-string v1, "/sdcard/x"
    invoke-direct {v0, v1}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V"""
START = """    const/4 v0, 0x0
    invoke-virtual {p0, v0}, La/b/Bridge;->startActivity(Landroid/content/Intent;)V"""
QUERY = """    const/4 v0, 0x0
    invoke-virtual {v0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V"""
NET = """    const/4 v0, 0x0
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"""
HARMLESS = """    const-string v0, "x"
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;"""
HELPER_CALL = """    invoke-direct {p0}, La/b/Bridge;->helper()V"""


def _build(tmp_path, bridge_methods, create=NEW_BRIDGE, extra='', min_sdk=None):
    files = {'a/b/Main': ACTIVITY.format(create=create, extra=extra),
             'a/b/Bridge': BRIDGE.format(methods=bridge_methods)}
    for name, text in files.items():
        path = tmp_path / 'smali' / (name + '.smali')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    if min_sdk is not None:
        (tmp_path / 'apktool.yml').write_text(
            "sdkInfo:\n  minSdkVersion: '%d'\n  targetSdkVersion: '27'\n" % min_sdk, encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == PATTERN]


def test_each_sensitive_kind_flagged(tmp_path):
    methods = ''.join(_method(n, b) for n, b in (
        ('readFile', READ_FILE), ('launch', START), ('sql', QUERY), ('fetch', NET),
        ('harmless', HARMLESS)))
    found = _build(tmp_path, methods)
    names = sorted(f['evidence'].split()[-1].split('(')[0] for f in found)
    assert names == ['fetch', 'launch', 'readFile', 'sql']
    f = found[0]
    assert f['component'] == 'a.b.Bridge'
    assert f['component_type'] == 'class'
    assert f['cwe'] == 'CWE-749'
    assert f['confidence'] == 'high'
    lines = (tmp_path / 'smali' / 'a' / 'b' / 'Bridge.smali').read_text().splitlines()
    assert lines[f['line'] - 1].strip() == f['evidence']


def test_one_level_call_followed(tmp_path):
    methods = _method('run', HELPER_CALL) + _method('helper', READ_FILE, annotated=False,
                                                    access='private')
    found = _build(tmp_path, methods)
    assert [f['evidence'] for f in found] == ['.method public run()V']


def test_unannotated_method_only_on_old_min_sdk(tmp_path):
    methods = _method('readFile', READ_FILE, annotated=False)
    assert _build(tmp_path, methods) == []
    d = tmp_path / 'old'
    d.mkdir()
    assert len(_build(d, methods, min_sdk=16)) == 1


def test_no_interface_call_no_finding(tmp_path):
    methods = _method('readFile', READ_FILE)
    found = _build(tmp_path, methods, create='    const/4 v1, 0x0')
    # The object is unknown (null), so annotated app classes are checked.
    assert len(found) == 1
    d = tmp_path / 'none'
    d.mkdir()
    path = d / 'smali' / 'a' / 'b' / 'Bridge.smali'
    path.parent.mkdir(parents=True)
    path.write_text(BRIDGE.format(methods=methods), encoding='utf-8')
    (d / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    assert [f for f in code_analyzer.analyze(str(d)) if f['pattern'] == PATTERN] == []


def test_this_as_interface(tmp_path):
    extra = _method('readFile', READ_FILE).replace('La/b/Bridge;', 'La/b/Main;')
    found = _build(tmp_path, '', create='    move-object v1, p0', extra=extra)
    assert [f['component'] for f in found] == ['a.b.Main']


@pytest.fixture(scope='module')
def decoded_bench():
    root = tempfile.mkdtemp(prefix='ate-p23-')
    cache = {}

    def get(bench, variant):
        path = os.path.join(ROOT, 'benchmarks', 'ghera', 'Web', bench, variant, *APK_REL)
        if not os.path.exists(path):
            pytest.skip('fixture APK not built: %s' % os.path.relpath(path, ROOT))
        if (bench, variant) not in cache:
            work = os.path.join(root, '%d' % len(cache))
            os.makedirs(work)
            cache[bench, variant] = apk.decode(path, work)['decoded_dir']
        return cache[bench, variant]
    yield get
    shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize('bench', WEB_BENCHES)
def test_web_benchmarks_reported(bench, decoded_bench):
    for variant in ('Benign', 'Secure'):
        found = [f for f in code_analyzer.analyze(decoded_bench(bench, variant))
                 if f['pattern'] == PATTERN]
        print('%s %s webview_js_interface findings: %d' % (bench, variant, len(found)))
