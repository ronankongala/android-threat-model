"""A4-2: rules from the miss analysis (docs/notes/miss-analysis.md).

Synthetic smali and manifests in a tmp dir, one Benign-like and one
Secure-like fixture per rule, shaped after the Ghera benchmark each rule
targets:
  default-task-affinity        TaskAffinity-LauncherActivity-PhishingAttack-Lean,
                               TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean
  null_deref_intent_extra      UnhandledException-DOS-Lean
  keystore_entry_unprotected   ExposedCredentials-InformationExposure-Lean
  server_socket_no_peer_check  OpenSocket-InformationLeak-Lean
  external_storage_io          ExternalStorage-DataInjection-Lean,
                               ExternalStorage-InformationLeak-Lean
  webview_ssl_proceed          WebViewIgnoreSSLWarning-MITM-Lean
  webview_override_allows_all  WebViewOverrideUrl-MITM-Lean
  webview_file_url_access      WebViewAllowFileAccess-UnauthorizedFileAccess-Lean
  taint CWE-927 (implicit startActivity)  HighPriority-ActivityHijack-Lean
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import code_analyzer  # noqa: E402
import surface  # noqa: E402
import taint_analyzer  # noqa: E402

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application{app_attrs}>
        <activity android:name="a.b.Main"{act_attrs}>
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="a.b.Other"{other_attrs}/>
    </application>
</manifest>
"""


def _manifest(tmp_path, app_attrs='', act_attrs='', other_attrs=''):
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(MANIFEST.format(app_attrs=app_attrs, act_attrs=act_attrs,
                                    other_attrs=other_attrs), encoding='utf-8')
    return str(path)


def _class(name, methods, sup='Ljava/lang/Object;'):
    return '.class public L%s;\n.super %s\n\n%s' % (name, sup, methods)


def _method(sig, body, locals_=6):
    return '.method public %s\n    .locals %d\n%s\n.end method\n\n' % (sig, locals_, body)


def _build(tmp_path, classes, **manifest):
    for name, text in classes.items():
        path = tmp_path / 'smali' / (name + '.smali')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    _manifest(tmp_path, **manifest)
    return str(tmp_path)


def _found(tmp_path, pattern, classes, **manifest):
    d = _build(tmp_path, classes, **manifest)
    return [f for f in code_analyzer.analyze(d) if f['pattern'] == pattern]


# ------------------------------------------------------- default-task-affinity

def _affinity(tmp_path, **manifest):
    man = apk.parse_manifest(_manifest(tmp_path, **manifest))
    return [f for f in surface._manifest_findings(man) if f['issue'] == 'default-task-affinity']


def test_default_task_affinity_fires_without_attribute(tmp_path):
    found = _affinity(tmp_path)
    assert len(found) == 1
    f = found[0]
    assert f['component'] == '(application)'
    assert f['component_type'] == 'application'
    assert f['cwe'] == 'CWE-1021'
    assert f['confidence'] == 'low'
    assert 'a.b.Main' in f['evidence']


def test_default_task_affinity_empty_affinity_is_secure(tmp_path):
    assert _affinity(tmp_path, app_attrs=' android:taskAffinity=""') == []


def test_default_task_affinity_activity_sets_own(tmp_path):
    assert _affinity(tmp_path, other_attrs=' android:taskAffinity=""') == []
    assert _affinity(tmp_path, act_attrs=' android:taskAffinity="a.b.x"') == []


def test_default_task_affinity_needs_launcher(tmp_path):
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(MANIFEST.format(app_attrs='', act_attrs='', other_attrs='')
                    .replace('android.intent.category.LAUNCHER', 'android.intent.category.DEFAULT'),
                    encoding='utf-8')
    man = apk.parse_manifest(str(path))
    assert [f for f in surface._manifest_findings(man) if f['issue'] == 'default-task-affinity'] == []


# ------------------------------------------------------- null_deref_intent_extra

GET_EXTRA = """    invoke-virtual {p0}, La/b/Main;->getIntent()Landroid/content/Intent;
    move-result-object v2
    const-string v4, "s1"
    invoke-virtual {v2, v4}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
"""
DEREF = """    invoke-virtual {v0}, Ljava/lang/String;->length()I
    move-result v5
    return-void"""
NULL_CHECKED = """    if-eqz v0, :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    move-result v5
    :cond_0
    return-void"""
IN_TRY = """    :try_start_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    move-result v5
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0
    return-void
    :catch_0
    move-exception v1
    return-void"""
IN_IO_TRY = IN_TRY.replace('Ljava/lang/NullPointerException;', 'Ljava/io/IOException;')
REASSIGNED = """    const-string v0, "x"
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    move-result v5
    return-void"""
AS_ARGUMENT = """    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z
    move-result v5
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    return-void"""


def _deref(tmp_path, tail, cls='a/b/Main', **manifest):
    body = GET_EXTRA.replace('La/b/Main;->getIntent', 'L%s;->getIntent' % cls) + tail
    classes = {cls: _class(cls, _method('onClick(Landroid/view/View;)V', body),
                           'Landroid/app/Activity;')}
    return _found(tmp_path, 'null_deref_intent_extra', classes, **manifest)


def test_null_deref_unchecked(tmp_path):
    found = _deref(tmp_path, DEREF)
    assert len(found) == 1
    f = found[0]
    assert f['cwe'] == 'CWE-476'
    assert f['confidence'] == 'medium'
    assert f['component'] == 'a.b.Main'
    assert 'String;->length()I' in f['evidence']
    lines = (tmp_path / 'smali' / 'a' / 'b' / 'Main.smali').read_text().splitlines()
    assert lines[f['line'] - 1].strip() == f['evidence']


def test_null_deref_inner_class_of_exported(tmp_path):
    assert len(_deref(tmp_path, DEREF, cls='a/b/Main$1')) == 1


def test_null_deref_not_exported_skipped(tmp_path):
    assert _deref(tmp_path, DEREF, cls='a/b/Other') == []


def test_null_deref_null_check_or_npe_catch(tmp_path):
    for name, tail in (('check', NULL_CHECKED), ('try', IN_TRY), ('reassigned', REASSIGNED),
                       ('isEmpty', AS_ARGUMENT)):
        d = tmp_path / name
        d.mkdir()
        assert _deref(d, tail) == [], name


def test_null_deref_other_catch_still_reported(tmp_path):
    assert len(_deref(tmp_path, IN_IO_TRY)) == 1


# ------------------------------------------------------- keystore_entry_unprotected

SET_ENTRY = """    const/4 v1, 0x0
    invoke-static {}, Ljava/security/KeyStore;->getDefaultType()Ljava/lang/String;
    move-result-object v3
    invoke-static {v3}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;
    move-result-object v3
    invoke-virtual {v3, v1, v1}, Ljava/security/KeyStore;->load(Ljava/io/InputStream;[C)V
    const-string v4, "SECRET_KEY"
    new-instance v5, Ljava/security/KeyStore$SecretKeyEntry;
    invoke-direct {v5, v2}, Ljava/security/KeyStore$SecretKeyEntry;-><init>(Ljavax/crypto/SecretKey;)V
{pp}    invoke-virtual {v3, v4, v5, v1}, Ljava/security/KeyStore;->setEntry(Ljava/lang/String;Ljava/security/KeyStore$Entry;Ljava/security/KeyStore$ProtectionParameter;)V
    return-void"""
PASSWORD = """    new-instance v1, Ljava/security/KeyStore$PasswordProtection;
    invoke-direct {v1, v0}, Ljava/security/KeyStore$PasswordProtection;-><init>([C)V
"""


def _keystore(tmp_path, pp):
    classes = {'a/b/Main': _class('a/b/Main', _method('save()V', SET_ENTRY.replace('{pp}', pp)))}
    return _found(tmp_path, 'keystore_entry_unprotected', classes)


def test_keystore_null_protection(tmp_path):
    found = _keystore(tmp_path, '')
    assert len(found) == 1
    assert found[0]['cwe'] == 'CWE-922'
    assert 'setEntry' in found[0]['evidence']


def test_keystore_password_protection(tmp_path):
    assert _keystore(tmp_path, PASSWORD) == []


# ------------------------------------------------------- server_socket_no_peer_check

SERVER = """    const/16 v0, 0x1f90
    new-instance v1, Ljava/net/ServerSocket;
    invoke-direct {{v1, v0}}, Ljava/net/ServerSocket;-><init>(I)V
    invoke-virtual {{v1}}, Ljava/net/ServerSocket;->accept()Ljava/net/Socket;
    move-result-object v3
{check}    invoke-virtual {{v3}}, Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v4
    return-void"""
PEER = """    invoke-virtual {v3}, Ljava/net/Socket;->getInetAddress()Ljava/net/InetAddress;
    move-result-object v2
"""


def _server(tmp_path, check):
    classes = {'a/b/Svc': _class('a/b/Svc', _method('onHandleIntent(Landroid/content/Intent;)V',
                                                    SERVER.format(check=check)),
                                 'Landroid/app/IntentService;')}
    return _found(tmp_path, 'server_socket_no_peer_check', classes)


def test_server_socket_without_peer_check(tmp_path):
    found = _server(tmp_path, '')
    assert len(found) == 1
    assert found[0]['cwe'] == 'CWE-940'
    assert found[0]['component'] == 'a.b.Svc'
    assert 'ServerSocket;-><init>(I)V' in found[0]['evidence']


def test_server_socket_with_peer_check(tmp_path):
    assert _server(tmp_path, PEER) == []


# ------------------------------------------------------- external_storage_io

EXT_FILE = """    new-instance v0, Ljava/io/File;
    const/4 v2, 0x0
    invoke-virtual {{p0, v2}}, La/b/Main;->{dir}(Ljava/lang/String;)Ljava/io/File;
    move-result-object v1
    const-string v3, "data.txt"
    invoke-direct {{v0, v1, v3}}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
{use}    return-void"""
WRITE = """    new-instance v2, Ljava/io/FileOutputStream;
    invoke-direct {v2, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
"""
READ_BY_PATH = """    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v1
    new-instance v4, Ljava/io/File;
    invoke-direct {v4, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    new-instance v2, Ljava/io/FileReader;
    invoke-direct {v2, v4}, Ljava/io/FileReader;-><init>(Ljava/io/File;)V
"""
ENV_CONCAT = """    invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
    move-result-object v0
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;
    move-result-object v1
    const-string v2, "/x.txt"
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v1
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    new-instance v3, Ljava/io/FileInputStream;
    invoke-direct {v3, v1}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V
    return-void"""


def _external(tmp_path, body):
    classes = {'a/b/Main': _class('a/b/Main', _method('onCreate(Landroid/os/Bundle;)V', body),
                                  'Landroid/app/Activity;')}
    return _found(tmp_path, 'external_storage_io', classes)


def test_external_storage_write_and_read(tmp_path):
    (tmp_path / 'w').mkdir()
    found = _external(tmp_path / 'w', EXT_FILE.format(dir='getExternalFilesDir', use=WRITE))
    assert len(found) == 1
    assert found[0]['cwe'] == 'CWE-922'
    assert 'FileOutputStream' in found[0]['evidence']
    (tmp_path / 'r').mkdir()
    found = _external(tmp_path / 'r', EXT_FILE.format(dir='getExternalFilesDir', use=READ_BY_PATH))
    assert len(found) == 1
    assert 'FileReader' in found[0]['evidence']
    (tmp_path / 'e').mkdir()
    assert len(_external(tmp_path / 'e', ENV_CONCAT)) == 1


def test_internal_storage_not_reported(tmp_path):
    body = EXT_FILE.format(dir='getFilesDir', use=WRITE).replace(
        'getFilesDir(Ljava/lang/String;)', 'getFilesDir()').replace('{p0, v2}', '{p0}')
    assert _external(tmp_path, body) == []


# ------------------------------------------------------- webview_ssl_proceed

SSL_SIG = ('onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;'
           'Landroid/net/http/SslError;)V')
PROCEED = """    const-string v0, "tag"
    invoke-static {v0, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
    return-void"""
CANCEL = PROCEED.replace('proceed()V', 'cancel()V')
COND_PROCEED = """    invoke-virtual {p3}, Landroid/net/http/SslError;->getPrimaryError()I
    move-result v0
    if-nez v0, :cond_0
    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
    :cond_0
    return-void"""


def _client(tmp_path, pattern, methods):
    classes = {'a/b/Client': _class('a/b/Client', methods, 'Landroid/webkit/WebViewClient;')}
    return _found(tmp_path, pattern, classes)


def test_ssl_proceed(tmp_path):
    found = _client(tmp_path, 'webview_ssl_proceed', _method(SSL_SIG, PROCEED))
    assert [(f['cwe'], f['confidence'], f['component']) for f in found] == \
        [('CWE-295', 'high', 'a.b.Client')]


def test_ssl_proceed_after_branch_medium(tmp_path):
    found = _client(tmp_path, 'webview_ssl_proceed', _method(SSL_SIG, COND_PROCEED))
    assert [f['confidence'] for f in found] == ['medium']


def test_ssl_cancel_not_reported(tmp_path):
    assert _client(tmp_path, 'webview_ssl_proceed', _method(SSL_SIG, CANCEL)) == []


# ------------------------------------------------------- webview_override_allows_all

OVR_STR = 'shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z'
OVR_REQ = 'shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z'
RETURN_FALSE = """    const-string v0, "tag"
    invoke-static {v0, p2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    const/4 v0, 0x0
    return v0"""
CHECKED = """    const-string v0, "https://trusted"
    invoke-virtual {p2, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z
    move-result v0
    if-nez v0, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0"""
DELEGATES = """    invoke-direct {p0, p1, p2}, La/b/Client;->check(Landroid/webkit/WebView;Ljava/lang/String;)Z
    move-result v0
    return v0"""


def test_override_returns_false(tmp_path):
    found = _client(tmp_path, 'webview_override_allows_all',
                    _method(OVR_STR, RETURN_FALSE) + _method(OVR_REQ, RETURN_FALSE.replace(
                        'invoke-static {v0, p2}', 'invoke-static {v0, v0}')))
    assert len(found) == 2
    assert {(f['cwe'], f['confidence']) for f in found} == {('CWE-829', 'low')}


def test_override_with_check_not_reported(tmp_path):
    assert _client(tmp_path, 'webview_override_allows_all',
                   _method(OVR_STR, CHECKED) + _method(OVR_REQ, DELEGATES)) == []


# ------------------------------------------------------- webview_file_url_access

SETTINGS = """    const/4 v3, 0x1
    invoke-virtual {{v1, v3}}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
    invoke-virtual {{v1, v3}}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    const/4 v3, {flag}
    invoke-virtual {{v1, v3}}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
    return-void"""


def _settings(tmp_path, flag):
    classes = {'a/b/Main': _class('a/b/Main', _method('onCreate(Landroid/os/Bundle;)V',
                                                      SETTINGS.format(flag=flag)))}
    d = _build(tmp_path, classes)
    return {(f['pattern'], f['cwe'], f['confidence']) for f in code_analyzer.analyze(d)
            if f['pattern'].startswith('webview_file')}


def test_file_url_access_with_js_is_cwe_830(tmp_path):
    assert _settings(tmp_path, '0x1') == {('webview_file_url_access', 'CWE-830', 'high'),
                                          ('webview_file_access', 'CWE-829', 'medium')}


def test_file_url_access_false_stays_829(tmp_path):
    assert _settings(tmp_path, '0x0') == {('webview_file_access', 'CWE-829', 'medium')}


# ------------------------------------------------------- taint: implicit startActivity

START_BODY = """    new-instance v0, Landroid/content/Intent;
{init}    const-string v1, "image"
    invoke-virtual {{p0}}, La/b/Main;->text()Landroid/widget/TextView;
    move-result-object v2
    invoke-virtual {{v2}}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;
    move-result-object v2
    invoke-virtual {{v0, v1, v2}}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/CharSequence;)Landroid/content/Intent;
    invoke-virtual {{p0, v0}}, La/b/Main;->startActivity(Landroid/content/Intent;)V
    return-void"""
IMPLICIT = """    invoke-direct {v0}, Landroid/content/Intent;-><init>()V
    const-string v1, "a.b.imageEditor"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;
"""
EXPLICIT = """    const-class v3, La/b/Other;
    invoke-direct {v0, p0, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
"""
WITH_PACKAGE = IMPLICIT + """    const-string v1, "a.b"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;
"""


def _taint(tmp_path, init):
    classes = {'a/b/Main': _class('a/b/Main', _method('onClick(Landroid/view/View;)V',
                                                      START_BODY.format(init=init)),
                                  'Landroid/app/Activity;')}
    d = _build(tmp_path, classes)
    return [f['cwe'] for f in taint_analyzer.analyze(d) if f['pattern'].endswith('->startActivity')]


def test_implicit_start_activity_is_cwe_927(tmp_path):
    assert _taint(tmp_path, IMPLICIT) == ['CWE-927']


def test_explicit_start_activity_stays_cwe_926(tmp_path):
    assert _taint(tmp_path, EXPLICIT) == ['CWE-926']


def test_start_activity_with_package_stays_cwe_926(tmp_path):
    assert _taint(tmp_path, WITH_PACKAGE) == ['CWE-926']
