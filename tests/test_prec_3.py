"""P-3: empty_trustmanager context. Synthetic smali shaped after
CheckValidity-InformationExposure-Lean (Secure: empty checkClientTrusted,
checkServerTrusted that calls checkValidity and throws) and
InsecureSSLSocket-MITM-Lean (both methods empty)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import code_analyzer  # noqa: E402

MANIFEST = ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
            '<application/></manifest>')
SIG = '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V'
EMPTY = '    return-void'


def _tm(client, server):
    m = ''
    for name, body in (('checkClientTrusted', client), ('checkServerTrusted', server)):
        if body is not None:
            m += '.method public %s%s\n    .locals 3\n%s\n.end method\n\n' % (name, SIG, body)
    return ('.class public La/b/TM;\n.super Ljava/lang/Object;\n'
            '.implements Ljavax/net/ssl/X509TrustManager;\n\n' + m)


def _found(tmp_path, client, server):
    (tmp_path / 'smali' / 'a' / 'b').mkdir(parents=True)
    (tmp_path / 'smali' / 'a' / 'b' / 'TM.smali').write_text(_tm(client, server), encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    return sorted((f['confidence'], f['evidence'].split('(')[0].split()[-1])
                  for f in code_analyzer.analyze(str(tmp_path))
                  if f['pattern'] == 'empty_trustmanager')


CHECKS = """    if-eqz p1, :cond_0
    const/4 v0, 0x0
    aget-object v1, p1, v0
    invoke-virtual {v1}, Ljava/security/cert/X509Certificate;->checkValidity()V
    return-void
    :cond_0
    new-instance v0, Ljava/lang/RuntimeException;
    const-string v1, "Empty Certificate Chain"
    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V
    throw v0"""

DELEGATE_RETHROW = """    :try_start_0
    iget-object v0, p0, La/b/TM;->d:Ljavax/net/ssl/X509TrustManager;
    invoke-interface {v0, p1, p2}, Ljavax/net/ssl/X509TrustManager;->checkServerTrusted%s
    :try_end_0
    .catch Ljava/security/cert/CertificateException; {:try_start_0 .. :try_end_0} :catch_0
    return-void
    :catch_0
    move-exception v1
    throw v1""" % SIG

DELEGATE_SWALLOW = """    :try_start_0
    iget-object v0, p0, La/b/TM;->d:Ljavax/net/ssl/X509TrustManager;
    invoke-interface {v0, p1, p2}, Ljavax/net/ssl/X509TrustManager;->checkServerTrusted%s
    :try_end_0
    .catch Ljava/security/cert/CertificateException; {:try_start_0 .. :try_end_0} :catch_0
    return-void
    :catch_0
    move-exception v1
    invoke-virtual {v1}, Ljava/lang/Exception;->printStackTrace()V
    return-void""" % SIG

NO_THROW = """    const-string v0, "TM"
    const-string v1, "server"
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void"""


def test_both_empty_high(tmp_path):
    assert _found(tmp_path, EMPTY, EMPTY) == [('high', 'checkClientTrusted'),
                                              ('high', 'checkServerTrusted')]


def test_empty_client_with_checking_server_low(tmp_path):
    assert _found(tmp_path, EMPTY, CHECKS) == [('low', 'checkClientTrusted')]


def test_delegate_rethrow_propagates(tmp_path):
    assert _found(tmp_path, EMPTY, DELEGATE_RETHROW) == [('low', 'checkClientTrusted')]


def test_delegate_swallowed_is_not_a_check(tmp_path):
    # The CertificateException is caught and the method returns: no path throws.
    assert _found(tmp_path, EMPTY, DELEGATE_SWALLOW) == [('high', 'checkClientTrusted'),
                                                         ('medium', 'checkServerTrusted')]


def test_server_code_without_throw_medium(tmp_path):
    assert _found(tmp_path, None, NO_THROW) == [('medium', 'checkServerTrusted')]


def test_client_only_class_high(tmp_path):
    # No checkServerTrusted body to vouch for the class: the empty client check stays high.
    assert _found(tmp_path, EMPTY, None) == [('high', 'checkClientTrusted')]
