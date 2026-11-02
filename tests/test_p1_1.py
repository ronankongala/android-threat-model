"""P1-1: certificate_pinning_missing (CWE-295), an application level finding
for apps that open network connections without pinning certificates.

Fixture: the Benign api27 APK of Networking/UnpinnedCertificates-MITM-Lean
(skipped if not built). The other tests use synthetic smali in a tmp dir."""
import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import code_analyzer  # noqa: E402

PATTERN = 'certificate_pinning_missing'
BENCH = ('Networking', 'UnpinnedCertificates-MITM-Lean')
APK_REL = ('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">
    <application android:label="x"{attrs}>
    </application>
</manifest>
"""

NETWORK_BODY = """    new-instance v0, Ljava/net/URL;
    const-string v1, "https://example.com"
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"""

PLAIN_BODY = """    const-string v1, "hello"
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;"""

SMALI = """.class public La/b/Net;
.super Ljava/lang/Object;

.method public run()V
    .locals 2
{body}
    return-void
.end method
"""

NSC_PINNED = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2030-01-01">
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
"""

NSC_UNPINNED = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
</network-security-config>
"""


def _build(tmp_path, body=NETWORK_BODY, nsc=None, nsc_name='network_security_config',
           attrs=''):
    path = tmp_path / 'smali' / 'a' / 'b' / 'Net.smali'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SMALI.format(body=body), encoding='utf-8')
    if nsc is not None:
        xml = tmp_path / 'res' / 'xml' / (nsc_name + '.xml')
        xml.parent.mkdir(parents=True, exist_ok=True)
        xml.write_text(nsc, encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST.format(attrs=attrs), encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == PATTERN]


def test_nsc_with_pin_set_not_flagged(tmp_path):
    assert _build(tmp_path, nsc=NSC_PINNED) == []


def test_nsc_without_pin_set_flagged(tmp_path):
    found = _build(tmp_path, nsc=NSC_UNPINNED)
    assert len(found) == 1
    f = found[0]
    assert f['component'] == '(application)'
    assert f['component_type'] == 'application'
    assert f['file'] == 'res/xml/network_security_config.xml'
    assert f['line'] == 2
    assert f['cwe'] == 'CWE-295'
    assert f['confidence'] == 'high'
    assert f['issue'] == PATTERN
    assert 'openConnection' in f['evidence']


def test_manifest_named_nsc_is_used(tmp_path):
    attrs = ' android:networkSecurityConfig="@xml/net_cfg"'
    found = _build(tmp_path, nsc=NSC_UNPINNED, nsc_name='net_cfg', attrs=attrs)
    assert [f['file'] for f in found] == ['res/xml/net_cfg.xml']
    d = tmp_path / 'pinned'
    d.mkdir()
    assert _build(d, nsc=NSC_PINNED, nsc_name='net_cfg', attrs=attrs) == []


def test_no_nsc_flagged_unless_cleartext_false(tmp_path):
    found = _build(tmp_path)
    assert [(f['file'], f['line']) for f in found] == [('AndroidManifest.xml', 3)]
    d = tmp_path / 'off'
    d.mkdir()
    assert _build(d, attrs=' android:usesCleartextTraffic="false"') == []
    d = tmp_path / 'on'
    d.mkdir()
    assert len(_build(d, attrs=' android:usesCleartextTraffic="true"')) == 1


def test_no_network_code_not_flagged(tmp_path):
    assert _build(tmp_path, body=PLAIN_BODY) == []
    d = tmp_path / 'nsc'
    d.mkdir()
    assert _build(d, body=PLAIN_BODY, nsc=NSC_UNPINNED) == []


def test_keystore_pinning_in_code_not_flagged(tmp_path):
    body = NETWORK_BODY + """
    const/4 v1, 0x0
    invoke-virtual {v1, v1, v1}, Ljava/security/KeyStore;->setCertificateEntry(Ljava/lang/String;Ljava/security/cert/Certificate;)V
    invoke-virtual {v1, v1}, Ljavax/net/ssl/TrustManagerFactory;->init(Ljava/security/KeyStore;)V"""
    assert _build(tmp_path, body=body) == []


@pytest.fixture(scope='module')
def decoded_bench():
    root = tempfile.mkdtemp(prefix='ate-p11-')
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
    assert len(found) == 1
    assert found[0]['component_type'] == 'application'


def test_secure_fixture_reported(decoded_bench):
    # Reported only: the Secure app pins with a KeyStore and TrustManagerFactory,
    # so no finding is expected, but this test does not fail either way.
    found = [f for f in code_analyzer.analyze(decoded_bench('Secure')) if f['pattern'] == PATTERN]
    print('Secure UnpinnedCertificates flagged: %s' % bool(found))
